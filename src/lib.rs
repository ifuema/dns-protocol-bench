// ============================================================================
// 共享内核 —— DNS wire 格式、五种协议的连接执行器、统一统计口径
//
// 两个二进制共用这一份实现：
//   dns-protocol-bench  固定一台服务器，横比五种「协议」
//   providers           横比各家「服务商」× 各家支持的「协议」矩阵
//
// 之所以抽成库：协议实现（DoT 分帧、DoQ 的 RFC 9250 细节、reqwest 的 h3
// 开关）是最容易写错也最容易过时的部分，绝不该存在两份副本。
//
// 口径约定（两个工具都遵守，见各自 README/注释）：
//   * 统一超时 QUERY_TIMEOUT 包住整次操作，不出现"某个协议每步各算 3 秒"的偏差
//   * hot  = 连接复用（DoH 复用 Client、DoT 复用一条 TLS 连接、DoQ 复用 QUIC 连接）
//     cold = 每条查询重建连接（DoU 除外——UDP 本来无状态）
//   * "空答案"（NOERROR 但无 A 记录）单独计数，不混进成功样本假装很快
//   * 连接出错即丢弃（对齐 mihomo 的真实行为，尤其 DoQ"任何错误都砸连接"）
// ============================================================================

use std::{
    collections::HashMap,
    env, fs,
    io::{IsTerminal, Write},
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use quinn::{ClientConfig as QuicClientConfig, Endpoint as QuicEndpoint};
use rustls::pki_types::ServerName;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{lookup_host, TcpStream, UdpSocket},
};
use tokio_rustls::{client::TlsStream, TlsConnector};

/// 统一超时：整次查询（含冷启动的建连 / 握手）都必须在这个时间内完成。
/// 命令行可以用 --timeout 放宽 —— 有些端点的 TLS 握手确实要好几秒。
pub const QUERY_TIMEOUT: Duration = Duration::from_secs(3);

/// 提前放弃的阈值：在**一次都没成功过**的前提下，连续失败这么多次就认定这个组合死了，
/// 不再把剩下的查询（每次都等满超时）跑完。
///
/// 为什么需要它：cold 口径下一轮全矩阵实测 1566 秒，其中 1260 秒（80%）全花在 7 个
/// "预热就超时"的组合上，每个白等 180 秒，换来的信息只等于"它不通"这一个结论。
/// 一旦已经一次都没成功、又连续失败 8 次（约 24 秒），继续测下去不可能翻盘。
pub const EARLY_ABORT_AFTER: usize = 8;

// ---------------------------------------------------------------------------
// 协议
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Udp,
    Dot,
    Doh,
    Doh3,
    Doq,
}

impl Proto {
    pub fn all() -> [Proto; 5] {
        [Proto::Udp, Proto::Dot, Proto::Doh, Proto::Doh3, Proto::Doq]
    }

    /// 带端口的名字，用在矩阵表头与排名里
    pub fn label(self) -> &'static str {
        match self {
            Proto::Udp => "UDP/53",
            Proto::Dot => "DoT/853",
            Proto::Doh => "DoH-h2",
            Proto::Doh3 => "DoH3",
            Proto::Doq => "DoQ/853",
        }
    }

    /// 不带端口的短名，用在标题行
    pub fn short(self) -> &'static str {
        match self {
            Proto::Udp => "UDP",
            Proto::Dot => "DoT",
            Proto::Doh => "DoH",
            Proto::Doh3 => "DoH3",
            Proto::Doq => "DoQ",
        }
    }

    pub fn is_udp(self) -> bool {
        matches!(self, Proto::Udp)
    }

    pub fn parse(s: &str) -> Option<Proto> {
        match s.trim().to_ascii_lowercase().as_str() {
            "udp" | "plain" => Some(Proto::Udp),
            "dot" | "tls" => Some(Proto::Dot),
            "doh" | "h2" => Some(Proto::Doh),
            "doh3" | "h3" => Some(Proto::Doh3),
            "doq" | "quic" => Some(Proto::Doq),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// 连接口径
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Hot,
    Cold,
}

impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Mode::Hot => "hot（连接复用）",
            Mode::Cold => "cold（每查询重建连接）",
        }
    }

    pub fn short(self) -> &'static str {
        match self {
            Mode::Hot => "hot",
            Mode::Cold => "cold",
        }
    }
}

// ---------------------------------------------------------------------------
// 一个上游端点的描述 —— 与协议解耦，同一个结构能描述任意服务商
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Endpoint {
    /// 明文 UDP 53
    Udp(SocketAddr),
    /// DoT：host:port + 证书校验 / SNI 用的名字
    Dot {
        host: String,
        port: u16,
        sni: String,
    },
    /// DoH：完整 URL；h3=true 时只讲 HTTP/3
    Doh { url: String, h3: bool },
    /// DoQ：host:port + SNI
    Doq {
        host: String,
        port: u16,
        sni: String,
    },
}

impl Endpoint {
    /// 人读的目标描述，用于打印
    pub fn describe(&self) -> String {
        match self {
            Endpoint::Udp(addr) => addr.to_string(),
            Endpoint::Dot { host, port, .. } => format!("{}:{}", host, port),
            Endpoint::Doh { url, h3 } => {
                if *h3 {
                    format!("{} (h3)", url)
                } else {
                    url.clone()
                }
            }
            Endpoint::Doq { host, port, .. } => format!("{}:{}", host, port),
        }
    }
}

// ---------------------------------------------------------------------------
// 错误
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum BenchError {
    Io(String),
    Tls(String),
    Http(String),
    Quic(String),
    BadName(String),
    BadResponse(String),
}

impl BenchError {
    pub fn label(&self) -> &'static str {
        match self {
            BenchError::Io(_) => "io",
            BenchError::Tls(_) => "tls",
            BenchError::Http(_) => "http",
            BenchError::Quic(_) => "quic",
            BenchError::BadName(_) => "bad_name",
            BenchError::BadResponse(_) => "bad_response",
        }
    }

    /// 具体错误内容。只保留第一条用于展示，避免刷屏。
    pub fn detail(&self) -> &str {
        match self {
            BenchError::Io(s)
            | BenchError::Tls(s)
            | BenchError::Http(s)
            | BenchError::Quic(s)
            | BenchError::BadName(s)
            | BenchError::BadResponse(s) => s,
        }
    }

    /// "label: detail" 一行摘要
    pub fn summary(&self) -> String {
        format!("{}: {}", self.label(), self.detail())
    }
}

impl std::fmt::Display for BenchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.summary())
    }
}

impl From<std::io::Error> for BenchError {
    fn from(e: std::io::Error) -> Self {
        BenchError::Io(e.to_string())
    }
}

impl From<reqwest::Error> for BenchError {
    fn from(e: reqwest::Error) -> Self {
        BenchError::Http(e.to_string())
    }
}

pub type R<T> = Result<T, BenchError>;

// ---------------------------------------------------------------------------
// DNS wire 格式：构造查询 + 解析应答
// ---------------------------------------------------------------------------

pub fn build_query(id: u16, domain: &str) -> R<Vec<u8>> {
    let domain = domain.trim().trim_end_matches('.');
    if domain.is_empty() {
        return Err(BenchError::BadName("empty domain".into()));
    }

    let mut packet = Vec::with_capacity(512);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    let mut name_len = 1usize;
    for label in domain.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty()
            || bytes.len() > 63
            || !bytes.is_ascii()
            || name_len + bytes.len() + 1 > 255
        {
            return Err(BenchError::BadName(format!("invalid label in {}", domain)));
        }
        packet.push(bytes.len() as u8);
        packet.extend_from_slice(bytes);
        name_len += bytes.len() + 1;
    }

    packet.push(0);
    packet.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
    packet.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    Ok(packet)
}

/// 返回 (rcode, A 记录)。rcode=3 表示 NXDOMAIN。
pub fn parse_answer(response: &[u8], expect_id: u16) -> R<(u8, Vec<Ipv4Addr>)> {
    if response.len() < 12 {
        return Err(BenchError::BadResponse("short header".into()));
    }

    let response_id = u16::from_be_bytes([response[0], response[1]]);
    let flags = u16::from_be_bytes([response[2], response[3]]);
    if response_id != expect_id || flags & 0x8000 == 0 {
        return Err(BenchError::BadResponse("id/qr mismatch".into()));
    }
    let rcode = (flags & 0x000f) as u8;

    let question_count = u16::from_be_bytes([response[4], response[5]]) as usize;
    let answer_count = u16::from_be_bytes([response[6], response[7]]) as usize;
    let mut offset = 12;

    for _ in 0..question_count {
        offset = skip_name(response, offset)?;
        offset = offset
            .checked_add(4)
            .ok_or_else(|| BenchError::BadResponse("q overflow".into()))?;
        if offset > response.len() {
            return Err(BenchError::BadResponse("q overflow".into()));
        }
    }

    let mut ips = Vec::new();
    for _ in 0..answer_count {
        offset = skip_name(response, offset)?;
        if offset + 10 > response.len() {
            return Err(BenchError::BadResponse("rr overflow".into()));
        }
        let record_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
        let record_class = u16::from_be_bytes([response[offset + 2], response[offset + 3]]);
        let data_len = u16::from_be_bytes([response[offset + 8], response[offset + 9]]) as usize;
        offset += 10;
        if offset + data_len > response.len() {
            return Err(BenchError::BadResponse("rdata overflow".into()));
        }
        if record_type == 1 && record_class == 1 && data_len == 4 {
            ips.push(Ipv4Addr::new(
                response[offset],
                response[offset + 1],
                response[offset + 2],
                response[offset + 3],
            ));
        }
        offset += data_len;
    }

    Ok((rcode, ips))
}

fn skip_name(response: &[u8], mut offset: usize) -> R<usize> {
    let start = offset;
    let mut labels = 0usize;
    loop {
        let len = *response
            .get(offset)
            .ok_or_else(|| BenchError::BadResponse("name truncated".into()))?;

        if len & 0xc0 == 0xc0 {
            let next = *response
                .get(offset + 1)
                .ok_or_else(|| BenchError::BadResponse("name ptr truncated".into()))?;
            let pointer = (((len & 0x3f) as usize) << 8) | next as usize;
            // 只允许向后跳，避免压缩指针成环
            if pointer >= response.len() || pointer >= start || labels > 16 {
                return Err(BenchError::BadResponse("bad name pointer".into()));
            }
            return Ok(offset + 2);
        }
        if len & 0xc0 != 0 {
            return Err(BenchError::BadResponse("bad label len".into()));
        }
        offset += 1;
        if len == 0 {
            return Ok(offset);
        }
        offset = offset
            .checked_add(len as usize)
            .ok_or_else(|| BenchError::BadResponse("label overflow".into()))?;
        if offset > response.len() {
            return Err(BenchError::BadResponse("label overflow".into()));
        }
        labels += 1;
    }
}

// ---------------------------------------------------------------------------
// Runner：一个端点 + 一份连接状态，hot/cold 的差别只体现在这里
// ---------------------------------------------------------------------------

enum Inner {
    Udp(SocketAddr),
    Dot {
        connector: TlsConnector,
        server: SocketAddr,
        sni: ServerName<'static>,
        // 装箱：rustls 的 ClientConnection 内嵌了较大的连接状态缓冲区，
        // 直接放进来会让整个枚举膨胀到 1KB 以上（clippy::large_enum_variant）
        conn: Option<Box<TlsStream<TcpStream>>>,
    },
    Https {
        client: Option<reqwest::Client>,
        url: String,
        h3: bool,
    },
    Doq {
        endpoint: QuicEndpoint,
        config: QuicClientConfig,
        server: SocketAddr,
        sni: String,
        conn: Option<quinn::Connection>,
    },
}

pub struct Runner {
    inner: Inner,
}

impl Runner {
    /// 建立执行器。注意：域名解析（DoT/DoQ 的 host → IP）在这里完成，
    /// 处于计时窗口之外 —— cold 口径测的是"重建连接"，不是"重解析服务器地址"。
    pub async fn new(endpoint: &Endpoint) -> R<Runner> {
        let inner = match endpoint {
            Endpoint::Udp(addr) => Inner::Udp(*addr),
            Endpoint::Dot { host, port, sni } => Inner::Dot {
                connector: build_tls_connector(),
                server: resolve_v4(host, *port).await?,
                sni: build_server_name(sni)?,
                conn: None,
            },
            Endpoint::Doh { url, h3 } => Inner::Https {
                client: Some(build_http_client(*h3)?),
                url: url.clone(),
                h3: *h3,
            },
            Endpoint::Doq { host, port, sni } => Inner::Doq {
                endpoint: build_quic_endpoint()?,
                config: build_quic_config()?,
                server: resolve_v4(host, *port).await?,
                sni: sni.clone(),
                conn: None,
            },
        };
        Ok(Runner { inner })
    }

    /// 跑一次查询，返回 (rcode, A 记录)。
    ///
    /// 取 rcode 而不是只取 IP，是因为"污染/劫持检查"要区分 NXDOMAIN(3) 和
    /// NOERROR(0)+伪造 A 记录 —— 这两者的区别正是整个检查的意义所在。
    pub async fn exchange(&mut self, domain: &str, mode: Mode) -> R<(u8, Vec<Ipv4Addr>)> {
        match &mut self.inner {
            Inner::Udp(server) => udp_exchange(*server, domain).await,
            Inner::Https { client, url, h3 } => {
                if mode == Mode::Cold {
                    let fresh = build_http_client(*h3)?;
                    return https_exchange(&fresh, url, domain, *h3).await;
                }
                if client.is_none() {
                    *client = Some(build_http_client(*h3)?);
                }
                let result = https_exchange(client.as_ref().unwrap(), url, domain, *h3).await;
                if result.is_err() {
                    // 与 mihomo 行为一致：请求失败就丢弃这条客户端，下一次重建
                    *client = None;
                }
                result
            }
            Inner::Dot {
                connector,
                server,
                sni,
                conn,
            } => {
                let need_dial = mode == Mode::Cold || conn.is_none();
                if need_dial {
                    let fresh = dot_connect(connector, *server, sni.clone()).await?;
                    if mode == Mode::Cold {
                        let mut fresh = fresh;
                        return dot_exchange(&mut fresh, domain).await;
                    }
                    *conn = Some(Box::new(fresh));
                }
                let result = dot_exchange(conn.as_mut().unwrap(), domain).await;
                if result.is_err() {
                    *conn = None;
                }
                result
            }
            Inner::Doq {
                endpoint,
                config,
                server,
                sni,
                conn,
            } => {
                let need_connect = mode == Mode::Cold || conn.is_none();
                if need_connect {
                    let fresh = quic_connect(endpoint, config, *server, sni).await?;
                    if mode == Mode::Cold {
                        let result = doq_exchange(&fresh, domain).await;
                        fresh.close(0u32.into(), b"");
                        return result;
                    }
                    *conn = Some(fresh);
                }
                let result = doq_exchange(conn.as_ref().unwrap(), domain).await;
                if result.is_err() {
                    // 与 mihomo 一致：DoQ 上任何错误都会把共享连接一起丢掉，下条查询从握手开始
                    *conn = None;
                }
                result
            }
        }
    }

    /// 主动断开（换目标前调用，避免测 N 家时把连接全堆着）
    pub fn close(&mut self) {
        match &mut self.inner {
            Inner::Udp(_) => {}
            Inner::Dot { conn, .. } => *conn = None,
            Inner::Https { client, .. } => *client = None,
            Inner::Doq { conn, .. } => {
                if let Some(c) = conn.take() {
                    c.close(0u32.into(), b"");
                }
            }
        }
    }
}

async fn resolve_v4(host: &str, port: u16) -> R<SocketAddr> {
    // host 直接是 IP 时不必走系统解析器
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(SocketAddr::from((ip, port)));
    }
    let target = format!("{}:{}", host, port);
    // 先收集成 owned 的 Vec：lookup_host 返回的迭代器借用 target
    let addrs: Vec<SocketAddr> = lookup_host(target.as_str())
        .await
        .map_err(|e| BenchError::Io(format!("resolve {} failed: {}", host, e)))?
        .collect();
    addrs
        .into_iter()
        .find(SocketAddr::is_ipv4)
        .ok_or_else(|| BenchError::Io(format!("no IPv4 for {}", host)))
}

/// rustls 同时启用 ring 与 aws-lc-rs 时，builder() 会因歧义 panic，这里指定默认 provider。
/// 两个二进制都必须在 main 开头调一次。
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn build_tls_connector() -> TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

fn build_server_name(name: &str) -> R<ServerName<'static>> {
    ServerName::try_from(name.to_owned())
        .map_err(|e| BenchError::Tls(format!("bad sni {}: {}", name, e)))
}

fn build_http_client(http3: bool) -> R<reqwest::Client> {
    let mut builder = reqwest::Client::builder();
    // 关键：reqwest 默认会读 HTTP_PROXY / HTTPS_PROXY 环境变量。
    // 一旦走了代理，测到的就是"到代理的延迟"而不是"到 DNS 服务器的延迟"，
    // 基准测试必须直连，所以这里显式禁用代理。
    builder = builder.no_proxy();
    if http3 {
        // 只讲 HTTP/3，不做 alt-svc 发现；请求时还需在 RequestBuilder 上设置 HTTP_3
        builder = builder.http3_prior_knowledge();
    }
    builder.build().map_err(|e| BenchError::Http(e.to_string()))
}

fn build_quic_endpoint() -> R<QuicEndpoint> {
    QuicEndpoint::client("0.0.0.0:0".parse().expect("invalid bind addr"))
        .map_err(|e| BenchError::Quic(e.to_string()))
}

fn build_quic_config() -> R<QuicClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    // DoQ 必须协商 ALPN "doq"（RFC 9250）
    tls.alpn_protocols = vec![b"doq".to_vec()];

    let inner = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls))
        .map_err(|e| BenchError::Quic(format!("tls config: {}", e)))?;
    Ok(QuicClientConfig::new(Arc::new(inner)))
}

// ---------------------------------------------------------------------------
// 各协议的一次交换
// ---------------------------------------------------------------------------

async fn udp_exchange(server: SocketAddr, domain: &str) -> R<(u8, Vec<Ipv4Addr>)> {
    let id = rand::random::<u16>();
    let packet = build_query(id, domain)?;

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.send_to(&packet, server).await?;

    let mut buf = [0u8; 1232];
    let (received, _) = socket.recv_from(&mut buf).await?;
    parse_answer(&buf[..received], id)
}

async fn https_exchange(
    client: &reqwest::Client,
    url: &str,
    domain: &str,
    http3: bool,
) -> R<(u8, Vec<Ipv4Addr>)> {
    let id = rand::random::<u16>();
    let packet = build_query(id, domain)?;

    let mut request = client
        .post(url)
        .header(reqwest::header::ACCEPT, "application/dns-message")
        .header(reqwest::header::CONTENT_TYPE, "application/dns-message");
    if http3 {
        request = request.version(reqwest::Version::HTTP_3);
    }

    let response = request.body(packet).send().await?;
    let status = response.status();
    if !status.is_success() {
        return Err(BenchError::Http(format!("status {}", status.as_u16())));
    }
    let body = response.bytes().await?;
    parse_answer(&body, id)
}

async fn dot_connect(
    connector: &TlsConnector,
    server: SocketAddr,
    sni: ServerName<'static>,
) -> R<TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(server).await?;
    tcp.set_nodelay(true).ok();
    let tls = connector
        .connect(sni, tcp)
        .await
        .map_err(|e| BenchError::Tls(e.to_string()))?;
    Ok(tls)
}

async fn dot_exchange(stream: &mut TlsStream<TcpStream>, domain: &str) -> R<(u8, Vec<Ipv4Addr>)> {
    let id = rand::random::<u16>();
    let packet = build_query(id, domain)?;

    // DoT 走 TCP 分帧：2 字节长度前缀（RFC 7858）
    let mut framed = Vec::with_capacity(packet.len() + 2);
    framed.extend_from_slice(&(packet.len() as u16).to_be_bytes());
    framed.extend_from_slice(&packet);
    stream.write_all(&framed).await?;
    stream.flush().await?;

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let response_len = u16::from_be_bytes(len_buf) as usize;
    let mut response = vec![0u8; response_len];
    stream.read_exact(&mut response).await?;

    parse_answer(&response, id)
}

async fn quic_connect(
    endpoint: &QuicEndpoint,
    config: &QuicClientConfig,
    server: SocketAddr,
    sni: &str,
) -> R<quinn::Connection> {
    // quinn 0.11 的 server_name 形参是 &str（SNI 与证书校验都用它）
    let connecting = endpoint
        .connect_with(config.clone(), server, sni)
        .map_err(|e| BenchError::Quic(e.to_string()))?;
    connecting
        .await
        .map_err(|e| BenchError::Quic(e.to_string()))
}

async fn doq_exchange(connection: &quinn::Connection, domain: &str) -> R<(u8, Vec<Ipv4Addr>)> {
    // RFC 9250：DoQ 的 Message ID 必须为 0，查询与响应的关联由 stream 完成
    let packet = build_query(0, domain)?;

    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|e| BenchError::Quic(e.to_string()))?;

    let mut framed = Vec::with_capacity(packet.len() + 2);
    framed.extend_from_slice(&(packet.len() as u16).to_be_bytes());
    framed.extend_from_slice(&packet);
    send.write_all(&framed)
        .await
        .map_err(|e| BenchError::Quic(e.to_string()))?;
    send.finish().map_err(|e| BenchError::Quic(e.to_string()))?;

    let mut len_buf = [0u8; 2];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|e| BenchError::Quic(e.to_string()))?;
    let response_len = u16::from_be_bytes(len_buf) as usize;
    let mut response = vec![0u8; response_len];
    recv.read_exact(&mut response)
        .await
        .map_err(|e| BenchError::Quic(e.to_string()))?;

    parse_answer(&response, 0)
}

// ---------------------------------------------------------------------------
// 统计
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct Tally {
    pub ok: usize,
    pub empty: usize,
    pub timeout: usize,
    pub errors: HashMap<String, usize>,
    /// 第一条错误的原文，用来解释"为什么这个组合全军覆没"
    pub first_error: Option<String>,
    /// 预热阶段出问题的记录。预热失败意味着"热口径"其实退化成了冷口径
    /// （连接没建起来，每条正式查询都在付建连成本），这是最容易误判的一种情况。
    pub warmup_note: Option<String>,
    /// 一次都没成功、连续失败到阈值后提前结束（剩下的次数没跑）
    pub aborted: bool,
}

impl Tally {
    pub fn attempts(&self) -> usize {
        self.ok + self.empty + self.timeout + self.errors.values().sum::<usize>()
    }

    pub fn errors_text(&self) -> String {
        let mut pairs: Vec<_> = self.errors.iter().collect();
        pairs.sort();
        pairs
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

pub struct Report {
    /// 分组名（providers 里是服务商名；protocol 版里等于协议名）
    pub group: String,
    /// 完整展示名
    pub label: String,
    pub proto: Proto,
    pub tally: Tally,
    /// 正式计时的样本（毫秒），只包含拿到 A 记录的查询
    pub samples: Vec<f64>,
}

impl Report {
    pub fn new(group: impl Into<String>, label: impl Into<String>, proto: Proto) -> Report {
        Report {
            group: group.into(),
            label: label.into(),
            proto,
            tally: Tally::default(),
            samples: Vec::new(),
        }
    }

    pub fn sorted(&self) -> Vec<f64> {
        let mut v = self.samples.clone();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        v
    }

    pub fn quantile(sorted: &[f64], q: f64) -> f64 {
        if sorted.is_empty() {
            return 0.0;
        }
        let idx = (((sorted.len() - 1) as f64) * q).round() as usize;
        sorted[idx]
    }

    pub fn p50(&self) -> f64 {
        Self::quantile(&self.sorted(), 0.50)
    }

    pub fn p90(&self) -> f64 {
        Self::quantile(&self.sorted(), 0.90)
    }

    pub fn p99(&self) -> f64 {
        Self::quantile(&self.sorted(), 0.99)
    }

    pub fn max(&self) -> f64 {
        self.sorted().last().copied().unwrap_or(0.0)
    }

    pub fn min(&self) -> f64 {
        self.sorted().first().copied().unwrap_or(0.0)
    }

    pub fn mean(&self) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        self.samples.iter().sum::<f64>() / self.samples.len() as f64
    }

    pub fn has_samples(&self) -> bool {
        !self.samples.is_empty()
    }

    /// 一行摘要，给"实时进度"的常驻记录用
    pub fn summary_line(&self, rounds: usize, name_width: usize) -> String {
        let name = fit(&self.label, name_width);
        if self.has_samples() {
            format!(
                "  ✅ {} p50 {:>7.1}  p90 {:>7.1}  成功 {}/{}",
                name,
                self.p50(),
                self.p90(),
                self.tally.ok,
                rounds
            )
        } else if self.tally.attempts() == 0 {
            format!("  ⛔ {} 未执行", name)
        } else {
            format!(
                "  ❌ {} 全部失败（超时 {}/{}）",
                name,
                self.tally.timeout,
                self.tally.attempts()
            )
        }
    }

    /// 详细块：成功/失败分类 + 分位数
    pub fn print_block(&self, rounds: usize) {
        println!("── {} ──────────────────────────", self.label);
        if self.tally.aborted {
            println!(
                "   成功 {} / {}（提前结束：一次没成功、连败 {} 次后放弃，原计划 {} 次）",
                self.tally.ok,
                self.tally.attempts(),
                EARLY_ABORT_AFTER,
                rounds
            );
        } else {
            println!(
                "   成功 {} / {}   空答案 {}   超时 {}",
                self.tally.ok, rounds, self.tally.empty, self.tally.timeout
            );
        }
        if !self.tally.errors.is_empty() {
            println!("   错误 {}", self.tally.errors_text());
        }
        if let Some(detail) = &self.tally.first_error {
            println!("   首条错误：{}", detail);
        }
        if self.samples.is_empty() {
            println!("   （没有成功样本，无法统计分位数）");
            return;
        }
        println!(
            "   min {:.1}  p50 {:.1}  p90 {:.1}  p99 {:.1}  max {:.1}  mean {:.1}   (ms)",
            self.min(),
            self.p50(),
            self.p90(),
            self.p99(),
            self.max(),
            self.mean()
        );
    }
}

// ---------------------------------------------------------------------------
// 实时进度
//
// 一轮完整测试要跑几分钟（失败的组合每条都要等满超时），全程黑屏会让人以为卡死。
// 这里做三件事：
//   * TTY 下用「单行原地刷新」画一条进度条 + 当前目标 + 阶段 + 已用/预计剩余
//   * 每完成一个目标补一行**常驻记录**（✓ p50 … / ✗ 全部失败），滚动历史里看得到
//   * 非 TTY（重定向、管道）不画进度条，免得把 \r 和 ANSI 转义写进日志
//
// 走 stderr：stdout 留给最终报告，所以 `... > out.txt` 拿到的还是干净的报告。
// ---------------------------------------------------------------------------

pub struct Progress {
    /// stderr 是终端才画进度条
    tty: bool,
    /// --no-progress：连常驻记录也不打，输出绝对干净
    quiet: bool,
    total: usize,
    /// 当前目标序号，从 1 开始
    index: usize,
    current: String,
    stage: String,
    run_start: Instant,
    last_render: Instant,
    /// 已完成目标的实际耗时合计，用来估计剩余
    spent: Duration,
}

impl Progress {
    pub fn new(total: usize) -> Progress {
        let now = Instant::now();
        Progress {
            tty: std::io::stderr().is_terminal(),
            quiet: false,
            total,
            index: 0,
            current: String::new(),
            stage: String::new(),
            run_start: now,
            last_render: now - Duration::from_secs(60),
            spent: Duration::ZERO,
        }
    }

    /// 关掉进度显示（--no-progress），用于希望输出绝对干净的场合
    pub fn disabled(total: usize) -> Progress {
        let now = Instant::now();
        Progress {
            tty: false,
            quiet: true,
            total,
            index: 0,
            current: String::new(),
            stage: String::new(),
            run_start: now,
            last_render: now,
            spent: Duration::ZERO,
        }
    }

    pub fn is_tty(&self) -> bool {
        self.tty
    }

    /// 「 3/25」形式的序号，供常驻记录使用
    pub fn counter(&self) -> String {
        let w = self.total.to_string().len();
        format!("{:>w$}/{}", self.index, self.total, w = w)
    }

    /// 开始一个新目标
    pub fn begin(&mut self, label: &str) {
        self.index += 1;
        self.current = label.to_owned();
        self.stage = "连接中…".to_owned();
        self.render(true);
    }

    /// 刷新当前阶段（只在 TTY 下生效）
    pub fn stage(&mut self, text: &str) {
        self.stage = text.to_owned();
        self.render(false);
    }

    /// 收尾当前目标：把进度行擦掉，补一行常驻记录
    pub fn finish(&mut self, summary: &str, elapsed: Duration) {
        self.spent += elapsed;
        self.clear();
        if !self.quiet {
            eprintln!("{}", summary);
        }
    }

    /// 全部跑完：擦掉进度行，报总耗时
    pub fn done(&mut self) {
        self.clear();
        if !self.quiet {
            eprintln!("总耗时      {:.1}s", self.run_start.elapsed().as_secs_f64());
        }
    }

    /// 带说明的收尾（同一进程里有多个阶段时用，避免出现两行"总耗时"）
    pub fn conclude(&mut self, label: &str) {
        self.clear();
        if !self.quiet {
            eprintln!(
                "{}{:.1}s",
                pad_to(label, 14),
                self.run_start.elapsed().as_secs_f64()
            );
        }
    }

    fn render(&mut self, force: bool) {
        if !self.tty || self.quiet {
            return;
        }
        // 限流：最多每 80ms 重绘一次，避免高频刷新拖慢终端
        if !force && self.last_render.elapsed().as_millis() < 80 {
            return;
        }
        self.last_render = Instant::now();

        const BAR: usize = 16;
        let completed = self.index.saturating_sub(1);
        let frac = if self.total == 0 {
            0.0
        } else {
            (completed as f64 / self.total as f64).clamp(0.0, 1.0)
        };
        let filled = ((frac * BAR as f64).round() as usize).min(BAR);
        let bar = format!("{}{}", "█".repeat(filled), "░".repeat(BAR - filled));

        // 转圈动画：让「当前这条查询正在等超时」也能看出程序还活着
        const SPIN: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
        let spin = SPIN[((self.run_start.elapsed().as_millis() / 100) % 10) as usize];

        let elapsed = self.run_start.elapsed().as_secs_f64();
        let remain = if self.spent.is_zero() || completed == 0 {
            "--:--".to_owned()
        } else {
            let avg = self.spent.as_secs_f64() / completed as f64;
            mmss(avg * (self.total.saturating_sub(completed)) as f64)
        };

        let line = format!(
            "  {} [{}] {} {:>4.0}%  {} · {}  已用 {}  剩 {}",
            spin,
            self.counter(),
            bar,
            frac * 100.0,
            fit(&self.current, 26),
            fit(&self.stage, 26),
            mmss(elapsed),
            remain
        );
        let mut err = std::io::stderr();
        let _ = write!(err, "\r\x1b[K{}", line);
        let _ = err.flush();
    }

    fn clear(&self) {
        if !self.tty || self.quiet {
            return;
        }
        let mut err = std::io::stderr();
        let _ = write!(err, "\r\x1b[K");
        let _ = err.flush();
    }
}

fn mmss(secs: f64) -> String {
    let s = secs.max(0.0).round() as u64;
    format!("{}:{:02}", s / 60, s % 60)
}

/// 截断到指定显示宽度（超出部分用 … 收尾）
pub fn truncate(s: &str, max: usize) -> String {
    if display_width(s) <= max {
        return s.to_owned();
    }
    let mut out = String::new();
    let mut w = 0usize;
    for c in s.chars() {
        let cw = if c.is_ascii() { 1 } else { 2 };
        if w + cw > max.saturating_sub(1) {
            break;
        }
        out.push(c);
        w += cw;
    }
    out.push('…');
    out
}

/// 截断 + 补齐到指定显示宽度（表格列用）
pub fn fit(s: &str, width: usize) -> String {
    pad_to(&truncate(s, width), width)
}
// ---------------------------------------------------------------------------
// 域名列表
// ---------------------------------------------------------------------------

/// 找不到域名文件时用的兜底列表（保证在任何工作目录下都能直接跑）
pub const BUILTIN_DOMAINS: &[&str] = &[
    "www.baidu.com",
    "www.qq.com",
    "www.taobao.com",
    "www.jd.com",
    "www.bilibili.com",
    "www.zhihu.com",
    "www.aliyun.com",
    "www.163.com",
    "www.sina.com.cn",
    "juejin.cn",
    "www.cnblogs.com",
    "www.iqiyi.com",
    "www.google.com",
    "www.github.com",
    "www.cloudflare.com",
    "www.microsoft.com",
    "www.apple.com",
    "www.wikipedia.org",
    "www.amazon.com",
    "www.reddit.com",
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",
    "fonts.googleapis.com",
    "www.bing.com",
];

pub fn load_domains(path: &str, explicit: bool) -> (Vec<String>, String) {
    if let Some(domains) = try_read_domains(path) {
        return (domains, path.to_owned());
    }

    if explicit {
        // 用户明确指定了路径就不偷偷兜底，直接报错并给出排查信息
        let cwd = env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "?".into());
        eprintln!("读取域名文件失败：{}", path);
        eprintln!("  当前工作目录：{}", cwd);
        eprintln!(
            "  可以改用绝对路径，例如：--domains {}/domains.txt",
            env!("CARGO_MANIFEST_DIR")
        );
        std::process::exit(1);
    }

    // 默认路径找不到时用编译期记录的包目录兜底（这样在任何工作目录下都能跑）
    let fallback = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("domains.txt");
    if let Some(domains) = try_read_domains(&fallback.to_string_lossy()) {
        return (domains, format!("{}（自动回退）", fallback.display()));
    }

    let builtin = BUILTIN_DOMAINS.iter().map(|s| s.to_string()).collect();
    (builtin, "内置列表".to_owned())
}

/// 读文件 → 清洗（去空行/注释/重复）。读不到或没有有效域名就返回 None。
pub fn try_read_domains(path: &str) -> Option<Vec<String>> {
    let content = fs::read_to_string(path).ok()?;
    let mut seen = std::collections::HashSet::new();
    let domains: Vec<String> = content
        .lines()
        .map(|line| line.trim().to_owned())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter(|line| seen.insert(line.clone()))
        .collect();
    if domains.is_empty() {
        None
    } else {
        Some(domains)
    }
}

// ---------------------------------------------------------------------------
// 打印小工具
// ---------------------------------------------------------------------------

/// 中文/全角字符在终端里占两列，Rust 的 `{:<26}` 按字符数填充，中文名字会歪。
/// 这里按"显示宽度"补空格，让列对齐。
pub fn display_width(s: &str) -> usize {
    s.chars().map(|c| if c.is_ascii() { 1 } else { 2 }).sum()
}

pub fn pad_to(s: &str, width: usize) -> String {
    let pad = width.saturating_sub(display_width(s));
    format!("{}{}", s, " ".repeat(pad))
}

/// 取下一个命令行参数值
pub fn next_value(iter: &mut std::vec::IntoIter<String>, key: &str) -> String {
    iter.next().unwrap_or_else(|| {
        eprintln!("参数 {} 缺少取值", key);
        std::process::exit(2);
    })
}
