// ============================================================================
// providers —— 「服务商 × 协议」矩阵对比：每一家 × 它支持的每一种协议
//
// 与 dns-protocol-bench 的区别：
//   那个工具固定一台服务器，横比五种协议（所以只能回答"协议之间差多少"）；
//   这个工具横比各家服务商，并且**把每家支持的协议全测一遍**，
//   于是能同时回答两个问题：
//     · 同一协议下，哪家服务商更快（这才是公平比较）
//     · 同一家服务商下，哪个协议更快（能看出每家在哪个协议上偷懒）
//
// 协议与默认端口：
//   UDP/53    明文 DNS（无加密、无握手成本）
//   DoT/853   DNS over TLS（RFC 7858）
//   DoH-h2    DoH over HTTP/2（RFC 8484，wire 格式 application/dns-message）
//   DoH3      DoH over HTTP/3（QUIC，UDP 443）
//   DoQ/853   DNS over QUIC（RFC 9250）
//
// 用法：
//   cargo run --release --bin providers                       # 全矩阵，hot 口径
//   cargo run --release --bin providers -- --mode cold
//   cargo run --release --bin providers -- --rounds 50 --warmup 10
//   cargo run --release --bin providers -- --list             # 只列清单（确认 --only 关键字）
//   cargo run --release --bin providers -- --only 阿里,腾讯
//   cargo run --release --bin providers -- --protos udp,dot,doh   # 只测指定几列
//   cargo run --release --bin providers -- --with-backups     # 加上各家的备用地址
//   cargo run --release --bin providers -- --probe            # 额外探测"未声明"的协议组合
//   cargo run --release --bin providers -- --verbose          # 打印每个组合的详细统计
//   cargo run --release --bin providers -- --isp 202.96.69.38 # 手动指定运营商裸 DNS
//   cargo run --release --bin providers -- --nxdomain-base youtube.com,google.com
//   cargo run --release --bin providers -- --no-progress     # 关掉实时进度，输出绝对干净
//
// 实时进度（`--no-progress` 可关）：
//   TTY 下在 **stderr** 上原地刷一条进度条——当前组合、组合内第几次查询、最近一次耗时、
//   已用时间、按已完成组合外推的预计剩余；每跑完一个组合再补一行常驻记录，
//   滚动历史里能看到刚跑完谁、多快、有没有超时。stdout 只留最终报告，
//   所以 `... > out.txt` 拿到的是干净报告，进度照旧在屏幕上显示。
//   重定向到文件（非 TTY）时不画进度条，免得把 \r 和控制字符写进日志。
//
// 口径（与 protocol 版共用 src/lib.rs，保证完全一致）：
//   串行分阶段、每查询串行、统一超时、先预热再计时、固定域名序列、连接出错即丢弃。
//   hot  = 连接复用（贴近 Clash/mihomo 的稳态）
//   cold = 每条查询重建连接（首字节体验）
// ============================================================================

use std::{
    env,
    net::{Ipv4Addr, SocketAddr},
    process::Command,
    time::{Duration, Instant},
};

use dns_protocol_bench::{
    display_width, install_crypto_provider, load_domains, next_value, pad_to, Endpoint, Mode,
    Progress, Proto, Report, Runner, EARLY_ABORT_AFTER, QUERY_TIMEOUT,
};
use tokio::time;

const PLAIN_PORT: u16 = 53;
const TLS_PORT: u16 = 853;

// ---------------------------------------------------------------------------
// 服务商注册表：想加减条目，直接改这里
//
// udp = 明文地址（IP）；dot = DoT 主机名；doh = DoH 端点 URL；doq = DoQ 主机名。
// None 表示该家没有公开提供这个协议（用 --probe 可以再试探一下）。
// 端口都按官方公布：DoT/DoQ 一律 853，DoH 一律 443。
//
// 关于"纯净版"：这里全部取各家**不做内容过滤**的那个地址。有几家的过滤版
// 只是 DNS 应答不同、速度基本一致，所以没必要进速度榜：
//   114DNS 家庭版 114.114.114.110 / 安全版 114.114.114.119
//   360 安全版本身带拦截，没有可选的纯净入口
// ---------------------------------------------------------------------------

struct Provider {
    name: &'static str,
    udp: Option<&'static str>,
    dot: Option<&'static str>,
    doh: Option<&'static str>,
    doq: Option<&'static str>,
}

const PROVIDERS: &[Provider] = &[
    Provider {
        name: "阿里 DNS",
        udp: Some("223.5.5.5"),
        dot: Some("dns.alidns.com"),
        doh: Some("https://dns.alidns.com/dns-query"),
        // 阿里是目前国内少见的同时提供 DoT / DoH / DoQ 的公共 DNS
        doq: Some("dns.alidns.com"),
    },
    Provider {
        name: "腾讯 DNSPod",
        udp: Some("119.29.29.29"),
        dot: Some("dot.pub"),
        doh: Some("https://doh.pub/dns-query"),
        doq: None,
    },
    Provider {
        name: "360 DNS",
        udp: Some("101.226.4.6"),
        dot: Some("dot.360.cn"),
        doh: Some("https://doh.360.cn/dns-query"),
        doq: None,
    },
    Provider {
        name: "OneDNS(微步)",
        udp: Some("117.50.10.10"),
        dot: Some("dot-pure.onedns.net"),
        // 官方给的就是这个端点。但实测在部分网络下 TCP 443 通、TLS 握手却挂死，
        // 跑出超时不一定是你的配置问题 —— 所以它只进参考矩阵，结论要留余地。
        doh: Some("https://doh-pure.onedns.net/dns-query"),
        doq: None,
    },
    Provider {
        name: "114 DNS",
        udp: Some("114.114.114.114"),
        dot: None,
        doh: None,
        doq: None,
    },
    Provider {
        name: "百度 DNS",
        udp: Some("180.76.76.76"),
        dot: None,
        doh: None,
        doq: None,
    },
    Provider {
        name: "字节 TrafficRoute",
        udp: Some("180.184.1.1"),
        dot: None,
        doh: None,
        doq: None,
    },
    Provider {
        name: "CNNIC DNS",
        udp: Some("1.2.4.8"),
        dot: None,
        doh: None,
        doq: None,
    },
];

/// 各家的备用地址（只有明文）。--with-backups 打开，能顺便看出"同家两台机器"差多少。
const BACKUPS: &[(&str, &str)] = &[
    ("阿里 备(223.6.6.6)", "223.6.6.6"),
    ("腾讯 备(119.28.28.28)", "119.28.28.28"),
    ("360 备(218.30.118.6)", "218.30.118.6"),
    ("114 备(114.114.115.115)", "114.114.115.115"),
    ("字节 备(180.184.2.2)", "180.184.2.2"),
    ("OneDNS 备(52.80.52.52)", "52.80.52.52"),
];

// ---------------------------------------------------------------------------
// 目标 = 服务商 × 协议
// ---------------------------------------------------------------------------

struct Target {
    provider: String,
    proto: Proto,
    endpoint: Endpoint,
    /// true = 这一格是"试探"来的（该家没声明支持），失败属正常
    speculative: bool,
}

impl Target {
    fn label(&self) -> String {
        format!("{} / {}", self.provider, self.proto.label())
    }
}

fn build_targets(opt: &Opt) -> Vec<Target> {
    let mut targets: Vec<Target> = Vec::new();

    let mut push = |provider: &str, proto: Proto, endpoint: Endpoint, speculative: bool| {
        if !opt.protos.contains(&proto) {
            return;
        }
        targets.push(Target {
            provider: provider.to_owned(),
            proto,
            endpoint,
            speculative,
        });
    };

    for p in PROVIDERS {
        if let Some(ip) = p.udp {
            let addr: Ipv4Addr = ip.parse().expect("invalid IPv4 in PROVIDERS");
            push(
                p.name,
                Proto::Udp,
                Endpoint::Udp(SocketAddr::from((addr, PLAIN_PORT))),
                false,
            );
        }
        if let Some(host) = p.dot {
            push(
                p.name,
                Proto::Dot,
                Endpoint::Dot {
                    host: host.to_owned(),
                    port: TLS_PORT,
                    sni: host.to_owned(),
                },
                false,
            );
        }
        if let Some(url) = p.doh {
            push(
                p.name,
                Proto::Doh,
                Endpoint::Doh {
                    url: url.to_owned(),
                    h3: false,
                },
                false,
            );
            // DoH3 与 DoH-h2 打的是同一个端点、同一份证书，只是走的传输不同，
            // 所以只要这家有 DoH，就应该把 h3 也测一遍 —— h3 支持与否和 h2 无关。
            push(
                p.name,
                Proto::Doh3,
                Endpoint::Doh {
                    url: url.to_owned(),
                    h3: true,
                },
                false,
            );
        }
        if let Some(host) = p.doq {
            push(
                p.name,
                Proto::Doq,
                Endpoint::Doq {
                    host: host.to_owned(),
                    port: TLS_PORT,
                    sni: host.to_owned(),
                },
                false,
            );
        }

        // --probe：拿已知的加密端点主机名去试它**没声明**的协议。
        // 最典型的用途是确认"这家到底支不支持 DoQ"——DoT 和 DoQ 都在 853，
        // 只是 ALPN 不同（doq vs dot），所以拿 DoT 的主机名试 DoQ 是干净的实验。
        if opt.probe {
            if let Some(dot_host) = p.dot {
                if p.doq.is_none() {
                    push(
                        p.name,
                        Proto::Doq,
                        Endpoint::Doq {
                            host: dot_host.to_owned(),
                            port: TLS_PORT,
                            sni: dot_host.to_owned(),
                        },
                        true,
                    );
                }
            }
            if let Some(url) = p.doh {
                if p.dot.is_none() {
                    if let Some(host) = host_of_url(url) {
                        push(
                            p.name,
                            Proto::Dot,
                            Endpoint::Dot {
                                host: host.clone(),
                                port: TLS_PORT,
                                sni: host,
                            },
                            true,
                        );
                    }
                }
            }
        }
    }

    if opt.with_backups {
        for (name, ip) in BACKUPS {
            if let Ok(addr) = ip.parse::<Ipv4Addr>() {
                push(
                    name,
                    Proto::Udp,
                    Endpoint::Udp(SocketAddr::from((addr, PLAIN_PORT))),
                    false,
                );
            }
        }
    }

    targets
}

fn host_of_url(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1)?;
    let host = rest.split('/').next()?;
    Some(host.split(':').next()?.to_owned())
}

// ---------------------------------------------------------------------------
// 配置
// ---------------------------------------------------------------------------

struct Opt {
    mode: Mode,
    rounds: usize,
    warmup: usize,
    timeout: Duration,
    domains_file: String,
    domains_explicit: bool,
    protos: Vec<Proto>,
    only: Option<Vec<String>>,
    isp: Option<String>,
    with_backups: bool,
    probe: bool,
    list_only: bool,
    verbose: bool,
    no_progress: bool,
    skip_hijack_check: bool,
    nxdomain_base: String,
}

impl Opt {
    fn from_env() -> Opt {
        let mut opt = Opt {
            mode: Mode::Hot,
            rounds: 30,
            warmup: 5,
            timeout: QUERY_TIMEOUT,
            domains_file: "domains.txt".to_owned(),
            domains_explicit: false,
            protos: Proto::all().to_vec(),
            only: None,
            isp: None,
            with_backups: false,
            probe: false,
            list_only: false,
            verbose: false,
            no_progress: false,
            skip_hijack_check: false,
            nxdomain_base: "youtube.com,google.com".to_owned(),
        };

        let args: Vec<String> = env::args().skip(1).collect();
        let mut iter = args.into_iter();
        while let Some(key) = iter.next() {
            match key.as_str() {
                "--mode" => {
                    let v = next_value(&mut iter, &key);
                    opt.mode = match v.as_str() {
                        "hot" => Mode::Hot,
                        "cold" => Mode::Cold,
                        other => {
                            eprintln!("--mode 只支持 hot / cold，收到 {}", other);
                            std::process::exit(2);
                        }
                    };
                }
                "--rounds" => {
                    opt.rounds = next_value(&mut iter, &key)
                        .parse()
                        .expect("--rounds 需要整数")
                }
                "--warmup" => {
                    opt.warmup = next_value(&mut iter, &key)
                        .parse()
                        .expect("--warmup 需要整数")
                }
                "--timeout" => {
                    let v: f64 = next_value(&mut iter, &key)
                        .parse()
                        .expect("--timeout 需要秒数");
                    opt.timeout = Duration::from_secs_f64(v);
                }
                "--domains" => {
                    opt.domains_file = next_value(&mut iter, &key);
                    opt.domains_explicit = true;
                }
                "--isp" => opt.isp = Some(next_value(&mut iter, &key)),
                "--nxdomain-base" => opt.nxdomain_base = next_value(&mut iter, &key),
                "--with-backups" => opt.with_backups = true,
                "--probe" => opt.probe = true,
                "--list" => opt.list_only = true,
                "--verbose" => opt.verbose = true,
                "--no-progress" => opt.no_progress = true,
                "--only" => {
                    let list = next_value(&mut iter, &key);
                    opt.only = Some(list.split(',').map(|s| s.trim().to_owned()).collect());
                }
                "--protos" => {
                    let list = next_value(&mut iter, &key);
                    let mut protos = Vec::new();
                    for item in list.split(',') {
                        match Proto::parse(item) {
                            Some(p) => protos.push(p),
                            None => {
                                eprintln!(
                                    "无法识别的协议名：{}（可用 udp,dot,doh,doh3,doq）",
                                    item
                                );
                                std::process::exit(2);
                            }
                        }
                    }
                    if protos.is_empty() {
                        eprintln!("--protos 不能为空");
                        std::process::exit(2);
                    }
                    opt.protos = protos;
                }
                "--no-hijack-check" => opt.skip_hijack_check = true,
                "--help" | "-h" => {
                    println!("providers [--mode hot|cold] [--rounds N] [--warmup N] [--timeout SEC] [--domains FILE]");
                    println!(
                        "          [--protos udp,dot,doh,doh3,doq] [--only 阿里,腾讯] [--isp IP]"
                    );
                    println!(
                        "          [--with-backups] [--probe] [--verbose] [--no-progress] [--list]"
                    );
                    println!(
                        "          [--nxdomain-base youtube.com,google.com] [--no-hijack-check]"
                    );
                    std::process::exit(0);
                }
                other => {
                    eprintln!("未知参数：{}（--help 查看用法）", other);
                    std::process::exit(2);
                }
            }
        }
        opt
    }
}

// ---------------------------------------------------------------------------
// 运营商 DNS 自动探测
// ---------------------------------------------------------------------------

fn detect_isp_dns() -> Vec<Ipv4Addr> {
    let mut found: Vec<Ipv4Addr> = Vec::new();
    let push = |text: &str, found: &mut Vec<Ipv4Addr>| {
        if let Ok(ip) = text.trim().trim_end_matches(',').parse::<Ipv4Addr>() {
            if !ip.is_loopback() && !ip.is_unspecified() && !found.contains(&ip) {
                found.push(ip);
            }
        }
    };

    if let Some(iface) = default_interface() {
        // ipconfig getpacket 读的是 DHCP 下发的 DNS，
        // 即使系统 DNS 被 Clash 改成 127.0.0.1 也照样能拿到
        if let Ok(output) = Command::new("ipconfig")
            .arg("getpacket")
            .arg(&iface)
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                if line.contains("domain_name_server") {
                    if let Some(inner) = line.split('{').nth(1).and_then(|s| s.split('}').next()) {
                        for part in inner.split(',') {
                            push(part, &mut found);
                        }
                    }
                }
            }
        }
    }

    if found.is_empty() {
        // 兜底：scutil 里的解析器列表（Clash 开 TUN 时可能只剩 127.0.0.1，所以放后面）
        if let Ok(output) = Command::new("scutil").arg("--dns").output() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                let line = line.trim();
                if let Some(rest) = line.strip_prefix("nameserver[") {
                    if let Some((_, v)) = rest.split_once(':') {
                        push(v, &mut found);
                    }
                }
            }
        }
    }

    found
}

fn default_interface() -> Option<String> {
    let output = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines().find_map(|line| {
        line.trim()
            .strip_prefix("interface:")
            .map(|v| v.trim().to_owned())
    })
}

/// 判断是不是内网地址（192.168/16、10/8、172.16/12）
fn is_private(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
}

// ---------------------------------------------------------------------------
// 跑一批目标
// ---------------------------------------------------------------------------

/// 一个组合失败原因的简短描述（用于进度行的收尾）
fn fail_reason(report: &Report) -> String {
    let tail = if report.tally.aborted {
        format!(" · 连败 {} 次后提前结束", EARLY_ABORT_AFTER)
    } else {
        String::new()
    };
    let head = if let Some(d) = &report.tally.first_error {
        truncate(d, 50)
    } else if let Some(n) = &report.tally.warmup_note {
        truncate(n, 50)
    } else if report.tally.timeout > 0 {
        format!("超时 {}/{}", report.tally.timeout, report.tally.attempts())
    } else {
        "无成功样本".to_owned()
    };
    format!("{}{}", head, tail)
}

async fn run_targets(targets: &[Target], domains: &[String], opt: &Opt) -> Vec<Report> {
    let mut reports = Vec::with_capacity(targets.len());
    let mut progress = if opt.no_progress {
        Progress::disabled(targets.len())
    } else {
        Progress::new(targets.len())
    };

    for target in targets {
        let label = target.label();
        let t_start = Instant::now();
        progress.begin(&label);

        let mut runner = match Runner::new(&target.endpoint).await {
            Ok(r) => r,
            Err(e) => {
                let mut report = Report::new(target.provider.clone(), label.clone(), target.proto);
                report.tally.first_error = Some(e.summary());
                *report.tally.errors.entry(e.label().to_owned()).or_insert(0) += 1;
                let elapsed = t_start.elapsed();
                let line = format!(
                    "✗ [{}] {} 初始化失败：{}  用时 {:.1}s",
                    progress.counter(),
                    pad_to(&label, 32),
                    truncate(&e.summary(), 50),
                    elapsed.as_secs_f64()
                );
                progress.finish(&line, elapsed);
                reports.push(report);
                continue;
            }
        };

        // 预热：把握手成本从分布里剔出去。
        // 这里必须记录预热是否成功 —— 预热失败意味着"热口径"其实退化成了冷口径
        // （连接一直没建起来，每条正式查询都在付建连成本），这是最容易误判的情况。
        let mut warmup_note: Option<String> = None;
        for i in 0..opt.warmup {
            progress.stage(&format!("预热 {}/{}", i + 1, opt.warmup));
            let domain = &domains[i % domains.len()];
            match time::timeout(opt.timeout, runner.exchange(domain, opt.mode)).await {
                Err(_) => {
                    if warmup_note.is_none() {
                        warmup_note = Some(format!("预热就超时（>{:?} 无响应）", opt.timeout));
                    }
                }
                Ok(Err(e)) => {
                    if warmup_note.is_none() {
                        warmup_note = Some(format!("预热失败：{}", truncate(&e.summary(), 60)));
                    }
                }
                Ok(Ok(_)) => {}
            }
        }

        let mut report = Report::new(target.provider.clone(), label.clone(), target.proto);
        report.tally.warmup_note = warmup_note;

        let mut consecutive_failures = 0usize;

        for i in 0..opt.rounds {
            let domain = &domains[i % domains.len()];
            let started = Instant::now();
            let outcome = time::timeout(opt.timeout, runner.exchange(domain, opt.mode)).await;
            let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;

            match outcome {
                Err(_) => {
                    report.tally.timeout += 1;
                    consecutive_failures += 1;
                }
                Ok(Err(e)) => {
                    if report.tally.first_error.is_none() {
                        report.tally.first_error = Some(e.summary());
                    }
                    *report.tally.errors.entry(e.label().to_owned()).or_insert(0) += 1;
                    consecutive_failures += 1;
                }
                Ok(Ok((rcode, ips))) => {
                    report.tally.ok += 1;
                    consecutive_failures = 0;
                    if rcode != 0 || ips.is_empty() {
                        report.tally.empty += 1;
                    } else {
                        report.samples.push(elapsed_ms);
                    }
                }
            }

            progress.stage(&format!(
                "查询 {}/{} · 最近 {:>6.1}ms",
                i + 1,
                opt.rounds,
                elapsed_ms
            ));

            // 提前放弃：一次都没成功过、又连续失败到阈值 —— 继续跑不可能翻盘，
            // 只会白等 (rounds - i) × timeout。cold 实测里这一步能省掉 80% 的总耗时。
            if report.tally.ok == 0 && consecutive_failures >= EARLY_ABORT_AFTER {
                report.tally.aborted = true;
                break;
            }
        }

        runner.close();

        let elapsed = t_start.elapsed();
        let counter = progress.counter();
        let line = if report.has_samples() {
            format!(
                "✓ [{}] {} p50 {:>7.1}  p90 {:>7.1}  max {:>8.1}  成功 {}/{}  用时 {:.1}s",
                counter,
                pad_to(&label, 32),
                report.p50(),
                report.p90(),
                report.max(),
                report.tally.ok,
                opt.rounds,
                elapsed.as_secs_f64()
            )
        } else {
            format!(
                "✗ [{}] {} 全部失败：{}  用时 {:.1}s",
                counter,
                pad_to(&label, 32),
                fail_reason(&report),
                elapsed.as_secs_f64()
            )
        };
        progress.finish(&line, elapsed);
        reports.push(report);
    }

    progress.done();
    println!();
    reports
}

/// 污染/劫持检查：查一个**不存在的子域**，看服务商是老实说"不存在"，
/// 还是塞给你一个 A 记录（被污染或被拦截页）。
/// 返回 (rcode, A 记录)；rcode=3 表示 NXDOMAIN。
async fn probe_nonexistent(
    runner: &mut Runner,
    mode: Mode,
    domain: &str,
    timeout: Duration,
) -> Result<(u8, Vec<Ipv4Addr>), String> {
    match time::timeout(timeout, runner.exchange(domain, mode)).await {
        Err(_) => Err("超时".to_owned()),
        Ok(Err(e)) => Err(e.summary()),
        Ok(Ok(v)) => Ok(v),
    }
}

// ---------------------------------------------------------------------------
// 输出
// ---------------------------------------------------------------------------

/// 右对齐单元格（数字用；按显示宽度算，所以中文也不会歪）
fn cell_right(s: &str, width: usize) -> String {
    let pad = width.saturating_sub(display_width(s));
    format!("{}{}", " ".repeat(pad), s)
}

fn print_matrix(
    reports: &[Report],
    providers: &[String],
    protos: &[Proto],
    speculative: &[(String, Proto)],
) {
    const CELL: usize = 11;
    let name_w = providers
        .iter()
        .map(|s| display_width(s))
        .max()
        .unwrap_or(12)
        .max(12)
        + 2;

    println!("══════════════════════════════════════════════════════════════");
    println!("【服务商 × 协议 矩阵】单元格 = p50 毫秒");
    println!("  ·  该家没有提供这个协议（也没探测）");
    println!("  ✗  有端点但每次都失败（原因见下面的清单）");
    println!("  ~  该格是 --probe 试行出来的，失败属正常");
    println!();
    print!("{}", pad_to("服务商", name_w));
    for p in protos {
        print!("{}", cell_right(p.label(), CELL));
    }
    println!();

    for prov in providers {
        print!("{}", pad_to(prov, name_w));
        for p in protos {
            let found = reports.iter().find(|r| &r.group == prov && r.proto == *p);
            let is_spec = speculative.iter().any(|(g, pr)| g == prov && pr == p);
            let text = match found {
                None => "·".to_owned(),
                Some(r) if r.has_samples() => {
                    if is_spec {
                        format!("~{:.1}", r.p50())
                    } else {
                        format!("{:.1}", r.p50())
                    }
                }
                Some(_) => {
                    if is_spec {
                        "~✗".to_owned()
                    } else {
                        "✗".to_owned()
                    }
                }
            };
            print!("{}", cell_right(&text, CELL));
        }
        println!();
    }
}

fn print_failures(reports: &[Report], timeout: Duration) {
    let failed: Vec<&Report> = reports
        .iter()
        .filter(|r| !r.has_samples() && r.tally.attempts() > 0)
        .collect();
    if failed.is_empty() {
        return;
    }

    println!();
    println!("──────────────────────────────────────────────────────────────");
    println!("全部失败的组合（首条错误）");
    for r in failed {
        let detail = match &r.tally.first_error {
            Some(d) => truncate(d, 70),
            None if r.tally.timeout > 0 => format!("{:?} 内无响应（每条都超时）", timeout),
            None => "?".into(),
        };
        println!(
            "  {}  超时 {}/{}  {}",
            pad_to(r.label.as_str(), 34),
            r.tally.timeout,
            r.tally.attempts(),
            detail
        );
        if let Some(note) = &r.tally.warmup_note {
            println!("      ⚠️ {}", note);
        }
    }
    println!();
    println!(
        "  提示：明文 UDP / QUIC 系（DoQ、DoH3）走 UDP，被网络屏蔽时表现为「静默丢包 → 超时」；"
    );
    println!("        DoT / DoH 走 TCP，被屏蔽时通常更快报错（connection refused / reset）。");
    println!("        超时不等于「这家不支持这个协议」——也可能是你的网络到它这条路径不通。");
    println!("        想区分「只是慢」和「真的不通」，用 --timeout 10 放宽再跑一次：能通就是慢，依然超时就是不通。");
}

fn truncate(s: &str, max: usize) -> String {
    if display_width(s) <= max {
        return s.to_owned();
    }
    let mut out = String::new();
    let mut w = 0;
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

fn print_protocol_rankings(reports: &[Report], protos: &[Proto], rounds: usize) {
    println!();
    println!("══════════════════════════════════════════════════════════════");
    println!("【同一协议下横比各家】—— 这才是服务商之间的公平比较");
    println!();
    for p in protos {
        let mut group: Vec<&Report> = reports
            .iter()
            .filter(|r| r.proto == *p && r.has_samples())
            .collect();
        println!("── {} ──────────────────────────────────", p.label());
        if group.is_empty() {
            println!("   （没有任何一家跑通）");
            println!();
            continue;
        }
        group.sort_by(|a, b| {
            a.p50()
                .partial_cmp(&b.p50())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let best = group[0].p50();
        for (i, r) in group.iter().enumerate() {
            println!(
                "  {}. {} p50 {:>7.1}  (+{:>5.1})  p90 {:>7.1}  max {:>8.1}  成功 {}/{}",
                i + 1,
                pad_to(&r.group, 20),
                r.p50(),
                r.p50() - best,
                r.p90(),
                r.max(),
                r.tally.ok,
                rounds
            );
        }
        println!();
    }
}

fn print_provider_bests(reports: &[Report]) {
    // 只统计"非试探"的组合
    let mut providers: Vec<String> = Vec::new();
    for r in reports {
        if !providers.contains(&r.group) {
            providers.push(r.group.clone());
        }
    }

    println!("══════════════════════════════════════════════════════════════");
    println!("【每家最快的协议】—— 同一个服务商内部比协议");
    println!();
    for prov in &providers {
        let mine: Vec<&Report> = reports
            .iter()
            .filter(|r| &r.group == prov && r.has_samples())
            .collect();
        if mine.is_empty() {
            println!("  {}  （全部失败）", pad_to(prov, 20));
            continue;
        }
        let mut sorted = mine.clone();
        sorted.sort_by(|a, b| {
            a.p50()
                .partial_cmp(&b.p50())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let best = sorted[0];
        let udp = mine.iter().find(|r| r.proto == Proto::Udp);

        let mut extra = String::new();
        if let Some(u) = udp {
            if u.proto != best.proto {
                let delta = u.p50() - best.p50();
                extra = format!("（比它自己的 UDP/53 快 {:.1}ms）", delta);
            } else {
                extra = "（就是它的明文 UDP，说明这家没有更快的加密协议）".to_owned();
            }
        }

        let line = format!(
            "{} → {}  p50 {:.1}ms  {}",
            pad_to(prov, 20),
            pad_to(best.proto.label(), 10),
            best.p50(),
            extra
        );
        println!("  {}", line.trim_end());

        // 顺便列出这家其它协议的相对位置
        if sorted.len() > 1 {
            let rest: Vec<String> = sorted[1..]
                .iter()
                .map(|r| format!("{} {:+.1}", r.proto.label(), r.p50() - best.p50()))
                .collect();
            println!("      {}", rest.join("   "));
        }
    }
}

// ---------------------------------------------------------------------------

fn matches_only(label: &str, only: &Option<Vec<String>>) -> bool {
    match only {
        None => true,
        Some(list) => list.iter().any(|k| label.contains(k.as_str())),
    }
}

#[tokio::main]
async fn main() {
    install_crypto_provider();

    let opt = Opt::from_env();
    let (domains, domains_source) = load_domains(&opt.domains_file, opt.domains_explicit);

    let mut targets = build_targets(&opt);

    // 运营商 DNS：优先用 --isp，否则自动探测（只有明文，所以只补 UDP 一列）
    if opt.protos.contains(&Proto::Udp) {
        let isp_ips: Vec<Ipv4Addr> = match &opt.isp {
            Some(spec) => spec
                .split(',')
                .filter_map(|s| s.trim().parse::<Ipv4Addr>().ok())
                .collect(),
            None => detect_isp_dns(),
        };
        if !isp_ips.is_empty() {
            // DHCP 下发的 DNS 常常是路由器本身（192.168.x / 10.x），它不是"运营商裸 DNS"，
            // 而是"路由器 → 运营商"这条链路上的第一跳。两者测出来是不同的东西，要分清楚。
            let label = match &opt.isp {
                Some(_) => "运营商 DNS(手动填写)",
                None if isp_ips.iter().all(is_private) => "运营商/网关 DNS(自动)",
                None => "运营商 DNS(自动)",
            };
            let ip_text = isp_ips
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join("/");
            targets.push(Target {
                provider: format!("{} {}", label, ip_text),
                proto: Proto::Udp,
                endpoint: Endpoint::Udp(SocketAddr::from((isp_ips[0], PLAIN_PORT))),
                speculative: false,
            });
            if opt.isp.is_none() && isp_ips.iter().all(is_private) {
                println!("提示        探测到的是内网地址，说明你的 DNS 请求先发给路由器；");
                println!("            想测运营商裸 DNS，登录路由器看 WAN 侧 DNS 后用 --isp 填进来");
                println!();
            }
        } else {
            eprintln!("⚠️  没能自动探测到运营商 DNS，可以用 --isp 202.96.69.38 手动指定");
        }
    }

    if opt.list_only {
        let name_w = targets
            .iter()
            .map(|t| display_width(&t.label()))
            .max()
            .unwrap_or(30)
            .max(30)
            + 2;
        println!("被测组合（--only 用「名字里包含」匹配，可逗号分隔多个）：");
        println!();
        for t in &targets {
            let tag = if t.speculative { "~试探" } else { "" };
            println!(
                "  {} {} {}",
                pad_to(&t.label(), name_w),
                t.endpoint.describe(),
                tag
            );
        }
        println!();
        if opt.with_backups {
            println!("提示        以上含各家的备用地址（--with-backups 已打开）");
        } else {
            println!("提示        加 --with-backups 会多出各家的备用地址（本次未列出）");
        }
        if !opt.probe {
            println!(
                "            加 --probe 会额外试探各家的未声明协议（主要用来确认 DoQ 支持情况）"
            );
        }
        println!(
            "            所有明文地址都是官方公布的公众 DNS，默认取「纯净版」（不做内容拦截）"
        );
        return;
    }

    targets.retain(|t| matches_only(&t.label(), &opt.only));
    if targets.is_empty() {
        eprintln!("过滤后没有剩下任何组合，检查一下 --only / --protos");
        std::process::exit(1);
    }

    // 矩阵里出现过的服务商顺序 = 注册表顺序 + 运营商
    let mut providers: Vec<String> = Vec::new();
    for t in &targets {
        if !providers.contains(&t.provider) {
            providers.push(t.provider.clone());
        }
    }
    let speculative: Vec<(String, Proto)> = targets
        .iter()
        .filter(|t| t.speculative)
        .map(|t| (t.provider.clone(), t.proto))
        .collect();

    println!(
        "域名        {} 个（来源：{}，顺序固定循环使用）",
        domains.len(),
        domains_source
    );
    println!(
        "口径        {}，预热 {} 次，每组合计时 {} 次",
        opt.mode.name(),
        opt.warmup,
        opt.rounds
    );
    println!("统一超时    {:?}", opt.timeout);
    println!(
        "被测组合    {} 个（{} 家 × 最多 {} 种协议）",
        targets.len(),
        providers.len(),
        opt.protos.len()
    );
    println!();

    let reports = run_targets(&targets, &domains, &opt).await;

    if opt.verbose {
        println!("══════════════════════════════════════════════════════════════");
        println!("【逐组合详细统计】");
        println!();
        for r in &reports {
            r.print_block(opt.rounds);
            println!();
        }
    }

    print_matrix(&reports, &providers, &opt.protos, &speculative);
    print_failures(&reports, opt.timeout);
    print_protocol_rankings(&reports, &opt.protos, opt.rounds);
    print_provider_bests(&reports);

    // 污染/劫持检查
    if !opt.skip_hijack_check {
        let bases: Vec<String> = opt
            .nxdomain_base
            .split(',')
            .map(|s| s.trim().trim_start_matches('.').to_owned())
            .filter(|s| !s.is_empty())
            .collect();
        // 投毒是概率性的，单次查询容易漏判，所以每个域名查 TRIES 次
        const TRIES: usize = 3;

        println!();
        println!("══════════════════════════════════════════════════════════════");
        println!("【污染/劫持检查】查「被封锁站点下随机不存在的子域」，正常应答应该是 NXDOMAIN");
        println!(
            "基准域名：{}（--nxdomain-base 可换；每个查 {} 次）",
            bases.join(", "),
            TRIES
        );

        // 只查每个服务商的加密代表 + 明文代表，避免把矩阵每个格子都查一遍
        let mut checked: Vec<(&str, &Endpoint)> = Vec::new();
        for t in &targets {
            if t.speculative {
                continue;
            }
            let key_exists = checked.iter().any(|(p, _)| *p == t.provider.as_str());
            if !key_exists {
                checked.push((t.provider.as_str(), &t.endpoint));
            }
        }

        let mut hprog = if opt.no_progress {
            Progress::disabled(checked.len() * bases.len())
        } else {
            Progress::new(checked.len() * bases.len())
        };

        for (provider, endpoint) in checked {
            let mut runner = match Runner::new(endpoint).await {
                Ok(r) => r,
                Err(e) => {
                    let line = format!(
                        "  {} 初始化失败：{}",
                        pad_to(provider, 30),
                        truncate(&e.summary(), 60)
                    );
                    hprog.begin(provider);
                    hprog.finish(&line, Duration::ZERO);
                    continue;
                }
            };
            // 先预热一次，避免把建连成本算进这次检查
            let _ = time::timeout(opt.timeout, runner.exchange(&domains[0], opt.mode)).await;

            for base in &bases {
                let task_started = Instant::now();
                hprog.begin(&format!("{} · {}", provider, base));
                let mut nxdomain = 0usize;
                let mut bad = 0usize;
                let mut ips: Vec<String> = Vec::new();
                let mut first_problem: Option<String> = None;

                for t in 0..TRIES {
                    hprog.stage(&format!("第 {}/{} 次", t + 1, TRIES));
                    let probe_domain = format!("nxd-check-{:08x}.{}", rand::random::<u32>(), base);
                    match probe_nonexistent(&mut runner, opt.mode, &probe_domain, opt.timeout).await
                    {
                        Ok((3, _)) => nxdomain += 1,
                        Ok((0, got)) if !got.is_empty() => {
                            bad += 1;
                            for ip in got {
                                let text = ip.to_string();
                                if !ips.contains(&text) {
                                    ips.push(text);
                                }
                            }
                        }
                        Ok((0, _)) => {
                            bad += 1;
                            if first_problem.is_none() {
                                first_problem = Some("NOERROR 但无 A 记录".into());
                            }
                        }
                        Ok((rcode, _)) => {
                            bad += 1;
                            if first_problem.is_none() {
                                first_problem = Some(format!("rcode={}", rcode));
                            }
                        }
                        Err(e) => {
                            if first_problem.is_none() {
                                first_problem = Some(e);
                            }
                        }
                    }
                }

                let verdict = if bad > 0 {
                    if ips.is_empty() {
                        format!(
                            "⚠️ {}/{} 次不老实：{}",
                            bad,
                            TRIES,
                            first_problem.unwrap_or_default()
                        )
                    } else {
                        format!(
                            "⚠️ {}/{} 次塞了 A 记录：{}（疑似污染/拦截）",
                            bad,
                            TRIES,
                            ips.join(", ")
                        )
                    }
                } else if nxdomain == TRIES {
                    "✅ 全部 NXDOMAIN（干净）".to_owned()
                } else if nxdomain > 0 {
                    format!(
                        "✅ {}/{} 次 NXDOMAIN，其余异常：{}",
                        nxdomain,
                        TRIES,
                        first_problem.unwrap_or_default()
                    )
                } else {
                    // 一次都没查通，不能打勾，否则会误读成"干净"
                    format!("❌ 全部查不通：{}", first_problem.unwrap_or_default())
                };

                // 用 finish 而不是 println!：TTY 下会把进度行原地替换成这条结果，
                // 非 TTY 下就是一行普通输出，两种情形都不会出现残缺的半行
                let line = format!(
                    "  {} {} {}",
                    pad_to(provider, 30),
                    pad_to(base, 14),
                    verdict
                );
                hprog.finish(&line, task_started.elapsed());
                runner.close();
            }
        }
        hprog.conclude("污染检查耗时");
    }

    println!();
    println!("说明：hot 口径测的是「连接已就绪时的查询延迟」，cold 测「首字节体验」。");
    println!("      明文 UDP 每条查询都新建 socket，所以它的 cold ≈ hot。");
    println!("      同一协议下比服务商才是公平的；跨协议比只能说明「这份配置更优」，不能说明「协议更好」。");
}
