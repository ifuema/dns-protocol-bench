// ============================================================================
// dns-protocol-bench —— 横向比较 Plain UDP / DoT / DoH(h2) / DoH3 / DoQ 的查询延迟
//
// 设计目标：**口径统一**，让"谁快"的结论只来自协议差异，而不是计时方式差异。
// 固定同一台服务器（默认 223.5.5.5，它五种协议全开），所以被比较的变量只剩协议。
//
// 对齐的六条规则（实现见 src/lib.rs）：
//   1. 串行分阶段：一个协议全部跑完，再跑下一个，避免协议之间抢 CPU / 带宽 / NAT 表。
//   2. 每条查询串行（不做并发）：这里测的是「延迟」，不是「吞吐」。
//   3. 统一超时：所有协议都用同一个 QUERY_TIMEOUT 包住整次操作。
//   4. 先 warm-up 再计时：默认预热 5 次，结果丢弃，避免把首个查询的握手成本算进分布。
//   5. 冷/热两种口径各自内部一致：
//        hot  —— 连接复用（DoQ 复用 Connection、DoH 复用 Client、DoT 复用一条 TLS 连接）
//        cold —— 每条查询都重建连接（DoQ 每条重连、DoH 每条新建 Client、DoT 每条新建 TCP+TLS）
//   6. 域名序列固定（按索引循环取用），五个协议面对的域名顺序完全一致。
//
// 另外两个明确的口径选择：
//   * DoH 与 DoH3 统一走 wire 格式端点（application/dns-message），不用 JSON 端点，
//     这样两者的请求体、解析路径完全一致。
//   * "空答案"（NOERROR 但无 A 记录）单独计数，不算失败也不混进成功样本里假装很快。
//
// 用法：
//   cargo run --release
//   cargo run --release -- --mode cold --rounds 50 --warmup 10
//   cargo run --release -- --only plain,doh,doq --domains /Users/lihuwu/Downloads/domains.txt
//
// 参数：
//   --mode hot|cold       连接口径，默认 hot（贴近 Clash/mihomo 的稳态）
//   --rounds N            每个协议正式计时的查询次数，默认 30
//   --warmup N            预热次数（结果丢弃），默认 5
//   --domains FILE        域名列表文件，每行一个，默认 ./domains.txt
//   --only a,b,c          只测指定协议，可取值 plain,dot,doh,doh3,doq
//   --server IP/HOST      被测服务器，默认 223.5.5.5（要它五种协议全开）
//   --doh-url URL         DoH 端点，默认 https://<server>/dns-query
//   --no-progress         关掉实时进度（进度走 stderr，见下）
//
// 实时进度：TTY 下在 stderr 上原地刷一条进度条（当前协议、组合内第几次查询、
// 最近一次耗时、已用/预计剩余），每跑完一个协议补一行常驻记录。
// stdout 只留最终报告，所以 `... > out.txt` 拿到的仍是干净报告。
//
// 想看"多家服务商 × 它们各自支持的协议"的矩阵，用另一个二进制：
//   cargo run --release --bin providers -- --help
// ============================================================================

use std::{
    env,
    net::{Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};

use dns_protocol_bench::{
    install_crypto_provider, load_domains, next_value, pad_to, Endpoint, Mode, Progress, Proto,
    Report, Runner, EARLY_ABORT_AFTER, QUERY_TIMEOUT,
};
use tokio::time;

const DEFAULT_SERVER: &str = "223.5.5.5";
const PLAIN_PORT: u16 = 53;
const DOT_PORT: u16 = 853;
const DOQ_PORT: u16 = 853;
/// DoT / DoQ 的 TLS SNI 与证书校验名。服务器写成 IP 时，通常就是那个 IP 本身。
const DEFAULT_SNI: &str = "223.5.5.5";

struct Opt {
    mode: Mode,
    rounds: usize,
    warmup: usize,
    timeout: Duration,
    domains_file: String,
    domains_explicit: bool,
    server: String,
    sni: String,
    doh_url: Option<String>,
    no_progress: bool,
    protos: Vec<Proto>,
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
            server: DEFAULT_SERVER.to_owned(),
            sni: DEFAULT_SNI.to_owned(),
            doh_url: None,
            no_progress: false,
            protos: Proto::all().to_vec(),
        };

        let args: Vec<String> = env::args().skip(1).collect();
        let mut iter = args.into_iter();

        while let Some(key) = iter.next() {
            match key.as_str() {
                "--mode" => {
                    let value = next_value(&mut iter, &key);
                    opt.mode = match value.as_str() {
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
                "--server" => {
                    opt.server = next_value(&mut iter, &key);
                    opt.sni = opt.server.clone();
                }
                "--sni" => opt.sni = next_value(&mut iter, &key),
                "--doh-url" => opt.doh_url = Some(next_value(&mut iter, &key)),
                "--no-progress" => opt.no_progress = true,
                "--only" => {
                    let list = next_value(&mut iter, &key);
                    let mut protos = Vec::new();
                    for item in list.split(',') {
                        match Proto::parse(item) {
                            Some(p) => protos.push(p),
                            None => {
                                eprintln!("无法识别的协议名：{}", item);
                                std::process::exit(2);
                            }
                        }
                    }
                    if protos.is_empty() {
                        eprintln!("--only 不能为空");
                        std::process::exit(2);
                    }
                    opt.protos = protos;
                }
                "--help" | "-h" => {
                    println!("dns-protocol-bench [--mode hot|cold] [--rounds N] [--warmup N] [--timeout SEC] [--domains FILE]");
                    println!("                   [--only plain,dot,doh,doh3,doq] [--server IP] [--sni NAME] [--doh-url URL]");
                    println!("                   [--no-progress]");
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

    fn doh_url(&self) -> String {
        self.doh_url
            .clone()
            .unwrap_or_else(|| format!("https://{}/dns-query", self.server))
    }
}

fn endpoint_for(proto: Proto, opt: &Opt) -> Endpoint {
    match proto {
        Proto::Udp => {
            let ip: Ipv4Addr = opt
                .server
                .parse()
                .unwrap_or_else(|_| panic!("plain 需要 --server 是 IP，收到 {}", opt.server));
            Endpoint::Udp(SocketAddr::from((ip, PLAIN_PORT)))
        }
        Proto::Dot => Endpoint::Dot {
            host: opt.server.clone(),
            port: DOT_PORT,
            sni: opt.sni.clone(),
        },
        Proto::Doh => Endpoint::Doh {
            url: opt.doh_url(),
            h3: false,
        },
        Proto::Doh3 => Endpoint::Doh {
            url: opt.doh_url(),
            h3: true,
        },
        Proto::Doq => Endpoint::Doq {
            host: opt.server.clone(),
            port: DOQ_PORT,
            sni: opt.sni.clone(),
        },
    }
}

#[tokio::main]
async fn main() {
    install_crypto_provider();
    let opt = Opt::from_env();
    let (domains, domains_source) = load_domains(&opt.domains_file, opt.domains_explicit);

    println!(
        "服务器      {} (plain:{}, dot:{}, doq:{}, doh:{})",
        opt.server,
        PLAIN_PORT,
        DOT_PORT,
        DOQ_PORT,
        opt.doh_url()
    );
    println!("口径        {}", opt.mode.name());
    println!(
        "域名        {} 个（来源：{}，顺序固定循环使用）",
        domains.len(),
        domains_source
    );
    println!("预热 / 计时 {} 次 / 每协议 {} 次", opt.warmup, opt.rounds);
    println!("统一超时    {:?}", opt.timeout);
    println!();

    let mut reports = Vec::new();
    let mut progress = if opt.no_progress {
        Progress::disabled(opt.protos.len())
    } else {
        Progress::new(opt.protos.len())
    };

    for proto in &opt.protos {
        let label = proto.label();
        let t_start = Instant::now();
        progress.begin(label);

        let endpoint = endpoint_for(*proto, &opt);
        let mut runner = match Runner::new(&endpoint).await {
            Ok(r) => r,
            Err(e) => {
                let elapsed = t_start.elapsed();
                let line = format!(
                    "✗ [{}] {} 初始化失败：{}",
                    progress.counter(),
                    pad_to(label, 12),
                    e.summary()
                );
                progress.finish(&line, elapsed);
                continue;
            }
        };

        // 预热：建立连接 / 让 reqwest 完成握手，结果全部丢弃
        for i in 0..opt.warmup {
            progress.stage(&format!("预热 {}/{}", i + 1, opt.warmup));
            let domain = &domains[i % domains.len()];
            let _ = time::timeout(opt.timeout, runner.exchange(domain, opt.mode)).await;
        }

        let mut report = Report::new(label, label, *proto);
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
                        // NOERROR 但没有 A 记录（或 NXDOMAIN）：既不是失败，
                        // 也不该混进"很快的成功样本"
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

            // 提前放弃：一次都没成功过、又连续失败到阈值。
            // 继续跑只会白等 (rounds - i) × timeout，换不来任何新信息。
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
                pad_to(label, 12),
                report.p50(),
                report.p90(),
                report.max(),
                report.tally.ok,
                opt.rounds,
                elapsed.as_secs_f64()
            )
        } else {
            let reason = report
                .tally
                .first_error
                .clone()
                .or_else(|| report.tally.warmup_note.clone())
                .unwrap_or_else(|| {
                    format!("超时 {}/{}", report.tally.timeout, report.tally.attempts())
                });
            let tail = if report.tally.aborted {
                format!(" · 连败 {} 次后提前结束", EARLY_ABORT_AFTER)
            } else {
                String::new()
            };
            format!(
                "✗ [{}] {} 全部失败：{}{}  用时 {:.1}s",
                counter,
                pad_to(label, 12),
                reason,
                tail,
                elapsed.as_secs_f64()
            )
        };
        progress.finish(&line, elapsed);
        reports.push(report);
    }

    progress.done();
    println!();

    println!("══════════════════════════════════════════════════════");
    for report in &reports {
        report.print_block(opt.rounds);
        println!();
    }

    // 汇总排名：按 p50 排序，只列有成功样本的协议
    let mut ranked: Vec<&Report> = reports.iter().filter(|r| r.has_samples()).collect();
    ranked.sort_by(|a, b| {
        a.p50()
            .partial_cmp(&b.p50())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    println!("══════════════════════════════════════════════════════");
    println!("按 p50 排名（口径：{}）", opt.mode.name());
    for (i, report) in ranked.iter().enumerate() {
        println!(
            "  {}. {} p50 {:>7.1}  p90 {:>7.1}  max {:>8.1}  mean {:>7.1}  (成功 {}/{}，超时 {})",
            i + 1,
            pad_to(report.label.as_str(), 12),
            report.p50(),
            report.p90(),
            report.max(),
            report.mean(),
            report.tally.ok,
            opt.rounds,
            report.tally.timeout
        );
    }

    println!();
    println!("提醒：hot 口径测的是「连接已就绪时的查询延迟」，cold 口径测的是「首字节体验」。");
    println!("      两者结论可能相反，横向比较时务必用同一种口径，别和别的工具的数字混着看。");
}
