# dns-protocol-bench

> **DNS 延迟实测：同一口径下，横比五种协议与主流公共 DNS。**

```
$ providers

服务商                 UDP/53    DoT/853    DoH-h2    DoH3    DoQ/853
阿里 DNS                 34.6      28.2      29.2      29.7      33.3
腾讯 DNSPod              37.9     161.9      31.4        ✗        ~✗
360 DNS                  57.2      54.5      31.9        ✗        ~✗
OneDNS(微步)             34.2      34.6        ✗         ✗        ~✗
114 DNS                  48.4        ·         ·         ·         ·
百度 DNS                 60.4        ·         ·         ·         ·
字节 TrafficRoute        45.5        ·         ·         ·         ·
CNNIC DNS                52.4        ·         ·         ·         ·
本地网关                  5.4        ·         ·         ·         ·

·  该家没有这个协议     ✗  有端点但都失败     ~  --probe 试出来的，失败属正常
```

一行命令，把中国主流公共 DNS 按「服务商 × 协议」摊开测一遍，每个格子是 p50 毫秒。

它不打算回答"哪个 DNS 最好" —— 那取决于你在哪、走哪家运营商。它只回答**在你这条网络上**，此刻谁更快、哪个组合根本不通。上面这张表是示意，数字会在你机器上完全不同。

> 内置的服务商清单（见[内置了哪些服务商](#内置了哪些服务商)）。

[![CI](https://github.com/ifuema/dns-protocol-bench/actions/workflows/ci.yml/badge.svg)](https://github.com/ifuema/dns-protocol-bench/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.88-blue.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 装好就能跑

```bash
git clone https://github.com/ifuema/dns-protocol-bench.git
cd dns-protocol-bench
cargo install --path .        # 装到 ~/.cargo/bin
```

需要 **Rust 1.88+**（首次编译要拉依赖）。不想安装就本地构建：

```bash
cargo build --release
./target/release/providers
```

安装会得到两个命令。下面统一写命令名，走 `cargo build` 方式的话把 `providers` 换成 `./target/release/providers`。

| 命令 | 用途 |
|---|---|
| `providers` | 比服务商：主流公共 DNS 各家 × 各自支持的协议 |
| `dns-protocol-bench` | 比协议：固定一台服务器（默认 223.5.5.5），横比五种传输方式 |

---

## 三条命令

```bash
# 我该用哪家 DNS
providers

# DoH 和 DoQ 到底差多少（固定服务器，只让协议变）
dns-protocol-bench

# "第一次打开网站"的体验（把建连成本算进去）
providers --mode cold
```

想先缩小范围：

```bash
providers --list                  # 看看有哪些组合可以选
providers --only 阿里,腾讯        # 只测这两家
providers --protos udp,doh        # 只测这两列
```

---

## 看结果的三条规则

这三条比工具本身重要 —— 同一份数据，看错方向会得出完全相反的结论。

**① 只在「同一列」里比服务商。**
一列 = 同一种协议，这时变量只有服务商，是公平的比较。跨列比绝对值没有意义：端口待遇、路径、服务器部署位置全都不同。

**② 看 p90，别只看 p50。**
平均延迟漂亮但 p90 崩了，体感就是"偶尔卡一下"。加 `--verbose` 能看到每个组合的完整分位数。

**③ `✗` 的意思是"在你这条网络上不通"，不等于"这家不支持"。**
UDP 系的协议（DoQ、DoH3）被屏蔽时表现为静默丢包 → 超时，看起来和不支援一模一样。想区分"只是慢"和"真的不通"：

```bash
providers --only 腾讯 --protos doq --timeout 10
```

能通就是慢，依然超时就是不通。

**另外两个容易误读的点：**

- **本地网关常常最快，但那通常是缓存命中**（一跳就到），不代表它的递归质量更好，也不能指导代理软件的 DNS 配置。
- 跑完会顺手做一次**污染检查**（查不存在的子域，正常应答该是 NXDOMAIN）。如果返回了 A 记录，说明这条链路上有人在伪造应答 —— **换任何一家同地区的 DNS 都一样**（污染发生在递归器跨境询问权威服务器那一段，加密协议管不到）。

---

## 常用参数

两个命令共用：

| 参数 | 默认 | 说明 |
|---|---|---|
| `--mode hot\|cold` | `hot` | `hot` 连接复用（贴近 Clash 稳态）；`cold` 每条查询重建连接 |
| `--rounds N` | 30 | 每个组合正式计时的次数 |
| `--warmup N` | 5 | 预热次数（结果丢弃） |
| `--timeout SEC` | 3 | 单次查询超时，支持小数 |
| `--domains FILE` | `./domains.txt` | 换成你自己的域名列表 |
| `--no-progress` | 关 | 关掉实时进度条（进度走 stderr，重定向 stdout 不影响报告） |

`providers` 专有：

| 参数 | 说明 |
|---|---|
| `--protos udp,dot,doh,doh3,doq` | 只测指定的协议列 |
| `--only 关键字` | 按名字包含过滤，逗号分隔 |
| `--probe` | 试探各家没声明的协议（主要用来确认某家到底支不支持 DoQ） |
| `--with-backups` | 带上各家的备用地址 |
| `--isp IP` | 手动指定你的 ISP 的 DNS（不填则自动探测） |
| `--list` / `--verbose` | 只列组合 / 打印每个组合的详细统计 |

完整参数见 `providers --help`、`dns-protocol-bench --help`。

### 内置了哪些服务商

默认清单（改 `src/bin/providers.rs` 顶部的 `PROVIDERS` 表即可自由增删）：

| 服务商 | UDP | DoT | DoH | DoQ |
|---|---|---|---|---|
| 阿里 DNS | `223.5.5.5` | `dns.alidns.com` | `https://dns.alidns.com/dns-query` | `dns.alidns.com` |
| 腾讯 DNSPod | `119.29.29.29` | `dot.pub` | `https://doh.pub/dns-query` | — |
| 360 DNS | `101.226.4.6` | `dot.360.cn` | `https://doh.360.cn/dns-query` | — |
| OneDNS（微步） | `117.50.10.10` | `dot-pure.onedns.net` | `https://doh-pure.onedns.net/dns-query` | — |
| 114 DNS | `114.114.114.114` | — | — | — |
| 百度 DNS | `180.76.76.76` | — | — | — |
| 字节 TrafficRoute | `180.184.1.1` | — | — | — |
| CNNIC DNS | `1.2.4.8` | — | — | — |
| 本地网关 | 自动探测 | — | — | — |

各家只收**公开提供、且不做内容过滤**的「纯净版」端点。这份清单以中国服务商为主；换成你所在地区的服务商，改这张表就行。

---

## 为什么这些数字可以互相比较

网上"DoH 比 DoT 快 / DoQ 天下第一"这类结论互相矛盾，绝大多数不是谁测错了，而是**口径不同**。本工具把这些变量全部固定：

| 规则 | 为什么 |
|---|---|
| 串行分阶段：一个目标跑完再跑下一个 | 否则"谁快"取决于谁先抢到 CPU / 带宽 / NAT 表 |
| 每条查询串行，不并发 | 测的是延迟不是吞吐；并发测出来的是排队时间 |
| 统一超时包住整次操作 | 避免"DoT 每步各 3 秒、DoH 整次 3 秒"这种不可比的口径 |
| 先预热再计时，预热丢弃 | 把握手成本剔出分布，测的是稳态 |
| 固定域名序列 | 所有被测对象面对完全相同的域名顺序 |
| 空答案单独计数 | NOERROR 但无 A 记录不算失败，也不该混进成功样本假装很快 |
| 连接出错即丢弃 | 对齐 mihomo / Clash 的真实行为（DoQ 尤其：任何错误都砸连接） |

### hot 与 cold 的差别，就是建连成本

`hot` 下五种协议的 p50 常常只差几毫秒；换到 `cold`，差距拉到几十毫秒，而且差额精确对应握手往返数 × RTT：

| 协议 | 建连成本 | cold 相对 hot 的增量 |
|---|---|---|
| `UDP/53` | 无握手 | ≈ 0 |
| `DoQ/853` | QUIC 握手 1 RTT | ≈ 1 × RTT |
| `DoH3` | 1 RTT + HTTP/3 建流 | ≈ 1 RTT 再多一点 |
| `DoT/853` / `DoH-h2` | TCP 1 RTT + TLS 1.3 1 RTT = 2 RTT | ≈ 2 × RTT |

⚠️ 两个口径的结论会完全不同，比较时务必用同一种，也别和别的工具的数字混着看。

### 两层防误判

- **预热失败会告警。** 预热没建起连接时，热口径其实退化成了冷口径（每条查询都在付建连成本），数字会明显偏高，报告里会标 `⚠️ 预热就超时`。
- **死掉的组合提前放弃。** 一次都没成功过又连续失败 8 次就跳过剩余查询。一轮全矩阵里往往一半时间花在早就确定死掉的组合上 —— 实测能把单个死组合从 180 秒压到 54 秒。

---

## 附带的诊断脚本

`tools/dnssec-probe.py` 是个独立的 Python 脚本（不需要 Rust 环境），用来检测各家 DNS 的 DNSSEC 支持情况：

```bash
python3 tools/dnssec-probe.py              # 测全部预设目标
python3 tools/dnssec-probe.py 223.5.5.5    # 只测指定服务器
python3 tools/dnssec-probe.py --no-tls     # 跳过 DoT/DoH，只测明文 UDP
```

判定分三档：

| 档位 | 含义 |
|---|---|
| ★ **验证型** | 真的验签：签名损坏的域名会返回 SERVFAIL |
| · **仅透传** | 不验证，但把 RRSIG 等记录原样给你，客户端可以自己验 |
| × **不支持** | 不验证，还把 DNSSEC 记录剥掉，客户端连材料都拿不到 |

它自带三项自查，都是为了不让结论被环境骗了：

- **明文 UDP 是否被劫持** —— 往 RFC 5737 保留段（公网不路由）发查询，能收到应答就说明被劫持了
- **TLS 信任库是否可用** —— 证书验不过时自动回退到 `certifi`；实在没有才降级为不校验，并在结果里标注
- **同通道两次答案是否自洽** —— 一次带 RRSIG 一次不带，说明链路有中间设备干扰，判为「数据可疑」而不硬下结论

结论可信度 `DoH > DoT > 明文 UDP`（前两者走 TLS，中间插不进去）。每个目标末尾会给一行综合判定，取可信度最高的那个通道。

---

## 项目结构

```
dns-protocol-bench/
├── Cargo.toml
├── .cargo/config.toml      # reqwest h3 需要的 rustflags（别删）
├── domains.txt             # 默认域名列表，可换
├── src/
│   ├── lib.rs              # 共享内核：DNS wire 格式、五种协议的 Runner、统计口径
│   ├── main.rs             # dns-protocol-bench：协议对比
│   └── bin/providers.rs    # providers：服务商 × 协议矩阵
├── tools/dnssec-probe.py   # DNSSEC 支持检测（独立脚本）
└── .github/workflows/ci.yml
```

协议实现放在 `src/lib.rs` 由两个二进制共用 —— DoT 的 TCP 分帧、DoQ 的 RFC 9250 细节、`reqwest` 的 h3 开关都是最容易写错也最容易过时的部分，不该存在两份副本。

想加减被测的服务商，直接改 `src/bin/providers.rs` 顶部的 `PROVIDERS` 表。

```bash
cargo fmt
cargo clippy --all-targets
cargo build --release
```

CI 在 Linux + macOS 上跑 `fmt --check` 和 `clippy -D warnings`，另有一个 job 用 Rust 1.88 跑 `build --locked` 守住 MSRV 声明。

> `cargo run` 不带 `--bin` 时跑 `dns-protocol-bench`（由 `Cargo.toml` 的 `default-run` 指定）。新增第三个二进制时记得同步这一行。

---

## 许可

[MIT](LICENSE)
