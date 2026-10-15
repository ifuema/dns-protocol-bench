# dns-protocol-bench

> 在**你自己的网络上**，用同一套口径实测：哪家公共 DNS 更快、哪种传输协议更快、哪些组合根本不通。

[![CI](https://github.com/ifuema/dns-protocol-bench/actions/workflows/ci.yml/badge.svg)](https://github.com/ifuema/dns-protocol-bench/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.88-blue.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

两个命令行工具，共用同一份协议实现和计时口径：

| 命令 | 回答的问题 | 怎么比 |
|---|---|---|
| `providers` | 我该用哪家 DNS？ | 主流公共 DNS 各家 × 各家支持的协议，摊成一张矩阵 |
| `dns-protocol-bench` | DoH 和 DoQ 到底差多少？ | 固定一台服务器（默认阿里 `223.5.5.5`），只让协议变 |

覆盖五种传输：`UDP/53` 明文、`DoT/853`（RFC 7858）、`DoH-h2`（RFC 8484，HTTP/2）、`DoH3`（HTTP/3）、`DoQ/853`（RFC 9250）。

```
$ providers --probe
...
【服务商 × 协议 矩阵】单元格 = p50 毫秒
  ·  该家没有提供这个协议（也没探测）
  ✗  有端点但每次都失败（原因见下面的清单）
  ~  该格是 --probe 试行出来的，失败属正常
  !  数字后带 ! = 预热失败过，p50 可能含建连成本而偏高（见下面的清单）

服务商                                UDP/53  DoT/853   DoH-h2     DoH3  DoQ/853
阿里 DNS                                34.6     28.2     29.2     29.7     33.3
腾讯 DNSPod                             37.9    161.9     31.4        ✗       ~✗
360 DNS                                 57.2     54.5     31.9        ✗       ~✗
OneDNS(微步)                            34.2     34.6        ✗        ✗       ~✗
114 DNS                                 48.4        ·        ·        ·        ·
百度 DNS                                60.4        ·        ·        ·        ·
字节 TrafficRoute                       45.5        ·        ·        ·        ·
CNNIC DNS                               52.4        ·        ·        ·        ·
运营商/网关 DNS(自动) 192.168.1.1        5.4        ·        ·        ·        ·
```

上面的数字只是示意，在你的机器上会完全不同。DNS 快慢取决于你在哪、走哪家运营商、此刻的线路 —— 这个工具不回答"哪家 DNS 最好"，只回答**在你这条网络上、此刻**谁快、谁不通。

---

## 安装

需要：

- Rust **1.88+**
- **cmake**（TLS 加密后端 `aws-lc-sys` 的构建依赖）；Linux 上还要 **nasm**

```bash
sudo apt install cmake nasm     # Debian / Ubuntu
brew install cmake              # macOS
```

然后：

```bash
git clone https://github.com/ifuema/dns-protocol-bench.git
cd dns-protocol-bench
cargo install --path .          # providers 和 dns-protocol-bench 装到 ~/.cargo/bin
```

不想装到全局就直接构建，并用 `./target/release/providers` 代替下文的 `providers`：

```bash
cargo build --release
```

## 快速上手

```bash
providers                       # 全矩阵：各家 × 各协议（hot 口径）
providers --mode cold           # 把建连成本算进去，≈「第一次打开网站」的体验
dns-protocol-bench              # 固定阿里 DNS，横比五种协议

providers --list                # 先看看有哪些组合，不测
providers --only 阿里,腾讯       # 只测名字里含这些关键字的组合
providers --protos udp,doh      # 只测这几列
```

全矩阵要跑几分钟。进度条和逐组合记录走 stderr，报告（含污染检查的结论）走 stdout，所以 `providers > report.txt` 拿到的是干净完整的报告，进度照样显示在屏幕上。

---

## 读懂报告

`providers` 的报告依次是：

1. **矩阵**：每格是该组合的 p50（毫秒），符号含义见上面的示例。
2. **预热失败但有样本的组合**：矩阵里带 `!` 的格子，附预热时的错误（为什么要单独列，见[两道防误判](#两道防误判)）。
3. **全部失败的组合**：每个 `✗` 的首条错误，以及是不是在预热阶段就已失败。
4. **同一协议下横比各家**：按 p50 排序，附与第一名的差距、p90 和 max；预热失败过的行尾标 `! 预热失败`。
5. **每家最快的协议**：同一家内部比协议，并给出比它自己的 UDP/53 快多少。
6. **污染/劫持检查**（见[下文](#污染劫持检查)）。

加 `--verbose` 还会打印每个组合的完整统计：min / p50 / p90 / p99 / max / mean、空答案数、错误分类。

### 三条规则

同一份数据，看错方向会得出相反的结论。

**① 只在同一列里比服务商。**
一列是同一种协议，变量只剩服务商，这才是公平比较。跨列比绝对值没有意义：端口待遇、路径、服务器部署位置都不同 —— 跨列只能说明「这份配置更快」，不能说明「这个协议更好」。

**② 看 p90，不只看 p50。**
p50 漂亮但 p90 崩了，体感就是"偶尔卡一下"。

**③ `✗` 是"在你的网络上不通"，不等于"这家不支持"。**
走 UDP 的协议（明文、DoQ、DoH3）被屏蔽时表现为静默丢包 → 超时，看起来和不支持一模一样；DoT / DoH 走 TCP，被拦时通常很快报 connection refused / reset。想分清"只是慢"还是"真不通"，放宽超时单独再测一次：

```bash
providers --only 腾讯 --protos doq --probe --timeout 10
```

能通就是慢，依然超时就是不通。（腾讯没有声明 DoQ，所以这里要加 `--probe` 才会测这一格。）

### 运营商 / 网关 DNS 那一行

除了内置的公共 DNS，`providers` 还会把你本机正在用的 DNS 加进 UDP/53 这一列作参照：

- **自动探测只支持 macOS**：读的是 DHCP 下发的 DNS，即使系统 DNS 已被 Clash 改成 127.0.0.1 也能拿到。其他系统会提示探测失败，用 `--isp 202.96.69.38` 手动指定即可。
- **探测到内网地址（192.168.x.x 等）说明请求先发到了路由器。** 它常常最快，但那多半是缓存命中、一跳就到，不代表它的递归质量更好，也不能拿来指导代理软件的 DNS 配置。想测运营商的裸 DNS，去路由器管理页看 WAN 侧的 DNS，再用 `--isp` 填进来。

### 污染/劫持检查

测完后，对每家（取它在清单里的第一个组合，通常是 UDP/53）查 3 次「被封锁站点下随机生成、实际不存在的子域」，默认基准是 `youtube.com` 和 `google.com`。老实的服务器应该回 NXDOMAIN；如果塞回了 A 记录，就是应答被污染或被拦截了。

国内递归服务器向境外权威服务器查询时就可能拿到被污染的结果，这发生在服务器那一侧 —— 你和它之间换成什么加密协议都管不到，换同地区的另一家多半也一样。

`--nxdomain-base a.com,b.com` 换基准域名，`--no-hijack-check` 跳过整个检查。

---

## 参数

两个命令共用：

| 参数 | 默认 | 说明 |
|---|---|---|
| `--mode hot\|cold` | `hot` | `hot` 复用连接（贴近 Clash / mihomo 的稳态）；`cold` 每条查询重建连接 |
| `--rounds N` | `30` | 每个组合正式计时的查询次数 |
| `--warmup N` | `5` | 预热次数，结果丢弃 |
| `--timeout SEC` | `3` | 单次查询的总超时（含建连），可写小数 |
| `--domains FILE` | `domains.txt` | 域名列表，见[域名列表](#域名列表) |
| `--no-progress` | — | 关掉进度条和逐组合记录，只留报告（污染检查结论照打） |

`providers`：

| 参数 | 说明 |
|---|---|
| `--protos udp,dot,doh,doh3,doq` | 只测这几列 |
| `--only 关键字,…` | 只测名字里包含任一关键字的组合（名字先用 `--list` 看） |
| `--list` | 只列出被测组合和端点，不测 |
| `--probe` | 额外试探各家没声明的协议：拿 DoT 主机名试 DoQ（两者都在 853 端口，只是 ALPN 不同），拿 DoH 主机名试 DoT |
| `--with-backups` | 加上各家的备用明文地址 |
| `--isp IP` | 手动指定运营商 DNS（非 macOS 必须手动指定） |
| `--verbose` | 打印每个组合的完整统计 |
| `--nxdomain-base 域名,…` | 污染检查的基准域名，默认 `youtube.com,google.com` |
| `--no-hijack-check` | 跳过污染检查 |

`dns-protocol-bench`：

| 参数 | 默认 | 说明 |
|---|---|---|
| `--only plain,dot,doh,doh3,doq` | 全部 | 只测这几种协议 |
| `--server IP` | `223.5.5.5` | 被测服务器。要测 `plain` 时必须写 IP |
| `--sni NAME` | 同 `--server` | DoT / DoQ 的 TLS SNI 与证书校验名（写在 `--server` 之后才生效） |
| `--doh-url URL` | `https://<server>/dns-query` | DoH / DoH3 的端点 |

> ⚠️ 两个命令的 `--only` 含义不同：在 `providers` 里按名字过滤服务商，在 `dns-protocol-bench` 里选协议。

换 `--server` 时，那台服务器得五种协议都开着，否则用 `--only` 去掉它不支持的。

### 域名列表

默认读当前目录的 `domains.txt`；找不到就回退到编译时仓库目录里的那份，再找不到就用内置列表 —— 所以在任何目录下都能直接跑。用 `--domains` 显式指定时不做回退，读不到直接报错。

列表会去掉空行、`#` 注释和重复项，按顺序循环使用。自带的列表国内、国外域名各 12 个：只测国内会低估跨境解析的差异，只测国外又会把污染带来的额外开销算进去。想让多次运行的结果可以互相比较，就别改它。

---

## 测量口径

网上"DoH 比 DoT 快""DoQ 天下第一"之类的结论互相矛盾，大多不是谁测错了，而是**口径不同**。本工具把这些变量全部固定，两个命令共用 `src/lib.rs` 里的同一份实现：

| 规则 | 为什么 |
|---|---|
| 串行分阶段：一个组合跑完再跑下一个 | 否则"谁快"取决于谁先抢到 CPU / 带宽 / NAT 表 |
| 每条查询串行，不并发 | 测的是延迟不是吞吐；并发测到的是排队时间 |
| 统一超时包住整次操作（含建连） | 避免"DoT 每步各 3 秒、DoH 整次 3 秒"这种不可比的口径 |
| 先预热再计时，预热结果丢弃 | 把首次握手剔出分布，hot 测的是稳态 |
| 固定域名序列 | 所有组合面对完全相同的域名顺序 |
| 服务器主机名在计时窗口外解析 | cold 测的是"重建连接"，不是"重新解析服务器地址" |
| DoH 与 DoH3 都用 POST + wire 格式（`application/dns-message`） | 两者的请求体、解析路径完全一致 |
| 空答案单独计数 | NOERROR 但无 A 记录不算失败，也不混进成功样本假装很快 |
| 连接出错即丢弃 | 对齐 mihomo / Clash 的实际行为（DoQ 尤其：任何错误都砸掉连接） |
| DoH 不走 `HTTP(S)_PROXY` | 走了代理，测到的就是到代理的延迟 |

### hot 与 cold：差的就是建连成本

hot 下五种协议的 p50 常常只差几毫秒；换到 cold，差距会拉开到几十毫秒，差额大致等于握手往返数 × RTT：

| 协议 | 建连成本 | cold 比 hot 多出 |
|---|---|---|
| `UDP/53` | 无握手（每条查询本来就新建 socket） | ≈ 0 |
| `DoQ/853` | QUIC 握手 1 RTT | ≈ 1 × RTT |
| `DoH3` | QUIC 1 RTT + HTTP/3 建流 | ≈ 1 RTT 再多一点 |
| `DoT/853`、`DoH-h2` | TCP 1 RTT + TLS 1.3 1 RTT | ≈ 2 × RTT |

两种口径的结论可能相反。比较时务必用同一种，也别和别的工具测出的数字混着看。

### 两道防误判

- **预热失败会标出来。** 预热没建起连接时，hot 其实退化成了 cold：正式查询有一部分在付建连成本，p50 看着正常其实偏高。这样的组合在矩阵里数字后带 `!`，矩阵下方单独列出并附预热时的错误，同协议排名的行尾也标 `! 预热失败`；全部失败的组合则在失败清单里注明是不是预热阶段就已失败。`--verbose` 和 `dns-protocol-bench` 的逐项统计里同样会打出这条告警。想确认就单独重跑它，例如 `providers --only 腾讯 --protos dot`。
- **死掉的组合提前放弃。** 一个组合一次都没成功、又连续失败 8 次，就跳过它剩下的查询 —— 继续跑只会每条都白等满超时，换不来新信息。在 cold 全矩阵的实测里，这一步省掉了约 80% 的总耗时。

---

## 内置服务商

| 服务商 | UDP/53 | DoT | DoH（h2 和 h3 都测） | DoQ |
|---|---|---|---|---|
| 阿里 DNS | `223.5.5.5` | `dns.alidns.com` | `https://dns.alidns.com/dns-query` | `dns.alidns.com` |
| 腾讯 DNSPod | `119.29.29.29` | `dot.pub` | `https://doh.pub/dns-query` | — |
| 360 DNS | `101.226.4.6` | `dot.360.cn` | `https://doh.360.cn/dns-query` | — |
| OneDNS（微步） | `117.50.10.10` | `dot-pure.onedns.net` | `https://doh-pure.onedns.net/dns-query` | — |
| 114 DNS | `114.114.114.114` | — | — | — |
| 百度 DNS | `180.76.76.76` | — | — | — |
| 字节 TrafficRoute | `180.184.1.1` | — | — | — |
| CNNIC DNS | `1.2.4.8` | — | — | — |

`--with-backups` 加入的备用地址：阿里 `223.6.6.6`、腾讯 `119.28.28.28`、360 `218.30.118.6`、114 `114.114.115.115`、字节 `180.184.2.2`、OneDNS `52.80.52.52`。

- 只收公开提供、不做内容过滤的「纯净版」端点。
- OneDNS 的 DoH 端点在部分网络下 TCP 能连上、TLS 握手却挂住，跑出超时不一定是你的问题。
- 清单以中国服务商为主。想加减或换成你所在地区的服务商，改 `src/bin/providers.rs` 顶部的 `PROVIDERS` 表（备用地址在 `BACKUPS`），重新构建即可。

## 已知限制

- **只测 IPv4**：查询的是 A 记录，DoT / DoQ 的服务器主机名也只取 IPv4 地址。
- **运营商 DNS 自动探测只支持 macOS**，其他系统用 `--isp`。
- **先关掉代理的 TUN 模式。** Clash / mihomo 等开着 TUN 时，流量（包括 53 端口的明文查询）可能被它接管，测到的就不是到服务商的真实延迟。

---

## DNSSEC 探测脚本

`tools/dnssec-probe.py` 是独立的 Python 3 脚本，只用标准库（`certifi` 可选），不需要 Rust：

```bash
python3 tools/dnssec-probe.py               # 测全部预设目标
python3 tools/dnssec-probe.py 223.5.5.5 腾讯 # 只测名字或地址包含这些关键字的目标
python3 tools/dnssec-probe.py --no-tls      # 跳过 DoT / DoH，只测明文 UDP
```

它用一对探针判定：签名故意损坏的 `dnssec-failed.org`，和签名正常的 `cloudflare.com`。

| 判定 | 含义 |
|---|---|
| ★ **验证型** | 真的验签：坏签名返回 SERVFAIL |
| ☆ **只置 AD 位** | 给正常域名置了 AD 位，但坏签名照样放行 |
| · **仅透传** | 不验证，但把 RRSIG 等记录原样返回，客户端可以自己验 |
| × **不支持** | 不验证，还把 DNSSEC 记录剥掉，客户端连材料都拿不到 |

只有 ★ 才算真正支持 DNSSEC。预设目标除了国内各家，还有 Cloudflare 和 Google 作参照组，用来确认探针本身没写错。

脚本自带三项自查，免得结论被环境骗了：

- **明文 UDP 是否被劫持**：往 RFC 5737 保留段（公网不路由）发查询，能收到应答就说明 53 端口被透明劫持，UDP 那一行不可信。
- **TLS 信任库是否可用**：系统根证书验不过时自动回退到 `certifi`；还不行才降级为不校验证书，并在结果里标注。
- **同一通道两次答案是否自洽**：一次带 RRSIG、一次不带，说明链路上有设备在干扰，判为「数据可疑」而不硬下结论。

每个目标最后给一行综合判定，取可信度最高的通道：DoH > DoT > 明文 UDP（前两者走 TLS，中间设备插不进去）。

---

## 开发

```
dns-protocol-bench/
├── src/
│   ├── lib.rs              # 共享内核：DNS 报文、五种协议的执行器、统计、进度条
│   ├── main.rs             # dns-protocol-bench
│   └── bin/providers.rs    # providers（服务商清单 PROVIDERS 在文件顶部）
├── tools/dnssec-probe.py   # DNSSEC 探测（独立脚本）
├── domains.txt             # 默认域名列表
├── .cargo/config.toml      # 开启 reqwest HTTP/3 所需的 cfg，别删
└── .github/workflows/ci.yml
```

协议实现集中在 `src/lib.rs` 由两个二进制共用 —— DoT 的 TCP 分帧、DoQ 的 RFC 9250 细节、reqwest 的 h3 开关，都是最容易写错也最容易过时的部分，不该有两份副本。

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo build --release
```

CI 在 Linux 和 macOS 上跑 `fmt --check` 与 `clippy -D warnings`，另用 Rust 1.88 跑一次 `build --locked`，守住 MSRV 声明。

`cargo run` 不带 `--bin` 时跑的是 `dns-protocol-bench`（由 `Cargo.toml` 的 `default-run` 指定）；跑另一个用 `cargo run --release --bin providers`。新增第三个二进制时记得检查这一行。

## 许可

[MIT](LICENSE)
