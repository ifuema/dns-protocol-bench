#!/usr/bin/env python3
# ============================================================================
# dnssec-probe.py —— 检测各家 DNS 的 DNSSEC 支持情况
#
# 用法：
#   python3 dnssec-probe.py                  # 测全部预设目标
#   python3 dnssec-probe.py 223.5.5.5        # 只测指定服务器
#   python3 dnssec-probe.py --no-tls         # 跳过 DoT/DoH，只测明文 UDP
#
# 判定分三档（必须用一对探针才能区分，只看一个会误判）：
#   ★ 验证型    —— 对「签名故意损坏」的域名返回 SERVFAIL（真的在做验证）
#   · 仅透传    —— 不验证，但把 RRSIG 等 DNSSEC 记录原样返回给客户端
#   × 不支持    —— 不验证，而且把 DNSSEC 记录剥掉（客户端想自己验也没材料）
#
# 为什么要有两对探针：
#   只查坏签名 → 分不清「验证型」和「拒绝服务」
#   只查好签名 → 分不清「验证型」和「只是把上游的 AD 位透传」
#
# 三项自带的自查：
#   ① 明文 UDP 是否被透明劫持 —— 往 RFC 5737 保留段发查询，能收到应答就是被劫持
#   ② TLS 信任库是否可用      —— 证书验不过时自动降级并标注，不让环境问题挡住结论
#   ③ 同通道两次答案是否自洽  —— 一次带 RRSIG 一次不带，说明链路有中间设备干扰
#
# 结论的可信度排序：DoH > DoT > 明文 UDP。综合判定取可信度最高的通道。
# ============================================================================

import random
import socket
import ssl
import struct
import sys
import urllib.error
import urllib.request

BAD = "dnssec-failed.org"   # 签名故意损坏：验证型必须 SERVFAIL
GOOD = "cloudflare.com"     # 签名正常：验证型应置 AD=1 并带 RRSIG

RC = {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}

# 判定码：validating > ad_only > passthru > none
RANK = {"validating": 3, "ad_only": 2, "passthru": 1, "none": 0}
CHANNEL_TRUST = {"DoH": 3, "DoT/853": 2, "UDP/53": 1}

# UDP(53) / DoT(853) / DoH，None 表示该家不提供
TARGETS = [
    ("阿里 DNS",      "223.5.5.5",        "dns.alidns.com",      "https://dns.alidns.com/dns-query"),
    ("腾讯 DNSPod",   "119.29.29.29",     "dot.pub",             "https://doh.pub/dns-query"),
    ("360 DNS",       "101.226.4.6",      "dot.360.cn",          "https://doh.360.cn/dns-query"),
    ("OneDNS(微步)",  "117.50.10.10",     "dot-pure.onedns.net", None),
    ("114 DNS",       "114.114.114.114",  None,                  None),
    ("百度 DNS",      "180.76.76.76",     None,                  None),
    ("CNNIC DNS",     "1.2.4.8",          None,                  None),
    ("字节 TrafficRoute", "180.184.1.1",  None,                  None),
    # 参照组：公认的验证型，用来确认探针本身没写错。
    # 注意：8.8.8.8 的明文在国内常被干扰，它的 UDP 行不可信，只看 DoH。
    ("— 参照 Cloudflare", "1.1.1.1",      "one.one.one.one",     "https://cloudflare-dns.com/dns-query"),
    ("— 参照 Google",     "8.8.8.8",      "dns.google",          "https://dns.google/dns-query"),
]

TLS_VERIFY_OK = True     # 启动时探测，False 则 DoT/DoH 降级为不校验证书
TLS_NOTE_OK = True       # 网络层是否通（区分「证书问题」和「网络不通」）
TLS_CAFILE = None        # 系统的根证书库不可用时，回退到 certifi 的 bundle


# ---------------------------------------------------------------------------
# DNS 报文构造 / 解析
# ---------------------------------------------------------------------------

def build_query(name, do=True):
    qid = random.randrange(65536)
    pkt = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 1 if do else 0)
    for label in name.split("."):
        pkt += bytes([len(label)]) + label.encode()
    pkt += b"\x00" + struct.pack(">HH", 1, 1)          # QTYPE=A QCLASS=IN
    if do:
        # EDNS0 OPT：type=41, class=UDP payload, TTL 高位 = DO 位, rdlen=0
        pkt += b"\x00" + struct.pack(">HHIH", 41, 4096, 0x00008000, 0)
    return qid, pkt


def skip_name(data, off):
    while True:
        ln = data[off]
        if ln & 0xC0 == 0xC0:
            return off + 2
        off += 1
        if ln == 0:
            return off
        off += ln


def parse(data, want_id):
    if len(data) < 12 or struct.unpack(">H", data[0:2])[0] != want_id:
        return None
    flags = struct.unpack(">H", data[2:4])[0]
    qd, an, ns, ar = struct.unpack(">HHHH", data[4:12])
    off = 12
    for _ in range(qd):
        off = skip_name(data, off) + 4
    records = []
    for count in (an, ns, ar):
        for _ in range(count):
            off = skip_name(data, off)
            if off + 10 > len(data):
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10 + rdlen
            if rtype in (46, 47, 48):
                records.append({46: "RRSIG", 47: "NSEC", 48: "DNSKEY"}[rtype])
    return (flags & 0xF, (flags >> 5) & 1, an, records)


# ---------------------------------------------------------------------------
# 自查一：明文 UDP 是否被透明劫持
# ---------------------------------------------------------------------------

def over_udp(ip, name, timeout=4):
    qid, pkt = build_query(name)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (ip, 53))
        data, _ = s.recvfrom(4096)
        return parse(data, qid)
    except socket.timeout:
        return ("ERR", "Timeout")
    except Exception as e:
        return ("ERR", type(e).__name__)
    finally:
        s.close()


def hijack_selfcheck():
    print("① 明文 DNS 是否被透明劫持")
    print("   做法：往 RFC 5737 保留段（公网不路由）发 DNS 查询，能收到应答就是被劫持")
    hijacked = False
    for probe_ip, label in [("192.0.2.1", "TEST-NET-1"), ("203.0.113.1", "TEST-NET-3")]:
        r = over_udp(probe_ip, "dnssec-failed.org", timeout=3)
        if isinstance(r, tuple) and r and r[0] == "ERR":
            print(f"   {label:12s} ({probe_ip}) 超时 —— 正常，没有被劫持")
        else:
            rcode = r[0] if r else "?"
            print(f"   {label:12s} ({probe_ip}) ⚠️ 收到应答 rcode={RC.get(rcode, rcode)}"
                  f" —— 这个地址不可能有 DNS 服务器，说明明文 UDP 53 被劫持了")
            hijacked = True
    print("   → " + ("明文 UDP 行不可信，只看 DoT / DoH 行。" if hijacked
                     else "明文 DNS 干净，UDP 行可以作为结论。"))
    print()
    return hijacked


# ---------------------------------------------------------------------------
# 自查二：TLS 信任库能不能用（证书验不过时不让结论一起废掉）
# ---------------------------------------------------------------------------

def certifi_bundle():
    try:
        import certifi
        return certifi.where()
    except Exception:
        return None


def tls_probe(host, port=443, timeout=6, cafile=None):
    """返回 ('ok'|'cert'|'unreachable', 详情)"""
    try:
        ctx = ssl.create_default_context(cafile=cafile)
        raw = socket.create_connection((host, port), timeout=timeout)
        ctx.wrap_socket(raw, server_hostname=host).close()
        return ("ok", None)
    except ssl.SSLCertVerificationError as e:
        return ("cert", str(e).split("(")[0].strip())
    except Exception as e:
        return ("unreachable", type(e).__name__)


def tls_selfcheck():
    global TLS_VERIFY_OK, TLS_NOTE_OK, TLS_CAFILE
    print("② TLS 信任库是否可用")
    state, detail = tls_probe("dns.alidns.com", 443)
    if state == "ok":
        print("   dns.alidns.com:443 TLS 校验通过 —— DoT/DoH 结果可信")
        print()
        return

    if state == "cert":
        # 系统根证书库坏了：先别急着关校验，试试 certifi 的 bundle
        bundle = certifi_bundle()
        if bundle:
            state2, _ = tls_probe("dns.alidns.com", 443, cafile=bundle)
            if state2 == "ok":
                TLS_CAFILE = bundle
                print(f"   ⚠️ 系统根证书库不可用（{detail}），但本机有 certifi —— 已回退用它校验。")
                print(f"      使用 {bundle}")
                print()
                return
        TLS_VERIFY_OK = False
        print(f"   ⚠️ 证书校验失败（{detail}）—— TCP/TLS 已连上，只是验不过证书。")
        print("      这通常是本机 Python 的根证书库为空，不是网络问题。")
        print("      修法（任选其一）：")
        print("        python3 -m pip install --user certifi    # 装完本脚本会自动回退用它")
        print("        brew install python3                     # 换成自带根证书的 Python")
        print("      已自动降级：DoT/DoH 改为不校验证书，并在结果里标注「证书未校验」。")
        print()
        return

    TLS_NOTE_OK = False
    print(f"   ⚠️ 连不上 dns.alidns.com:443（{detail}）—— DoT/DoH 会被跳过，只看 UDP。")
    print()


def tls_context(verify):
    ctx = ssl.create_default_context(cafile=TLS_CAFILE)
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ---------------------------------------------------------------------------
# DoT / DoH
# ---------------------------------------------------------------------------

def over_dot(host, name, port=853, timeout=8):
    qid, pkt = build_query(name)
    verify = TLS_VERIFY_OK
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        tls = tls_context(verify).wrap_socket(raw, server_hostname=host)
        tls.sendall(struct.pack(">H", len(pkt)) + pkt)
        n = struct.unpack(">H", tls.recv(2))[0]
        body = b""
        while len(body) < n:
            body += tls.recv(n - len(body))
        tls.close()
        return parse(body, qid)
    except ssl.SSLCertVerificationError:
        if verify:
            # 第一次撞上证书问题就地降级，让这一轮仍有结果
            try:
                raw = socket.create_connection((host, port), timeout=timeout)
                tls = tls_context(False).wrap_socket(raw, server_hostname=host)
                tls.sendall(struct.pack(">H", len(pkt)) + pkt)
                n = struct.unpack(">H", tls.recv(2))[0]
                body = b""
                while len(body) < n:
                    body += tls.recv(n - len(body))
                tls.close()
                return parse(body, qid)
            except Exception as e:
                return ("ERR", type(e).__name__)
        return ("ERR", "CertVerify")
    except Exception as e:
        return ("ERR", type(e).__name__)


def over_doh(url, name, timeout=10):
    qid, pkt = build_query(name)
    req = urllib.request.Request(url, data=pkt, headers={
        "accept": "application/dns-message",
        "content-type": "application/dns-message",
    })
    for verify in ([True, False] if TLS_VERIFY_OK else [False]):
        try:
            handlers = [urllib.request.ProxyHandler({})]
            if not verify:
                ctx = tls_context(False)
                handlers.append(urllib.request.HTTPSHandler(context=ctx))
            opener = urllib.request.build_opener(*handlers)
            with opener.open(req, timeout=timeout) as resp:
                return parse(resp.read(), qid)
        except urllib.error.URLError as e:
            # 证书问题就地降级重试一次
            if isinstance(getattr(e, "reason", None), ssl.SSLCertVerificationError) and verify:
                continue
            return ("ERR", type(e.reason).__name__ if getattr(e, "reason", None) else "URLError")
        except Exception as e:
            return ("ERR", type(e).__name__)
    return ("ERR", "URLError")


# ---------------------------------------------------------------------------
# 判定
# ---------------------------------------------------------------------------

def is_err(t):
    return t is None or (isinstance(t, tuple) and t and t[0] == "ERR")


def fmt(t):
    if t is None:
        return "无应答"
    if isinstance(t, tuple) and t and t[0] == "ERR":
        return f"失败({t[1]})"
    rcode, ad, an, records = t
    return f"{RC.get(rcode, rcode):9s} AD={ad} 答案={an} DNSSEC记录={','.join(sorted(set(records))) or '无'}"


def judge(bad, good):
    """返回 (判定码或 None, 展示文本)"""
    if is_err(bad) and is_err(good):
        return None, "端点不通，无法判定"
    if not is_err(bad) and bad[0] == 2:
        return "validating", "★ 验证型（拒收坏签名）"
    # 坏签名探针没拿到应答，而好签名探针却带 AD/RRSIG —— 这时无法区分
    # 「验证型」和「仅置 AD 位」，不能硬下结论
    if is_err(bad) and (not is_err(good)) and (good[1] == 1 or good[3]):
        return None, "⚠️ 坏签名探针未拿到应答，与「仅置 AD 位」无法区分（再跑一次）"
    bad_rr = (not is_err(bad)) and bool(bad[3])
    good_rr = (not is_err(good)) and bool(good[3])
    # 自查三：同一通道两次答案自相矛盾，说明有中间设备在动手脚，不能据此下结论
    if not is_err(bad) and not is_err(good) and bad_rr != good_rr:
        return None, "⚠️ 数据可疑（同通道两次不自洽，疑似被干扰）"
    if not is_err(good) and good[1] == 1:
        return "ad_only", "☆ 置 AD 位但不拒坏签名"
    if good_rr:
        return "passthru", "· 仅透传 DNSSEC 记录，不验证"
    return "none", "× 不支持（连 DNSSEC 记录都剥离）"


# ---------------------------------------------------------------------------

USAGE = """\
用法：python3 dnssec-probe.py [选项] [关键字 ...]

  关键字        只测名字/地址里包含该关键字的目标（可给多个，如 223.5.5.5 阿里）
  --no-tls      跳过 DoT/DoH，只测明文 UDP
  -h, --help    显示本帮助

不带关键字就测全部预设目标。完整说明见脚本头部注释或 README。"""


def main():
    argv = sys.argv[1:]
    if "-h" in argv or "--help" in argv:
        print(USAGE)
        return
    known = {"--no-tls"}
    unknown = [a for a in argv if a.startswith("-") and a not in known]
    if unknown:
        print(f"未知选项：{' '.join(unknown)}\n")
        print(USAGE)
        sys.exit(2)

    args = [a for a in argv if not a.startswith("-")]
    skip_tls = "--no-tls" in argv

    hijacked = hijack_selfcheck()
    if skip_tls:
        print("② TLS 检查已按 --no-tls 跳过")
        print()
    else:
        tls_selfcheck()

    only = args
    targets = TARGETS
    if only:
        targets = [t for t in TARGETS if any(o in t[1] or o in t[0] for o in only)]

    print("③ DNSSEC 支持检测")
    print(f"   坏签名探针 {BAD}（验证型必 SERVFAIL） / 好签名探针 {GOOD}（验证型应 AD=1）")
    print("   " + "=" * 100)

    for name, udp_ip, dot_host, doh_url in targets:
        print(f"\n{name}")
        found = []          # [(通道, 判定码, 展示文本)]
        for label, fn in [
            ("UDP/53",  (lambda n, ip=udp_ip: over_udp(ip, n)) if udp_ip else None),
            ("DoT/853", (lambda n, h=dot_host: over_dot(h, n)) if (dot_host and not skip_tls) else None),
            ("DoH",     (lambda n, u=doh_url: over_doh(u, n)) if (doh_url and not skip_tls) else None),
        ]:
            if fn is None:
                continue
            bad, good = fn(BAD), fn(GOOD)
            code, text = judge(bad, good)
            notes = []
            if label == "UDP/53" and hijacked:
                notes.append("明文通道被劫持")
            if label in ("DoT/853", "DoH") and not TLS_VERIFY_OK:
                notes.append("证书未校验")
            suffix = ("  ⚠️ " + "、".join(notes)) if notes else ""
            print(f"  {label:8s} {text}{suffix}")
            print(f"          坏签名 {fmt(bad)}")
            print(f"          好签名 {fmt(good)}")
            if code:
                found.append((label, code, text))

        # 综合判定：取可信度最高的通道（DoH > DoT > UDP）
        usable = [(CHANNEL_TRUST.get(ch, 0), code, ch) for ch, code, _ in found]
        if usable:
            usable.sort(key=lambda x: -x[0])
            best_code, best_ch = usable[0][1], usable[0][2]
            label = {3: "★ 验证型", 2: "☆ 仅置 AD 位", 1: "· 仅透传，不验证", 0: "× 不支持"}[RANK[best_code]]
            print(f"  ── 综合判定：{label}（以 {best_ch} 为准）")
        else:
            print("  ── 综合判定：无可用结论（所有通道均失败或被判定为可疑）")

    print("\n说明：★ 才叫「支持 DNSSEC」；· 只是把签名原样转给你（得客户端自己验）；× 连材料都不给你。")
    print("      结论可信度：DoH > DoT > 明文 UDP —— 前两者走 TLS，中间设备插不进去。")


if __name__ == "__main__":
    main()
