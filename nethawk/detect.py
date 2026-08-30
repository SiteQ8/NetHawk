"""The detection engine.

Each detector turns flows or DNS events into findings. Thresholds live in
Config so they are easy to tune. The detectors are deliberately explainable:
every finding carries the evidence that produced it.
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from statistics import median
from typing import Dict, List, Set

from .flows import is_internal
from .models import DnsEvent, Finding, Flow

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Config:
    scan_min_ports: int = 15
    scan_min_hosts: int = 15
    beacon_min_conns: int = 6
    beacon_min_score: float = 0.7
    exfil_min_bytes: int = 5_000_000
    exfil_ratio: float = 5.0
    dns_tunnel_min_subdomains: int = 20
    dns_tunnel_min_entropy: float = 3.2
    dga_min_nxdomain: int = 20
    dga_min_ratio: float = 0.5
    long_conn_seconds: int = 3600
    long_conn_min_bytes: int = 100_000
    fanout_min_hosts: int = 50
    rare_ua_tokens: tuple = (
        "curl", "wget", "python-requests", "python-urllib", "go-http-client",
        "powershell", "winhttp", "libwww-perl", "httpie", "java/", "nikto",
        "sqlmap", "masscan", "nmap",
    )
    iocs: Set[str] = field(default_factory=set)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _human_interval(seconds: float) -> str:
    if seconds < 90:
        return f"{seconds:.0f}s"
    if seconds < 5400:
        return f"{seconds / 60:.0f}m"
    return f"{seconds / 3600:.1f}h"


def _human_bytes(n: int) -> str:
    x = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if x < 1024 or unit == "TB":
            return f"{x:.1f} {unit}" if unit != "B" else f"{int(x)} B"
        x /= 1024
    return f"{n} B"


def _split_domain(qname: str):
    labels = qname.strip(".").split(".")
    if len(labels) <= 2:
        return qname, ""
    return ".".join(labels[-2:]), ".".join(labels[:-2])


def detect_port_scans(flows: List[Flow], cfg: Config) -> List[Finding]:
    findings: List[Finding] = []
    vertical: Dict[tuple, list] = defaultdict(list)
    horizontal: Dict[tuple, dict] = defaultdict(
        lambda: {"hosts": set(), "unest": 0, "total": 0, "first": None, "last": None})

    for f in flows:
        if f.proto != "TCP" or not f.saw_syn:
            continue
        vertical[(f.a_ip, f.b_ip)].append((f.b_port, f.established, f.first_ts, f.last_ts))
        h = horizontal[(f.a_ip, f.b_port)]
        h["hosts"].add(f.b_ip)
        h["total"] += 1
        if not f.established:
            h["unest"] += 1
        h["first"] = f.first_ts if h["first"] is None else min(h["first"], f.first_ts)
        h["last"] = f.last_ts if h["last"] is None else max(h["last"], f.last_ts)

    for (a, b), lst in vertical.items():
        ports = {p for p, _, _, _ in lst}
        unest = sum(1 for _, est, _, _ in lst if not est)
        if len(ports) >= cfg.scan_min_ports and unest >= 0.7 * len(lst):
            first = min(t for _, _, t, _ in lst)
            last = max(t for _, _, _, t in lst)
            findings.append(Finding(
                "port_scan", "high", a, b, "Vertical port scan",
                f"{a} probed {len(ports)} ports on {b}, mostly without completing a connection.",
                first, last, 25,
                {"ports": len(ports), "attempts": len(lst), "unanswered": unest}))

    for (a, port), h in horizontal.items():
        if len(h["hosts"]) >= cfg.scan_min_hosts and h["unest"] >= 0.7 * h["total"]:
            findings.append(Finding(
                "port_scan", "high", a, "", "Network sweep",
                f"{a} contacted {len(h['hosts'])} hosts on port {port}, mostly without completing a connection.",
                h["first"] or 0, h["last"] or 0, 25,
                {"hosts": len(h["hosts"]), "port": port}))
    return findings


def detect_dns_anomalies(dns_events: List[DnsEvent], cfg: Config) -> List[Finding]:
    findings: List[Finding] = []
    tunnels: Dict[tuple, dict] = defaultdict(
        lambda: {"subs": set(), "ent": [], "first": None, "last": None, "count": 0})
    nx: Dict[str, dict] = defaultdict(lambda: {"nx": 0, "total": 0, "first": None, "last": None})

    for e in dns_events:
        if e.is_response:
            d = nx[e.client]
            d["total"] += 1
            if e.rcode == 3:
                d["nx"] += 1
            d["first"] = e.ts if d["first"] is None else min(d["first"], e.ts)
            d["last"] = e.ts if d["last"] is None else max(d["last"], e.ts)
        else:
            parent, sub = _split_domain(e.qname)
            if not sub:
                continue
            t = tunnels[(e.client, parent)]
            t["subs"].add(sub)
            t["ent"].append(_entropy(sub.replace(".", "")))
            t["count"] += 1
            t["first"] = e.ts if t["first"] is None else min(t["first"], e.ts)
            t["last"] = e.ts if t["last"] is None else max(t["last"], e.ts)

    for (client, parent), t in tunnels.items():
        if len(t["subs"]) >= cfg.dns_tunnel_min_subdomains and t["ent"]:
            avg = sum(t["ent"]) / len(t["ent"])
            if avg >= cfg.dns_tunnel_min_entropy:
                findings.append(Finding(
                    "dns_tunnel", "high", client, parent, "Possible DNS tunneling",
                    f"{len(t['subs'])} unique high entropy subdomains under {parent} "
                    f"(average entropy {avg:.1f}).",
                    t["first"] or 0, t["last"] or 0, 30,
                    {"parent": parent, "unique_subdomains": len(t["subs"]),
                     "avg_entropy": round(avg, 2), "queries": t["count"]}))

    for client, d in nx.items():
        if d["nx"] >= cfg.dga_min_nxdomain and d["total"] and d["nx"] / d["total"] >= cfg.dga_min_ratio:
            findings.append(Finding(
                "dga", "medium", client, "", "High rate of failed lookups",
                f"{d['nx']} failed lookups out of {d['total']} responses, "
                f"which can indicate algorithmically generated domains.",
                d["first"] or 0, d["last"] or 0, 20,
                {"nxdomain": d["nx"], "responses": d["total"]}))
    return findings


def detect_beaconing(flows: List[Flow], cfg: Config, ip_domain: Dict[str, str] = None) -> List[Finding]:
    ip_domain = ip_domain or {}
    findings: List[Finding] = []
    groups: Dict[tuple, list] = defaultdict(list)
    for f in flows:
        groups[(f.a_ip, f.b_ip, f.b_port)].append((f.first_ts, f.a_to_b_bytes))

    for (a, b, port), evs in groups.items():
        if len(evs) < cfg.beacon_min_conns:
            continue
        evs.sort()
        ts = [t for t, _ in evs]
        intervals = [t2 - t1 for t1, t2 in zip(ts, ts[1:]) if t2 - t1 >= 0]
        if len(intervals) < cfg.beacon_min_conns - 1:
            continue
        med = median(intervals)
        if med <= 0.5:
            continue
        mad = median([abs(x - med) for x in intervals])
        score = max(0.0, 1.0 - (mad / med if med else 1.0))
        sizes = [s for _, s in evs]
        if len(sizes) >= 2 and median(sizes) > 0:
            size_disp = median([abs(s - median(sizes)) for s in sizes]) / median(sizes)
            if size_disp < 0.25:
                score = min(1.0, score + 0.05)
        if score >= cfg.beacon_min_score:
            dom = ip_domain.get(b, "")
            external = not is_internal(b)
            sev = "high" if external else "medium"
            name = f"{b}" + (f" ({dom})" if dom else "")
            findings.append(Finding(
                "beacon", sev, a, b, "Periodic beaconing",
                f"{len(evs)} connections to {name} on port {port}, about every {_human_interval(med)}.",
                ts[0], ts[-1], 35 if external else 20,
                {"count": len(evs), "interval_seconds": round(med, 1),
                 "regularity": round(score, 2), "port": port, "domain": dom}))
    return findings


def detect_exfil(flows: List[Flow], cfg: Config, ip_domain: Dict[str, str] = None) -> List[Finding]:
    ip_domain = ip_domain or {}
    findings: List[Finding] = []
    agg: Dict[tuple, dict] = defaultdict(
        lambda: {"out": 0, "in": 0, "first": None, "last": None, "sni": ""})
    for f in flows:
        if not f.b_ip or is_internal(f.b_ip):
            continue
        d = agg[(f.a_ip, f.b_ip)]
        d["out"] += f.a_to_b_bytes
        d["in"] += f.b_to_a_bytes
        d["first"] = f.first_ts if d["first"] is None else min(d["first"], f.first_ts)
        d["last"] = f.last_ts if d["last"] is None else max(d["last"], f.last_ts)
        if f.sni and not d["sni"]:
            d["sni"] = f.sni

    for (a, b), d in agg.items():
        if d["out"] >= cfg.exfil_min_bytes and d["out"] >= cfg.exfil_ratio * max(d["in"], 1):
            dom = d["sni"] or ip_domain.get(b, "")
            sev = "critical" if d["out"] >= 50_000_000 else "high"
            name = f"{b}" + (f" ({dom})" if dom else "")
            findings.append(Finding(
                "exfil", sev, a, b, "Large outbound transfer",
                f"{_human_bytes(d['out'])} sent from {a} to {name}, far more than was received.",
                d["first"] or 0, d["last"] or 0, 35,
                {"bytes_out": d["out"], "bytes_in": d["in"], "domain": dom}))
    return findings


def detect_iocs(flows: List[Flow], dns_events: List[DnsEvent], cfg: Config) -> List[Finding]:
    if not cfg.iocs:
        return []
    findings: List[Finding] = []
    seen = set()
    for f in flows:
        hit = next((c for c in (f.b_ip, f.a_ip, f.sni, f.http_host) if c and c in cfg.iocs), None)
        if hit and (f.a_ip, hit) not in seen:
            seen.add((f.a_ip, hit))
            findings.append(Finding(
                "ioc", "critical", f.a_ip, f.b_ip, "Contact with a known indicator",
                f"Traffic involving indicator {hit}.",
                f.first_ts, f.last_ts, 40, {"indicator": hit}))
    for e in dns_events:
        for cand in [e.qname] + e.answers:
            if cand in cfg.iocs and (e.client, cand) not in seen:
                seen.add((e.client, cand))
                findings.append(Finding(
                    "ioc", "critical", e.client, cand if "." in cand and cand[0].isalpha() else "",
                    "Contact with a known indicator",
                    f"DNS activity involving indicator {cand}.",
                    e.ts, e.ts, 40, {"indicator": cand}))
    return findings


def detect_cleartext_creds(flows: List[Flow], cfg: Config) -> List[Finding]:
    findings: List[Finding] = []
    seen = set()
    for f in flows:
        if f.http_auth and (f.a_ip, f.b_ip) not in seen:
            seen.add((f.a_ip, f.b_ip))
            host = f.http_host or f.b_ip
            findings.append(Finding(
                "cleartext_creds", "high", f.a_ip, f.b_ip, "Credentials sent in clear text",
                f"An HTTP authorization header was sent to {host} without TLS.",
                f.first_ts, f.last_ts, 30, {"host": host}))
    return findings


def detect_long_connections(flows: List[Flow], cfg: Config) -> List[Finding]:
    findings: List[Finding] = []
    for f in flows:
        if f.proto != "TCP":
            continue
        if f.duration >= cfg.long_conn_seconds and f.total_bytes >= cfg.long_conn_min_bytes:
            external = not is_internal(f.b_ip)
            dom = f.sni or f.http_host
            name = f"{f.b_ip}" + (f" ({dom})" if dom else "")
            findings.append(Finding(
                "long_connection", "medium" if external else "low", f.a_ip, f.b_ip,
                "Long lived connection",
                f"A single connection to {name} on port {f.b_port} lasted {_human_interval(f.duration)}.",
                f.first_ts, f.last_ts, 15 if external else 8,
                {"duration_seconds": round(f.duration, 1), "port": f.b_port, "bytes": f.total_bytes}))
    return findings


def detect_rare_user_agents(flows: List[Flow], cfg: Config) -> List[Finding]:
    findings: List[Finding] = []
    seen = set()
    for f in flows:
        ua = (f.user_agent or "").lower()
        if not ua:
            continue
        hit = next((t for t in cfg.rare_ua_tokens if t in ua), None)
        if hit and (f.a_ip, hit) not in seen:
            seen.add((f.a_ip, hit))
            findings.append(Finding(
                "rare_user_agent", "low", f.a_ip, f.b_ip, "Automation user agent",
                f'{f.a_ip} used the user agent "{f.user_agent}", which is common for scripts and tools.',
                f.first_ts, f.last_ts, 8, {"user_agent": f.user_agent}))
    return findings


_CLEARTEXT_SERVICES = {21: "FTP", 23: "Telnet", 110: "POP3", 143: "IMAP"}


def detect_cleartext_protocol(flows: List[Flow], cfg: Config) -> List[Finding]:
    findings: List[Finding] = []
    seen = set()
    for f in flows:
        if f.proto != "TCP":
            continue
        svc = _CLEARTEXT_SERVICES.get(f.b_port)
        if not svc:
            continue
        if not f.established:
            continue
        key = (f.a_ip, f.b_ip, f.b_port)
        if key in seen:
            continue
        seen.add(key)
        sev = "medium" if f.b_port in (21, 23) else "low"
        findings.append(Finding(
            "cleartext_protocol", sev, f.a_ip, f.b_ip, f"{svc} in clear text",
            f"{svc} traffic to {f.b_ip} on port {f.b_port} is unencrypted and can expose data or credentials.",
            f.first_ts, f.last_ts, 12 if sev == "medium" else 6,
            {"service": svc, "port": f.b_port}))
    return findings


def detect_external_fanout(flows: List[Flow], cfg: Config) -> List[Finding]:
    dsts: Dict[str, set] = defaultdict(set)
    span: Dict[str, list] = defaultdict(lambda: [None, None])
    for f in flows:
        if not is_internal(f.a_ip) or is_internal(f.b_ip) or not f.b_ip:
            continue
        dsts[f.a_ip].add(f.b_ip)
        s = span[f.a_ip]
        s[0] = f.first_ts if s[0] is None else min(s[0], f.first_ts)
        s[1] = f.last_ts if s[1] is None else max(s[1], f.last_ts)
    findings: List[Finding] = []
    for host, ds in dsts.items():
        if len(ds) >= cfg.fanout_min_hosts:
            s = span[host]
            findings.append(Finding(
                "external_fanout", "medium", host, "", "Many external destinations",
                f"{host} connected to {len(ds)} distinct external hosts, which can indicate scanning or automated activity.",
                s[0] or 0, s[1] or 0, 15, {"external_hosts": len(ds)}))
    return findings


# Map each finding category to MITRE ATT&CK techniques.
MITRE = {
    "port_scan": [("T1046", "Network Service Discovery")],
    "external_fanout": [("T1046", "Network Service Discovery")],
    "dns_tunnel": [("T1071.004", "Application Layer Protocol: DNS")],
    "dga": [("T1568.002", "Dynamic Resolution: Domain Generation Algorithms")],
    "beacon": [("T1071", "Application Layer Protocol")],
    "exfil": [("T1048", "Exfiltration Over Alternative Protocol")],
    "cleartext_creds": [("T1552", "Unsecured Credentials")],
    "cleartext_protocol": [("T1040", "Network Sniffing")],
    "long_connection": [("T1572", "Protocol Tunneling")],
    "rare_user_agent": [("T1071.001", "Application Layer Protocol: Web Protocols")],
    "ioc": [("T1071", "Application Layer Protocol")],
}


def run_detectors(flows, dns_events, ip_domain, cfg: Config) -> List[Finding]:
    findings: List[Finding] = []
    findings += detect_port_scans(flows, cfg)
    findings += detect_dns_anomalies(dns_events, cfg)
    findings += detect_beaconing(flows, cfg, ip_domain)
    findings += detect_exfil(flows, cfg, ip_domain)
    findings += detect_cleartext_creds(flows, cfg)
    findings += detect_cleartext_protocol(flows, cfg)
    findings += detect_long_connections(flows, cfg)
    findings += detect_rare_user_agents(flows, cfg)
    findings += detect_external_fanout(flows, cfg)
    findings += detect_iocs(flows, dns_events, cfg)
    for f in findings:
        f.mitre = [{"id": i, "name": n} for i, n in MITRE.get(f.category, [])]
    findings.sort(key=lambda f: (SEV_RANK.get(f.severity, 9), -f.score))
    return findings
