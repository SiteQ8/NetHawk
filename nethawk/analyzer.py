"""Risk scoring and the top level analyze() entry point."""
from __future__ import annotations

import os
import tempfile
from collections import Counter, defaultdict
from typing import Dict, List, Optional

from .correlate import correlate
from .decode import decode
from .detect import Config, run_detectors
from .flows import FlowTable
from .models import Analysis, Finding, Flow
from .pcap import read_packets


def score_hosts(findings: List[Finding]) -> Dict[str, int]:
    scores: Dict[str, int] = defaultdict(int)
    for f in findings:
        if f.src:
            scores[f.src] += f.score
    return {host: min(100, value) for host, value in scores.items()}


def compute_stats(flows: List[Flow]) -> Dict:
    protocols: Counter = Counter()
    talkers: Counter = Counter()
    ports: Counter = Counter()
    for f in flows:
        protocols[f.proto] += 1
        talkers[f.a_ip] += f.total_bytes
        talkers[f.b_ip] += f.total_bytes
        if f.proto in ("TCP", "UDP") and f.b_port:
            ports[f.b_port] += 1
    return {
        "protocols": dict(protocols.most_common()),
        "top_talkers": [{"host": h, "bytes": b} for h, b in talkers.most_common(10)],
        "top_ports": [{"port": p, "flows": c} for p, c in ports.most_common(10)],
    }


def analyze(path: str, cfg: Config = None) -> Analysis:
    cfg = cfg or Config()
    table = FlowTable()
    for ts, linktype, data in read_packets(path):
        packet = decode(ts, linktype, data)
        if packet is not None:
            table.add(packet)

    flows, internal, external = table.finalize()
    findings = run_detectors(flows, table.dns_events, table.ip_domain, cfg)

    analysis = Analysis(
        path=path,
        packet_count=table.count,
        first_ts=table.first_ts or 0.0,
        last_ts=table.last_ts or 0.0,
        flows=flows,
        dns_events=table.dns_events,
        findings=findings,
        hosts_internal=internal,
        hosts_external=external,
    )
    analysis.host_scores = score_hosts(findings)
    analysis.incidents = correlate(findings, flows, table.dns_events, table.ip_domain)
    analysis.stats = compute_stats(flows)
    return analysis


def analyze_bytes(data: bytes, cfg: Config = None, name: str = "upload.pcap") -> Analysis:
    """Analyze a capture provided as raw bytes. Used by the API and GUI."""
    fd, path = tempfile.mkstemp(suffix=".pcap")
    try:
        os.write(fd, data)
        os.close(fd)
        analysis = analyze(path, cfg)
        analysis.path = name
        return analysis
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
