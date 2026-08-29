"""Risk scoring and the top level analyze() entry point."""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from .correlate import correlate
from .decode import decode
from .detect import Config, run_detectors
from .flows import FlowTable
from .models import Analysis, Finding
from .pcap import read_packets


def score_hosts(findings: List[Finding]) -> Dict[str, int]:
    scores: Dict[str, int] = defaultdict(int)
    for f in findings:
        if f.src:
            scores[f.src] += f.score
    return {host: min(100, value) for host, value in scores.items()}


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
    return analysis
