"""Correlate findings into incidents, each with a reconstructed timeline.

This is the part that turns a pile of alerts into a story. For each internal
host that has findings, we pick a hypothesis, estimate confidence from how many
independent signals line up, and build a timeline that weaves together the DNS
lookups, first contacts, and detections in the order they happened.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from .models import DnsEvent, Finding, Flow, Incident, TimelineEvent


def _looks_ip(value: str) -> bool:
    if ":" in value:
        return True
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def _finding_headline(f: Finding) -> str:
    dom = f.evidence.get("domain", "")
    if f.category == "beacon":
        target = f.dst + (f" ({dom})" if dom else "")
        every = f.evidence.get("interval_seconds")
        return f"Periodic beaconing to {target} begins" + (f", about every {every:.0f}s" if every else "")
    if f.category == "exfil":
        target = f.dst + (f" ({dom})" if dom else "")
        return f"Large outbound transfer to {target} detected"
    if f.category == "port_scan":
        return f.title + (f" of {f.dst}" if f.dst else "")
    if f.category == "dns_tunnel":
        return f"Possible DNS tunneling to {f.dst}"
    if f.category == "dga":
        return "High rate of failed DNS lookups"
    if f.category == "ioc":
        return f"Contact with known indicator {f.evidence.get('indicator', f.dst)}"
    return f.title


def _hypothesis(cats: set) -> str:
    has = cats.__contains__
    if has("ioc"):
        return "Contact with a known indicator"
    if has("beacon") and has("exfil"):
        return "Possible command and control with data exfiltration"
    if has("beacon") and (has("dns_tunnel") or has("dga")):
        return "Possible command and control channel"
    if has("beacon"):
        return "Possible command and control beaconing"
    if has("dns_tunnel"):
        return "Possible DNS tunneling or covert channel"
    if has("exfil"):
        return "Possible data exfiltration"
    if has("port_scan"):
        return "Possible internal reconnaissance"
    if has("dga"):
        return "Possible algorithmically generated domain activity"
    return "Unusual network activity"


def _confidence(findings: List[Finding]) -> int:
    cats = {f.category for f in findings}
    base = {
        "ioc": 75, "beacon": 55, "dns_tunnel": 55, "exfil": 55,
        "port_scan": 50, "dga": 45,
    }
    start = max((base.get(c, 35) for c in cats), default=35)
    conf = start + (len(cats) - 1) * 10
    for f in findings:
        if f.category == "beacon":
            conf += int(f.evidence.get("regularity", 0) * 10)
        if f.category == "ioc":
            conf += 10
    return max(20, min(95, conf))


def correlate(findings: List[Finding], flows: List[Flow], dns_events: List[DnsEvent],
              ip_domain: Dict[str, str]) -> List[Incident]:
    by_host: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        if f.src:
            by_host[f.src].append(f)

    # Pre index for enrichment.
    flows_by_pair: Dict[tuple, List[float]] = defaultdict(list)
    for fl in flows:
        flows_by_pair[(fl.a_ip, fl.b_ip)].append(fl.first_ts)

    incidents: List[Incident] = []
    for host, host_findings in by_host.items():
        cats = {f.category for f in host_findings}
        hypothesis = _hypothesis(cats)
        confidence = _confidence(host_findings)

        indicators = set()
        timeline: List[TimelineEvent] = []
        for f in host_findings:
            if f.dst:
                indicators.add(f.dst)
            for key in ("domain", "parent", "indicator"):
                if f.evidence.get(key):
                    indicators.add(f.evidence[key])
            timeline.append(TimelineEvent(f.first_ts, host, _finding_headline(f)))

        # Weave in DNS lookups and first contacts for IP indicators.
        for f in host_findings:
            dst = f.dst
            if dst and _looks_ip(dst):
                dom = ip_domain.get(dst, "")
                if dom:
                    q = [e.ts for e in dns_events
                         if not e.is_response and e.client == host and dom in e.qname]
                    if q:
                        timeline.append(TimelineEvent(min(q), host, f"DNS query for {dom}"))
                conns = flows_by_pair.get((host, dst))
                if conns:
                    timeline.append(TimelineEvent(min(conns), host, f"First connection to {dst}"))

        seen = set()
        ordered: List[TimelineEvent] = []
        for ev in sorted(timeline, key=lambda e: e.ts):
            key = (round(ev.ts, 3), ev.text)
            if key in seen:
                continue
            seen.add(key)
            ordered.append(ev)

        incidents.append(Incident(
            host=host, hypothesis=hypothesis, confidence=confidence,
            findings=host_findings, timeline=ordered,
            indicators=sorted(x for x in indicators if x)))

    incidents.sort(key=lambda i: i.confidence, reverse=True)
    return incidents
