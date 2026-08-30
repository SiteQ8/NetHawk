"""Correlate findings into incidents, each with a reconstructed timeline.

This is the part that turns a pile of alerts into a story. For each internal
host that has findings, we pick a hypothesis, estimate confidence from how many
independent signals line up, and build a timeline that weaves together the DNS
lookups, first contacts, and detections in the order they happened.
"""
from __future__ import annotations

import datetime
from collections import defaultdict
from typing import Dict, List

from .models import DnsEvent, Finding, Flow, Incident, TimelineEvent

_SUMMARY_ORDER = ["ioc", "beacon", "exfil", "dns_tunnel", "dga", "cleartext_creds",
                  "cleartext_protocol", "port_scan", "external_fanout",
                  "long_connection", "rare_user_agent"]


def _clock(ts: float) -> str:
    return datetime.datetime.utcfromtimestamp(ts).strftime("%H:%M:%S") if ts else "??:??:??"


def _clause(f: Finding) -> str:
    cat, ev, dst = f.category, f.evidence, f.dst
    dom = ev.get("domain", "")
    name = dst + (" (" + dom + ")" if dom else "")
    if cat == "beacon":
        return "periodic beaconing to " + (name or dst)
    if cat == "exfil":
        return "a large outbound transfer to " + (name or dst)
    if cat == "port_scan":
        return "a port scan of " + (dst or "internal hosts")
    if cat == "dns_tunnel":
        return "DNS tunneling under " + ev.get("parent", dst)
    if cat == "dga":
        return "a high rate of failed DNS lookups"
    if cat == "cleartext_creds":
        return "credentials sent in the clear"
    if cat == "cleartext_protocol":
        return ev.get("service", "a service") + " used in clear text"
    if cat == "long_connection":
        return "a long lived connection to " + dst
    if cat == "rare_user_agent":
        return "an automation user agent"
    if cat == "external_fanout":
        return "connections to many external hosts"
    if cat == "ioc":
        return "contact with a known indicator"
    return f.title.lower()


def _summarize(host, hypothesis, confidence, findings, indicators, timeline) -> str:
    by_cat = {}
    for f in findings:
        by_cat.setdefault(f.category, f)
    parts = [_clause(by_cat[c]) for c in _SUMMARY_ORDER if c in by_cat]
    for c in by_cat:
        if c not in _SUMMARY_ORDER:
            parts.append(_clause(by_cat[c]))
    s = host + ": " + hypothesis[0].lower() + hypothesis[1:] + " (confidence " + str(confidence) + "%)."
    ts = [e.ts for e in timeline if e.ts]
    if ts:
        s += " Activity ran from " + _clock(min(ts)) + " to " + _clock(max(ts)) + "."
    if parts:
        if len(parts) == 1:
            joined = parts[0]
        elif len(parts) == 2:
            joined = parts[0] + " and " + parts[1]
        else:
            joined = ", ".join(parts[:-1]) + ", and " + parts[-1]
        s += " It involved " + joined + "."
    if indicators:
        s += " Indicators: " + ", ".join(indicators) + "."
    return s


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
    if f.category == "cleartext_creds":
        return f"Credentials sent in clear text to {f.evidence.get('host', f.dst)}"
    if f.category == "long_connection":
        return f"Long lived connection to {f.dst} on port {f.evidence.get('port', '')}"
    if f.category == "cleartext_protocol":
        return f"{f.evidence.get('service', 'A service')} in clear text to {f.dst}"
    if f.category == "external_fanout":
        return f"Connections to {f.evidence.get('external_hosts', 'many')} external hosts"
    if f.category == "rare_user_agent":
        return f"Automation user agent seen: {f.evidence.get('user_agent', '')}"
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
    if has("cleartext_creds"):
        return "Credentials exposed in clear text"
    if has("port_scan") or has("external_fanout"):
        return "Possible internal reconnaissance"
    if has("cleartext_protocol"):
        return "Sensitive service exposed in clear text"
    if has("dga"):
        return "Possible algorithmically generated domain activity"
    return "Unusual network activity"


def _confidence(findings: List[Finding]) -> int:
    cats = {f.category for f in findings}
    base = {
        "ioc": 75, "beacon": 55, "dns_tunnel": 55, "exfil": 55,
        "cleartext_creds": 60, "port_scan": 50, "dga": 45,
        "external_fanout": 45, "cleartext_protocol": 40,
        "long_connection": 35, "rare_user_agent": 30,
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

        inds = sorted(x for x in indicators if x)
        incidents.append(Incident(
            host=host, hypothesis=hypothesis, confidence=confidence,
            findings=host_findings, timeline=ordered, indicators=inds,
            summary=_summarize(host, hypothesis, confidence, host_findings, inds, ordered)))

    incidents.sort(key=lambda i: i.confidence, reverse=True)
    return incidents
