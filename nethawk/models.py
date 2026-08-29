"""Data models used across NetHawk."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class Packet:
    ts: float
    src_ip: str
    dst_ip: str
    proto: str            # TCP | UDP | ICMP | ICMPv6 | ARP | OTHER
    src_port: int = 0
    dst_port: int = 0
    length: int = 0       # length of the ip payload in bytes
    flags: int = 0        # tcp flags
    payload: bytes = b""  # transport payload, used transiently for app parsing


# TCP flag bits.
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20


@dataclass
class Flow:
    proto: str
    a_ip: str             # initiator
    a_port: int
    b_ip: str             # responder
    b_port: int
    first_ts: float
    last_ts: float
    a_to_b_bytes: int = 0
    b_to_a_bytes: int = 0
    a_to_b_pkts: int = 0
    b_to_a_pkts: int = 0
    flags: int = 0        # OR of all tcp flags seen
    saw_syn: bool = False
    saw_synack: bool = False
    saw_rst: bool = False
    saw_fin: bool = False
    sni: str = ""
    http_host: str = ""

    @property
    def key(self) -> Tuple:
        return (self.proto, self.a_ip, self.a_port, self.b_ip, self.b_port)

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)

    @property
    def total_bytes(self) -> int:
        return self.a_to_b_bytes + self.b_to_a_bytes

    @property
    def established(self) -> bool:
        return self.saw_syn and self.saw_synack

    def to_dict(self) -> dict:
        return {
            "proto": self.proto,
            "src": self.a_ip, "src_port": self.a_port,
            "dst": self.b_ip, "dst_port": self.b_port,
            "first_ts": self.first_ts, "last_ts": self.last_ts,
            "duration": round(self.duration, 3),
            "bytes_out": self.a_to_b_bytes, "bytes_in": self.b_to_a_bytes,
            "pkts_out": self.a_to_b_pkts, "pkts_in": self.b_to_a_pkts,
            "established": self.established,
            "reset": self.saw_rst,
            "sni": self.sni, "http_host": self.http_host,
        }


@dataclass
class DnsEvent:
    ts: float
    client: str
    server: str
    qname: str
    qtype: int
    is_response: bool
    rcode: int
    answers: List[str] = field(default_factory=list)   # resolved ips


@dataclass
class Finding:
    category: str         # port_scan | dns_tunnel | dga | beacon | exfil | ioc | ...
    severity: str         # critical | high | medium | low | info
    src: str              # the internal host most associated with the finding
    dst: str              # the external peer or target, when relevant
    title: str
    detail: str
    first_ts: float = 0.0
    last_ts: float = 0.0
    score: int = 0        # contribution to risk
    evidence: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "severity": self.severity,
            "src": self.src,
            "dst": self.dst,
            "title": self.title,
            "detail": self.detail,
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
            "score": self.score,
            "evidence": self.evidence,
        }


@dataclass
class TimelineEvent:
    ts: float
    host: str
    text: str

    def to_dict(self) -> dict:
        return {"ts": self.ts, "host": self.host, "text": self.text}


@dataclass
class Incident:
    host: str
    hypothesis: str
    confidence: int                     # 0..100
    findings: List[Finding] = field(default_factory=list)
    timeline: List[TimelineEvent] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "hypothesis": self.hypothesis,
            "confidence": self.confidence,
            "indicators": self.indicators,
            "findings": [f.to_dict() for f in self.findings],
            "timeline": [t.to_dict() for t in self.timeline],
        }


@dataclass
class Analysis:
    path: str = ""
    packet_count: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    flows: List[Flow] = field(default_factory=list)
    dns_events: List[DnsEvent] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    incidents: List[Incident] = field(default_factory=list)
    host_scores: Dict[str, int] = field(default_factory=dict)
    hosts_internal: List[str] = field(default_factory=list)
    hosts_external: List[str] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "packet_count": self.packet_count,
            "duration": round(self.duration, 3),
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
            "hosts_internal": self.hosts_internal,
            "hosts_external": self.hosts_external,
            "host_scores": self.host_scores,
            "flows": [f.to_dict() for f in self.flows],
            "findings": [f.to_dict() for f in self.findings],
            "incidents": [i.to_dict() for i in self.incidents],
        }
