"""Aggregate decoded packets into flows and pull out DNS, TLS, and HTTP facts."""
from __future__ import annotations

from typing import Dict, List, Optional

from .apps import parse_dns, parse_http, parse_tls_sni
from .models import ACK, FIN, RST, SYN, DnsEvent, Flow, Packet


def is_internal(ip: str) -> bool:
    if ":" in ip:  # ipv6
        low = ip.lower()
        return low == "::1" or low.startswith("fe80") or low.startswith("fc") or low.startswith("fd")
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    if a == 10 or a == 127:
        return True
    if a == 192 and b == 168:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 169 and b == 254:
        return True
    return False


class FlowTable:
    def __init__(self) -> None:
        self.flows: Dict[tuple, Flow] = {}
        self.dns_events: List[DnsEvent] = []
        self.ip_domain: Dict[str, str] = {}
        self.first_ts: Optional[float] = None
        self.last_ts: Optional[float] = None
        self.count = 0
        self.ips = set()

    def add(self, p: Packet) -> None:
        self.count += 1
        if p.ts:
            self.first_ts = p.ts if self.first_ts is None else min(self.first_ts, p.ts)
            self.last_ts = p.ts if self.last_ts is None else max(self.last_ts, p.ts)
        if p.src_ip:
            self.ips.add(p.src_ip)
        if p.dst_ip:
            self.ips.add(p.dst_ip)
        if p.proto not in ("TCP", "UDP"):
            return
        if p.proto == "UDP" and (p.dst_port == 53 or p.src_port == 53):
            self._dns(p)
        self._flow(p)

    def _dns(self, p: Packet) -> None:
        msg = parse_dns(p.payload)
        if not msg:
            return
        if msg.is_response:
            client, server = p.dst_ip, p.src_ip
            for ip in msg.answers:
                self.ip_domain[ip] = msg.qname
        else:
            client, server = p.src_ip, p.dst_ip
        self.dns_events.append(DnsEvent(
            ts=p.ts, client=client, server=server, qname=msg.qname,
            qtype=msg.qtype, is_response=msg.is_response, rcode=msg.rcode,
            answers=list(msg.answers),
        ))

    def _flow(self, p: Packet) -> None:
        a = (p.src_ip, p.src_port)
        b = (p.dst_ip, p.dst_port)
        key = (p.proto,) + tuple(sorted([a, b]))
        fl = self.flows.get(key)
        if fl is None:
            initiator_is_sender = True
            if p.proto == "TCP" and (p.flags & (SYN | ACK)) == (SYN | ACK):
                initiator_is_sender = False
            if initiator_is_sender:
                fl = Flow(p.proto, p.src_ip, p.src_port, p.dst_ip, p.dst_port, p.ts, p.ts)
            else:
                fl = Flow(p.proto, p.dst_ip, p.dst_port, p.src_ip, p.src_port, p.ts, p.ts)
            self.flows[key] = fl

        if p.src_ip == fl.a_ip and p.src_port == fl.a_port:
            fl.a_to_b_bytes += p.length
            fl.a_to_b_pkts += 1
        else:
            fl.b_to_a_bytes += p.length
            fl.b_to_a_pkts += 1

        if p.ts:
            fl.first_ts = min(fl.first_ts, p.ts) if fl.first_ts else p.ts
            fl.last_ts = max(fl.last_ts, p.ts)

        if p.proto == "TCP":
            fl.flags |= p.flags
            masked = p.flags & (SYN | ACK)
            if masked == SYN:
                fl.saw_syn = True
            elif masked == (SYN | ACK):
                fl.saw_synack = True
            if p.flags & RST:
                fl.saw_rst = True
            if p.flags & FIN:
                fl.saw_fin = True
            if p.payload:
                if p.payload[:1] == b"\x16" and not fl.sni:
                    sni = parse_tls_sni(p.payload)
                    if sni:
                        fl.sni = sni
                elif not fl.http_host:
                    http = parse_http(p.payload)
                    if http:
                        fl.http_host = http.host
                        if http.user_agent and not fl.user_agent:
                            fl.user_agent = http.user_agent
                        if http.has_auth:
                            fl.http_auth = True

    def finalize(self):
        flows = list(self.flows.values())
        internal = sorted({ip for ip in self.ips if is_internal(ip)})
        external = sorted({ip for ip in self.ips if not is_internal(ip)})
        return flows, internal, external
