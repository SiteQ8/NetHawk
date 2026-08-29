"""Helpers that craft small benign packets and pcap files for tests.

This lives under tests on purpose: NetHawk itself only reads captures, it does
not build or send traffic. These builders exist so the tests have fixtures.
"""
from __future__ import annotations

import struct
from typing import List, Tuple

MAC_A = b"\x02\x00\x00\x00\x00\x01"
MAC_B = b"\x02\x00\x00\x00\x00\x02"


def eth(payload: bytes, ethertype: int = 0x0800, src=MAC_A, dst=MAC_B) -> bytes:
    return dst + src + struct.pack("!H", ethertype) + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes, total_len_override: int = 0) -> bytes:
    total = total_len_override if total_len_override else 20 + len(payload)
    hdr = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, proto, 0,
        bytes(int(x) for x in src.split(".")),
        bytes(int(x) for x in dst.split(".")),
    )
    return hdr + payload


def tcp(sport: int, dport: int, flags: int, payload: bytes = b"", seq: int = 0, ack: int = 0) -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload


def udp(sport: int, dport: int, payload: bytes = b"") -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def _name(n: str) -> bytes:
    out = b""
    for label in n.split("."):
        out += bytes([len(label)]) + label.encode("latin-1")
    return out + b"\x00"


def dns_query(qname: str, qtype: int = 1, ident: int = 0x1234) -> bytes:
    q = _name(qname) + struct.pack("!HH", qtype, 1)
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + q


def dns_response(qname: str, ips: List[str], qtype: int = 1, ident: int = 0x1234, rcode: int = 0) -> bytes:
    q = _name(qname) + struct.pack("!HH", qtype, 1)
    ans = b""
    for ip in ips:
        ans += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes(int(x) for x in ip.split("."))
    header = struct.pack("!HHHHHH", ident, 0x8180 | rcode, 1, len(ips), 0, 0)
    return header + q + ans


def tls_client_hello(server_name: str) -> bytes:
    sni = server_name.encode("latin-1")
    server_name_list = b"\x00" + struct.pack("!H", len(sni)) + sni
    ext_body = struct.pack("!H", len(server_name_list)) + server_name_list
    ext = struct.pack("!HH", 0x0000, len(ext_body)) + ext_body
    exts = struct.pack("!H", len(ext)) + ext
    body = (b"\x03\x03" + b"\x00" * 32 + b"\x00" + struct.pack("!H", 0) + b"\x01\x00" + exts)
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    record = b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs
    return record


def pcap_bytes(packets: List[Tuple[float, bytes]], linktype: int = 1) -> bytes:
    out = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for ts, raw in packets:
        sec = int(ts)
        usec = int(round((ts - sec) * 1_000_000))
        out += struct.pack("<IIII", sec, usec, len(raw), len(raw)) + raw
    return out
