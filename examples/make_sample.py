#!/usr/bin/env python3
"""Generate examples/sample.pcap: a small capture with a realistic scenario.

The scenario contains benign browsing plus three things worth finding: a
compromised workstation beaconing to a command and control server it resolved
by name, the same workstation later uploading a large amount of data to a
second external host, and a different workstation running a port scan.

NetHawk itself only reads captures. This generator lives under examples so the
project ships with a reproducible fixture. It uses only the standard library.
"""
from __future__ import annotations

import calendar
import os
import struct

MAC_A = b"\x02\x00\x00\x00\x00\x01"
MAC_B = b"\x02\x00\x00\x00\x00\x02"

SYN, ACK, PSH = 0x02, 0x10, 0x08


def eth(payload, ethertype=0x0800):
    return MAC_B + MAC_A + struct.pack("!H", ethertype) + payload


def ipv4(src, dst, proto, payload, total_len_override=0):
    total = total_len_override if total_len_override else 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, proto, 0,
                      bytes(int(x) for x in src.split(".")),
                      bytes(int(x) for x in dst.split(".")))
    return hdr + payload


def tcp(sport, dport, flags, payload=b""):
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 65535, 0, 0) + payload


def udp(sport, dport, payload=b""):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def _name(n):
    out = b""
    for label in n.split("."):
        out += bytes([len(label)]) + label.encode("latin-1")
    return out + b"\x00"


def dns_query(qname, qtype=1, ident=0x1111):
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + _name(qname) + struct.pack("!HH", qtype, 1)


def dns_response(qname, ips, ident=0x1111):
    q = _name(qname) + struct.pack("!HH", 1, 1)
    ans = b""
    for ip in ips:
        ans += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes(int(x) for x in ip.split("."))
    return struct.pack("!HHHHHH", ident, 0x8180, 1, len(ips), 0, 0) + q + ans


def tls_client_hello(server_name):
    sni = server_name.encode("latin-1")
    snl = b"\x00" + struct.pack("!H", len(sni)) + sni
    ext_body = struct.pack("!H", len(snl)) + snl
    ext = struct.pack("!HH", 0x0000, len(ext_body)) + ext_body
    exts = struct.pack("!H", len(ext)) + ext
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + struct.pack("!H", 0) + b"\x01\x00" + exts
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def build():
    base = calendar.timegm((2024, 5, 14, 9, 15, 0, 0, 0, 0))
    pkts = []

    def at(offset, frame):
        pkts.append((base + offset, frame))

    # Benign browsing from 192.168.1.24.
    at(0.0, eth(ipv4("192.168.1.24", "192.168.1.1", 17, udp(50100, 53, dns_query("www.example.com")))))
    at(0.1, eth(ipv4("192.168.1.1", "192.168.1.24", 17, udp(53, 50100, dns_response("www.example.com", ["93.184.216.34"])))))
    at(0.3, eth(ipv4("192.168.1.24", "93.184.216.34", 6, tcp(52001, 443, SYN))))
    at(0.4, eth(ipv4("93.184.216.34", "192.168.1.24", 6, tcp(443, 52001, SYN | ACK))))
    at(0.5, eth(ipv4("192.168.1.24", "93.184.216.34", 6, tcp(52001, 443, PSH | ACK, tls_client_hello("www.example.com")))))
    for i in range(6):
        at(1 + i, eth(ipv4("93.184.216.34", "192.168.1.24", 6, tcp(443, 52001, PSH | ACK, b"x"), total_len_override=1400)))

    # Compromised host 192.168.1.42 resolves and beacons to a C2 server.
    at(3.0, eth(ipv4("192.168.1.42", "192.168.1.1", 17, udp(50200, 53, dns_query("cdn.telemetry-sync.net")))))
    at(3.1, eth(ipv4("192.168.1.1", "192.168.1.42", 17, udp(53, 50200, dns_response("cdn.telemetry-sync.net", ["203.0.113.66"])))))
    for i in range(15):
        t = 4 + i * 60
        sp = 53000 + i
        payload = tls_client_hello("cdn.telemetry-sync.net") if i == 0 else b"\x17\x03\x03\x00\x20" + b"\x33" * 32
        at(t, eth(ipv4("192.168.1.42", "203.0.113.66", 6, tcp(sp, 443, SYN))))
        at(t + 0.1, eth(ipv4("203.0.113.66", "192.168.1.42", 6, tcp(443, sp, SYN | ACK))))
        at(t + 0.2, eth(ipv4("192.168.1.42", "203.0.113.66", 6, tcp(sp, 443, PSH | ACK, payload))))
        at(t + 0.3, eth(ipv4("203.0.113.66", "192.168.1.42", 6, tcp(443, sp, PSH | ACK, b"\x17\x03\x03\x00\x10" + b"\x44" * 16))))

    # The same host then uploads a large amount of data to a second external host.
    at(1200.0, eth(ipv4("192.168.1.42", "198.51.100.23", 6, tcp(55123, 443, SYN))))
    at(1200.1, eth(ipv4("198.51.100.23", "192.168.1.42", 6, tcp(443, 55123, SYN | ACK))))
    at(1200.2, eth(ipv4("192.168.1.42", "198.51.100.23", 6, tcp(55123, 443, PSH | ACK, tls_client_hello("backup-sync.example")))))
    for i in range(200):
        at(1201 + i * 0.05, eth(ipv4("192.168.1.42", "198.51.100.23", 6, tcp(55123, 443, PSH | ACK, b"\x17\x03\x03"), total_len_override=64000)))
    at(1260.0, eth(ipv4("198.51.100.23", "192.168.1.42", 6, tcp(443, 55123, PSH | ACK, b"ok"))))

    # A different workstation runs a vertical port scan.
    for i, port in enumerate([21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993,
                              995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]):
        at(300 + i * 0.1, eth(ipv4("192.168.1.55", "192.168.1.10", 6, tcp(40000 + i, port, SYN))))

    pkts.sort(key=lambda x: x[0])
    out = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ts, raw in pkts:
        sec = int(ts)
        usec = int(round((ts - sec) * 1_000_000))
        out += struct.pack("<IIII", sec, usec, len(raw), len(raw)) + raw
    return out


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "sample.pcap")
    with open(path, "wb") as fh:
        fh.write(build())
    print(f"wrote {path} ({os.path.getsize(path)} bytes)")


if __name__ == "__main__":
    main()
