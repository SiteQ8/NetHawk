"""Build a small gallery of demo captures for the hosted demo.

Each capture is synthetic and benign to hold; it only represents a scenario so
visitors can see how NetHawk reacts to different traffic. Run this from the repo
root, then the files land in docs/samples/ where the demo can fetch them.

    PYTHONPATH=. python3 examples/make_demo_samples.py
"""
from __future__ import annotations

import calendar
import os
import random
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tests.pktbuild as B  # noqa: E402
from nethawk.models import ACK, FIN, PSH, SYN  # noqa: E402

BASE = calendar.timegm((2024, 5, 14, 10, 0, 0, 0, 0, 0))
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "samples")


def handshake(pkts, t, client, server, sport, dport, payload=b"", resp=b""):
    pkts.append((t, B.eth(B.ipv4(client, server, 6, B.tcp(sport, dport, SYN)))))
    pkts.append((t + 0.01, B.eth(B.ipv4(server, client, 6, B.tcp(dport, sport, SYN | ACK)))))
    if payload:
        pkts.append((t + 0.02, B.eth(B.ipv4(client, server, 6, B.tcp(sport, dport, PSH | ACK, payload)))))
    if resp:
        pkts.append((t + 0.03, B.eth(B.ipv4(server, client, 6, B.tcp(dport, sport, PSH | ACK, resp)))))


def write(name, pkts):
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, name)
    with open(path, "wb") as fh:
        fh.write(B.pcap_bytes(pkts))
    print(f"wrote {path} ({os.path.getsize(path)} bytes)")


def dns_tunnel():
    pkts = []
    rnd = random.Random(7)
    client, resolver = "192.168.1.30", "192.168.1.1"
    t = BASE
    for i in range(32):
        label = "".join(rnd.choice("0123456789abcdef") for _ in range(22))
        qname = f"{label}.data.exfil-tunnel.net"
        pkts.append((t, B.eth(B.ipv4(client, resolver, 17, B.udp(40000 + i, 53, B.dns_query(qname))))))
        pkts.append((t + 0.05, B.eth(B.ipv4(resolver, client, 17, B.udp(53, 40000 + i,
                     B.dns_response(qname, [], rcode=3))))))
        t += rnd.choice([1, 2, 4, 5, 8, 11, 3, 7])
    write("dns_tunnel.pcap", pkts)


def cleartext():
    pkts = []
    client, web, telnet = "192.168.1.40", "203.0.113.80", "192.168.1.9"
    # HTTP request with Basic auth and a scripting user agent, over port 80.
    req = (b"GET /admin HTTP/1.1\r\nHost: intranet.local\r\n"
           b"Authorization: Basic dXNlcjpwYXNzd29yZA==\r\n"
           b"User-Agent: curl/8.4.0\r\n\r\n")
    handshake(pkts, BASE, client, web, 51000, 80, payload=req,
              resp=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    # A Telnet session, unencrypted interactive login.
    handshake(pkts, BASE + 5, client, telnet, 51500, 23,
              payload=b"login: admin\r\n", resp=b"Password: ")
    pkts.append((BASE + 5.1, B.eth(B.ipv4(client, telnet, 6, B.tcp(51500, 23, PSH | ACK, b"admin\r\n")))))
    write("cleartext.pcap", pkts)


def scan():
    pkts = []
    attacker, target = "192.168.1.66", "10.0.0.5"
    for i, port in enumerate(range(1, 31)):
        pkts.append((BASE + i * 0.05, B.eth(B.ipv4(attacker, target, 6, B.tcp(40000 + i, port, SYN)))))
    write("scan.pcap", pkts)


def clean():
    pkts = []
    client, resolver = "192.168.1.20", "192.168.1.1"
    sites = [("www.example.com", "93.184.216.34"), ("cdn.example.org", "93.184.216.35")]
    t = BASE
    for i, (host, ip) in enumerate(sites):
        pkts.append((t, B.eth(B.ipv4(client, resolver, 17, B.udp(41000 + i, 53, B.dns_query(host))))))
        pkts.append((t + 0.05, B.eth(B.ipv4(resolver, client, 17, B.udp(53, 41000 + i, B.dns_response(host, [ip]))))))
        handshake(pkts, t + 0.1, client, ip, 52000 + i, 443,
                  payload=B.tls_client_hello(host), resp=b"\x16\x03\x03\x00\x40")
        t += 2
    write("clean.pcap", pkts)


def incident():
    src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample.pcap")
    if os.path.exists(src):
        os.makedirs(OUT, exist_ok=True)
        shutil.copy(src, os.path.join(OUT, "incident.pcap"))
        print(f"copied incident.pcap from {src}")


if __name__ == "__main__":
    incident()
    dns_tunnel()
    cleartext()
    scan()
    clean()
