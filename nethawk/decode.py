"""Decode link, network, and transport layers into Packet records."""
from __future__ import annotations

import struct
from typing import Optional

from .models import Packet

# Link layer types we understand.
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113


def _ipv6_str(b: bytes) -> str:
    parts = [f"{(b[i] << 8) | b[i + 1]:x}" for i in range(0, 16, 2)]
    return ":".join(parts)


def _ipv4_str(b: bytes) -> str:
    return ".".join(str(x) for x in b)


def decode(ts: float, linktype: int, data: bytes) -> Optional[Packet]:
    et, l3, off = _link(linktype, data)
    if l3 is None:
        return None
    if et == "ip4":
        return _ipv4(ts, data, off)
    if et == "ip6":
        return _ipv6(ts, data, off)
    if et == "arp":
        return Packet(ts=ts, src_ip="", dst_ip="", proto="ARP")
    return None


def _link(linktype: int, data: bytes):
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None, None, 0
        et = struct.unpack("!H", data[12:14])[0]
        return _ethertype(et, data, 14)
    if linktype == LINKTYPE_LINUX_SLL:
        if len(data) < 16:
            return None, None, 0
        et = struct.unpack("!H", data[14:16])[0]
        return _ethertype(et, data, 16)
    if linktype == LINKTYPE_RAW:
        if not data:
            return None, None, 0
        ver = data[0] >> 4
        if ver == 4:
            return "ip4", data, 0
        if ver == 6:
            return "ip6", data, 0
        return None, None, 0
    if linktype == LINKTYPE_NULL:
        if len(data) < 4:
            return None, None, 0
        fam = struct.unpack("<I", data[0:4])[0]
        if fam > 0xFFFF:
            fam = struct.unpack(">I", data[0:4])[0]
        if fam == 2:
            return "ip4", data, 4
        if fam in (23, 24, 28, 30):
            return "ip6", data, 4
        return None, None, 0
    # Unknown link layer: try Ethernet as a best effort.
    if len(data) >= 14:
        et = struct.unpack("!H", data[12:14])[0]
        return _ethertype(et, data, 14)
    return None, None, 0


def _ethertype(et: int, data: bytes, off: int):
    # Strip any stack of VLAN tags: 802.1Q (0x8100) and 802.1ad QinQ (0x88a8).
    hops = 0
    while et in (0x8100, 0x88A8) and len(data) >= off + 4 and hops < 4:
        et = struct.unpack("!H", data[off + 2:off + 4])[0]
        off += 4
        hops += 1
    if et == 0x0800:
        return "ip4", data, off
    if et == 0x86DD:
        return "ip6", data, off
    if et == 0x0806:
        return "arp", data, off
    return None, None, off


def _ipv4(ts: float, data: bytes, off: int) -> Optional[Packet]:
    if len(data) < off + 20:
        return None
    b0 = data[off]
    ihl = (b0 & 0x0F) * 4
    if ihl < 20 or len(data) < off + ihl:
        return None
    total_len = struct.unpack("!H", data[off + 2:off + 4])[0]
    proto = data[off + 9]
    src = _ipv4_str(data[off + 12:off + 16])
    dst = _ipv4_str(data[off + 16:off + 20])
    l4 = off + ihl
    ip_payload_len = max(0, total_len - ihl)
    return _transport(ts, src, dst, proto, data, l4, ip_payload_len)


def _ipv6(ts: float, data: bytes, off: int) -> Optional[Packet]:
    if len(data) < off + 40:
        return None
    payload_len = struct.unpack("!H", data[off + 4:off + 6])[0]
    nexthdr = data[off + 6]
    src = _ipv6_str(data[off + 8:off + 24])
    dst = _ipv6_str(data[off + 24:off + 40])
    l4 = off + 40
    # Follow a couple of common extension headers.
    hops = 0
    while nexthdr in (0, 43, 60) and hops < 4 and len(data) >= l4 + 2:
        ext_len = (data[l4 + 1] + 1) * 8
        nexthdr = data[l4]
        l4 += ext_len
        hops += 1
    return _transport(ts, src, dst, nexthdr, data, l4, payload_len)


def _transport(ts, src, dst, proto, data, off, ip_payload_len) -> Optional[Packet]:
    if proto == 6:  # tcp
        if len(data) < off + 20:
            return None
        sport, dport = struct.unpack("!HH", data[off:off + 4])
        data_off = (data[off + 12] >> 4) * 4
        flags = data[off + 13]
        payload = data[off + data_off:] if len(data) > off + data_off else b""
        length = ip_payload_len if ip_payload_len else len(data) - off
        return Packet(ts, src, dst, "TCP", sport, dport, length, flags, payload)
    if proto == 17:  # udp
        if len(data) < off + 8:
            return None
        sport, dport, ulen = struct.unpack("!HHH", data[off:off + 6])
        payload = data[off + 8:]
        length = ip_payload_len if ip_payload_len else len(data) - off
        return Packet(ts, src, dst, "UDP", sport, dport, length, 0, payload)
    if proto in (1, 58):  # icmp, icmpv6
        name = "ICMP" if proto == 1 else "ICMPv6"
        return Packet(ts, src, dst, name, 0, 0, ip_payload_len, 0, b"")
    return Packet(ts, src, dst, "OTHER", 0, 0, ip_payload_len, 0, b"")
