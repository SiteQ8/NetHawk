"""Light application protocol parsing: DNS, the TLS client hello, and HTTP.

These take a transport payload and pull out the few fields that matter for
threat hunting: queried names and answers, the TLS server name, and the HTTP
host and request line.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class DnsMsg:
    is_response: bool
    rcode: int
    qname: str
    qtype: int
    answers: List[str] = field(default_factory=list)   # resolved ip strings


def _read_name(data: bytes, off: int, depth: int = 0) -> Tuple[Optional[str], int]:
    if depth > 12:
        return None, off
    labels: List[str] = []
    n = len(data)
    while True:
        if off >= n:
            return None, off
        length = data[off]
        if length == 0:
            off += 1
            break
        if (length & 0xC0) == 0xC0:
            if off + 2 > n:
                return None, off
            ptr = ((length & 0x3F) << 8) | data[off + 1]
            sub, _ = _read_name(data, ptr, depth + 1)
            off += 2
            if sub:
                labels.append(sub)
            return ".".join(labels), off
        off += 1
        if off + length > n:
            return None, off
        labels.append(data[off:off + length].decode("latin-1", "replace"))
        off += length
    return ".".join(labels), off


def parse_dns(data: bytes) -> Optional[DnsMsg]:
    if len(data) < 12:
        return None
    try:
        _ident, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    except struct.error:
        return None
    if qd < 1:
        return None
    qr = (flags >> 15) & 1
    rcode = flags & 0x000F
    off = 12
    qname, off = _read_name(data, off)
    if qname is None:
        return None
    if off + 4 <= len(data):
        qtype, _qclass = struct.unpack("!HH", data[off:off + 4])
        off += 4
    else:
        qtype = 0
    answers: List[str] = []
    for _ in range(an):
        _name, off = _read_name(data, off)
        if off + 10 > len(data):
            break
        atype, _aclass, _ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        off += rdlen
        if atype == 1 and rdlen == 4:
            answers.append(".".join(str(b) for b in rdata))
        elif atype == 28 and rdlen == 16:
            answers.append(":".join(f"{(rdata[i] << 8) | rdata[i + 1]:x}" for i in range(0, 16, 2)))
    return DnsMsg(is_response=bool(qr), rcode=rcode, qname=qname, qtype=qtype, answers=answers)


def parse_tls_sni(data: bytes) -> Optional[str]:
    # TLS record: content type 22 is handshake.
    if len(data) < 6 or data[0] != 0x16:
        return None
    off = 5
    if data[off] != 0x01:   # client hello
        return None
    hs_len = int.from_bytes(data[off + 1:off + 4], "big")
    end = min(len(data), off + 4 + hs_len)
    off += 4
    off += 2 + 32           # client version + random
    if off >= end:
        return None
    sid_len = data[off]
    off += 1 + sid_len
    if off + 2 > end:
        return None
    cs_len = int.from_bytes(data[off:off + 2], "big")
    off += 2 + cs_len
    if off + 1 > end:
        return None
    comp_len = data[off]
    off += 1 + comp_len
    if off + 2 > end:
        return None
    ext_total = int.from_bytes(data[off:off + 2], "big")
    off += 2
    ext_end = min(end, off + ext_total)
    while off + 4 <= ext_end:
        etype = int.from_bytes(data[off:off + 2], "big")
        elen = int.from_bytes(data[off + 2:off + 4], "big")
        off += 4
        if etype == 0x0000:
            p = off
            if p + 2 > ext_end:
                return None
            p += 2  # server name list length
            if p + 3 > ext_end:
                return None
            p += 1  # name type
            nlen = int.from_bytes(data[p:p + 2], "big")
            p += 2
            if p + nlen > ext_end:
                return None
            return data[p:p + nlen].decode("latin-1", "replace")
        off += elen
    return None


@dataclass
class HttpInfo:
    method: str
    host: str
    path: str
    user_agent: str = ""
    has_auth: bool = False


_HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ",
                 b"OPTIONS ", b"PATCH ", b"CONNECT ")


def parse_http(data: bytes):
    """Return an HttpInfo for a plaintext HTTP request, or None."""
    if not data.startswith(_HTTP_METHODS):
        return None
    head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
    lines = head.split("\r\n")
    if not lines:
        return None
    first = lines[0].split(" ")
    if len(first) < 2:
        return None
    method, path = first[0], first[1]
    host = ua = ""
    has_auth = False
    for line in lines[1:]:
        low = line.lower()
        if low.startswith("host:"):
            host = line.split(":", 1)[1].strip()
        elif low.startswith("user-agent:"):
            ua = line.split(":", 1)[1].strip()
        elif low.startswith("authorization:"):
            has_auth = True
    return HttpInfo(method=method, host=host, path=path, user_agent=ua, has_auth=has_auth)
