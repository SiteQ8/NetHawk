"""Read packets from classic pcap and from pcapng files.

Yields tuples of (timestamp, link_layer_type, raw_bytes). Only the standard
library is used. Truncated files are handled by stopping cleanly.
"""
from __future__ import annotations

import struct
from typing import Iterator, Tuple

# Classic pcap magic bytes mapped to (endian, ticks_per_second).
_CLASSIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


class PcapError(Exception):
    pass


def read_packets(path: str) -> Iterator[Tuple[float, int, bytes]]:
    with open(path, "rb") as fh:
        head = fh.read(4)
        fh.seek(0)
        if len(head) < 4:
            raise PcapError("file is too short to be a capture")
        if head in _CLASSIC:
            yield from _read_classic(fh)
        elif head == _PCAPNG_MAGIC:
            yield from _read_pcapng(fh.read())
        else:
            raise PcapError("not a pcap or pcapng file")


def _read_classic(fh) -> Iterator[Tuple[float, int, bytes]]:
    magic = fh.read(4)
    endian, ticks = _CLASSIC[magic]
    rest = fh.read(20)
    if len(rest) < 20:
        raise PcapError("truncated global header")
    linktype = struct.unpack(endian + "I", rest[16:20])[0]
    record = endian + "IIII"
    while True:
        hdr = fh.read(16)
        if len(hdr) < 16:
            return
        ts_sec, ts_frac, incl, _orig = struct.unpack(record, hdr)
        data = fh.read(incl)
        if len(data) < incl:
            return
        yield ts_sec + ts_frac / ticks, linktype, data


def _idb_tsresol(body: bytes, endian: str) -> float:
    off = 8  # after linktype(2) + reserved(2) + snaplen(4)
    n = len(body)
    while off + 4 <= n:
        code, length = struct.unpack(endian + "HH", body[off:off + 4])
        off += 4
        if code == 0:
            break
        if code == 9 and length >= 1:
            b = body[off]
            return float(1 << (b & 0x7F)) if (b & 0x80) else float(10 ** b)
        off += length + ((4 - length % 4) % 4)
    return 1_000_000.0


def _read_pcapng(data: bytes) -> Iterator[Tuple[float, int, bytes]]:
    n = len(data)
    off = 0
    endian = "<"
    linktypes = []
    resols = []
    while off + 8 <= n:
        btype = data[off:off + 4]
        if btype == _PCAPNG_MAGIC:
            bom = data[off + 8:off + 12]
            # Bytes 1a2b3c4d in file order mean big endian; 4d3c2b1a mean little.
            if bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                endian = "<"
            total = struct.unpack(endian + "I", data[off + 4:off + 8])[0]
            if total < 12 or off + total > n:
                return
            off += total
            continue

        total = struct.unpack(endian + "I", data[off + 4:off + 8])[0]
        if total < 12 or off + total > n:
            return
        body = data[off + 8:off + total - 4]
        t = struct.unpack(endian + "I", btype)[0]

        if t == 0x00000001:  # interface description
            linktype = struct.unpack(endian + "H", body[0:2])[0]
            linktypes.append(linktype)
            resols.append(_idb_tsresol(body, endian))
        elif t == 0x00000006:  # enhanced packet
            iface = struct.unpack(endian + "I", body[0:4])[0]
            ts_high, ts_low = struct.unpack(endian + "II", body[4:12])
            cap_len = struct.unpack(endian + "I", body[12:16])[0]
            pkt = body[20:20 + cap_len]
            res = resols[iface] if iface < len(resols) else 1_000_000.0
            lt = linktypes[iface] if iface < len(linktypes) else 1
            yield ((ts_high << 32) | ts_low) / res, lt, pkt
        elif t == 0x00000003:  # simple packet
            orig = struct.unpack(endian + "I", body[0:4])[0]
            pkt = body[4:4 + orig]
            lt = linktypes[0] if linktypes else 1
            yield 0.0, lt, pkt

        off += total
