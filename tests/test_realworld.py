"""Regression tests for real-world capture formats.

These were prompted by running NetHawk against the tcpdump test corpus, which
turned up two bugs: pcapng little endian files were read with the wrong byte
order, and 802.1ad QinQ double tagged frames were dropped. The captures here are
built by hand to be format accurate so the fixes stay fixed.
"""
import struct
import unittest

import tests.pktbuild as B
from nethawk.decode import decode
from nethawk.pcap import read_packets


def _block(btype, body, e):
    total = 12 + len(body)
    return struct.pack(e + "I", btype) + struct.pack(e + "I", total) + body + struct.pack(e + "I", total)


def make_pcapng(packet, e="<", linktype=1):
    """A minimal single packet pcapng: section header, one interface, one packet."""
    shb = _block(0x0A0D0D0A, struct.pack(e + "IHHq", 0x1A2B3C4D, 1, 0, -1), e)
    idb = _block(0x00000001, struct.pack(e + "HHI", linktype, 0, 65535), e)
    pad = (4 - len(packet) % 4) % 4
    epb_body = struct.pack(e + "IIIII", 0, 0, 0, len(packet), len(packet)) + packet + b"\x00" * pad
    epb = _block(0x00000006, epb_body, e)
    return shb + idb + epb


def _write(tmp, data):
    tmp.write(data)
    tmp.flush()
    return tmp.name


class TestPcapngByteOrder(unittest.TestCase):
    def _roundtrip(self, endian):
        packet = B.eth(B.ipv4("10.0.0.1", "10.0.0.2", 17, B.udp(1234, 53, b"hello")))
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".pcapng") as tmp:
            _write(tmp, make_pcapng(packet, endian))
            pkts = list(read_packets(tmp.name))
            self.assertEqual(len(pkts), 1, f"endian {endian}")
            ts, lt, data = pkts[0]
            dec = decode(ts, lt, data)
            self.assertIsNotNone(dec)
            self.assertEqual((dec.proto, dec.src_ip, dec.dst_ip), ("UDP", "10.0.0.1", "10.0.0.2"))

    def test_little_endian(self):
        self._roundtrip("<")

    def test_big_endian(self):
        self._roundtrip(">")


class TestVlanStacks(unittest.TestCase):
    def _frame(self, tags):
        mac_a, mac_b = b"\x02\x00\x00\x00\x00\x01", b"\x02\x00\x00\x00\x00\x02"
        inner = B.ipv4("10.0.0.1", "10.0.0.2", 17, B.udp(4321, 53, b"x"))
        f = mac_b + mac_a
        for tpid in tags:
            f += struct.pack("!H", tpid) + struct.pack("!H", 0x0064)
        f += struct.pack("!H", 0x0800) + inner
        return f

    def test_single_vlan(self):
        dec = decode(0.0, 1, self._frame([0x8100]))
        self.assertEqual((dec.proto, dec.src_ip), ("UDP", "10.0.0.1"))

    def test_qinq_dot1ad(self):
        # Outer 802.1ad (0x88a8) then inner 802.1Q (0x8100), the QinQ case.
        dec = decode(0.0, 1, self._frame([0x88A8, 0x8100]))
        self.assertIsNotNone(dec)
        self.assertEqual((dec.proto, dec.src_ip, dec.dst_ip), ("UDP", "10.0.0.1", "10.0.0.2"))

    def test_qinq_stacked_dot1q(self):
        dec = decode(0.0, 1, self._frame([0x8100, 0x8100]))
        self.assertEqual((dec.proto, dec.dst_ip), ("UDP", "10.0.0.2"))


class TestRobustness(unittest.TestCase):
    def test_ipv6_frame(self):
        # Hand built IPv6 over Ethernet with a UDP payload.
        src = bytes(15) + b"\x01"
        dst = bytes(15) + b"\x02"
        udp = struct.pack("!HHHH", 5000, 53, 8, 0)
        ip6 = struct.pack("!IHBB", (6 << 28), len(udp), 17, 64) + src + dst + udp
        frame = b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01" + struct.pack("!H", 0x86DD) + ip6
        dec = decode(0.0, 1, frame)
        self.assertIsNotNone(dec)
        self.assertEqual(dec.proto, "UDP")

    def test_truncated_frame_does_not_crash(self):
        for data in [b"", b"\x00", b"\x02\x00\x00\x00\x00\x02\x08\x00", b"\x02" * 13 + struct.pack("!H", 0x0800)]:
            try:
                decode(0.0, 1, data)
            except Exception as exc:  # noqa: BLE001
                self.fail(f"decode raised on truncated input {data!r}: {exc!r}")


if __name__ == "__main__":
    unittest.main()
