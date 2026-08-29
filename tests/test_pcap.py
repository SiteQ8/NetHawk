import os
import tempfile
import unittest

import tests.pktbuild as B
from nethawk import pcap, decode
from nethawk.apps import parse_dns, parse_tls_sni, parse_http
from nethawk.models import SYN


class TestPcapRoundTrip(unittest.TestCase):
    def _write(self, packets):
        raw = B.pcap_bytes(packets)
        fd, path = tempfile.mkstemp(suffix=".pcap")
        os.write(fd, raw)
        os.close(fd)
        self.addCleanup(os.unlink, path)
        return path

    def test_reads_all_packets(self):
        packets = [
            (1.0, B.eth(B.ipv4("10.0.0.1", "10.0.0.2", 6, B.tcp(1234, 80, SYN)))),
            (2.0, B.eth(B.ipv4("10.0.0.1", "10.0.0.2", 17, B.udp(5000, 53, B.dns_query("a.example.com"))))),
        ]
        path = self._write(packets)
        got = list(pcap.read_packets(path))
        self.assertEqual(len(got), 2)

    def test_tcp_fields(self):
        path = self._write([(1.0, B.eth(B.ipv4("10.0.0.1", "203.0.113.9", 6, B.tcp(40000, 443, SYN))))])
        ts, lt, data = next(iter(pcap.read_packets(path)))
        p = decode.decode(ts, lt, data)
        self.assertEqual(p.proto, "TCP")
        self.assertEqual(p.src_ip, "10.0.0.1")
        self.assertEqual(p.dst_ip, "203.0.113.9")
        self.assertEqual(p.dst_port, 443)
        self.assertEqual(p.flags, SYN)

    def test_truncated_length_is_reported(self):
        # A packet that claims 65000 bytes but only carries a few.
        frame = B.eth(B.ipv4("10.0.0.1", "10.0.0.2", 6, B.tcp(1, 2, 0x18, b"xy"), total_len_override=65000))
        path = self._write([(1.0, frame)])
        ts, lt, data = next(iter(pcap.read_packets(path)))
        p = decode.decode(ts, lt, data)
        self.assertEqual(p.length, 65000 - 20)

    def test_bad_file_raises(self):
        fd, path = tempfile.mkstemp(suffix=".bin")
        os.write(fd, b"not a capture at all")
        os.close(fd)
        self.addCleanup(os.unlink, path)
        with self.assertRaises(pcap.PcapError):
            list(pcap.read_packets(path))


class TestAppParsing(unittest.TestCase):
    def test_dns_query_and_response(self):
        q = parse_dns(B.dns_query("host.example.com"))
        self.assertFalse(q.is_response)
        self.assertEqual(q.qname, "host.example.com")

        r = parse_dns(B.dns_response("host.example.com", ["93.184.216.34"]))
        self.assertTrue(r.is_response)
        self.assertEqual(r.answers, ["93.184.216.34"])

    def test_tls_sni(self):
        self.assertEqual(parse_tls_sni(B.tls_client_hello("secure.example.com")), "secure.example.com")

    def test_http_host(self):
        req = b"GET /path HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: curl/8\r\n\r\n"
        method, host, path, ua = parse_http(req)
        self.assertEqual(method, "GET")
        self.assertEqual(host, "www.example.com")
        self.assertEqual(path, "/path")


if __name__ == "__main__":
    unittest.main()
