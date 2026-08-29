import unittest

import tests.pktbuild as B
from nethawk.decode import decode
from nethawk.flows import FlowTable, is_internal
from nethawk.models import ACK, SYN, PSH


def feed(table, frame, ts=1.0, linktype=1):
    p = decode(ts, linktype, frame)
    if p is not None:
        table.add(p)


class TestIsInternal(unittest.TestCase):
    def test_private_ranges(self):
        for ip in ("10.1.2.3", "192.168.0.9", "172.16.5.5", "127.0.0.1", "169.254.1.1"):
            self.assertTrue(is_internal(ip), ip)

    def test_public_ranges(self):
        for ip in ("8.8.8.8", "203.0.113.10", "198.51.100.1"):
            self.assertFalse(is_internal(ip), ip)


class TestFlowAggregation(unittest.TestCase):
    def test_bidirectional_flow_and_direction(self):
        table = FlowTable()
        # client SYN, server SYN-ACK, client data
        feed(table, B.eth(B.ipv4("192.168.1.10", "203.0.113.5", 6, B.tcp(51000, 443, SYN))), ts=1.0)
        feed(table, B.eth(B.ipv4("203.0.113.5", "192.168.1.10", 6, B.tcp(443, 51000, SYN | ACK))), ts=1.1)
        feed(table, B.eth(B.ipv4("192.168.1.10", "203.0.113.5", 6, B.tcp(51000, 443, PSH | ACK, b"hello"))), ts=1.2)

        flows, internal, external = table.finalize()
        self.assertEqual(len(flows), 1)
        fl = flows[0]
        self.assertEqual(fl.a_ip, "192.168.1.10")   # initiator is the client
        self.assertEqual(fl.b_ip, "203.0.113.5")
        self.assertTrue(fl.established)
        self.assertGreater(fl.a_to_b_bytes, 0)
        self.assertIn("192.168.1.10", internal)
        self.assertIn("203.0.113.5", external)

    def test_dns_event_and_resolution_map(self):
        table = FlowTable()
        feed(table, B.eth(B.ipv4("192.168.1.10", "192.168.1.1", 17,
                                 B.udp(50000, 53, B.dns_query("evil.example.com")))), ts=1.0)
        feed(table, B.eth(B.ipv4("192.168.1.1", "192.168.1.10", 17,
                                 B.udp(53, 50000, B.dns_response("evil.example.com", ["203.0.113.5"])))), ts=1.1)
        self.assertEqual(len(table.dns_events), 2)
        self.assertEqual(table.ip_domain.get("203.0.113.5"), "evil.example.com")

    def test_tls_sni_attached_to_flow(self):
        table = FlowTable()
        payload = B.tls_client_hello("secure.example.com")
        feed(table, B.eth(B.ipv4("192.168.1.10", "203.0.113.5", 6, B.tcp(51000, 443, PSH | ACK, payload))), ts=1.0)
        flows, _, _ = table.finalize()
        self.assertEqual(flows[0].sni, "secure.example.com")


if __name__ == "__main__":
    unittest.main()
