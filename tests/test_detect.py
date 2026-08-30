import unittest

from nethawk.detect import (
    Config, detect_beaconing, detect_dns_anomalies, detect_exfil, detect_port_scans,
)
from nethawk.models import DnsEvent, Flow


def flow(a_ip, a_port, b_ip, b_port, first, last=None, out=0, inb=0,
         proto="TCP", syn=True, synack=False):
    fl = Flow(proto, a_ip, a_port, b_ip, b_port, first, last if last is not None else first)
    fl.a_to_b_bytes = out
    fl.b_to_a_bytes = inb
    fl.saw_syn = syn
    fl.saw_synack = synack
    return fl


class TestPortScan(unittest.TestCase):
    def test_vertical_scan_detected(self):
        flows = [flow("192.168.1.5", 30000 + i, "192.168.1.9", 20 + i, first=i * 0.1)
                 for i in range(20)]
        found = detect_port_scans(flows, Config())
        self.assertTrue(any(f.category == "port_scan" and f.title == "Vertical port scan" for f in found))

    def test_no_scan_when_established(self):
        flows = [flow("192.168.1.5", 30000 + i, "192.168.1.9", 20 + i, first=i * 0.1, synack=True)
                 for i in range(20)]
        found = detect_port_scans(flows, Config())
        self.assertEqual(found, [])


class TestBeaconing(unittest.TestCase):
    def test_regular_beacon_detected(self):
        flows = [flow("192.168.1.10", 40000 + i, "203.0.113.7", 443,
                      first=100 + i * 60, synack=True, out=200) for i in range(12)]
        found = detect_beaconing(flows, Config())
        beacons = [f for f in found if f.category == "beacon"]
        self.assertTrue(beacons)
        self.assertGreaterEqual(beacons[0].evidence["regularity"], 0.7)

    def test_irregular_traffic_not_beacon(self):
        times = [100, 103, 180, 181, 400, 900, 905, 1500, 1502, 3000, 3001, 7000]
        flows = [flow("192.168.1.10", 40000 + i, "203.0.113.7", 443, first=t, synack=True)
                 for i, t in enumerate(times)]
        found = detect_beaconing(flows, Config())
        self.assertFalse([f for f in found if f.category == "beacon"])


class TestExfil(unittest.TestCase):
    def test_large_outbound_detected(self):
        flows = [flow("192.168.1.10", 50000, "198.51.100.4", 443,
                      first=1.0, last=60.0, out=8_000_000, inb=10_000)]
        found = detect_exfil(flows, Config())
        self.assertTrue(any(f.category == "exfil" for f in found))

    def test_balanced_traffic_not_exfil(self):
        flows = [flow("192.168.1.10", 50000, "198.51.100.4", 443,
                      first=1.0, out=6_000_000, inb=6_000_000)]
        found = detect_exfil(flows, Config())
        self.assertEqual(found, [])

    def test_internal_destination_ignored(self):
        flows = [flow("192.168.1.10", 50000, "192.168.1.20", 445,
                      first=1.0, out=8_000_000, inb=1000)]
        found = detect_exfil(flows, Config())
        self.assertEqual(found, [])


class TestDnsAnomalies(unittest.TestCase):
    def test_dns_tunneling_detected(self):
        import hashlib
        events = []
        for i in range(30):
            label = hashlib.sha1(str(i).encode()).hexdigest()  # 40 high entropy hex chars
            events.append(DnsEvent(ts=float(i), client="192.168.1.10", server="192.168.1.1",
                                   qname=f"{label}.tunnel.example", qtype=16,
                                   is_response=False, rcode=0))
        found = detect_dns_anomalies(events, Config())
        self.assertTrue(any(f.category == "dns_tunnel" for f in found))

    def test_nxdomain_burst_flagged(self):
        events = [DnsEvent(ts=float(i), client="192.168.1.10", server="192.168.1.1",
                           qname=f"rnd{i}.example", qtype=1, is_response=True, rcode=3)
                  for i in range(25)]
        found = detect_dns_anomalies(events, Config())
        self.assertTrue(any(f.category == "dga" for f in found))


class TestNewDetectors(unittest.TestCase):
    def test_cleartext_credentials(self):
        from nethawk.detect import detect_cleartext_creds
        f = flow("192.168.1.10", 40000, "203.0.113.9", 80, first=1.0)
        f.http_auth = True
        f.http_host = "intranet.example"
        found = detect_cleartext_creds([f], Config())
        self.assertTrue(any(x.category == "cleartext_creds" for x in found))

    def test_long_connection(self):
        from nethawk.detect import detect_long_connections
        f = flow("192.168.1.10", 40000, "203.0.113.9", 443, first=0.0, last=7200.0,
                 out=500_000, inb=500_000)
        found = detect_long_connections([f], Config())
        self.assertTrue(any(x.category == "long_connection" for x in found))

    def test_short_connection_not_flagged(self):
        from nethawk.detect import detect_long_connections
        f = flow("192.168.1.10", 40000, "203.0.113.9", 443, first=0.0, last=30.0,
                 out=500_000, inb=500_000)
        self.assertEqual(detect_long_connections([f], Config()), [])

    def test_rare_user_agent(self):
        from nethawk.detect import detect_rare_user_agents
        f = flow("192.168.1.10", 40000, "203.0.113.9", 80, first=1.0)
        f.user_agent = "python-requests/2.31.0"
        found = detect_rare_user_agents([f], Config())
        self.assertTrue(any(x.category == "rare_user_agent" for x in found))



class TestEnrichedDetectors(unittest.TestCase):
    def test_cleartext_protocol_telnet(self):
        from nethawk.detect import detect_cleartext_protocol
        f = flow("192.168.1.10", 40000, "192.168.1.9", 23, first=1.0, out=200, inb=200, synack=True)
        found = detect_cleartext_protocol([f], Config())
        self.assertTrue(any(x.category == "cleartext_protocol" for x in found))

    def test_external_fanout(self):
        from nethawk.detect import detect_external_fanout
        flows = [flow("192.168.1.10", 40000 + i, "203.0.113." + str(i % 250 + 1), 443, first=float(i))
                 for i in range(60)]
        found = detect_external_fanout(flows, Config())
        self.assertTrue(any(x.category == "external_fanout" for x in found))

    def test_mitre_attached(self):
        from nethawk.detect import run_detectors
        flows = [flow("192.168.1.5", 30000 + i, "192.168.1.9", 20 + i, first=i * 0.1) for i in range(20)]
        found = run_detectors(flows, [], {}, Config())
        scan = [f for f in found if f.category == "port_scan"][0]
        self.assertTrue(scan.mitre and scan.mitre[0]["id"] == "T1046")



class TestIncidentSummary(unittest.TestCase):
    def test_summary_reads_well(self):
        from nethawk.analyzer import analyze
        import os
        sample = os.path.join(os.path.dirname(__file__), "..", "examples", "sample.pcap")
        if not os.path.exists(sample):
            self.skipTest("sample not built")
        a = analyze(sample, Config())
        top = a.incidents[0]
        self.assertTrue(top.summary.startswith(top.host + ":"))
        self.assertIn("confidence", top.summary)
        self.assertIn("It involved", top.summary)


if __name__ == "__main__":
    unittest.main()
