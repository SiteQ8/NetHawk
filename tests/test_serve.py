import json
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer

import tests.pktbuild as B
from nethawk import analyze_bytes
from nethawk.detect import Config
from nethawk.models import SYN, ACK, PSH
from nethawk.serve import _make_handler, render_page


def _sample_capture() -> bytes:
    pkts = []
    # DNS lookup resolving a C2 name, then regular beaconing to it.
    pkts.append((99.0, B.eth(B.ipv4("192.168.1.100", "192.168.1.1", 17,
                                    B.udp(51000, 53, B.dns_query("c2.evil.example"))))))
    pkts.append((99.1, B.eth(B.ipv4("192.168.1.1", "192.168.1.100", 17,
                                    B.udp(53, 51000, B.dns_response("c2.evil.example", ["203.0.113.5"]))))))
    for i in range(10):
        t = 100 + i * 30
        sp = 52000 + i
        pkts.append((t, B.eth(B.ipv4("192.168.1.100", "203.0.113.5", 6, B.tcp(sp, 443, SYN)))))
        pkts.append((t + 0.1, B.eth(B.ipv4("203.0.113.5", "192.168.1.100", 6, B.tcp(443, sp, SYN | ACK)))))
        pkts.append((t + 0.2, B.eth(B.ipv4("192.168.1.100", "203.0.113.5", 6, B.tcp(sp, 443, PSH | ACK, b"\x17\x03\x03..")))))
    return B.pcap_bytes(pkts)


class TestAnalyzeBytes(unittest.TestCase):
    def test_analyze_bytes_finds_beacon(self):
        a = analyze_bytes(_sample_capture(), Config(), name="mem.pcap")
        self.assertEqual(a.path, "mem.pcap")
        self.assertTrue(any(f.category == "beacon" for f in a.findings))


class TestApi(unittest.TestCase):
    def setUp(self):
        handler = _make_handler(Config(), _sample_capture())
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def _get(self, path):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}", timeout=5) as r:
            return r.status, r.read()

    def test_health(self):
        status, body = self._get("/api/health")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["status"], "ok")
        self.assertTrue(data["sample"])

    def test_index_serves_page(self):
        status, body = self._get("/")
        self.assertEqual(status, 200)
        self.assertIn(b"NetHawk", body)

    def test_analyze_endpoint(self):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/api/analyze",
                                     data=_sample_capture(), method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        self.assertIn("incidents", data)
        self.assertTrue(any(f["category"] == "beacon" for f in data["findings"]))

    def test_sample_endpoint(self):
        status, body = self._get("/api/sample")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("findings", data)


class TestRenderPage(unittest.TestCase):
    def test_embeds_json(self):
        page = render_page('{"a":1}')
        self.assertIn('window.__EMBEDDED__={"a":1};', page)
        self.assertIn("Reconstruct attacks", page)


if __name__ == "__main__":
    unittest.main()
