import os
import tempfile
import unittest

import alerts
import demo
import scanner
from app import create_app


class ScannerTests(unittest.TestCase):
    def test_validate_target_accepts_private(self):
        self.assertEqual(scanner.validate_target("192.168.1.0/24"), "192.168.1.0/24")
        self.assertEqual(scanner.validate_target("10.0.0.5"), "10.0.0.5/32")

    def test_validate_target_rejects_public_and_invalid(self):
        for bad in ["8.8.8.8", "1.1.1.0/24", "pas-une-ip", "10.0.0.0/8", "192.168.1.1; rm -rf /"]:
            with self.assertRaises(scanner.ScanError):
                scanner.validate_target(bad)

    def test_parse_hosts(self):
        hosts = demo.demo_hosts()
        self.assertEqual(len(hosts), 5)
        router = hosts[0]
        self.assertEqual(router["ip"], "192.168.1.1")
        self.assertEqual(router["vendor"], "TP-Link")
        self.assertEqual(router["hostname"], "routeur.local")

    def test_parse_ports(self):
        ports = demo.demo_ports("192.168.1.34")
        self.assertEqual([p["port"] for p in ports], [23, 80, 554])
        self.assertEqual(demo.demo_ports("192.168.1.12"), [])


class AlertTests(unittest.TestCase):
    def test_sensitive_ports_raise_alerts(self):
        result = alerts.evaluate(demo.demo_ports("192.168.1.50"))
        self.assertEqual({a["severity"] for a in result}, {"élevé"})
        self.assertEqual(len(result), 3)

    def test_safe_ports_raise_nothing(self):
        self.assertEqual(alerts.evaluate([{"port": 443, "protocol": "tcp", "service": "https", "product": ""}]), [])

    def test_highest_severity(self):
        self.assertEqual(alerts.highest_severity(["faible", "élevé", "moyen"]), "élevé")
        self.assertEqual(alerts.highest_severity([]), "info")


class AppTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.app = create_app(db_path=os.path.join(self.tmp, "test.db"), demo_mode=True)
        self.client = self.app.test_client()

    def test_empty_dashboard(self):
        page = self.client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Aucun appareil".encode(), page.data)

    def test_demo_scan_fills_dashboard_and_is_idempotent(self):
        self.client.post("/scan", data={"target": "192.168.1.0/24"})
        devices = self.client.get("/api/devices").get_json()
        self.assertEqual(len(devices), 5)
        first_alerts = len(self.client.get("/api/alerts").get_json())
        self.client.post("/scan", data={"target": "192.168.1.0/24"})
        second_alerts = len(self.client.get("/api/alerts").get_json())
        self.assertEqual(first_alerts, second_alerts)  # pas de doublons au second scan
        self.assertIn(b"camera-salon", self.client.get("/").data)

    def test_real_mode_rejects_public_target(self):
        app = create_app(db_path=os.path.join(self.tmp, "real.db"), demo_mode=False)
        client = app.test_client()
        response = client.post("/scan", data={"target": "8.8.8.8"}, follow_redirects=True)
        self.assertIn("réseaux privés".encode(), response.data)
        self.assertEqual(client.get("/api/devices").get_json(), [])


if __name__ == "__main__":
    unittest.main()
