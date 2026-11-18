import os
import sqlite3
import json
import unittest
from app import (
    app,
    init_db,
    DB_PATH,
    ssh_attempts,
    port_scans,
    rdp_attempts,
    login_attempts,
    zone_request_times,
    firewall_decision,
    firewall_decision_detailed,
    ids_check,
    assign_severity
)

class NetworkSecurityTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        init_db()
        self.client.post('/api/clear_logs')

    def test_firewall_rules(self):
        # Same zone
        self.assertEqual(firewall_decision("Student Lab", "Student Lab", 22, "tcp"), "allow")
        # Allowed DMZ web
        self.assertEqual(firewall_decision("Faculty", "Public Web Server / DMZ", 80, "tcp"), "allow")
        self.assertEqual(firewall_decision("Student Lab", "Public Web Server / DMZ", 443, "tcp"), "allow")
        # Denied DMZ non-web
        self.assertEqual(firewall_decision("Faculty", "Public Web Server / DMZ", 22, "tcp"), "deny")
        self.assertEqual(firewall_decision("Student Lab", "Public Web Server / DMZ", 8080, "tcp"), "deny")
        # Denied inter-zone
        self.assertEqual(firewall_decision("Student Lab", "Faculty", 22, "tcp"), "deny")
        self.assertEqual(firewall_decision("Student Lab", "Administration", 1433, "tcp"), "deny")

    def test_ids_readme_scenarios(self):
        ssh_attempts.clear()
        port_scans.clear()

        # Scenario 1: Student Lab -> Student Lab, 22
        alerts1 = ids_check("Student Lab", "Student Lab", 22, "tcp")
        self.assertEqual(alerts1, [])

        # Scenario 2: Faculty -> Public Web Server / DMZ, 80
        alerts2 = ids_check("Faculty", "Public Web Server / DMZ", 80, "tcp")
        self.assertEqual(alerts2, [])

        # Scenario 3: Student Lab -> Faculty, 22 (1x)
        alerts3 = ids_check("Student Lab", "Faculty", 22, "tcp")
        self.assertEqual(alerts3, [])

        # Scenario 4: Student Lab -> Faculty, 22 (attempts 2 and 3)
        alerts4_2 = ids_check("Student Lab", "Faculty", 22, "tcp")
        self.assertEqual(alerts4_2, [])
        alerts4_3 = ids_check("Student Lab", "Faculty", 22, "tcp")
        self.assertIn("Repeated SSH Scan Detected", alerts4_3)

        # Scenario 5: 5 different ports
        ssh_attempts.clear()
        port_scans.clear()
        for p in [1001, 1002, 1003, 1004]:
            self.assertEqual(ids_check("Student Lab", "Faculty", p, "tcp"), [])
        alerts5 = ids_check("Student Lab", "Faculty", 1005, "tcp")
        self.assertIn("Suspicious Port Scan Detected", alerts5)

    def test_ids_unauthorized_access(self):
        # Student Lab to Administration
        alerts_admin = ids_check("Student Lab", "Administration", 1433, "tcp")
        self.assertTrue(any("Restricted Administration Zone Access" in a for a in alerts_admin))

        # DMZ to internal zone (Lateral Movement)
        alerts_dmz = ids_check("Public Web Server / DMZ", "Faculty", 22, "tcp")
        self.assertTrue(any("Lateral Movement" in a for a in alerts_dmz))

    def test_generate_suspicious_traffic_diversity(self):
        """Verify that Generate Suspicious Traffic produces diverse, randomized results on every click."""
        decisions_seen = set()
        patterns_seen = set()
        alerts_seen = set()
        events_collected = []

        # Simulate 20 clicks
        for _ in range(20):
            resp = self.client.post('/api/generate_suspicious')
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertEqual(data.get("status"), "completed")
            events = data.get("events", [])
            self.assertGreater(len(events), 0)

            pattern = data.get("pattern")
            if pattern:
                patterns_seen.add(pattern)

            for ev in events:
                events_collected.append(ev)
                decisions_seen.add(ev["decision"])
                for a in ev.get("alerts", []):
                    alerts_seen.add(a)

        print(f"Patterns observed across 20 clicks: {patterns_seen}")
        print(f"Decisions observed: {decisions_seen}")
        print(f"Distinct alerts observed: {alerts_seen}")

        self.assertIn("allow", decisions_seen)
        self.assertIn("deny", decisions_seen)
        self.assertGreater(len(patterns_seen), 1)
        self.assertGreater(len(alerts_seen), 1)

        conn = sqlite3.connect(DB_PATH)
        row_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        conn.close()
        self.assertEqual(row_count, len(events_collected))

    def test_api_events_and_reset(self):
        self.client.post('/api/generate_suspicious')
        resp = self.client.get('/api/events')
        self.assertEqual(resp.status_code, 200)
        events = resp.get_json()
        self.assertGreater(len(events), 0)

        resp_clear = self.client.post('/api/clear_logs')
        self.assertEqual(resp_clear.status_code, 200)
        resp_after_clear = self.client.get('/api/events')
        self.assertEqual(len(resp_after_clear.get_json()), 0)

        self.client.post('/api/generate_suspicious')
        resp_reset = self.client.get('/api/reset')
        self.assertEqual(resp_reset.status_code, 200)
        resp_after_reset = self.client.get('/api/events')
        self.assertEqual(len(resp_after_reset.get_json()), 0)

    def test_advanced_firewall_rules_crud(self):
        """Test adding custom rule, priority evaluation, toggling and deleting."""
        # Add high-priority rule allowing Student Lab to Faculty on port 9090
        r_add = self.client.post('/api/rules', json={
            "name": "Custom Student Lab to Faculty 9090",
            "source": "Student Lab",
            "destination": "Faculty",
            "port": "9090",
            "protocol": "TCP",
            "action": "allow",
            "priority": 5,
            "description": "Test high-priority allow"
        })
        self.assertEqual(r_add.status_code, 201)
        rule_id = r_add.get_json()["rule_id"]

        # Now test that 9090 is allowed
        dec, reason = firewall_decision_detailed("Student Lab", "Faculty", 9090, "tcp")
        self.assertEqual(dec, "allow")
        self.assertIn("Custom Student Lab", reason)

        # Toggle rule to disabled
        r_tog = self.client.post(f'/api/rules/{rule_id}/toggle')
        self.assertEqual(r_tog.status_code, 200)
        self.assertFalse(r_tog.get_json()["enabled"])

        # Now test that 9090 is denied (default deny applies)
        dec_disabled, _ = firewall_decision_detailed("Student Lab", "Faculty", 9090, "tcp")
        self.assertEqual(dec_disabled, "deny")

        # Delete rule
        r_del = self.client.delete(f'/api/rules/{rule_id}')
        self.assertEqual(r_del.status_code, 200)

    def test_advanced_ids_severity_assignment(self):
        """Verify proper severity mapping."""
        self.assertEqual(assign_severity(["Unauthorized Access Attempt: DMZ to Internal Network (Lateral Movement)"], "deny"), "CRITICAL")
        self.assertEqual(assign_severity(["Unauthorized Access Attempt: Restricted Administration Zone Access"], "deny"), "CRITICAL")
        self.assertEqual(assign_severity(["Suspicious Port Scan Detected"], "deny"), "HIGH")
        self.assertEqual(assign_severity(["Repeated SSH Scan Detected"], "deny"), "HIGH")
        self.assertEqual(assign_severity(["Repeated Login Attempts Detected (HTTP/HTTPS Brute Force)"], "allow"), "MEDIUM")
        self.assertEqual(assign_severity(["Suspicious Port Activity: Prohibited Service Probe (SMB (Port 445))"], "deny"), "MEDIUM")
        self.assertEqual(assign_severity([], "deny"), "LOW")
        self.assertEqual(assign_severity([], "allow"), "SAFE")

    def test_stats_and_csv_export(self):
        """Verify /api/stats computes metrics from SQLite and CSV exports clean data."""
        self.client.post('/api/generate_traffic_stream')
        resp_stats = self.client.get('/api/stats')
        self.assertEqual(resp_stats.status_code, 200)
        stats = resp_stats.get_json()

        self.assertGreater(stats["total_traffic"], 0)
        self.assertEqual(stats["total_traffic"], stats["allowed_count"] + stats["blocked_count"])
        self.assertIn(stats["threat_level"], ["NORMAL", "ELEVATED", "HIGH", "CRITICAL"])

        resp_csv = self.client.get('/api/export_csv')
        self.assertEqual(resp_csv.status_code, 200)
        self.assertIn("text/csv", resp_csv.headers.get("Content-Type", ""))
        self.assertIn("Event ID", resp_csv.text)

    def test_all_pages_and_auth(self):
        """Verify all new pages render HTTP 200 and auth works."""
        pages = ['/dashboard', '/simulation', '/analytics', '/rules', '/settings', '/report', '/login']
        for p in pages:
            res = self.client.get(p)
            self.assertEqual(res.status_code, 200, f"Page {p} failed")

        # Test valid login
        res_login = self.client.post('/login', data={'username': 'admin', 'password': 'admin123'}, follow_redirects=True)
        self.assertEqual(res_login.status_code, 200)

        # Test logout
        res_logout = self.client.get('/logout', follow_redirects=True)
        self.assertEqual(res_logout.status_code, 200)

if __name__ == '__main__':
    unittest.main()
