import os
import sys
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import detector  # noqa: E402

T0 = datetime(2026, 11, 9, 1, 0, 0)


def ev(sec, eid, user="", ip="", ltype="", subject="", computer="PC1"):
    return {"time": T0 + timedelta(seconds=sec), "id": eid, "computer": computer,
            "user": user, "subject": subject, "ip": ip, "ltype": ltype}


class DetectorTests(unittest.TestCase):
    def test_parse_time_handles_powershell_format(self):
        t = detector.parse_time("2026-11-09T01:02:03.1234567+06:00")
        self.assertEqual(t, datetime(2026, 11, 8, 19, 2, 3, 123456))

    def test_bruteforce_below_threshold_is_quiet(self):
        events = [ev(i * 10, 4625, "bob", "203.0.113.9") for i in range(4)]
        self.assertEqual(detector.detect_bruteforce(events), [])

    def test_bruteforce_detected(self):
        events = [ev(i * 10, 4625, "bob", "203.0.113.9") for i in range(6)]
        f = detector.detect_bruteforce(events)
        self.assertEqual([x["rule"] for x in f], ["WIN-001"])

    def test_failures_spread_over_time_do_not_alert(self):
        events = [ev(i * 600, 4625, "bob", "203.0.113.9") for i in range(6)]  # 10 min apart
        self.assertEqual(detector.detect_bruteforce(events), [])

    def test_spray_detected(self):
        users = ["a", "b", "c", "d", "e", "f"]
        events = [ev(i * 5, 4625, u, "198.51.100.7") for i, u in enumerate(users)]
        self.assertEqual(detector.detect_bruteforce(events)[0]["rule"], "WIN-002")

    def test_success_after_failures_is_high(self):
        events = [ev(i * 5, 4625, "admin", "203.0.113.45", "3") for i in range(6)]
        events.append(ev(60, 4624, "admin", "203.0.113.45", "10"))
        rules = {x["rule"]: x["severity"] for x in detector.detect_bruteforce(events)}
        self.assertEqual(rules["WIN-003"], "HIGH")

    def test_success_from_other_ip_not_linked(self):
        events = [ev(i * 5, 4625, "admin", "203.0.113.45", "3") for i in range(6)]
        events.append(ev(60, 4624, "admin", "192.0.2.10", "2"))
        self.assertNotIn("WIN-003", [x["rule"] for x in detector.detect_bruteforce(events)])

    def test_new_account_then_admin_group(self):
        events = [ev(0, 4720, "svc2", subject="root"), ev(120, 4732, "Administrators", subject="root")]
        f = detector.detect_privilege_changes(events)
        self.assertEqual(len(f), 1)
        self.assertIn("T1136.001", f[0]["attack"])

    def test_non_admin_group_ignored(self):
        self.assertEqual(detector.detect_privilege_changes([ev(0, 4732, "Backup Operators")]), [])

    def test_log_cleared(self):
        f = detector.detect_log_clearing([ev(0, 1102, subject="root")])
        self.assertEqual(f[0]["severity"], "HIGH")

    def test_end_to_end_on_sample_data(self):
        import subprocess
        import tempfile
        here = os.path.join(os.path.dirname(__file__), "..")
        with tempfile.TemporaryDirectory() as d:
            subprocess.check_call([sys.executable, os.path.join(here, "make_sample_events.py")], cwd=d)
            events = detector.load_events(os.path.join(d, "events.csv"))
            rules = [f["rule"] for f in detector.run_all(events)]
        for expected in ("WIN-001", "WIN-002", "WIN-003", "WIN-004", "WIN-005", "WIN-006"):
            self.assertIn(expected, rules)


if __name__ == "__main__":
    unittest.main()
