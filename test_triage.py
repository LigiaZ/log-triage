"""Run with: python -m unittest test_triage.py"""

import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

import triage

SAMPLES = Path(__file__).parent / "samples"


class ParseLine(unittest.TestCase):
    def test_text_line_with_bracketed_service(self):
        e = triage.parse_line("2026-03-14T09:12:03.120Z ERROR [payments-svc] Pool exhausted")
        self.assertEqual((e.level, e.service, e.message), ("ERROR", "payments-svc", "Pool exhausted"))
        self.assertEqual(e.ts, datetime(2026, 3, 14, 9, 12, 3, 120000, tzinfo=timezone.utc))

    def test_text_line_with_colon_service_and_comma_millis(self):
        e = triage.parse_line("2026-03-14 09:12:03,5 [WARNING] checkout-svc: Slow query")
        self.assertEqual((e.level, e.service, e.message), ("WARN", "checkout-svc", "Slow query"))

    def test_text_line_without_service(self):
        e = triage.parse_line("2026-03-14T09:12:03+0200 info Timeout after 30s")
        self.assertEqual((e.service, e.message), ("-", "Timeout after 30s"))
        self.assertEqual(e.ts.utcoffset().total_seconds(), 7200)

    def test_json_line(self):
        line = json.dumps({"@timestamp": "2026-05-03T00:00:02Z", "level": "error",
                           "service": "auth-svc", "message": "certificate has expired"})
        e = triage.parse_line(line)
        self.assertEqual((e.level, e.service), ("ERROR", "auth-svc"))

    def test_json_line_with_nested_keys(self):
        line = json.dumps({"time": "2026-05-03T00:00:02Z", "log": {"level": "warn"},
                           "service": {"name": "api"}, "msg": "slow"})
        e = triage.parse_line(line)
        self.assertEqual((e.level, e.service, e.message), ("WARN", "api", "slow"))

    def test_unparseable_lines_are_skipped(self):
        for line in ["", "hello world", "{not json", "2026-03-14T09:12:03Z SHOUTING msg"]:
            self.assertIsNone(triage.parse_line(line), line)


class Normalize(unittest.TestCase):
    def test_variable_parts_collapse_to_one_signature(self):
        a = triage.normalize("Timeout after 3012ms for order 8812 from 10.0.3.4:8080")
        b = triage.normalize("Timeout after 2950ms for order 1203 from 10.2.9.1:443")
        self.assertEqual(a, b)
        self.assertEqual(a, "Timeout after <n> for order <n> from <ip>")

    def test_ids_and_timestamps_are_masked(self):
        msg = 'user a.b@example.com req 3f2a9c1e-77b0-4c1d-9a4e-2b1f0c9d8e7a at 2026-05-03T00:00:02Z said "hi"'
        self.assertEqual(triage.normalize(msg), "user <email> req <uuid> at <ts> said <str>")

    def test_words_containing_digits_are_kept(self):
        self.assertEqual(triage.normalize("Upstream sha256 v2 failed"), "Upstream sha256 v2 failed")


class DetectSpikes(unittest.TestCase):
    def test_flat_background_has_no_spikes(self):
        self.assertEqual(triage.detect_spikes([1, 0, 2, 1, 1, 0, 2, 1]), [])

    def test_clear_spike_is_found(self):
        self.assertEqual(triage.detect_spikes([1, 0, 2, 1, 30, 42, 1, 0, 1]), [4, 5])

    def test_long_outage_does_not_hide_itself(self):
        # A third of the window is broken; a mean-based baseline would swallow it.
        counts = [1] * 20 + [25] * 10
        self.assertEqual(triage.detect_spikes(counts), list(range(20, 30)))

    def test_tiny_counts_are_ignored(self):
        self.assertEqual(triage.detect_spikes([0, 0, 0, 0, 2, 0, 0]), [])


class EndToEnd(unittest.TestCase):
    def test_checkout_outage_points_at_the_deploy_and_the_pool(self):
        report = triage.analyze((SAMPLES / "checkout-outage.log").read_text().splitlines())
        self.assertEqual(report.lines_parsed, report.lines_total)
        self.assertEqual(len(report.incidents), 1)
        inc = report.incidents[0]
        self.assertEqual(inc["top"][0][0].pattern, "DB connection pool exhausted (active=<n>/<n>, waiting=<n>)")
        self.assertIn("version=2.14.0", inc["changes_before"][0].message)
        self.assertIn("Connection pool nearing capacity", inc["earliest_new_signal"].example)

    def test_cert_expiry_finds_the_x509_error(self):
        report = triage.analyze((SAMPLES / "auth-cert-expiry.jsonl").read_text().splitlines())
        self.assertEqual(len(report.incidents), 1)
        self.assertIn("x509", report.incidents[0]["earliest_new_signal"].example)

    def test_browser_entry_point_returns_json(self):
        out = json.loads(triage.analyze_text((SAMPLES / "checkout-outage.log").read_text()))
        self.assertEqual(len(out["incidents"]), 1)
        self.assertIn("Incident 1", out["summary"])

    def test_empty_input(self):
        report = triage.analyze([])
        self.assertEqual(report.lines_parsed, 0)
        self.assertIn("No log lines", triage.summarize(report))


if __name__ == "__main__":
    unittest.main()
