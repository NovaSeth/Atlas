#!/usr/bin/env python3
"""
"Cannot measure" must never read as "clean", the session sensor must not suppress or
repeat wrongly, and the escalation log is a machine log in English. Nothing here touches
a real state directory, real sudo, certbot, journalctl or mail.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
ATLAS = HERE.parent
ROOT = ATLAS.parent
sys.path.insert(0, str(ATLAS))
sys.path.insert(0, str(HERE))
from test_iteration1 import Collector, make_patrol, patrol, write_atomic  # noqa: E402

import atlas  # noqa: E402

HEALTHY_CERT = "Certificate Name: ok.example\n    Expiry Date: 2027-01-01 00:00:00+00:00 (VALID: 60 days)\n"
EXPIRED_CERT = "Certificate Name: expired.example\n    Expiry Date: 2026-10-01 00:00:00+00:00 (INVALID: EXPIRED)\n"


def snap(certs, cert_error=""):
    return {"certs": certs, "vitals": {"disk_used_pct": "41%", "mem_available_mb": "3700", "certs_error": cert_error}}


class TestCerts(unittest.TestCase):
    def measure(self, rc, out):
        with (
            mock.patch.object(atlas, "run_checked", return_value=(rc, out, "")),
            mock.patch.object(atlas, "have", return_value=True),
        ):
            return atlas.certs_measure()

    def test_certbot_not_installed_is_no_certs_not_unknown(self):
        with mock.patch.object(atlas, "have", return_value=False):
            self.assertEqual(atlas.certs_measure(), ({}, ""))

    def test_r1_failing_certbot_is_unknown(self):
        res, err = self.measure(1, "")
        self.assertTrue(err)
        a, n = atlas.thresholds(snap(res, err), 1)
        self.assertTrue(n and not a)

    def test_r1_certbot_timeout_is_unknown(self):
        res, err = self.measure(None, "__ERROR__ timeout")
        self.assertTrue(err)

    def sites(self, *files):
        d = Path(tempfile.mkdtemp(prefix="sites-"))
        self.addCleanup(shutil.rmtree, d, True)
        for f in files:
            (d / f).write_text("x\n")
        return str(d)

    def test_r1_failing_vhost_read_is_unknown(self):
        with mock.patch.object(atlas, "run_checked", return_value=(1, "", "sudo: a password is required")):
            self.assertIsNone(atlas.ssl_vhost_count(self.sites("a.conf")))
        a, n = atlas.thresholds(snap({"ok.example": {"days": 60}}), None)
        self.assertTrue(n and not a)

    def test_r1_no_ssl_vhosts_is_zero_not_unknown(self):
        with mock.patch.object(atlas, "run_checked", return_value=(0, "<VirtualHost *:80>\n", "")):
            self.assertEqual(atlas.ssl_vhost_count(self.sites("a.conf")), 0)
        with mock.patch.object(atlas, "run_checked", return_value=(0, "<VirtualHost *:443>\n  SSLEngine on\n", "")):
            self.assertEqual(atlas.ssl_vhost_count(self.sites("a.conf", "b.conf")), 2)

    def test_r1_no_apache_is_zero(self):
        self.assertEqual(atlas.ssl_vhost_count(str(Path(tempfile.gettempdir()) / "no-such-sites-dir")), 0)

    def test_r1_healthy_is_clean(self):
        res, err = self.measure(0, HEALTHY_CERT)
        self.assertEqual(err, "")
        self.assertEqual(atlas.thresholds(snap(res, err), 1), ([], []))

    def test_r2_expired_cert_alarms_by_name(self):
        res, err = self.measure(0, HEALTHY_CERT + EXPIRED_CERT)
        self.assertEqual(err, "")
        a, n = atlas.thresholds(snap(res, err), 2)
        self.assertEqual(n, [])
        self.assertTrue(any("expired.example" in ln for ln in a), a)
        self.assertFalse(any("ok.example" in ln for ln in a), a)

    def test_r2_unparseable_expiry_is_unknown_not_dropped(self):
        res, err = self.measure(0, HEALTHY_CERT + "Certificate Name: weird.example\n    Expiry Date: ???\n")
        self.assertIn("weird.example", res)
        a, n = atlas.thresholds(snap(res, err), 2)
        self.assertTrue(any("weird.example" in ln for ln in n), n)

    def test_r2_cert_without_expiry_line_is_unknown(self):
        res, err = self.measure(0, "Certificate Name: noexp.example\n    Domains: a.b\n")
        self.assertIn("noexp.example", res)
        a, n = atlas.thresholds(snap(res, err), 1)
        self.assertTrue(any("noexp.example" in ln for ln in n), n)


class TestSilentFailures(unittest.TestCase):
    TIMERS = "Thu 2026-10-22 10:00 CEST 1h left x ago certbot.timer certbot.service\n"

    def fake(self, journal_rc, journal_out, timers_rc=0):
        def f(cmd, timeout=25):
            if "list-timers" in cmd:
                return timers_rc, self.TIMERS if timers_rc == 0 else "", ""
            return journal_rc, journal_out, "" if journal_rc == 0 else "journalctl: boom"

        return f

    def test_r3_journal_failure_is_unknown(self):
        with mock.patch.object(atlas, "run_checked", side_effect=self.fake(1, "")):
            res, unknown = atlas.silent_failures_checked()
        self.assertEqual(res, {})
        self.assertIn("certbot.service", unknown)

    def test_r3_failed_last_line_is_event(self):
        j = "2026-10-20T03:00:00+0200 h systemd[1]: certbot.service: Failed with result 'exit-code'.\n"
        with mock.patch.object(atlas, "run_checked", side_effect=self.fake(0, j)):
            res, unknown = atlas.silent_failures_checked()
        self.assertIn("certbot.service", res)
        self.assertEqual(unknown, {})

    def test_r3_success_last_line_is_clean(self):
        j = (
            "2026-10-19T03:00:00+0200 h systemd[1]: certbot.service: Failed with result 'exit-code'.\n"
            "2026-10-20T03:00:00+0200 h systemd[1]: Finished certbot.service.\n"
        )
        with mock.patch.object(atlas, "run_checked", side_effect=self.fake(0, j)):
            self.assertEqual(atlas.silent_failures_checked(), ({}, {}))

    def test_r3_timers_listing_failure_is_unknown(self):
        with mock.patch.object(atlas, "run_checked", side_effect=self.fake(0, "", timers_rc=1)):
            res, unknown = atlas.silent_failures_checked()
        self.assertTrue(unknown)

    def test_r3_silent_cmd_exit_codes(self):
        for vit, rc in (
            ({"silent_failures": {"u": "x"}, "silent_unknown": {}}, 1),
            ({"silent_failures": {}, "silent_unknown": {"u": "journal"}}, 2),
            ({"silent_failures": {}, "silent_unknown": {}}, 0),
        ):
            d = Path(tempfile.mkdtemp())
            self.addCleanup(shutil.rmtree, d, True)
            (d / "current.json").write_text(json.dumps({"vitals": vit}))
            with (
                mock.patch.object(atlas, "CURRENT", str(d / "current.json")),
                mock.patch.object(sys, "argv", ["atlas.py", "silent"]),
                mock.patch("sys.stdout"),
                mock.patch("sys.stderr"),
            ):
                self.assertEqual(atlas.main(), rc, vit)


class TestPatrolSilent(unittest.TestCase):
    def setUp(self):
        self.d = make_patrol()
        self.addCleanup(shutil.rmtree, self.d, True)

    def test_r4_silent_exit_2_is_unknown(self):
        r = patrol(self.d, STUB_SILENT_RC=2, STUB_SILENT_ERR="journal unreadable")
        self.assertEqual(r.returncode, 1)
        txt = (self.d / "ALERT").read_text()
        self.assertIn("UNKNOWN: silent-failures", txt)
        self.assertIn("journal unreadable", txt)
        self.assertIn("unknown", (self.d / "heartbeat.log").read_text())

    def test_r4_silent_timeout_is_unknown(self):
        r = patrol(self.d, STUB_SILENT_SLEEP=5, PATROL_T_SILENT=1)
        self.assertEqual(r.returncode, 1)
        self.assertIn("UNKNOWN: silent-failures", (self.d / "ALERT").read_text())

    def test_r4_silent_exit_1_is_alarm_section(self):
        patrol(self.d, STUB_SILENT_OUT="  certbot.service: padl", STUB_SILENT_RC=1)
        self.assertIn("SILENT FAILURES", (self.d / "ALERT").read_text())
        self.assertIn("alarm (silent-failures)", (self.d / "heartbeat.log").read_text())

    def test_r4_reverse_control_clean(self):
        r = patrol(self.d, STUB_SILENT_RC=0)
        self.assertEqual(r.returncode, 0)
        self.assertFalse((self.d / "ALERT").exists())
        self.assertTrue((self.d / "heartbeat.log").read_text().strip().endswith(" ok"))


class SensorCase(unittest.TestCase):
    def start(self):
        self.d = Path(tempfile.mkdtemp(prefix="sensor-r2-"))
        self.addCleanup(shutil.rmtree, self.d, True)
        env = dict(
            os.environ,
            SENTINEL_ATLAS=str(self.d),
            SENTINEL_ESCALATION_LOG=str(self.d / "esc.log"),
            SENTINEL_INTERVAL="0.2",
        )
        p = subprocess.Popen(
            ["bash", str(ROOT / "sentinel" / "session-sensor.sh")], env=env, stdout=subprocess.PIPE, text=True
        )
        self.addCleanup(p.kill)
        return Collector(p)

    @staticmethod
    def wait():
        time.sleep(0.9)


class TestSessionSensorR2(SensorCase):
    def test_r5_old_ack_does_not_suppress_new_alert(self):
        k = self.start()
        write_atomic(self.d / "ALERT", "2026-10-22T10:00:00Z\nATLAS: A\n")
        os.utime(self.d / "ALERT", (1000, 1000))
        (self.d / "ALERT.acked").touch()
        os.utime(self.d / "ALERT.acked", (2000, 2000))
        self.wait()
        self.assertEqual(k.lines, [], k.lines)  # ack newer than ALERT: silent
        write_atomic(self.d / "ALERT", "2026-10-22T11:00:00Z\nATLAS: B\n")  # mtime = now > ack
        self.wait()
        self.assertEqual(len(k.lines), 1, k.lines)
        self.assertIn("ATLAS: B", k.lines[0])

    def test_r6_escalation_timestamp_does_not_rewake(self):
        k = self.start()
        log = self.d / "esc.log"
        log.write_text("2026-10-22T10:00:00+02:00 PROBLEM: patrol-silent\n")
        self.wait()
        with open(log, "a") as f:
            f.write("2026-10-22T10:10:00+02:00 PROBLEM: patrol-silent\n")
        self.wait()
        self.assertEqual(len(k.lines), 1, k.lines)
        with open(log, "a") as f:
            f.write("2026-10-22T10:20:00+02:00 PROBLEM: resident-dead\n")
        self.wait()
        self.assertEqual(len(k.lines), 2, k.lines)
        with open(log, "a") as f:
            f.write("2026-10-22T10:30:00+02:00 ok (patrol alive)\n")
        self.wait()
        self.assertEqual(len(k.lines), 3, k.lines)
        self.assertIn("clear", k.lines[-1])
        self.assertNotIn("ESCALATION", k.lines[-1])

    def test_r7_change_after_300_bytes_is_detected(self):
        k = self.start()
        head = "x" * 400
        write_atomic(self.d / "ALERT", f"2026-10-22T10:00:00Z\n{head}A\n")
        self.wait()
        self.assertEqual(len(k.lines), 1, k.lines)
        write_atomic(self.d / "ALERT", f"2026-10-22T10:00:00Z\n{head}B\n")
        self.wait()
        self.assertEqual(len(k.lines), 2, k.lines)
        self.assertLessEqual(len(k.lines[1]), 400)  # only the displayed text is truncated


class TestEscalationLogR8(unittest.TestCase):
    def test_r8_log_has_english_kind(self):
        d = Path(tempfile.mkdtemp(prefix="esc-r2-"))
        self.addCleanup(shutil.rmtree, d, True)
        atl, state, bindir = d / "atlas", d / "state", d / "bin"
        atl.mkdir()
        bindir.mkdir()
        hb = atl / "heartbeat.log"
        hb.write_text("old\n")
        os.utime(hb, (1000000000, 1000000000))
        for n, body in (("mail", "cat >/dev/null"), ("screen", "exit 1"), ("systemctl", "exit 3")):
            (bindir / n).write_text(f"#!/usr/bin/env bash\n{body}\n")
            os.chmod(bindir / n, 0o755)
        env = dict(
            os.environ,
            PATH=f"{bindir}:{os.environ['PATH']}",
            SENTINEL_ATLAS=str(atl),
            SENTINEL_STATE=str(state),
            SENTINEL_EMAIL="ops@localhost",
            SENTINEL_RESIDENT_SCREEN="agent",
            SENTINEL_RESIDENT_UNIT="agent.service",
            SENTINEL_STREAM_HEARTBEAT=str(d / "stream.heartbeat"),
        )  # absent = stream-silent
        subprocess.run(
            ["bash", str(ROOT / "sentinel" / "escalation.sh")], env=env, capture_output=True, text=True, timeout=60
        )
        log = (state / "escalation.log").read_text()
        self.assertIn("PROBLEM: patrol-silent", log)
        self.assertIn("resident-dead", log)
        self.assertNotIn("PATROL MILCZY", log)


if __name__ == "__main__":
    unittest.main()
