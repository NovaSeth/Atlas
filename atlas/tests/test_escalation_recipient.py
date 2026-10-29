"""Escalation: a working notify command counts as a recipient; the alarm mail does not misdescribe the problem.

Seen in the clean-VM acceptance run: with only SENTINEL_NOTIFY_CMD configured, escalation delivered through it but still
logged "no recipient configured" and exited 2, so the unit failed every 10 minutes and the patrol raised SILENT FAILURES.
And an unacknowledged alarm went out under the subject "silence in the supervision layer".
Everything runs in a temp dir with stubs: no real mail, no real state.
"""

import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ESC = ROOT / "sentinel" / "escalation.sh"


class EscalationRecipient(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="esc-recipient-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.atlas, self.state, self.bin = self.tmp / "atlas", self.tmp / "state", self.tmp / "bin"
        for d in (self.atlas, self.state, self.bin, self.atlas / "pauses"):
            d.mkdir()
        self.mails = self.tmp / "mails.txt"
        self.calls = self.tmp / "notify.calls"
        stubs = {
            "mail": 'echo "MAIL $*" >> %s; cat >/dev/null' % self.mails,
            "notify-stub": 'printf "%%s\\n" "$1" >> %s' % self.calls,
            "screen": "exit 0",
            "systemctl": "exit 0",
        }
        for n, body in stubs.items():
            (self.bin / n).write_text("#!/bin/bash\n%s\n" % body)
            (self.bin / n).chmod(0o755)
        (self.atlas / "heartbeat.log").write_text("x ok\n")
        self.hb = self.tmp / "stream.heartbeat"
        self.hb.touch()

    def run_esc(self, email="", notify=""):
        env = dict(
            os.environ,
            SENTINEL_ATLAS=str(self.atlas),
            SENTINEL_STATE=str(self.state),
            SENTINEL_EMAIL=email,
            SENTINEL_NOTIFY_CMD=notify,
            SENTINEL_LANG="en",
            SENTINEL_RESIDENT_UNIT="",
            SENTINEL_RESIDENT_SCREEN="",
            SENTINEL_STREAM_HEARTBEAT=str(self.hb),
            PATH="%s:%s" % (self.bin, os.environ["PATH"]),
        )
        r = subprocess.run(["bash", str(ESC)], env=env, capture_output=True, text=True, timeout=60)
        log = (self.state / "escalation.log").read_text() if (self.state / "escalation.log").exists() else ""
        return r.returncode, log.strip().splitlines()[-1] if log.strip() else ""

    def old_unacked_alert(self):
        a = self.atlas / "ALERT"
        a.write_text("2026-01-01T00:00:00Z\n== ATLAS DRIFT ==\nsomething changed\n")
        old = time.time() - 3 * 3600
        os.utime(a, (old, old))
        (self.atlas / "ALERT.since").write_text("")
        os.utime(self.atlas / "ALERT.since", (old, old))

    def test_notify_only_is_a_recipient_and_healthy_run_is_ok(self):
        rc, last = self.run_esc(notify=str(self.bin / "notify-stub"))
        self.assertEqual(rc, 0, last)
        self.assertIn("ok (", last)
        self.assertNotIn("no recipient", last)

    def test_neither_channel_is_unknown(self):
        rc, last = self.run_esc()
        self.assertEqual(rc, 2, last)
        self.assertIn("no recipient configured", last)

    def test_notify_only_delivers_a_problem_and_reports_problem(self):
        self.old_unacked_alert()
        rc, last = self.run_esc(notify=str(self.bin / "notify-stub"))
        self.assertEqual(rc, 1, last)
        self.assertIn("PROBLEM: alert-unacked", last)
        subjects = self.calls.read_text().splitlines()
        self.assertEqual(len(subjects), 1)
        self.assertFalse(self.mails.exists(), "no mail without SENTINEL_EMAIL")

    def test_alarm_subject_does_not_call_an_unacked_alert_silence(self):
        self.old_unacked_alert()
        self.run_esc(notify=str(self.bin / "notify-stub"))
        subject = self.calls.read_text().splitlines()[0].lower()
        self.assertIn("alert-unacked", subject)
        self.assertNotIn("silence", subject)

    def test_throttle_line_does_not_claim_a_mail_when_only_notify_was_used(self):
        self.old_unacked_alert()
        self.run_esc(notify=str(self.bin / "notify-stub"))
        self.run_esc(notify=str(self.bin / "notify-stub"))
        log = (self.state / "escalation.log").read_text()
        self.assertIn("quiet: alert-unacked", log)
        self.assertNotIn("mail sent <", log)


if __name__ == "__main__":
    unittest.main()
