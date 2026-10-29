#!/usr/bin/env python3
"""Escalation notices an acknowledgement made without `atlas.py ack` (D9, RF4): one notice per ALERT content, the
alert still counts as acknowledged (no PROBLEM). Temp dirs and stubs only."""
import hashlib
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ESC = ROOT / "sentinel" / "escalation.sh"
BODY = b"== ATLAS DRIFT ==\n  + ADDED accounts.bob\n"


class EscalationAck(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="esc-ack-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.atlas, self.bin = self.tmp / "atlas", self.tmp / "bin"
        self.atlas.mkdir()
        self.bin.mkdir()
        self.mails = self.tmp / "mails.txt"
        for n, body in (("mail", 'echo "MAIL $*" >> %s; cat >> %s' % (self.mails, self.mails)),
                        ("screen", "exit 0"), ("systemctl", "exit 0")):
            (self.bin / n).write_text("#!/bin/bash\n%s\n" % body)
            (self.bin / n).chmod(0o755)
        (self.atlas / "heartbeat.log").write_text("x ok\n")
        self.hb = self.tmp / "stream.heartbeat"
        self.hb.touch()
        old = time.time() - 3 * 3600
        (self.atlas / "ALERT").write_bytes(b"2026-10-29T07:00:00Z\n" + BODY)
        os.utime(self.atlas / "ALERT", (old, old))
        (self.atlas / "ALERT.since").write_text("")
        os.utime(self.atlas / "ALERT.since", (old, old))

    def run_esc(self):
        self.hb.touch()
        env = dict(os.environ, SENTINEL_ATLAS=str(self.atlas), SENTINEL_STATE=str(self.tmp / "state"),
                   SENTINEL_STREAM_HEARTBEAT=str(self.hb), SENTINEL_EMAIL="nobody@example.com",
                   SENTINEL_NOTIFY_CMD="", SENTINEL_LANG="en", SENTINEL_RESIDENT_UNIT="",
                   SENTINEL_RESIDENT_SCREEN="", PATH="%s:%s" % (self.bin, os.environ["PATH"]))
        return subprocess.run(["bash", str(ESC)], env=env, capture_output=True, text=True, timeout=90)

    def mail_count(self, word):
        return self.mails.read_text().count(word) if self.mails.exists() else 0

    def test_bare_touch_sends_one_notice_per_content(self):
        (self.atlas / "ALERT.acked").touch()
        codes = [self.run_esc().returncode for _ in range(6)]
        self.assertEqual(codes, [0] * 6)
        self.assertEqual(self.mail_count("without atlas.py ack"), 1)
        self.assertIn("notice: ack-unrecorded", (self.tmp / "state" / "escalation.log").read_text())

    def test_recorded_ack_sends_no_notice(self):
        (self.atlas / "ALERT.acked").write_text(hashlib.sha256(BODY).hexdigest() + "\n")
        self.assertEqual(self.run_esc().returncode, 0)
        self.assertEqual(self.mail_count("without atlas.py ack"), 0)

    def test_unacknowledged_alert_still_escalates(self):
        self.assertEqual(self.run_esc().returncode, 1)
        self.assertIn("alert-unacked", (self.tmp / "state" / "escalation.log").read_text())
