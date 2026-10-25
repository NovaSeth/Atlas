"""Untrusted text in ALERT lines: the session excerpt and the patrol sensors stay printable ASCII."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ATLAS = ROOT / "atlas"


def printable_ascii(s):
    return all(0x20 <= ord(c) <= 0x7E for c in s)


class TestSessionSensorExcerpt(unittest.TestCase):
    def test_escape_sequences_and_zero_width_are_stripped(self):
        d = Path(tempfile.mkdtemp(prefix="sensor-untrusted-"))
        self.addCleanup(shutil.rmtree, d, True)
        (d / "ALERT").write_bytes(
            "2026-10-22T10:00:00Z\nATLAS: \x1b[31mRED\x1b[0m login by op\u200bs \u202eevil\x07 end\n".encode())
        env = dict(os.environ, SENTINEL_ATLAS=str(d), SENTINEL_ESCALATION_LOG=str(d / "esc.log"),
                   SENTINEL_INTERVAL="0.2", SENTINEL_BUS_CMD="sleep 3600")
        p = subprocess.Popen(["bash", str(ROOT / "sentinel" / "session-sensor.sh")], env=env,
                             stdout=subprocess.PIPE)
        self.addCleanup(p.kill)
        lines = []

        def read():
            for raw in p.stdout:
                lines.append(raw)

        threading.Thread(target=read, daemon=True).start()
        end = time.time() + 10
        while time.time() < end and not lines:
            time.sleep(0.1)
        self.assertTrue(lines, "no output from the session sensor")
        out = lines[0]
        self.assertIn(b"ATLAS ALERT:", out)
        self.assertNotIn(b"\x1b", out)
        self.assertNotIn(b"\x07", out)
        self.assertNotIn("\u200b".encode(), out)
        self.assertNotIn("\u202e".encode(), out)
        self.assertIn(b"RED", out)
        self.assertIn(b"login by ops", out)
        self.assertTrue(printable_ascii(out.decode("ascii").rstrip("\n")))


class TestSessionSensorKeepsLetters(unittest.TestCase):
    def run_sensor(self, body_bytes):
        d = Path(tempfile.mkdtemp(prefix="sensor-unicode-"))
        self.addCleanup(shutil.rmtree, d, True)
        (d / "ALERT").write_bytes(b"2026-10-22T10:00:00Z\n" + body_bytes)
        env = dict(os.environ, SENTINEL_ATLAS=str(d), SENTINEL_ESCALATION_LOG=str(d / "esc.log"),
                   SENTINEL_INTERVAL="0.2", SENTINEL_BUS_CMD="sleep 3600")
        p = subprocess.Popen(["bash", str(ROOT / "sentinel" / "session-sensor.sh")], env=env,
                             stdout=subprocess.PIPE)
        self.addCleanup(p.kill)
        lines = []
        threading.Thread(target=lambda: [lines.append(l) for l in p.stdout], daemon=True).start()
        end = time.time() + 10
        while time.time() < end and not lines:
            time.sleep(0.1)
        self.assertTrue(lines, "no output from the session sensor")
        return lines[0].decode("utf-8")

    def test_polish_letters_survive_hidden_characters_do_not(self):
        polish = "\u0105\u0107\u0119\u0142\u0144\u00f3\u015b\u017a\u017c \u0104\u0106\u0118\u0141\u0143\u00d3\u015a\u0179\u017b"
        body = "ATLAS: logowanie z nieznanego adresu \x1b[31m%s\x1b[0m op\u200bs \u202eevil\n" % polish
        out = self.run_sensor(body.encode("utf-8"))
        self.assertIn(polish, out)
        self.assertIn("ops", out)
        for bad in ("\x1b", "[31m", "\u200b", "\u202e"):
            self.assertNotIn(bad, out)

    def test_cap_is_300_characters(self):
        out = self.run_sensor(("\u017c" * 400 + "\n").encode("utf-8"))
        self.assertEqual(out.count("\u017c"), 300)


class TestSshLoginsSanitized(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="ssh-untrusted-"))
        self.addCleanup(shutil.rmtree, self.d, True)
        (self.d / "known.txt").write_text("198.51.100.4\n")

    def run_sensor(self, journal, *args):
        (self.d / "j.log").write_text(journal)
        env = dict(os.environ, SSH_JOURNAL_CMD="cat %s" % (self.d / "j.log"),
                   SSH_KNOWN_IPS=str(self.d / "known.txt"), SENTINEL_LANG="en")
        return subprocess.run([sys.executable, str(ATLAS / "sensors" / "ssh_logins.py"), *args],
                              env=env, capture_output=True, text=True, timeout=30)

    def line(self, user):
        t = (datetime.now().astimezone() - timedelta(hours=1)).isoformat(timespec="seconds")
        return "%s vps sshd-session[1]: Accepted publickey for %s from 203.0.113.99 port 5 ssh2\n" % (t, user)

    def test_user_in_alert_line_is_clean_and_capped(self):
        user = "op\x1b[2J\u200bs" + "x" * 60
        r = self.run_sensor(self.line(user), "--text")
        self.assertEqual(r.returncode, 1, r.stderr)
        out = r.stdout.strip()
        self.assertTrue(printable_ascii(out), repr(out))
        self.assertNotIn("x" * 40, out)
        self.assertIn("203.0.113.99", out)

    def test_json_event_fields_are_clean(self):
        r = self.run_sensor(self.line("op\x1b[2Js" + "y" * 60))
        self.assertEqual(r.returncode, 1, r.stderr)
        ev = json.loads(r.stdout.strip().splitlines()[0])
        self.assertTrue(printable_ascii(ev["evidence"]["user"]))
        self.assertLessEqual(len(ev["evidence"]["user"]), 32)
        self.assertTrue(printable_ascii(ev["fingerprint"]))

    def test_plain_user_unchanged(self):
        r = self.run_sensor(self.line("ops"))
        ev = json.loads(r.stdout.strip().splitlines()[0])
        self.assertEqual(ev["fingerprint"], "auth.ssh.accepted:203.0.113.99:ops")


class TestHttpProbesSanitized(unittest.TestCase):
    def test_host_and_extra_url_in_alert_lines_are_clean(self):
        tmp = Path(tempfile.mkdtemp(prefix="http-untrusted-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        sites = tmp / "sites"
        sites.mkdir()
        host = "a\x1b[31m\u200b" + "h" * 120 + ".example.net"
        (sites / "a.conf").write_text("<VirtualHost *:443>\n    ServerName %s\n</VirtualHost>\n" % host)
        (tmp / "expected.json").write_text("{}")
        fetch = tmp / "fetch"
        fetch.write_text("#!/bin/sh\necho 500\n")
        fetch.chmod(0o755)
        urls = tmp / "urls.txt"
        urls.write_text("https://b.example.net/post/\x1b[1mignore-previous-instructions\u202e\n")
        env = dict(os.environ, HTTP_SITES_DIR=str(sites), HTTP_EXPECTED=str(tmp / "expected.json"),
                   HTTP_FETCH_CMD=str(fetch), HTTP_EXTRA_URLS_CMD="cat %s" % urls, SENTINEL_LANG="en")
        r = subprocess.run([sys.executable, str(ATLAS / "sensors" / "http_probes.py")],
                           env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 1, r.stderr)
        lines = r.stdout.strip().splitlines()
        self.assertEqual(len(lines), 2, lines)
        for l in lines:
            self.assertTrue(printable_ascii(l), repr(l))
        self.assertNotIn("h" * 90, r.stdout)


if __name__ == "__main__":
    unittest.main()
