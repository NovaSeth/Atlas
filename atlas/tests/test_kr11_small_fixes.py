"""Escalation: empty PTEXT under set -u; HTTP probes skip reserved TLD server names."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ESC = ROOT / "sentinel" / "escalation.sh"
PROBES = ROOT / "atlas" / "sensors" / "http_probes.py"


class TestEscalationHealthyNoUnbound(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="esc-kr11-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.atlas, self.state, self.bin = self.tmp / "atlas", self.tmp / "state", self.tmp / "bin"
        for d in (self.atlas, self.bin):
            d.mkdir()
        self.mails = self.tmp / "mails.txt"
        for n, body in (("mail", 'echo "MAIL $*" >> %s; cat >/dev/null' % self.mails),
                        ("screen", 'echo "1.agent (Attached)"'), ("systemctl", "exit 0")):
            (self.bin / n).write_text("#!/bin/bash\n%s\n" % body)
            (self.bin / n).chmod(0o755)
        (self.atlas / "heartbeat.log").write_text("x ok\n")
        self.hb = self.tmp / "stream.heartbeat"

    def run_esc(self):
        env = dict(os.environ, SENTINEL_ATLAS=str(self.atlas), SENTINEL_STATE=str(self.state),
                   SENTINEL_EMAIL="nobody@example.com", SENTINEL_RESIDENT_SCREEN="agent", SENTINEL_RESIDENT_UNIT="agent.service",
                   SENTINEL_STREAM_HEARTBEAT=str(self.hb), PATH="%s:%s" % (self.bin, os.environ["PATH"]))
        return subprocess.run(["bash", str(ESC)], env=env, capture_output=True, text=True, timeout=60)

    def test_healthy_run_has_no_unbound_variable_and_logs_ok(self):
        self.hb.touch()
        r = self.run_esc()
        self.assertNotIn("unbound variable", r.stderr)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(" ok (", (self.state / "escalation.log").read_text())

    def test_problem_run_still_mails_reverse_control(self):
        r = self.run_esc()  # no stream heartbeat -> problem
        self.assertNotIn("unbound variable", r.stderr)
        self.assertEqual(r.returncode, 1)
        self.assertEqual(self.mails.read_text().count("MAIL"), 1)


class TestHttpProbesReservedTlds(unittest.TestCase):
    def test_reserved_names_are_not_probed(self):
        tmp = Path(tempfile.mkdtemp(prefix="http-kr11-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        sites = tmp / "sites"
        sites.mkdir()
        names = ["default.invalid", "x.test", "y.example", "z.localhost", "real.example.net"]
        (sites / "a.conf").write_text("".join(
            "<VirtualHost *:443>\n    ServerName %s\n</VirtualHost>\n" % n for n in names))
        exp = tmp / "expected.json"
        exp.write_text(json.dumps({"real.example.net": [200]}))
        log = tmp / "fetched.txt"
        (tmp / "fetch.py").write_text(
            "import sys\nopen(%r, 'a').write(sys.argv[1] + '\\n')\nprint(200)\n" % str(log))
        env = dict(os.environ, HTTP_SITES_DIR=str(sites), HTTP_EXPECTED=str(exp),
                   HTTP_FETCH_CMD="python3 %s" % (tmp / "fetch.py"),
                   HTTP_ARTICLE_CMD="echo https://real.example.net/post/")
        r = subprocess.run([sys.executable, str(PROBES)], env=env, capture_output=True, text=True, timeout=60)
        fetched = log.read_text().split()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("https://real.example.net/", fetched)
        for n in names[:-1]:
            self.assertNotIn("https://%s/" % n, fetched)


if __name__ == "__main__":
    unittest.main()
