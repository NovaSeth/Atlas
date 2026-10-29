#!/usr/bin/env python3
"""install.sh first run: the escalation timer starts only after a first patrol, the resident unit key is not
written before the resident exists, the operator's SSH address and the current vhost answers are recorded.
Dry-run plans only; no root, no system change."""

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / "install.sh"


class FirstRun(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="atlas-install-first-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.state = self.tmp / "state"
        self.sites = self.tmp / "sites"

    def run_install(self, *args, ssh=None, sites=True):
        env = {k: v for k, v in os.environ.items() if k != "SSH_CONNECTION"}
        env["ATLAS_ETC_DIR"] = str(self.tmp / "etc")
        env["HTTP_SITES_DIR"] = str(self.sites)
        if ssh:
            env["SSH_CONNECTION"] = ssh
        shutil.rmtree(self.sites, True)
        if sites:
            self.sites.mkdir()
            (self.sites / "a.conf").write_text("<VirtualHost *:443>\n ServerName www.example.org\n</VirtualHost>\n")
        r = subprocess.run(
            ["bash", str(INSTALL), "--dry-run", "--code", "/opt/atlas", "--state", str(self.state)]
            + ["--user", "atlas-test-nobody", *args],
            capture_output=True,
            text=True,
            timeout=120,
            stdin=subprocess.DEVNULL,
            env=env,
        )
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return r

    def test_order_snapshot_patrol_escalation_timer(self):
        out = self.run_install("--yes").stdout
        snap = out.index("atlas.py snap")
        patrol = out.index("atlas/patrol.sh", snap)
        timer = out.index("enable --now sentinel-escalation.timer")
        self.assertLess(snap, patrol)
        self.assertLess(patrol, timer)
        self.assertRegex(out, r"\[dry-run\] .*enable --now sentinel-stream\.service\n")
        self.assertNotRegex(out[:snap], r"enable --now .*sentinel-escalation\.timer")

    def test_resident_unit_is_not_written_but_explained(self):
        out = self.run_install("--resident-user", "ops-test", "--permission-mode", "plan").stdout
        self.assertNotRegex(out, r"\[dry-run\].*sed.*SENTINEL_RESIDENT_UNIT")
        self.assertRegex(
            out, r"(?s)systemctl enable --now atlas-resident.*SENTINEL_RESIDENT_UNIT=atlas-resident\.service"
        )

    def test_ssh_address_added_with_yes(self):
        out = self.run_install("--yes", ssh="198.51.100.7 51234 203.0.113.1 22").stdout
        planned = [ln for ln in out.splitlines() if ln.startswith("[dry-run] sudo") and "known-ips.txt" in ln]
        self.assertTrue(any("198.51.100.7" in ln for ln in planned), out)
        self.assertRegex(out, r"operator\\? address\\? added\\? by\\? the\\? installer")

    def test_ssh_ipv6_address_accepted(self):
        out = self.run_install("--yes", ssh="2001:db8::7 51234 2001:db8::1 22").stdout
        self.assertRegex(out, r"\[dry-run\] sudo.*2001:db8::7.*known-ips\.txt")

    def test_invalid_ssh_address_is_refused(self):
        for bad in ("192.0.2.999", "evil;rm", "$(id)", "192.0.2", "::g1"):
            r = self.run_install("--yes", ssh="%s 1 203.0.113.2 22" % bad)
            self.assertNotRegex(
                r.stdout, r"\[dry-run\] (?!install -m).*known-ips\.txt|\[dry-run\] .*%s" % re.escape(bad), bad
            )
            self.assertIn("not a valid IP address", r.stderr, bad)

    def test_without_ssh_it_prints_how_to_add(self):
        out = self.run_install("--yes").stdout
        self.assertNotRegex(out, r"\[dry-run\] (?!install -m).*known-ips\.txt")
        self.assertIn("known-ips.txt", out)

    def test_http_expectations_learned_on_fresh_state_with_vhosts(self):
        out = self.run_install("--yes", "--with-apache").stdout
        learn = [ln for ln in out.splitlines() if ln.startswith("[dry-run] sudo") and "http-expected.json" in ln]
        self.assertEqual(len(learn), 1, out)
        self.assertIn("python3", learn[0])
        snap = out.index("atlas.py snap")
        self.assertLess(out.index("http-expected.json", snap), out.index("atlas/patrol.sh", snap))

    def test_no_learning_without_apache_or_vhosts(self):
        for args, sites in ((("--yes",), True), (("--yes", "--with-apache"), False)):
            out = self.run_install(*args, sites=sites).stdout
            self.assertNotRegex(out, r"\[dry-run\].*python3 -I.*http-expected", out)

    def test_upgrade_keeps_existing_files(self):
        self.state.mkdir()
        (self.state / "known-ips.txt").write_text("203.0.113.9\n")
        (self.state / "http-expected.json").write_text('{"my.host": [200]}\n')
        out = self.run_install("--yes", "--with-apache", ssh="198.51.100.7 1 203.0.113.2 22").stdout
        self.assertNotRegex(out, r"\[dry-run\] (?!install -m).*known-ips\.txt")
        self.assertNotRegex(out, r"\[dry-run\].*python3 -I.*http-expected")
        self.assertEqual((self.state / "known-ips.txt").read_text(), "203.0.113.9\n")


class LearnSnippet(unittest.TestCase):
    """The python snippet install.sh runs: records the first status of each vhost via http_probes."""

    def snippet(self):
        m = re.search(r"<<'PY'\n(.*?)\nPY\n", INSTALL.read_text(), re.S)
        self.assertTrue(m, "learn snippet not found in install.sh")
        return m.group(1)

    def test_snippet_records_status_codes(self):
        tmp = Path(tempfile.mkdtemp(prefix="atlas-learn-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        sites = tmp / "sites"
        sites.mkdir()
        (sites / "a.conf").write_text("ServerName www.example.org\n")
        fetch = tmp / "fetch.sh"
        fetch.write_text("#!/bin/sh\necho 301\n")
        fetch.chmod(0o755)
        out = tmp / "http-expected.json"
        out.write_text("{}")
        env = {**os.environ, "HTTP_SITES_DIR": str(sites), "HTTP_FETCH_CMD": str(fetch), "SENTINEL_ATLAS": str(tmp)}
        r = subprocess.run(
            ["python3", "-I", "-c", self.snippet(), str(ROOT), str(out)],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
        )
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        import json

        self.assertEqual(json.loads(out.read_text())["www.example.org"], [301])
        self.assertIn("www.example.org", r.stdout)


if __name__ == "__main__":
    unittest.main()
