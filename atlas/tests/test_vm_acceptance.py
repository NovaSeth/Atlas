#!/usr/bin/env python3
"""Bugs found by installing Atlas from zero on a clean Debian 13 cloud VM (README Quick start).

Each test pins one of them; nothing here touches real sudo, real state or the network.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
ATLAS = HERE.parent
ROOT = ATLAS.parent
sys.path.insert(0, str(ATLAS))
import atlas  # noqa: E402

PROBES = ATLAS / "sensors" / "http_probes.py"


class TestOptionalToolsAbsent(unittest.TestCase):
    """A missing optional tool is "not present": never a sudo call (sudo logs a denied command for a
    binary that is not installed, every patrol) and visible as such in the snapshot."""

    def vitals_with(self, installed):
        calls = []

        def fake_run(cmd, timeout=25):
            calls.append(cmd)
            return "/dev/vda1 5.8G 1G 4.8G 18% /" if cmd.startswith("df") else "1"

        with mock.patch.object(atlas, "run", side_effect=fake_run), \
                mock.patch.object(atlas, "silent_failures_checked", return_value=({}, {})), \
                mock.patch.object(atlas, "have", side_effect=lambda tool: tool in installed):
            v = atlas.vitals()
        return v, calls

    def test_fail2ban_absent_is_not_asked_through_sudo(self):
        v, calls = self.vitals_with(installed=set())
        self.assertFalse([c for c in calls if "fail2ban" in c], calls)
        self.assertEqual(v["banned_sshd"], "")

    def test_fail2ban_present_is_asked(self):
        v, calls = self.vitals_with(installed={"fail2ban-client"})
        self.assertTrue([c for c in calls if "sudo fail2ban-client status sshd" in c], calls)

    def test_snapshot_lists_not_present_tools(self):
        v, _ = self.vitals_with(installed={"docker"})
        self.assertEqual(v["not_present"], ["certbot", "fail2ban-client", "ufw"])


class TestHttpProbesDefaultSite(unittest.TestCase):
    """A fresh Apache has only 000-default.conf, without a ServerName: there is nothing to probe by name.
    That is a real (empty) measurement, not UNKNOWN forever. An empty sites directory stays UNKNOWN
    (glob cannot tell it from an unreadable one)."""

    def run_probes(self, files):
        d = Path(tempfile.mkdtemp(prefix="sites-"))
        self.addCleanup(shutil.rmtree, d, True)
        sites = d / "sites-enabled"
        sites.mkdir()
        for name, body in files.items():
            (sites / name).write_text(body)
        (d / "http-expected.json").write_text("{}")
        env = dict(os.environ, SENTINEL_ATLAS=str(d), HTTP_SITES_DIR=str(sites),
                   HTTP_EXPECTED=str(d / "http-expected.json"), HTTP_FETCH_CMD="false")
        return subprocess.run([sys.executable, str(PROBES)], env=env, capture_output=True, text=True, timeout=30)

    def test_default_site_without_server_name_is_clean_with_a_note(self):
        r = self.run_probes({"000-default.conf": "<VirtualHost *:80>\n\t#ServerName www.example.com\n"
                                                 "\tDocumentRoot /var/www/html\n</VirtualHost>\n"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("not present", r.stdout)

    def test_empty_sites_directory_is_still_unknown(self):
        self.assertEqual(self.run_probes({}).returncode, 2)


if __name__ == "__main__":
    unittest.main()
