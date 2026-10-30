#!/usr/bin/env python3
"""T-KR-33 (A33): Atlas state files are never group- or other-writable, whatever the caller's umask.
The patrol and atlas.py write under the state dir; cron runs them with the login umask (002 on Debian)."""

import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "atlas" / "tests"))
from test_iteration1 import make_patrol  # noqa: E402
from test_state_dir import load  # noqa: E402

INSTALL = ROOT / "install.sh"
SNAP = {
    "generated_at": "2026-10-29T10:00:00Z",
    "host": {"kernel": "6.1"},
    "accounts": {"root": {"uid": 0}},
    "vitals": {"measure_errors": {}, "certs_error": "", "silent_unknown": {}},
}


def loose_files(d):
    """Regular files under d with a group or other write bit."""
    out = []
    for p in Path(d).rglob("*"):
        if p.is_file() and not p.is_symlink() and stat.S_IMODE(p.stat().st_mode) & 0o022:
            out.append((str(p.relative_to(d)), oct(stat.S_IMODE(p.stat().st_mode))))
    return sorted(out)


def umask_002():
    os.umask(0o002)


class StateModes(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="state-modes-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.state = self.tmp / "state"
        self.state.mkdir()
        self.addCleanup(os.umask, os.umask(0o002))

    def test_s3_patrol_under_umask_002_leaves_no_loose_file(self):
        code = make_patrol()
        self.addCleanup(shutil.rmtree, code, True)
        env = dict(os.environ, SENTINEL_ATLAS=str(self.state), SENTINEL_BUS_CMD="true")
        for rc, out in (("1", "ATLAS: 1 change"), ("0", "ATLAS OK"), ("1", "ATLAS: 2 changes")):
            r = subprocess.run(
                ["bash", str(code / "patrol.sh")],
                env=dict(env, STUB_CHECK_RC=rc, STUB_CHECK_OUT=out),
                capture_output=True,
                text=True,
                timeout=90,
                preexec_fn=umask_002,
            )
            self.assertIn(r.returncode, (0, 1), r.stdout + r.stderr)
        names = {p.name for p in self.state.iterdir()}
        self.assertIn("heartbeat.log", names)
        self.assertIn("drift.log", names)
        self.assertEqual(loose_files(self.state), [])

    def atlas_main(self, cmd):
        stub = self.tmp / "notify-stub"
        stub.write_text("#!/bin/sh\nexit 0\n")
        stub.chmod(0o755)
        env = {
            "SENTINEL_ATLAS": str(self.state),
            "SENTINEL_NOTIFY_CMD": str(stub),
            "SENTINEL_EMAIL": "",
            "SENTINEL_LANG": "en",
            "SUDO_USER": "ops",
        }
        m = load(ROOT / "atlas" / "atlas.py", "atlas_state_modes", env)
        m.snapshot = lambda: json.loads(json.dumps(SNAP))
        with (
            mock.patch.dict(os.environ, env),
            mock.patch.object(sys, "argv", ["atlas.py", cmd]),
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()),
        ):
            os.umask(0o002)  # the caller's umask; main() must tighten it
            return m.main()

    def test_s3_bless_check_ack_under_umask_002_leave_no_loose_file(self):
        self.assertEqual(self.atlas_main("bless"), 0)
        (self.state / "ALERT").write_text("2026-10-29T10:00:00Z\n== x ==\nbody\n")
        self.assertEqual(self.atlas_main("ack"), 0)
        self.atlas_main("check")
        self.assertTrue((self.state / "baseline.json").exists())
        self.assertTrue((self.state / "ALERT.acked").exists())
        self.assertEqual(loose_files(self.state), [])

    def test_s4_installer_plans_to_remove_group_other_write(self):
        r = subprocess.run(
            ["bash", str(INSTALL), "--dry-run", "--code", "/opt/atlas", "--state", str(self.state), "--user", "nobody"],
            capture_output=True,
            text=True,
            timeout=120,
            stdin=subprocess.DEVNULL,
        )
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        steps = [ln for ln in r.stdout.splitlines() if ln.startswith("[dry-run]") and "-perm" in ln]
        self.assertEqual(len(steps), 1, r.stdout)
        for part in ("find", "-xdev", "-type", "-perm", "go-w"):
            self.assertIn(part, steps[0])
        self.assertIn("state files", r.stdout)
        self.assertIn("non-group-writable", r.stdout)


if __name__ == "__main__":
    unittest.main()
