"""Tests never see the host's Sentinel/Atlas/resident environment.

A resident session inherits SENTINEL_ATLAS and RESIDENT_ENV from its service unit. The conftest files remove every
SENTINEL_*, ATLAS_* and RESIDENT_* variable at import time, so a test run cannot touch a live install.
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PREFIXES = ("SENTINEL_", "ATLAS_", "RESIDENT_")


def snapshot(d: Path) -> dict:
    return {p.name: p.read_bytes() for p in sorted(d.iterdir())}


class TestEnvIsolation(unittest.TestCase):
    def test_no_host_variables_in_process(self):
        leaked = sorted(k for k in os.environ if k.startswith(PREFIXES) and k != "SENTINEL_SENDMAIL_CMD")
        self.assertEqual(leaked, [])

    def test_inherited_live_state_is_never_touched(self):
        with tempfile.TemporaryDirectory() as tmp:
            live = Path(tmp) / "live"
            live.mkdir()
            (live / "sentinel.env").write_text("SENTINEL_LANG=pl\n")
            (live / "heartbeat.log").write_text("2000-01-01T00:00:00Z patrol ok\n")
            before = snapshot(live)
            env = dict(os.environ)
            for k in [k for k in env if k.startswith(PREFIXES)]:
                del env[k]
            env["SENTINEL_ATLAS"] = str(live)
            env["RESIDENT_ENV"] = str(live / "r.env")
            cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"]
            cmd += ["atlas/tests/test_iteration1.py", "-k", "TestStableAlert"]
            r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True, timeout=300)
            self.assertEqual(r.returncode, 0, r.stdout[-1500:] + r.stderr[-500:])
            self.assertEqual(snapshot(live), before)


if __name__ == "__main__":
    unittest.main()
