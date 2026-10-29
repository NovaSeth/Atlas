"""Runtime state lives in $SENTINEL_ATLAS/runtime, owned by the Atlas user; a foreign, symlinked or
group-writable directory is refused (audit item 8, RF5)."""

import os
import subprocess
import sys
import time
import unittest
from unittest import mock

import bus  # noqa: E402
import router  # noqa: E402
from helpers import SENTINEL, tmpdir

ROOT = SENTINEL.parent
ESC = SENTINEL / "escalation.sh"


class RuntimeDir(unittest.TestCase):
    def setUp(self):
        self.tmp = tmpdir(self)
        p = mock.patch.dict(os.environ, {"SENTINEL_ATLAS": str(self.tmp)})
        p.start()
        self.addCleanup(p.stop)
        os.environ.pop("SENTINEL_STATE_DIR", None)

    def test_default_is_under_the_state_dir(self):
        self.assertEqual(bus.runtime_dir(), self.tmp / "runtime")
        self.assertEqual(router.state_dir(), self.tmp / "runtime")

    def test_missing_dir_is_created_private(self):
        p = bus.ensure_private_dir(self.tmp / "runtime")
        self.assertEqual(p.stat().st_mode & 0o777, 0o750)

    def test_group_writable_is_refused(self):
        d = self.tmp / "runtime"
        d.mkdir()
        d.chmod(0o775)
        with self.assertRaises(bus.UnsafeStateDir) as c:
            bus.ensure_private_dir(d)
        self.assertEqual(c.exception.code, "group-or-other-writable")

    def test_symlink_is_refused(self):
        real = self.tmp / "real"
        real.mkdir(mode=0o750)
        (self.tmp / "runtime").symlink_to(real)
        with self.assertRaises(bus.UnsafeStateDir) as c:
            bus.ensure_private_dir(self.tmp / "runtime")
        self.assertEqual(c.exception.code, "symlink")

    def test_foreign_owner_is_refused(self):
        d = self.tmp / "runtime"
        d.mkdir(mode=0o750)
        with mock.patch.object(bus.os, "geteuid", return_value=os.geteuid() + 1):
            with self.assertRaises(bus.UnsafeStateDir) as c:
                bus.ensure_private_dir(d)
        self.assertEqual(c.exception.code, "foreign-owner")

    def test_no_var_tmp_default_is_left(self):
        for f in (
            "sentinel/router.py",
            "sentinel/escalation.sh",
            "sentinel/session-sensor.sh",
            "sentinel/stream.py",
            "sentinel/bus.py",
            "sentinel/notify.py",
        ):
            self.assertNotIn("/var/tmp", (ROOT / f).read_text(), f)


class StreamRefusesUnsafeDir(unittest.TestCase):
    def test_stream_exits_3_on_unsafe_runtime(self):
        tmp = tmpdir(self)
        d = tmp / "runtime"
        d.mkdir()
        d.chmod(0o777)
        env = dict(os.environ, SENTINEL_ATLAS=str(tmp), SENTINEL_JOURNAL_CMD="sleep 30", SENTINEL_WEB_CMD="sleep 30")
        env.pop("SENTINEL_STATE_DIR", None)
        t = time.time()
        r = subprocess.run(
            [sys.executable, str(SENTINEL / "stream.py")], env=env, capture_output=True, text=True, timeout=30
        )
        self.assertEqual(r.returncode, 3, r.stderr)
        self.assertLess(time.time() - t, 10)
        self.assertIn("unsafe runtime directory", r.stderr)
        self.assertFalse((d / "stream.heartbeat").exists())


class EscalationUnsafeDir(unittest.TestCase):
    def setUp(self):
        self.tmp = tmpdir(self)
        self.atlas, self.bin = self.tmp / "atlas", self.tmp / "bin"
        self.atlas.mkdir()
        self.bin.mkdir()
        self.mails = self.tmp / "mails.txt"
        for n, body in (
            ("mail", 'echo "MAIL $*" >> %s; cat >/dev/null' % self.mails),
            ("screen", "exit 0"),
            ("systemctl", "exit 0"),
        ):
            (self.bin / n).write_text("#!/bin/bash\n%s\n" % body)
            (self.bin / n).chmod(0o755)
        (self.atlas / "heartbeat.log").write_text("x ok\n")

    def run_esc(self, runtime):
        env = dict(
            os.environ,
            SENTINEL_ATLAS=str(self.atlas),
            SENTINEL_EMAIL="nobody@example.com",
            SENTINEL_NOTIFY_CMD="",
            SENTINEL_LANG="en",
            SENTINEL_RESIDENT_UNIT="",
            SENTINEL_RESIDENT_SCREEN="",
            PATH="%s:%s" % (self.bin, os.environ["PATH"]),
        )
        for k in ("SENTINEL_STATE", "SENTINEL_STATE_DIR", "SENTINEL_STREAM_HEARTBEAT"):
            env.pop(k, None)
        return subprocess.run(["bash", str(ESC)], env=env, capture_output=True, text=True, timeout=60)

    def test_default_state_is_the_runtime_dir(self):
        self.run_esc(None)
        self.assertTrue((self.atlas / "runtime" / "escalation.log").exists())
        self.assertEqual((self.atlas / "runtime").stat().st_mode & 0o777, 0o750)

    def test_escalation_mails_once_and_exits_2(self):
        d = self.atlas / "runtime"
        d.mkdir()
        d.chmod(0o777)
        r1, r2 = self.run_esc(d), self.run_esc(d)
        self.assertEqual((r1.returncode, r2.returncode), (2, 2), r1.stderr + r2.stderr)
        self.assertEqual(self.mails.read_text().count("MAIL"), 1)
        self.assertTrue((self.atlas / "escalation-unsafe-state.sent").exists())
        self.assertEqual(list(d.iterdir()), [])
