#!/usr/bin/env python3
"""Escalation throttle per kind, alert episode age, dead screen sessions, atlas collectors
reporting UNKNOWN on failure, bless refusing, REPORT-TO-SEND ignored by git.
Everything uses temp dirs, PATH stubs and env overrides; nothing mails, nothing touches production.
"""
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
ATLAS = HERE.parent
ROOT = ATLAS.parent
ESC = ROOT / "sentinel" / "escalation.sh"
PATROL = ATLAS / "patrol.sh"
JOBS = ATLAS / "jobs.sh"


def load_atlas():
    spec = importlib.util.spec_from_file_location("atlas_mod_t", ATLAS / "atlas.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def age_file(path, minutes):
    t = time.time() - minutes * 60
    os.utime(path, (t, t))


class TmpCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="acc-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)


class EscalationCase(TmpCase):
    def setUp(self):
        super().setUp()
        self.atlas = self.tmp / "atlas"
        self.state = self.tmp / "state"
        self.bin = self.tmp / "bin"
        for d in (self.atlas, self.bin):
            d.mkdir()
        self.mails = self.tmp / "mails.txt"
        self.write_stub("mail", f'#!/bin/bash\necho "MAIL $*" >> {self.mails}\ncat >/dev/null\n')
        self.set_screen("")
        self.set_unit(True)
        (self.atlas / "heartbeat.log").write_text("x ok\n")
        # escalation also watches the stream daemon heartbeat; keep it fresh here
        self.stream_hb = self.tmp / "stream.heartbeat"
        self.stream_hb.touch()

    def write_stub(self, name, text):
        p = self.bin / name
        p.write_text(text)
        p.chmod(0o755)

    def set_screen(self, listing):
        (self.tmp / "screen.txt").write_text(listing)
        self.write_stub("screen", f"#!/bin/bash\ncat {self.tmp}/screen.txt\n")

    def set_unit(self, active):
        self.write_stub("systemctl", "#!/bin/bash\nexit %d\n" % (0 if active else 3))

    def run_esc(self):
        env = dict(os.environ, SENTINEL_ATLAS=str(self.atlas), SENTINEL_STATE=str(self.state),
                   SENTINEL_EMAIL="nobody@example.com", SENTINEL_RESIDENT_SCREEN="agent", SENTINEL_RESIDENT_UNIT="agent.service",
                   SENTINEL_STREAM_HEARTBEAT=str(self.stream_hb),
                   PATH=f"{self.bin}:{os.environ['PATH']}")
        r = subprocess.run(["bash", str(ESC)], env=env, capture_output=True, text=True, timeout=60)
        return r

    def mail_count(self):
        return len(self.mails.read_text().splitlines()) if self.mails.exists() else 0


class TestThrottlePerKind(EscalationCase):
    def patrol_silent(self, on):
        age_file(self.atlas / "heartbeat.log", 120 if on else 0)

    def test_kind_b_not_suppressed_by_kind_a(self):
        self.patrol_silent(True)
        r = self.run_esc()
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertEqual(self.mail_count(), 1)
        self.set_unit(False)   # resident-dead appears while patrol-silent still stands
        self.run_esc()
        self.assertEqual(self.mail_count(), 2)

    def test_same_kind_suppressed_within_window(self):
        self.patrol_silent(True)
        self.run_esc()
        self.run_esc()
        self.assertEqual(self.mail_count(), 1)

    def test_marker_removed_only_when_that_kind_healthy(self):
        self.patrol_silent(True)
        self.run_esc()
        self.set_unit(False)
        self.run_esc()
        self.assertTrue((self.state / "sent-patrol-silent").exists())
        self.assertTrue((self.state / "sent-resident-dead").exists())
        self.set_unit(True)     # resident healthy, patrol still silent
        self.run_esc()
        self.assertTrue((self.state / "sent-patrol-silent").exists())
        self.assertFalse((self.state / "sent-resident-dead").exists())
        self.assertEqual(self.mail_count(), 2)   # patrol-silent still suppressed

    def test_healthy_then_again_mails(self):
        self.patrol_silent(True)
        self.run_esc()
        self.patrol_silent(False)
        r = self.run_esc()
        self.assertEqual(r.returncode, 0)
        self.patrol_silent(True)
        self.run_esc()
        self.assertEqual(self.mail_count(), 2)


class TestDeadScreen(EscalationCase):
    def test_dead_screen_is_not_alive(self):
        self.set_unit(False)
        self.set_screen("There is a screen on:\n\t1234.agent\t(10/22/2026 10:00:00 PM)\t(Dead ???)\n")
        r = self.run_esc()
        self.assertEqual(r.returncode, 1)
        self.assertIn("resident-dead", (self.state / "escalation.log").read_text())

    def test_live_screen_counts(self):
        self.set_unit(False)
        self.set_screen("There is a screen on:\n\t1234.agent\t(10/22/2026 10:00:00 PM)\t(Detached)\n")
        r = self.run_esc()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


class TestAlertEpisode(EscalationCase):
    def make_alert(self, body_age_min, since_age_min=None):
        a = self.atlas / "ALERT"
        a.write_text("stamp\nbody\n")
        age_file(a, body_age_min)
        if since_age_min is not None:
            s = self.atlas / "ALERT.since"
            s.write_text("")
            age_file(s, since_age_min)

    def test_changing_body_escalates_by_episode_age(self):
        self.make_alert(body_age_min=1, since_age_min=90)
        r = self.run_esc()
        self.assertEqual(r.returncode, 1)
        self.assertIn("alert-unacked", (self.state / "escalation.log").read_text())

    def test_young_episode_does_not_escalate(self):
        self.make_alert(body_age_min=1, since_age_min=10)
        self.assertEqual(self.run_esc().returncode, 0)

    def test_ack_after_last_change_blocks(self):
        self.make_alert(body_age_min=30, since_age_min=90)
        ack = self.atlas / "ALERT.acked"
        ack.write_text("")
        age_file(ack, 5)
        self.assertEqual(self.run_esc().returncode, 0)

    def test_ack_before_last_change_does_not_block(self):
        self.make_alert(body_age_min=1, since_age_min=90)
        ack = self.atlas / "ALERT.acked"
        ack.write_text("")
        age_file(ack, 30)
        self.assertEqual(self.run_esc().returncode, 1)


class TestPatrolEpisode(TmpCase):
    def setUp(self):
        super().setUp()
        self.dir = self.tmp / "atlas"
        (self.dir / "sensors").mkdir(parents=True)
        shutil.copy(PATROL, self.dir / "patrol.sh")
        (self.dir / "atlas.py").write_text(
            "import sys,os\n"
            "if sys.argv[1]=='check':\n"
            "    p=os.path.join(os.path.dirname(os.path.abspath(__file__)),'stub-out')\n"
            "    t=open(p).read() if os.path.exists(p) else ''\n"
            "    print(t,end='')\n"
            "    sys.exit(1 if t else 0)\n")
        for n, body in (("jobs.sh", "exit 0\n"),):
            (self.dir / n).write_text("#!/bin/bash\n" + body)
            (self.dir / n).chmod(0o755)
        for n in ("lib.sh", "i18n.py", "envfile.py"):
            os.symlink(ATLAS / n, self.dir / n)
        (self.dir / "sensors" / "ssh_logins.py").write_text("")
        # patrol.sh also runs sensors/http_probes.py; a clean stub keeps this test offline
        (self.dir / "sensors" / "http_probes.py").write_text("")

    def patrol(self, out):
        p = self.dir / "stub-out"
        if out:
            p.write_text(out)
        elif p.exists():
            p.unlink()
        return subprocess.run(["bash", str(self.dir / "patrol.sh")], env=dict(os.environ, PATROL_NICE="1"),
                              capture_output=True, text=True, timeout=60)

    def test_episode_start_survives_body_change_and_resets_on_clean(self):
        self.patrol("disk 91%\n")
        since = self.dir / "ALERT.since"
        self.assertTrue(since.exists())
        age_file(since, 100)
        mt = since.stat().st_mtime
        self.patrol("disk 92%\n")
        self.assertIn("92%", (self.dir / "ALERT").read_text())
        self.assertEqual(since.stat().st_mtime, mt)
        self.patrol("")
        self.assertFalse((self.dir / "ALERT").exists())
        self.assertFalse(since.exists())
        self.patrol("disk 93%\n")
        self.assertGreater(since.stat().st_mtime, mt)


class TestAtlasUnknown(TmpCase):
    FAIL = (1, "", "sudo: a password is required")

    def setUp(self):
        super().setUp()
        self.a = load_atlas()
        self.a.CURRENT = str(self.tmp / "current.json")
        self.a.BASELINE = str(self.tmp / "baseline.json")
        self.a.SNAPDIR = str(self.tmp / "snaps")

    def patch(self, fake):
        self.a.run_checked = fake
        self.a.have = lambda tool: True   # pretend docker/ufw/certbot are installed: their failure counts
        self.a.run = lambda cmd, timeout=25: ""
        self.a.MEAS_ERRORS.clear()

    def test_failing_collectors_record_errors(self):
        self.patch(lambda cmd, timeout=25: self.FAIL)
        for name in ("services", "timers", "listeners", "containers", "sudoers", "vhosts",
                     "crontabs", "packages", "setuid", "firewall", "sensitive_files"):
            self.a.MEAS_ERRORS.clear()
            try:
                getattr(self.a, name)()
            except Exception:
                pass
            self.assertTrue(self.a.MEAS_ERRORS, name + " swallowed a failing command")

    def test_empty_but_successful_is_empty(self):
        self.patch(lambda cmd, timeout=25: (0, "", ""))
        self.assertEqual(self.a.setuid(), [])
        self.assertEqual(self.a.listeners(), [])
        self.assertEqual(self.a.firewall(), [])
        self.assertEqual(self.a.containers(), {})
        self.assertEqual(dict(self.a.MEAS_ERRORS), {})

    def test_check_exits_2_and_bless_refuses(self):
        self.patch(lambda cmd, timeout=25: self.FAIL)
        old = sys.argv
        try:
            sys.argv = ["atlas.py", "check"]
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                rc = self.a.main()
            self.assertEqual(rc, 2)
            self.assertFalse(os.path.exists(self.a.BASELINE), "baseline must not be created from a blind snapshot")
            self.assertTrue(err.getvalue().strip())
            sys.argv = ["atlas.py", "bless"]
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                rc = self.a.main()
            self.assertEqual(rc, 2)
            self.assertFalse(os.path.exists(self.a.BASELINE))
        finally:
            sys.argv = old


class TestGitignore(unittest.TestCase):
    def test_report_to_send_ignored(self):
        r = subprocess.run(["git", "check-ignore", "atlas/REPORT-TO-SEND", "atlas/ALERT.since"], cwd=ROOT,
                           capture_output=True, text=True)
        self.assertEqual(sorted(r.stdout.split()), ["atlas/ALERT.since", "atlas/REPORT-TO-SEND"])


class TestLocalReadFailures(TmpCase):
    def setUp(self):
        super().setUp()
        if os.geteuid() == 0:
            self.skipTest("root ignores file modes")
        self.a = load_atlas()
        self.a.MEAS_ERRORS.clear()
        self.apt = self.tmp / "apt"
        (self.apt / "sources.list.d").mkdir(parents=True)
        (self.apt / "sources.list").write_text("deb x\n")
        self.a.APT_LIST = str(self.apt / "sources.list")
        self.a.APT_DIR = str(self.apt / "sources.list.d")
        self.addCleanup(self.unlock)

    def unlock(self):
        for p in (self.apt / "sources.list.d", self.apt / "sources.list.d" / "x.list"):
            if p.exists():
                p.chmod(0o755 if p.is_dir() else 0o644)

    def test_unreadable_file_is_unknown_not_value(self):
        f = self.apt / "sources.list.d" / "x.list"
        f.write_text("deb y\n")
        f.chmod(0)
        res = self.a.apt_sources()
        self.assertTrue(self.a.MEAS_ERRORS, "read failure was not recorded")
        self.assertNotIn("__unreadable__", json.dumps(res))

    def test_unreadable_directory_is_unknown_not_absent(self):
        d = self.apt / "sources.list.d"
        (d / "x.list").write_text("deb y\n")
        d.chmod(0)
        self.a.apt_sources()
        self.assertTrue(self.a.MEAS_ERRORS, "unreadable directory looked absent")

    def test_readable_is_normal_value(self):
        (self.apt / "sources.list.d" / "x.list").write_text("deb y\n")
        res = self.a.apt_sources()
        self.assertEqual(dict(self.a.MEAS_ERRORS), {})
        self.assertEqual(len(res), 2)
        self.assertTrue(all(len(v) == 16 for v in res.values()))

    def test_missing_directory_is_really_absent(self):
        shutil.rmtree(self.apt / "sources.list.d")
        res = self.a.apt_sources()
        self.assertEqual(dict(self.a.MEAS_ERRORS), {})
        self.assertEqual(len(res), 1)


class TestBlessRefusesAnyUnknown(TmpCase):
    def setUp(self):
        super().setUp()
        self.a = load_atlas()
        self.a.CURRENT = str(self.tmp / "current.json")
        self.a.BASELINE = str(self.tmp / "baseline.json")
        Path(self.a.BASELINE).write_text('{"old": 1}')

    def bless(self, vitals):
        Path(self.a.CURRENT).write_text(json.dumps({"vitals": vitals, "new": 2}))
        old = sys.argv
        try:
            sys.argv = ["atlas.py", "bless"]
            err = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(err):
                rc = self.a.main()
        finally:
            sys.argv = old
        return rc, err.getvalue()

    def test_certs_error_refuses(self):
        rc, err = self.bless({"certs_error": "certbot rc=1", "measure_errors": {}, "silent_unknown": {}})
        self.assertNotEqual(rc, 0)
        self.assertIn("certs_error", err)
        self.assertEqual(json.loads(Path(self.a.BASELINE).read_text()), {"old": 1})

    def test_silent_unknown_refuses(self):
        rc, err = self.bless({"certs_error": "", "measure_errors": {}, "silent_unknown": {"u.service": "journalctl rc=1"}})
        self.assertNotEqual(rc, 0)
        self.assertIn("u.service", err)
        self.assertEqual(json.loads(Path(self.a.BASELINE).read_text()), {"old": 1})

    def test_clean_blesses(self):
        rc, _ = self.bless({"certs_error": "", "measure_errors": {}, "silent_unknown": {}})
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(Path(self.a.BASELINE).read_text())["new"], 2)


if __name__ == "__main__":
    unittest.main()
