#!/usr/bin/env python3
"""jobs.sh is a generic runner: helpers + every $SENTINEL_ATLAS/jobs.d/*.sh in sorted order.
No contract is hardcoded. The shipped examples (examples/jobs.d/) are exercised through the runner,
including the hourly "one line per run" contract (fresh/stale log, last line, last success, skips).
Everything runs on temp dirs; no real log is read."""

import os
import shutil
import subprocess
import tempfile
import time
import unittest
from datetime import datetime, timedelta
from pathlib import Path

ATLAS = Path(__file__).resolve().parents[1]
ROOT = ATLAS.parent
JOBS = ATLAS / "jobs.sh"
EXAMPLES = ROOT / "examples" / "jobs.d"


class RunnerCase(unittest.TestCase):
    def setUp(self):
        self.state = Path(tempfile.mkdtemp(prefix="jobs-runner-"))
        self.addCleanup(shutil.rmtree, self.state, True)
        (self.state / "jobs.d").mkdir()
        (self.state / "pauses").mkdir()

    def contract(self, name, body):
        (self.state / "jobs.d" / name).write_text(body)

    def run_jobs(self, **extra):
        env = dict(os.environ, SENTINEL_ATLAS=str(self.state))
        for k in ("JOBS_PAUSE_DIR", "JOBS_D", "SENTINEL_LANG"):
            env.pop(k, None)
        env.update({k: str(v) for k, v in extra.items()})
        return subprocess.run(["bash", str(JOBS)], env=env, capture_output=True, text=True, timeout=60)


class TestRunner(RunnerCase):
    def test_no_contracts_is_clean(self):
        shutil.rmtree(self.state / "jobs.d")
        r = self.run_jobs()
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, "", ""))

    def test_runner_holds_no_contract(self):
        text = JOBS.read_text()
        code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
        self.assertNotRegex(code, r'(?m)^\s*check(_last_line|_last_match)? "')  # only helper definitions

    def test_contracts_run_in_sorted_order(self):
        self.contract("20-b.sh", 'problem "second"\n')
        self.contract("10-a.sh", 'problem "first"\n')
        self.contract("README", 'problem "not a contract"\n')
        r = self.run_jobs()
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stdout, "  first\n  second\n")

    def test_check_missing_stale_and_no_success(self):
        fresh = self.state / "fresh.log"
        fresh.write_text("started\nstill working\n")
        old = self.state / "old.log"
        old.write_text("backup: OK\n")
        t = time.time() - 30 * 3600
        os.utime(old, (t, t))
        self.contract(
            "10-x.sh",
            'check "missing" "%s" 26 "OK"\ncheck "old" "%s" 26 "OK"\ncheck "fresh" "%s" 26 "backup: OK"\n'
            % (self.state / "nope.log", old, fresh),
        )
        r = self.run_jobs()
        self.assertEqual(r.returncode, 1)
        self.assertIn("missing: log file missing", r.stdout)
        self.assertIn("old: log has not changed for 30h (limit 26h)", r.stdout)
        self.assertIn("fresh: log is fresh but has no success confirmation", r.stdout)
        fresh.write_text("backup: OK\n")
        old.unlink()
        self.contract("10-x.sh", 'check "fresh" "%s" 26 "backup: OK"\n' % fresh)
        self.assertEqual(self.run_jobs().returncode, 0)  # reverse control

    def test_polish_catalog(self):
        self.contract("10-x.sh", 'check "nocny" "%s" 26 "OK"\n' % (self.state / "nope.log"))
        r = self.run_jobs(SENTINEL_LANG="pl")
        self.assertIn("nocny: brak pliku logu", r.stdout)
        self.assertIn("nocny: log file missing", self.run_jobs(SENTINEL_LANG="en").stdout)

    def test_language_from_sentinel_env(self):
        self.contract("10-x.sh", 'check "nocny" "%s" 26 "OK"\n' % (self.state / "nope.log"))
        (self.state / "sentinel.env").write_text("# comment\nSENTINEL_LANG=pl\n")
        self.assertIn("brak pliku logu", self.run_jobs().stdout)
        self.assertIn("log file missing", self.run_jobs(SENTINEL_LANG="en").stdout)  # the environment wins

    def test_syntax_error_is_unknown_not_clean(self):
        self.contract("10-broken.sh", "if then fi (\n")
        self.contract("20-ok.sh", 'problem "still evaluated"\n')
        r = self.run_jobs()
        self.assertEqual(r.returncode, 2)
        self.assertIn("10-broken.sh", r.stderr)
        self.assertIn("still evaluated", r.stderr)

    def test_unknown_helper(self):
        self.contract("10-x.sh", 'unknown "cannot reach the job host"\n')
        r = self.run_jobs()
        self.assertEqual(r.returncode, 2)
        self.assertIn("cannot reach the job host", r.stderr)

    def test_pause_silences_only_its_contract(self):
        log = self.state / "x.log"
        log.write_text("boom\n")
        self.contract("10-a.sh", 'paused a || check "job a" "%s" 26 "OK"\n' % log)
        self.contract("20-b.sh", 'paused b || check "job b" "%s" 26 "OK"\n' % log)
        (self.state / "pauses" / "a").write_text("reason\nadmin, 2026-01-01\n")
        r = self.run_jobs()
        self.assertEqual(r.returncode, 1)
        self.assertNotIn("job a", r.stdout)
        self.assertIn("job b", r.stdout)
        other = self.state / "other-pauses"
        other.mkdir()
        self.assertIn("job a", self.run_jobs(JOBS_PAUSE_DIR=other).stdout)  # override wins


class TestNightlyExample(RunnerCase):
    def setUp(self):
        super().setUp()
        shutil.copy(EXAMPLES / "10-nightly-backup.sh", self.state / "jobs.d")
        self.log = self.state / "nightly.log"

    def test_ok_stale_and_paused(self):
        self.log.write_text("start\nbackup: OK\n")
        self.assertEqual(self.run_jobs(NIGHTLY_BACKUP_LOG=self.log).returncode, 0)
        t = time.time() - 27 * 3600
        os.utime(self.log, (t, t))
        r = self.run_jobs(NIGHTLY_BACKUP_LOG=self.log)
        self.assertEqual(r.returncode, 1)
        self.assertIn("nightly backup", r.stdout)
        (self.state / "pauses" / "nightly-backup").write_text("disk replaced\nadmin, 2026-01-01\n")
        self.assertEqual(self.run_jobs(NIGHTLY_BACKUP_LOG=self.log).returncode, 0)


class TestHourlyExample(RunnerCase):
    """The one-line-per-run contract: freshness 120 min, last line OK or SKIPPED busy, last OK < 180 min."""

    def setUp(self):
        super().setUp()
        shutil.copy(EXAMPLES / "20-hourly-task.sh", self.state / "jobs.d")
        self.log = self.state / "hourly.log"

    def problems(self):
        r = self.run_jobs(HOURLY_TASK_LOG=self.log)
        return [ln for ln in r.stdout.splitlines() if "hourly task" in ln]

    @staticmethod
    def ts(minutes_ago):
        return (datetime.now() - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%S")

    def age(self, minutes):
        t = time.time() - minutes * 60
        os.utime(self.log, (t, t))

    def test_missing_log_fires(self):
        self.assertTrue(self.problems())

    def test_stale_log_fires(self):
        self.log.write_text(f"{self.ts(180)} OK up to date\n")
        self.age(180)
        self.assertTrue(self.problems())

    def test_failed_last_line_fires(self):
        self.log.write_text(f"{self.ts(90)} OK up to date\n{self.ts(30)} FAILED push rejected\n")
        self.assertTrue(self.problems())

    def test_fresh_skipped_busy_is_quiet(self):
        self.log.write_text(f"{self.ts(90)} OK up to date\n{self.ts(30)} SKIPPED busy\n")
        self.assertEqual(self.problems(), [])

    def test_stale_skipped_busy_fires(self):
        self.log.write_text(f"{self.ts(180)} SKIPPED busy\n")
        self.age(180)
        self.assertTrue(self.problems())

    def test_fresh_ok_after_failure_is_quiet(self):
        self.log.write_text(f"{self.ts(90)} FAILED x\n{self.ts(30)} OK pushed abc1234\n")
        self.assertEqual(self.problems(), [])

    def test_old_ok_with_fresh_skips_fires(self):
        self.log.write_text(
            f"{self.ts(240)} OK up to date\n{self.ts(120)} SKIPPED busy\n"
            f"{self.ts(60)} SKIPPED busy\n{self.ts(0)} SKIPPED busy\n"
        )
        self.assertTrue(self.problems())

    def test_recent_ok_with_skips_quiet(self):
        self.log.write_text(f"{self.ts(120)} OK up to date\n{self.ts(60)} SKIPPED busy\n{self.ts(0)} SKIPPED busy\n")
        self.assertEqual(self.problems(), [])

    def test_no_ok_at_all_fires(self):
        self.log.write_text(f"{self.ts(0)} SKIPPED busy\n")
        self.assertTrue(self.problems())


if __name__ == "__main__":
    unittest.main()
