#!/usr/bin/env python3
"""
Code and instance state are separate. SENTINEL_ATLAS selects the state directory for atlas/ and
sentinel/; unset = next to the code. The repository carries code and templates only: units,
crontab and sudoers are templates, contracts and bridges are plugins in the state directory.
Everything runs on temp dirs and stubs: no real snapshot, no sudo, no mail, no network.
"""
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
ATLAS = HERE.parent
ROOT = ATLAS.parent
sys.path.insert(0, str(HERE))
from test_iteration1 import make_patrol, Collector  # noqa: E402

LITERAL = "/home/"   # no instance path of any kind in code: everything comes from config or the state dir


def tree(d):
    return sorted(str(p.relative_to(d)) for p in Path(d).rglob("*"))


def load(path, name, env):
    """Import a module file fresh with the given environment (module-level defaults read env)."""
    with mock.patch.dict(os.environ, env, clear=False):
        spec = importlib.util.spec_from_file_location(name, str(path))
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
    return m


class TestPatrolStateDir(unittest.TestCase):
    """Acceptance 1."""

    def setUp(self):
        self.code = make_patrol()
        self.tmp = Path(tempfile.mkdtemp(prefix="state-dir-"))
        self.addCleanup(shutil.rmtree, self.code, True)
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.state = self.tmp / "state-not-yet-created"
        self.cwd = self.tmp / "elsewhere"
        self.cwd.mkdir()

    def add_bridge(self, name, body):
        b = self.state / "bridges.d" / name
        b.parent.mkdir(parents=True, exist_ok=True)
        b.write_text("#!/usr/bin/env bash\n" + body)
        b.chmod(0o755)
        return b

    def run_patrol(self, **extra):
        env = dict(os.environ, SENTINEL_ATLAS=str(self.state),
                   SENTINEL_BUS_CMD="true", STUB_CHECK_OUT="ATLAS: 1 change", STUB_CHECK_RC="1")
        env.update({k: str(v) for k, v in extra.items()})
        return subprocess.run(["bash", str(self.code / "patrol.sh")], env=env, cwd=str(self.cwd),
                              capture_output=True, text=True, timeout=90)

    def test_everything_lands_in_state_dir_only(self):
        # a bridge that remembers what it reported in a marker under $SENTINEL_ATLAS
        self.add_bridge("daily.sh", '[ -f "$SENTINEL_ATLAS/daily.marker" ] && exit 0\n'
                                    'touch "$SENTINEL_ATLAS/daily.marker"; echo "report body"\n')
        before = tree(self.code)
        r = self.run_patrol()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        for name in ("ALERT", "ALERT.since", "drift.log", "heartbeat.log", "bus-sections.state",
                     "REPORT-TO-SEND", "daily.marker"):
            self.assertTrue((self.state / name).exists(), (name, tree(self.state) if self.state.exists() else None))
        self.assertEqual(tree(self.code), before, "code dir must be untouched")
        self.assertEqual(tree(self.cwd), [], "cwd must be untouched")

    def test_bridges_become_report_sections_once(self):
        self.add_bridge("10-first.sh", '[ -f "$SENTINEL_ATLAS/m1" ] && exit 0; touch "$SENTINEL_ATLAS/m1"; echo one\n')
        self.add_bridge("20-second.sh", "echo two\n")
        self.add_bridge("30-silent.sh", "exit 0\n")
        self.add_bridge("40-broken.sh", "echo partial; exit 3\n")   # output counts, the exit code does not
        (self.state / "bridges.d" / "50-not-executable.sh").write_text("echo never\n")
        self.run_patrol(STUB_CHECK_RC="0", STUB_CHECK_OUT="ATLAS OK")
        rep = (self.state / "REPORT-TO-SEND").read_text()
        self.assertIn("NEW REPORT (10-first) - to be sent to the human:\none", rep)
        self.assertIn("NEW REPORT (20-second) - to be sent to the human:\ntwo", rep)
        self.assertLess(rep.index("10-first"), rep.index("20-second"))
        self.assertNotIn("30-silent", rep)
        self.assertNotIn("never", rep)
        self.assertIn("NEW REPORT (20-second)", (self.state / "drift.log").read_text())
        (self.state / "REPORT-TO-SEND").unlink()       # the resident delivered it
        (self.state / "bridges.d" / "20-second.sh").unlink()
        (self.state / "bridges.d" / "40-broken.sh").unlink()
        self.run_patrol(STUB_CHECK_RC="0", STUB_CHECK_OUT="ATLAS OK")
        self.assertFalse((self.state / "REPORT-TO-SEND").exists(), "the first bridge reported again")

    def test_hung_bridge_is_cut_off(self):
        self.add_bridge("slow.sh", "sleep 30; echo late\n")
        r = self.run_patrol(STUB_CHECK_RC="0", STUB_CHECK_OUT="ATLAS OK", PATROL_T_REPORT="1")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse((self.state / "REPORT-TO-SEND").exists())

    def test_clean_run_creates_missing_state_dir_and_heartbeat(self):
        r = self.run_patrol(STUB_CHECK_RC="0", STUB_CHECK_OUT="ATLAS OK")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(" ok", (self.state / "heartbeat.log").read_text())
        self.assertFalse((self.state / "ALERT").exists())

    def test_unset_variable_keeps_state_next_to_code(self):
        env = dict(os.environ, STUB_CHECK_OUT="ATLAS: x", STUB_CHECK_RC="1")
        env.pop("SENTINEL_ATLAS", None)
        subprocess.run(["bash", str(self.code / "patrol.sh")], env=env, cwd=str(self.cwd),
                       capture_output=True, text=True, timeout=90)
        self.assertTrue((self.code / "ALERT").exists())
        self.assertTrue((self.code / "heartbeat.log").exists())


class TestAtlasPyStateDir(unittest.TestCase):
    """Acceptance 2: snap / bless / check with a stubbed snapshot (no real 24 s measurement)."""

    SNAP = {"generated_at": "2026-10-23T10:00:00Z", "vitals": {}, "host": {}}

    def run_main(self, cmd, env):
        m = load(ATLAS / "atlas.py", "atlas_under_test", env)
        m.snapshot = lambda: dict(self.SNAP)
        with mock.patch.object(sys, "argv", ["atlas.py", cmd]):
            return m, m.main()

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="atlas-state-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.before = tree(ATLAS)

    def test_snap_bless_check_use_state_dir(self):
        env = {"SENTINEL_ATLAS": str(self.tmp)}
        _, rc = self.run_main("snap", env)
        self.assertEqual(rc, 0)
        self.assertTrue((self.tmp / "current.json").exists())
        self.assertEqual(len(list((self.tmp / "snapshots").glob("*.json"))), 1)
        _, rc = self.run_main("bless", env)
        self.assertEqual(rc, 0)
        self.assertTrue((self.tmp / "baseline.json").exists())
        _, rc = self.run_main("check", env)
        self.assertEqual(rc, 0)
        self.assertEqual(tree(ATLAS), self.before, "code dir must be untouched")

    def test_unset_means_code_dir(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SENTINEL_ATLAS", None)
            m = load(ATLAS / "atlas.py", "atlas_unset", {})
        self.assertEqual(m.CURRENT, str(ATLAS / "current.json"))
        self.assertEqual(m.BASELINE, str(ATLAS / "baseline.json"))
        self.assertEqual(m.SNAPDIR, str(ATLAS / "snapshots"))


class TestInstanceFileDefaults(unittest.TestCase):
    """Acceptance 3."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="defaults-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_http_probes_default_and_override(self):
        m = load(ATLAS / "sensors" / "http_probes.py", "hp1", {"SENTINEL_ATLAS": str(self.tmp)})
        self.assertEqual(m.EXPECTED, str(self.tmp / "http-expected.json"))
        m = load(ATLAS / "sensors" / "http_probes.py", "hp2",
                 {"SENTINEL_ATLAS": str(self.tmp), "HTTP_EXPECTED": "/x/specific.json"})
        self.assertEqual(m.EXPECTED, "/x/specific.json")

    def test_ssh_known_ips_default_and_override(self):
        m = load(ATLAS / "sensors" / "ssh_logins.py", "ssh1", {"SENTINEL_ATLAS": str(self.tmp)})
        self.assertEqual(m.KNOWN, str(self.tmp / "known-ips.txt"))
        m = load(ATLAS / "sensors" / "ssh_logins.py", "ssh2",
                 {"SENTINEL_ATLAS": str(self.tmp), "SSH_KNOWN_IPS": "/x/ips.txt"})
        self.assertEqual(m.KNOWN, "/x/ips.txt")

    def test_ssh_sensor_end_to_end_reads_state_file(self):
        when = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        line = "%s host sshd[1]: Accepted publickey for ops from 203.0.113.9 port 22" % when
        (self.tmp / "known-ips.txt").write_text("203.0.113.9\n")
        env = dict(os.environ, SENTINEL_ATLAS=str(self.tmp), SSH_JOURNAL_CMD="echo '%s'" % line)
        env.pop("SSH_KNOWN_IPS", None)
        cmd = [sys.executable, str(ATLAS / "sensors" / "ssh_logins.py"), "--text"]
        self.assertEqual(subprocess.run(cmd, env=env, capture_output=True, text=True).returncode, 0)
        (self.tmp / "known-ips.txt").write_text("198.51.100.1\n")   # reverse control: now unknown
        self.assertEqual(subprocess.run(cmd, env=env, capture_output=True, text=True).returncode, 1)

    def jobs(self, **extra):
        log = self.tmp / "nightly.log"
        log.write_text("backup: FAILED\n")
        (self.tmp / "jobs.d").mkdir(exist_ok=True)
        (self.tmp / "jobs.d" / "10-nightly.sh").write_text(
            'paused nightly || check "nightly" "%s" 26 "backup: OK"\n' % log)
        env = dict(os.environ, SENTINEL_ATLAS=str(self.tmp))
        env.pop("JOBS_PAUSE_DIR", None)
        env.pop("JOBS_D", None)
        env.update({k: str(v) for k, v in extra.items()})
        return subprocess.run(["bash", str(ATLAS / "jobs.sh")], env=env, capture_output=True, text=True)

    def test_jobs_pauses_from_state_dir_and_specific_override_wins(self):
        self.assertEqual(self.jobs().returncode, 1)               # no pause: the failed job shows
        (self.tmp / "pauses").mkdir()
        (self.tmp / "pauses" / "nightly").write_text("paused\n")
        r = self.jobs()
        self.assertEqual(r.returncode, 0, r.stdout)
        other = self.tmp / "other-pauses"
        other.mkdir()
        self.assertEqual(self.jobs(JOBS_PAUSE_DIR=other).returncode, 1)   # override wins: no marker there


class TestSentinelScriptsFindTheirOwnCode(unittest.TestCase):
    """Acceptance 4: the state dir has no sibling sentinel/ directory."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="state-only-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.state = self.tmp / "atlas-state"
        self.state.mkdir()
        self.assertFalse((self.tmp / "sentinel").exists())

    def test_session_sensor_follows_real_bus_from_its_own_dir(self):
        env = dict(os.environ, SENTINEL_ATLAS=str(self.state), SENTINEL_ESCALATION_LOG=str(self.tmp / "esc.log"),
                   SENTINEL_INTERVAL="0.2")
        env.pop("SENTINEL_BUS_CMD", None)
        env.pop("SENTINEL_BUS", None)
        p = subprocess.Popen(["bash", str(ROOT / "sentinel" / "session-sensor.sh")], env=env,
                             stdout=subprocess.PIPE, text=True)
        self.addCleanup(p.kill)
        k = Collector(p)
        time.sleep(1.5)
        ev = json.dumps({"sensor": "t.state", "severity": "alert", "confidence": "measured",
                         "what": "synthetic", "message": "x", "evidence": {}, "command": "x",
                         "fingerprint": "t.state:1"})
        r = subprocess.run([sys.executable, str(ROOT / "sentinel" / "bus.py"), "emit", "--json", ev],
                           env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue((self.state / "events.jsonl").exists())
        time.sleep(2.0)
        self.assertIn("t.state:1", "\n".join(k.lines), k.lines)

    def test_escalation_runs_clean_and_mail_names_the_state_dir(self):
        bin_ = self.tmp / "bin"
        bin_.mkdir()
        mails = self.tmp / "mails.txt"
        for n, body in (("mail", 'cat >> %s' % mails), ("screen", 'echo "1.agent (Attached)"'),
                        ("systemctl", "exit 0")):
            (bin_ / n).write_text("#!/bin/bash\n%s\n" % body)
            (bin_ / n).chmod(0o755)
        (self.state / "heartbeat.log").write_text("x ok\n")
        env = dict(os.environ, SENTINEL_ATLAS=str(self.state), SENTINEL_STATE=str(self.tmp / "st"),
                   SENTINEL_EMAIL="nobody@example.com", SENTINEL_RESIDENT_SCREEN="agent", SENTINEL_RESIDENT_UNIT="agent.service",
                   SENTINEL_STREAM_HEARTBEAT=str(self.tmp / "hb"), PATH="%s:%s" % (bin_, os.environ["PATH"]))
        r = subprocess.run(["bash", str(ROOT / "sentinel" / "escalation.sh")], env=env,
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)    # stream heartbeat missing = a problem
        body = mails.read_text()
        self.assertIn("tail %s/heartbeat.log" % self.state, body)
        self.assertIn("cat  %s/ALERT" % self.state, body)
        self.assertNotIn(LITERAL, body)


class TestNoInstanceLiterals(unittest.TestCase):
    """Acceptance 5."""

    def test_no_home_path_in_code(self):
        files = []
        for pat in ("atlas/*.py", "atlas/*.sh", "atlas/sensors/*.py", "sentinel/*.py", "sentinel/*.sh",
                    "sentinel/units/*", "examples/*", "examples/*/*", "*.sh"):
            files += sorted(ROOT.glob(pat))
        files = [f for f in files if f.is_file() and f.name != "test_state_dir.py"]
        self.assertTrue(files)
        hits = [f"{f.relative_to(ROOT)}:{i}" for f in files
                for i, l in enumerate(f.read_text().splitlines(), 1) if LITERAL in l]
        self.assertEqual(hits, [])


class TestUnits(unittest.TestCase):
    """Units, crontab and sudoers are templates: no instance path, only placeholders."""

    U = ROOT / "sentinel" / "units"

    def test_units_are_templates_with_state_env(self):
        for n in ("sentinel-stream.service", "sentinel-escalation.service"):
            t = (self.U / n).read_text()
            self.assertNotIn(LITERAL, t, n)
            self.assertIn("@ATLAS_CODE@/sentinel/", t, n)
            self.assertRegex(t, r"(?m)^User=@ATLAS_USER@$", n)
            self.assertRegex(t, r"(?m)^Environment=SENTINEL_ATLAS=@ATLAS_STATE@$", n)
            self.assertRegex(t, r"(?m)^EnvironmentFile=@ATLAS_STATE@/sentinel\.env$", n)  # no "-": fail loudly
        self.assertIn("WorkingDirectory=@ATLAS_CODE@\n", (self.U / "sentinel-stream.service").read_text())
        esc = (self.U / "sentinel-escalation.service").read_text()
        self.assertIn("ExecStart=@ATLAS_CODE@/sentinel/escalation.sh", esc)
        self.assertIn("OnCalendar=*:0/10", (self.U / "sentinel-escalation.timer").read_text())

    def test_env_example_documents_every_variable(self):
        text = (ROOT / "examples" / "sentinel.env").read_text()
        keys = {l.split("=", 1)[0] for l in text.splitlines() if l and not l.startswith("#") and "=" in l}
        for k in ("SENTINEL_EMAIL", "SENTINEL_NOTIFY_CMD", "SENTINEL_LANG", "SENTINEL_TRUSTED_SUDO_USERS",
                  "SENTINEL_RESIDENT_UNIT", "SENTINEL_RESIDENT_SCREEN", "SENTINEL_WEB_LOG", "HTTP_SITES_DIR",
                  "ATLAS_DISK_PCT", "ATLAS_RAM_MB", "ATLAS_CERT_DAYS"):
            self.assertIn(k, keys)
        self.assertNotIn("SENTINEL_ATLAS", keys)   # it selects the file's own directory
        self.assertRegex(text, r"(?m)^SENTINEL_EMAIL=$")   # no recipient shipped
        self.assertNotIn(LITERAL, text)

    def test_crontab_template(self):
        lines = [l for l in (self.U / "crontab.example").read_text().splitlines() if l and not l.startswith("#")]
        self.assertEqual(len(lines), 2, lines)
        self.assertTrue(lines[0].startswith("7,37 * * * * SENTINEL_ATLAS=@ATLAS_STATE@ @ATLAS_CODE@/atlas/patrol.sh >/dev/null 2>&1"), lines[0])
        self.assertTrue(lines[1].startswith("40 4 * * * find @ATLAS_STATE@/snapshots -name '*.json' -mtime +30 -delete"), lines[1])
        self.assertTrue(all("atlas-managed" in l for l in lines))   # the installer replaces exactly these


if __name__ == "__main__":
    unittest.main()
