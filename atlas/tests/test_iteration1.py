#!/usr/bin/env python3
"""
Patrol, session sensor, atlas collectors and the SSH sensor. Every check: raising, clearing and
the reverse control. Nothing writes to a real state directory, calls real sudo or a notify
command, or sends mail: temporary directories, commands replaced via environment variables or
unittest.mock.
"""
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
from unittest import mock

ATLAS = Path(__file__).resolve().parents[1]
ROOT = ATLAS.parent
sys.path.insert(0, str(ATLAS))

STUB_ATLAS = r'''#!/usr/bin/env python3
import os, sys
c = sys.argv[1]
if c == "check":
    print(os.environ.get("STUB_CHECK_OUT", "ATLAS OK - no changes")); sys.exit(int(os.environ.get("STUB_CHECK_RC", "0")))
if c == "thresholds":
    o = os.environ.get("STUB_THRESHOLDS_OUT", "")
    if o: print(o)
    if os.environ.get("STUB_THRESHOLDS_ERR"): print(os.environ["STUB_THRESHOLDS_ERR"], file=sys.stderr)
    sys.exit(int(os.environ.get("STUB_THRESHOLDS_RC", "0")))
if c == "silent":
    import time
    time.sleep(float(os.environ.get("STUB_SILENT_SLEEP", "0")))
    o = os.environ.get("STUB_SILENT_OUT", "")
    if o: print(o)
    if os.environ.get("STUB_SILENT_ERR"): print(os.environ["STUB_SILENT_ERR"], file=sys.stderr)
    sys.exit(int(os.environ.get("STUB_SILENT_RC", "1" if o else "0")))
'''


def write_atomic(path, text):
    """Write like patrol.sh does (temp file in the same directory + rename): a reader polling the
    file must never see it empty. A plain write_text truncates first and made tests flaky."""
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp-test")
    tmp.write_text(text)
    os.replace(tmp, path)


def link_libs(d):
    """The shared helpers next to a copied script: symlinks, so i18n.py still finds the real catalogs
    (it resolves its own path) and the copy never carries a stale helper."""
    for n in ("lib.sh", "i18n.py", "envfile.py"):
        os.symlink(ATLAS / n, Path(d) / n)


def make_patrol():
    """A copy of patrol.sh in a temporary directory with stubs for the rest."""
    d = Path(tempfile.mkdtemp(prefix="patrol-test-"))
    shutil.copy(ATLAS / "patrol.sh", d / "patrol.sh")
    link_libs(d)
    (d / "atlas.py").write_text(STUB_ATLAS)
    for n in ("jobs.sh",):
        (d / n).write_text("#!/usr/bin/env bash\nexit 0\n")
        os.chmod(d / n, 0o755)
    (d / "sensors").mkdir()
    (d / "sensors" / "ssh_logins.py").write_text("import sys; sys.exit(0)\n")
    # patrol.sh also runs sensors/http_probes.py; a clean stub keeps these tests offline.
    (d / "sensors" / "http_probes.py").write_text("import sys; sys.exit(0)\n")
    os.chmod(d / "patrol.sh", 0o755)
    return d


def patrol(d, **env):
    e = dict(os.environ)
    e.update({k: str(v) for k, v in env.items()})
    return subprocess.run(["bash", str(d / "patrol.sh")], env=e, capture_output=True, text=True, timeout=60)


def age_file(path, sec=1000000000):
    os.utime(path, (sec, sec))


class TestStableAlert(unittest.TestCase):
    def setUp(self):
        self.d = make_patrol()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.alert = self.d / "ALERT"

    def test_same_content_three_runs_leaves_file_untouched(self):
        first = None
        for i in range(3):
            patrol(self.d, STUB_CHECK_OUT="ATLAS: 1 change(s) against baseline:\n  + ADDED x", STUB_CHECK_RC=1)
            if i == 0:
                first = self.alert.read_text().splitlines()[0]
                age_file(self.alert)
            time.sleep(1.1)  # a different STAMP in every run
        self.assertEqual(int(self.alert.stat().st_mtime), 1000000000)
        self.assertEqual(self.alert.read_text().splitlines()[0], first)

    def test_content_change_writes_new_file(self):
        patrol(self.d, STUB_CHECK_OUT="ATLAS: A", STUB_CHECK_RC=1)
        age_file(self.alert)
        patrol(self.d, STUB_CHECK_OUT="ATLAS: B", STUB_CHECK_RC=1)
        self.assertGreater(self.alert.stat().st_mtime, 1500000000)
        self.assertIn("ATLAS: B", self.alert.read_text())

    def test_clean_run_removes_alert_and_does_not_create_it(self):
        patrol(self.d)  # reverse control: clean -> no ALERT
        self.assertFalse(self.alert.exists())
        patrol(self.d, STUB_CHECK_OUT="ATLAS: A", STUB_CHECK_RC=1)
        self.assertTrue(self.alert.exists())
        patrol(self.d)
        self.assertFalse(self.alert.exists())

    def test_ack_stays_valid_for_same_content_and_dies_for_new(self):
        patrol(self.d, STUB_CHECK_OUT="ATLAS: A", STUB_CHECK_RC=1)
        age_file(self.alert)
        ack = self.d / "ALERT.acked"
        ack.touch()
        os.utime(ack, (1000000100, 1000000100))
        patrol(self.d, STUB_CHECK_OUT="ATLAS: A", STUB_CHECK_RC=1)
        self.assertGreaterEqual(ack.stat().st_mtime, self.alert.stat().st_mtime)  # escalation.sh: acked=1
        patrol(self.d, STUB_CHECK_OUT="ATLAS: OTHER", STUB_CHECK_RC=1)
        self.assertLess(ack.stat().st_mtime, self.alert.stat().st_mtime)  # invalid

    def test_sensor_exit_2_is_unknown_section_and_alarm(self):
        r = patrol(self.d, STUB_THRESHOLDS_RC=2, STUB_THRESHOLDS_ERR="brak danych o dysku")
        self.assertEqual(r.returncode, 1)
        txt = self.alert.read_text()
        self.assertIn("UNKNOWN: thresholds", txt)
        self.assertIn("brak danych o dysku", txt)
        self.assertIn("unknown", (self.d / "heartbeat.log").read_text())

    def test_heartbeat_ok_and_alarm(self):
        patrol(self.d)
        self.assertTrue((self.d / "heartbeat.log").read_text().strip().endswith(" ok"))
        patrol(self.d, STUB_CHECK_OUT="x", STUB_CHECK_RC=1)
        self.assertIn(" alarm (", (self.d / "heartbeat.log").read_text().splitlines()[-1])

    def test_silent_failures_and_thresholds_have_headers(self):
        patrol(self.d, STUB_SILENT_OUT="  certbot.service: padl", STUB_THRESHOLDS_OUT="  dysk 95%", STUB_THRESHOLDS_RC=1)
        txt = self.alert.read_text()
        self.assertIn("SILENT FAILURES", txt)
        self.assertIn("RESOURCE AND CERTIFICATE THRESHOLDS", txt)


class Collector:
    def __init__(self, proc):
        self.lines = []
        threading.Thread(target=self._read, args=(proc,), daemon=True).start()

    def _read(self, proc):
        for l in proc.stdout:
            self.lines.append(l.rstrip("\n"))


class TestSessionSensor(unittest.TestCase):
    def test_same_content_other_stamp_is_one_line(self):
        d = Path(tempfile.mkdtemp(prefix="sensor-test-"))
        self.addCleanup(shutil.rmtree, d, True)
        env = dict(os.environ, SENTINEL_ATLAS=str(d), SENTINEL_ESCALATION_LOG=str(d / "esc.log"), SENTINEL_INTERVAL="0.2")
        p = subprocess.Popen(["bash", str(ROOT / "sentinel" / "session-sensor.sh")], env=env,
                             stdout=subprocess.PIPE, text=True)
        self.addCleanup(p.kill)
        k = Collector(p)
        write_atomic(d / "ALERT", "2026-10-22T10:00:00Z\nATLAS: A\n")
        time.sleep(0.8)
        write_atomic(d / "ALERT", "2026-10-22T10:30:00Z\nATLAS: A\n")
        time.sleep(0.8)
        self.assertEqual(len(k.lines), 1, k.lines)
        write_atomic(d / "ALERT", "2026-10-22T11:00:00Z\nATLAS: B\n")
        time.sleep(0.8)
        self.assertEqual(len(k.lines), 2, k.lines)
        (d / "ALERT").unlink()
        time.sleep(0.8)
        self.assertEqual(len(k.lines), 3, k.lines)
        self.assertIn("clear", k.lines[-1])


class TestPackagesCrontabsThresholds(unittest.TestCase):
    def setUp(self):
        import atlas
        self.atlas = atlas

    def test_snapshot_has_packages_key_only_ii(self):
        dpkg = "ii  zlib1g=1.3\nrc  old=1.0\nii  bash=5.2\n"
        def fake_rc(c, timeout=25):
            return (0, dpkg if "dpkg-query" in c else "abcdef", "")
        with mock.patch.object(self.atlas, "run", side_effect=lambda c, timeout=25: dpkg if "dpkg-query" in c else "abcdef"), \
                mock.patch.object(self.atlas, "run_checked", side_effect=fake_rc):
            self.assertEqual(self.atlas.packages(), ["bash=5.2", "zlib1g=1.3"])
            self.assertIn("packages", self.atlas.snapshot())

    def test_shortening_packages(self):
        new = {"packages": [f"p{i:03d}=2" for i in range(100)], "x": 1}
        ch = self.atlas.shorten_packages(self.atlas.diff({"packages": [], "x": 0}, new))
        pkg = [c for c in ch if "packages" in c or "package changes" in c]
        self.assertEqual(len(pkg), 25 + 1)
        self.assertIn("and 75 more", pkg[-1])
        self.assertTrue(any("x" in c and "CHANGED" in c for c in ch))  # other changes untouched
        short = self.atlas.shorten_packages(self.atlas.diff({"packages": []}, {"packages": ["a=1", "b=1"]}))
        self.assertEqual(len(short), 2)  # reverse control: <=25 without a counter

    def test_crontab_users(self):
        d = Path(tempfile.mkdtemp(prefix="cron-test-"))
        self.addCleanup(shutil.rmtree, d, True)
        (d / "passwd").write_text("root:x:0:0:r:/root:/bin/bash\nnewuser:x:1005:1005::/home/newuser:/bin/bash\n")
        def fake_rc(c, timeout=25):
            return (0, "" if "test -d" in c else "ops\nwww-data", "")
        with mock.patch.object(self.atlas, "run_checked", side_effect=fake_rc):
            u = self.atlas.crontab_users(str(d / "passwd"))
        self.assertEqual(u, ["newuser", "ops", "root", "www-data"])
        self.assertNotIn("nobody", u)

    def snap(self, certs, disk="41%", mem="3700"):
        return {"certs": certs, "vitals": {"disk_used_pct": disk, "mem_available_mb": mem}}

    def test_certs(self):
        a, n = self.atlas.thresholds(self.snap({"x.pl": {"days": 10}}), 1)
        self.assertTrue(any("x.pl" in l for l in a))
        a, n = self.atlas.thresholds(self.snap({"x.pl": {"days": 60}}), 1)
        self.assertEqual((a, n), ([], []))  # reverse
        a, n = self.atlas.thresholds(self.snap({}), 2)
        self.assertTrue(n and not a)  # unknown, not clean
        a, n = self.atlas.thresholds(self.snap({}), 0)
        self.assertEqual((a, n), ([], []))

    def test_resources(self):
        a, n = self.atlas.thresholds(self.snap({"x": {"days": 60}}, disk="95%"), 1)
        self.assertTrue(any("disk" in l for l in a))
        a, n = self.atlas.thresholds(self.snap({"x": {"days": 60}}, mem="100"), 1)
        self.assertTrue(any("RAM" in l for l in a))
        a, n = self.atlas.thresholds(self.snap({"x": {"days": 60}}, disk="41%", mem="3700"), 1)
        self.assertEqual((a, n), ([], []))
        a, n = self.atlas.thresholds(self.snap({"x": {"days": 60}}, disk="?", mem=""), 1)
        self.assertTrue(n)


class TestSsh(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="ssh-test-"))
        self.addCleanup(shutil.rmtree, self.d, True)
        (self.d / "known.txt").write_text("# comment\n198.51.100.4  # ops\n")

    def run_sensor(self, journal, cmd=None, known=None):
        (self.d / "j.log").write_text(journal)
        env = dict(os.environ,
                   SSH_JOURNAL_CMD=cmd or f"cat {self.d / 'j.log'}",
                   SSH_KNOWN_IPS=known or str(self.d / "known.txt"))
        return subprocess.run([sys.executable, str(ATLAS / "sensors" / "ssh_logins.py")],
                              env=env, capture_output=True, text=True, timeout=30)

    def line(self, ip, hours_ago=1, text="Accepted publickey for ops from"):
        t = (datetime.now().astimezone() - timedelta(hours=hours_ago)).isoformat(timespec="seconds")
        return f"{t} vps sshd-session[1]: {text} {ip} port 5 ssh2: ED25519 SHA256:abc\n"

    def test_unknown_ip_gives_event(self):
        r = self.run_sensor(self.line("203.0.113.99"))
        self.assertEqual(r.returncode, 1, r.stderr)
        z = json.loads(r.stdout.strip().splitlines()[0])
        self.assertEqual(z["sensor"], "auth.ssh.accepted-login")
        self.assertEqual(z["severity"], "critical")
        self.assertEqual(z["fingerprint"], "auth.ssh.accepted:203.0.113.99:ops")
        self.assertEqual(z["evidence"]["ip"], "203.0.113.99")

    def test_known_ip_gives_none(self):
        self.assertEqual(self.run_sensor(self.line("198.51.100.4")).returncode, 0)

    def test_pubkey_accepted_algorithms_gives_none(self):
        l = self.line("203.0.113.99", text="userauth_pubkey: key type ssh-rsa not in PubkeyAcceptedAlgorithms [preauth] from")
        self.assertEqual(self.run_sensor(l).returncode, 0)

    def test_older_than_window_clears(self):
        self.assertEqual(self.run_sensor(self.line("203.0.113.99", hours_ago=30)).returncode, 0)

    def test_adding_to_list_clears(self):
        self.assertEqual(self.run_sensor(self.line("203.0.113.99")).returncode, 1)
        (self.d / "known.txt").write_text("203.0.113.99\n")
        self.assertEqual(self.run_sensor(self.line("203.0.113.99")).returncode, 0)

    def test_journalctl_error_is_exit_2(self):
        self.assertEqual(self.run_sensor("", cmd="false").returncode, 2)

    def test_missing_list_is_exit_2(self):
        self.assertEqual(self.run_sensor(self.line("198.51.100.4"), known=str(self.d / "missing")).returncode, 2)


if __name__ == "__main__":
    unittest.main()
