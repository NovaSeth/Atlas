#!/usr/bin/env python3
"""
Bus wiring in patrol / session sensor / escalation, atomic ALERT writes and the HTTP probes.
Nothing here touches real state, mails, or does real HTTP: the bus CLI is a stub
(SENTINEL_BUS_CMD), the fetcher is a stub (HTTP_FETCH_CMD), the extra-URL lookup is a stub
(HTTP_EXTRA_URLS_CMD).
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
from pathlib import Path

HERE = Path(__file__).resolve().parent
ATLAS = HERE.parent
ROOT = ATLAS.parent
sys.path.insert(0, str(HERE))
from test_iteration1 import make_patrol, patrol, Collector  # noqa: E402

PROBES = ATLAS / "sensors" / "http_probes.py"
ESC = ROOT / "sentinel" / "escalation.sh"

# Stub bus: `emit --json X` appends X to $BUS_LOG; `follow ...` records its args and then
# prints every new line of $BUS_FEED (poll), so the session sensor merge can be observed.
STUB_BUS = r"""#!/usr/bin/env python3
import os, sys, time
log = os.environ["BUS_LOG"]
if sys.argv[1] == "emit":
    if os.environ.get("BUS_EMIT_FAIL"):
        sys.exit(2)
    with open(log, "a") as f:
        f.write(sys.argv[3] + "\n")
    sys.exit(0)
if sys.argv[1] == "follow":
    with open(log + ".follow-args", "a") as f:
        f.write(" ".join(sys.argv[2:]) + "\n")
    feed = os.environ["BUS_FEED"]
    seen = 0
    while True:
        try:
            lines = open(feed).read().splitlines()
        except FileNotFoundError:
            lines = []
        for l in lines[seen:]:
            print(l, flush=True)
        seen = len(lines)
        time.sleep(0.1)
"""


def stub_bus(d):
    p = d / "stubbus.py"
    p.write_text(STUB_BUS)
    return p


def events(log):
    p = Path(log)
    return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []


class TestAtomicAlert(unittest.TestCase):
    def setUp(self):
        self.d = make_patrol()
        self.addCleanup(shutil.rmtree, self.d, True)

    def test_patrol_never_truncates_alert_in_place(self):
        txt = (ATLAS / "patrol.sh").read_text()
        for line in txt.splitlines():
            code = line.split("#", 1)[0]
            self.assertNotRegex(code, r">\s*\"?\$?\{?[A-Za-z_]*ALERT\"?\s*$", line)
        self.assertRegex(txt, r"mv\b.*\bALERT\b")

    def test_reader_never_sees_empty_alert_during_50_rewrites(self):
        stop = threading.Event()
        bad = []
        alert = self.d / "ALERT"

        def reader():
            while not stop.is_set():
                try:
                    b = alert.read_bytes()
                except FileNotFoundError:
                    continue
                if not b:
                    bad.append("empty")
                time.sleep(0.0005)  # still catches a truncation window; yields the single vCPU

        t = threading.Thread(target=reader, daemon=True)
        t.start()
        try:
            for i in range(50):
                # PATROL_NICE=1 skips the nice re-exec: under load 50 niced runs starve for minutes
                patrol(self.d, STUB_CHECK_OUT="ATLAS: change %d" % i, STUB_CHECK_RC=1, PATROL_NICE=1)
        finally:
            stop.set()
            t.join()
        self.assertEqual(bad, [])
        self.assertIn("ATLAS: change 49", alert.read_text())


class TestPatrolEmit(unittest.TestCase):
    def setUp(self):
        self.d = make_patrol()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.bus = stub_bus(self.d)
        self.log = self.d / "bus.log"
        self.env = dict(SENTINEL_BUS_CMD="python3 %s" % self.bus, BUS_LOG=self.log)

    def test_one_event_per_new_section_none_for_unchanged(self):
        patrol(self.d, STUB_CHECK_OUT="ATLAS: A", STUB_CHECK_RC=1, **self.env)
        ev = events(self.log)
        self.assertEqual(len(ev), 1, ev)
        e = ev[0]
        self.assertEqual(e["severity"], "alert")
        self.assertEqual(e["confidence"], "measured")
        self.assertIn("ATLAS DRIFT", e["fingerprint"])
        self.assertRegex(e["fingerprint"], r"[0-9a-f]{16}")
        self.assertNotRegex(e["fingerprint"], r"\d{4}-\d\d-\d\d|\d\d:\d\d")
        patrol(self.d, STUB_CHECK_OUT="ATLAS: A", STUB_CHECK_RC=1, **self.env)
        self.assertEqual(len(events(self.log)), 1)  # unchanged: nothing
        patrol(self.d, STUB_CHECK_OUT="ATLAS: B", STUB_CHECK_RC=1, **self.env)
        ev = events(self.log)
        self.assertEqual(len(ev), 2)
        self.assertNotEqual(ev[0]["fingerprint"], ev[1]["fingerprint"])

    def test_second_section_emits_only_the_new_one(self):
        patrol(self.d, STUB_CHECK_OUT="ATLAS: A", STUB_CHECK_RC=1, **self.env)
        patrol(
            self.d,
            STUB_CHECK_OUT="ATLAS: A",
            STUB_CHECK_RC=1,
            STUB_SILENT_OUT="  x.service failed",
            STUB_SILENT_RC=1,
            **self.env,
        )
        ev = events(self.log)
        self.assertEqual(len(ev), 2, ev)
        self.assertIn("SILENT", ev[1]["fingerprint"])

    def test_unknown_section_is_alert_with_confidence_unknown(self):
        patrol(self.d, STUB_SILENT_RC=2, STUB_SILENT_ERR="journal unreadable", **self.env)
        ev = events(self.log)
        self.assertEqual(len(ev), 1, ev)
        self.assertEqual(ev[0]["severity"], "alert")
        self.assertEqual(ev[0]["confidence"], "unknown")

    def test_clean_run_emits_nothing_and_realert_emits_again(self):
        patrol(self.d, **self.env)
        self.assertEqual(events(self.log), [])
        patrol(self.d, STUB_CHECK_OUT="ATLAS: A", STUB_CHECK_RC=1, **self.env)
        patrol(self.d, **self.env)  # cleared
        patrol(self.d, STUB_CHECK_OUT="ATLAS: A", STUB_CHECK_RC=1, **self.env)
        self.assertEqual(len(events(self.log)), 2)

    def test_emit_failure_never_breaks_patrol_and_is_retried(self):
        r = patrol(self.d, STUB_CHECK_OUT="ATLAS: A", STUB_CHECK_RC=1, BUS_EMIT_FAIL=1, **self.env)
        self.assertEqual(r.returncode, 1)
        self.assertIn("ATLAS: A", (self.d / "ALERT").read_text())
        self.assertIn("bus", (self.d / "drift.log").read_text().lower())
        patrol(self.d, STUB_CHECK_OUT="ATLAS: A", STUB_CHECK_RC=1, **self.env)
        self.assertEqual(len(events(self.log)), 1)  # failed emit was not recorded as sent

    def test_missing_bus_behaves_as_before(self):
        # no SENTINEL_BUS_CMD and no sentinel/bus.py next to the copied patrol
        r = patrol(self.d, STUB_CHECK_OUT="ATLAS: A", STUB_CHECK_RC=1)
        self.assertEqual(r.returncode, 1)
        self.assertIn("ATLAS: A", (self.d / "ALERT").read_text())
        self.assertIn("alarm (atlas-drift)", (self.d / "heartbeat.log").read_text())
        log = (self.d / "drift.log").read_text()
        self.assertEqual(log.lower().count("bus unavailable"), 1, log)


# Stub follower that honours --from-end against the real bus file (like bus.py would).
STUB_FILE_BUS = r"""#!/usr/bin/env python3
import json, os, sys, time
bus = os.environ["BUS_FILE"]
if sys.argv[1] != "follow":
    sys.exit(0)
pos = os.path.getsize(bus) if "--from-end" in sys.argv else 0
while True:
    with open(bus) as f:
        f.seek(pos)
        data = f.read()
    cut = data.rfind("\n") + 1
    for l in data[:cut].splitlines():
        e = json.loads(l)
        print("10:00 %s %s: %s [%s]" % (e["severity"].upper(), e["sensor"], e["what"], e["fingerprint"]), flush=True)
    pos += len(data[:cut].encode())
    time.sleep(0.1)
"""


class TestSessionSensorGap(unittest.TestCase):
    def ev(self, fp):
        return (
            json.dumps(
                {
                    "ts": "2026-10-22T10:00:00Z",
                    "sensor": "atlas.patrol",
                    "severity": "alert",
                    "confidence": "measured",
                    "what": "w-" + fp,
                    "fingerprint": fp,
                }
            )
            + "\n"
        )

    def test_event_during_follower_gap_is_printed_exactly_once(self):
        d = Path(tempfile.mkdtemp(prefix="sensor-gap-"))
        self.addCleanup(shutil.rmtree, d, True)
        stub = d / "stubfile.py"
        stub.write_text(STUB_FILE_BUS)
        bus = d / "events.jsonl"
        bus.write_text(self.ev("old"))
        env = dict(
            os.environ,
            SENTINEL_ATLAS=str(d),
            SENTINEL_ESCALATION_LOG=str(d / "esc.log"),
            SENTINEL_INTERVAL="0.2",
            SENTINEL_FOLLOW_RETRY="2",
            BUS_FILE=str(bus),
            SENTINEL_BUS_CMD="python3 %s" % stub,
        )
        p = subprocess.Popen(
            ["bash", str(ROOT / "sentinel" / "session-sensor.sh")], env=env, stdout=subprocess.PIPE, text=True
        )
        self.addCleanup(p.kill)
        k = Collector(p)
        time.sleep(1.0)
        with open(bus, "a") as f:
            f.write(self.ev("live"))
        time.sleep(0.6)
        subprocess.run(["pkill", "-f", str(stub)])
        time.sleep(0.5)
        with open(bus, "a") as f:
            f.write(self.ev("gap"))  # appended while no follower runs
        time.sleep(4.5)  # retry sleep + restart
        with open(bus, "a") as f:
            f.write(self.ev("after"))
        time.sleep(1.0)
        joined = "\n".join(k.lines)
        for fp, n in (("old", 0), ("live", 1), ("gap", 1), ("after", 1)):
            self.assertEqual(joined.count("[%s]" % fp), n, (fp, k.lines))


class TestSessionSensorBus(unittest.TestCase):
    def start(self, bus_cmd):
        self.d = Path(tempfile.mkdtemp(prefix="sensor-i2-"))
        self.addCleanup(shutil.rmtree, self.d, True)
        self.feed = self.d / "feed.txt"
        self.log = self.d / "bus.log"
        env = dict(
            os.environ,
            SENTINEL_ATLAS=str(self.d),
            SENTINEL_ESCALATION_LOG=str(self.d / "esc.log"),
            SENTINEL_INTERVAL="0.2",
            BUS_LOG=str(self.log),
            BUS_FEED=str(self.feed),
        )
        if bus_cmd:
            env["SENTINEL_BUS_CMD"] = bus_cmd
        else:
            env.pop("SENTINEL_BUS_CMD", None)
        p = subprocess.Popen(
            ["bash", str(ROOT / "sentinel" / "session-sensor.sh")], env=env, stdout=subprocess.PIPE, text=True
        )
        self.addCleanup(p.kill)
        self.proc = p
        return Collector(p)

    def test_bus_lines_merged_with_alert_lines(self):
        bus = Path(tempfile.mkdtemp(prefix="bus-"))
        self.addCleanup(shutil.rmtree, bus, True)
        k = self.start("python3 %s" % stub_bus(bus))
        time.sleep(0.8)
        self.feed.write_text("10:00 ALERT auth.x: something [fp1]\n")
        (self.d / "ALERT").write_text("2026-10-22T10:00:00Z\nATLAS: A\n")
        time.sleep(1.2)
        joined = "\n".join(k.lines)
        self.assertIn("something [fp1]", joined, k.lines)
        self.assertIn("ATLAS ALERT: ATLAS: A", joined, k.lines)
        args = Path(str(self.log) + ".follow-args").read_text()
        for part in ("--min-severity alert", "--dedup-seconds 3600", "--from-end"):
            self.assertIn(part, args)

    def test_no_bus_keeps_old_behaviour(self):
        k = self.start(None)
        (self.d / "ALERT").write_text("2026-10-22T10:00:00Z\nATLAS: A\n")
        time.sleep(0.9)
        self.assertEqual(len(k.lines), 1, k.lines)

    def test_follower_dies_with_the_sensor(self):
        bus = Path(tempfile.mkdtemp(prefix="bus-"))
        self.addCleanup(shutil.rmtree, bus, True)
        stub = stub_bus(bus)
        self.start("python3 %s" % stub)
        time.sleep(0.8)
        self.proc.kill()
        self.proc.wait()
        time.sleep(3.5)
        r = subprocess.run(["pgrep", "-f", str(stub)], capture_output=True, text=True)
        self.assertEqual(r.stdout.strip(), "", "orphaned follower")


class TestEscalationStream(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="esc-i2-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.atlas, self.state, self.bin = self.tmp / "atlas", self.tmp / "state", self.tmp / "bin"
        for d in (self.atlas, self.bin, self.atlas / "pauses"):
            d.mkdir()
        self.mails = self.tmp / "mails.txt"
        for n, body in (
            ("mail", 'echo "MAIL $*" >> %s; cat >/dev/null' % self.mails),
            ("screen", 'echo "1.agent (Attached)"'),
            ("systemctl", "exit 0"),
        ):
            (self.bin / n).write_text("#!/bin/bash\n%s\n" % body)
            (self.bin / n).chmod(0o755)
        (self.atlas / "heartbeat.log").write_text("x ok\n")
        self.hb = self.tmp / "stream.heartbeat"

    def run_esc(self):
        env = dict(
            os.environ,
            SENTINEL_ATLAS=str(self.atlas),
            SENTINEL_STATE=str(self.state),
            SENTINEL_EMAIL="nobody@example.com",
            SENTINEL_RESIDENT_SCREEN="agent",
            SENTINEL_RESIDENT_UNIT="agent.service",
            SENTINEL_STREAM_HEARTBEAT=str(self.hb),
            PATH="%s:%s" % (self.bin, os.environ["PATH"]),
        )
        return subprocess.run(["bash", str(ESC)], env=env, capture_output=True, text=True, timeout=60)

    def log(self):
        return (self.state / "escalation.log").read_text()

    def test_missing_heartbeat_is_stream_silent(self):
        r = self.run_esc()
        self.assertEqual(r.returncode, 1)
        self.assertIn("stream-silent", self.log())
        self.assertTrue((self.state / "sent-stream-silent").exists())

    def test_old_heartbeat_is_stream_silent(self):
        self.hb.touch()
        t = time.time() - 6 * 60
        os.utime(self.hb, (t, t))
        self.assertIn("stream-silent", self.run_esc().stdout + self.log())

    def test_fresh_heartbeat_is_ok_reverse_control(self):
        self.hb.touch()
        t = time.time() - 4 * 60
        os.utime(self.hb, (t, t))
        r = self.run_esc()
        self.assertEqual(r.returncode, 0, self.log())
        self.assertNotIn("stream-silent", self.log())

    def test_pause_file_silences_it(self):
        (self.atlas / "pauses" / "sentinel-stream").write_text("daemon disabled\n")
        r = self.run_esc()
        self.assertEqual(r.returncode, 0, self.log())

    def test_throttled_like_other_kinds(self):
        self.run_esc()
        self.run_esc()
        self.assertEqual(self.mails.read_text().count("MAIL"), 1)


class TestHttpProbes(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="http-i2-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.sites = self.tmp / "sites"
        self.sites.mkdir()
        (self.sites / "a.conf").write_text("<VirtualHost *:443>\n    ServerName a.example.net\n</VirtualHost>\n")
        (self.sites / "a-80.conf").write_text(
            "<VirtualHost *:80>\n    ServerName a.example.net\n</VirtualHost>\n"
            "<VirtualHost *:80>\n    ServerName b.example.net\n</VirtualHost>\n"
        )
        self.expected = self.tmp / "expected.json"
        self.expected.write_text(json.dumps({"a.example.net": [200], "b.example.net": [301, 302]}))
        # stub fetcher: prints the status for the URL from $CODES (json), exit 1 for "ERR"
        (self.tmp / "fetch.py").write_text(
            "import json, os, sys\n"
            "c = json.loads(os.environ['CODES'])[sys.argv[1]]\n"
            "if c == 'ERR':\n    print('connection refused', file=sys.stderr); sys.exit(1)\n"
            "print(c)\n"
        )
        self.codes = {
            "https://a.example.net/": 200,
            "https://b.example.net/": 301,
            "https://example.net/blog/post-1/": 200,
        }

    def run_probe(self, article="https://example.net/blog/post-1/", article_rc=0, **over):
        codes = dict(self.codes, **over)
        env = dict(
            os.environ,
            HTTP_SITES_DIR=str(self.sites),
            HTTP_EXPECTED=str(self.expected),
            HTTP_FETCH_CMD="python3 %s" % (self.tmp / "fetch.py"),
            CODES=json.dumps(codes),
            HTTP_EXTRA_URLS_CMD="echo %s; exit %d" % (article, article_rc),
        )
        return subprocess.run([sys.executable, str(PROBES)], env=env, capture_output=True, text=True, timeout=60)

    def test_all_match_is_zero(self):
        r = self.run_probe()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_mismatch_is_one(self):
        r = self.run_probe(**{"https://a.example.net/": 500})
        self.assertEqual(r.returncode, 1)
        self.assertIn("a.example.net", r.stdout)
        self.assertIn("500", r.stdout)

    def test_fetch_error_is_two(self):
        r = self.run_probe(**{"https://b.example.net/": "ERR"})
        self.assertEqual(r.returncode, 2)
        self.assertIn("b.example.net", r.stderr)

    def test_unlisted_host_is_event(self):
        self.expected.write_text(json.dumps({"a.example.net": [200]}))
        r = self.run_probe()
        self.assertEqual(r.returncode, 1)
        self.assertIn("unknown expectation", r.stdout)

    def test_article_not_200_is_one(self):
        r = self.run_probe(**{"https://example.net/blog/post-1/": 404})
        self.assertEqual(r.returncode, 1)
        self.assertIn("example.net/blog/post-1", r.stdout)

    def test_article_lookup_failure_is_two(self):
        r = self.run_probe(article="", article_rc=3)
        self.assertEqual(r.returncode, 2)

    def test_missing_expected_file_is_two(self):
        self.expected.unlink()
        self.assertEqual(self.run_probe().returncode, 2)

    def test_extra_urls_from_config_key(self):
        cfg = {
            "a.example.net": [200],
            "b.example.net": [301, 302],
            "_extra_urls_cmd": "printf 'https://example.net/one/\\nhttps://example.net/two/\\n'",
        }
        self.expected.write_text(json.dumps(cfg))
        env = dict(
            os.environ,
            HTTP_SITES_DIR=str(self.sites),
            HTTP_EXPECTED=str(self.expected),
            HTTP_FETCH_CMD="python3 %s" % (self.tmp / "fetch.py"),
            CODES=json.dumps(dict(self.codes, **{"https://example.net/one/": 200, "https://example.net/two/": 500})),
        )
        env.pop("HTTP_EXTRA_URLS_CMD", None)
        env.pop("HTTP_ARTICLE_CMD", None)
        r = subprocess.run([sys.executable, str(PROBES)], env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("example.net/two/", r.stdout)
        self.assertNotIn("example.net/one/", r.stdout)
        self.assertNotIn("_extra_urls_cmd", r.stdout + r.stderr)  # a config key is never a host
        cfg["_extra_urls_cmd"] = ""  # empty = no extra URLs
        self.expected.write_text(json.dumps(cfg))
        r = subprocess.run([sys.executable, str(PROBES)], env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_no_sites_directory_means_nothing_to_probe(self):
        env = dict(os.environ, HTTP_SITES_DIR=str(self.tmp / "no-apache-here"), HTTP_EXPECTED=str(self.expected))
        r = subprocess.run([sys.executable, str(PROBES)], env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual((r.returncode, r.stdout), (0, ""))

    def test_shipped_expected_json_is_valid(self):
        d = json.loads((ROOT / "examples" / "http-expected.json").read_text())
        self.assertTrue(d)
        self.assertIn("_extra_urls_cmd", d)
        for host, codes in d.items():
            if host.startswith("_"):
                continue
            self.assertTrue(host.endswith(("example.com", "example.org")), host)
            self.assertIsInstance(codes, list)
            self.assertTrue(all(isinstance(c, int) for c in codes), host)

    def test_patrol_runs_http_probes_as_own_section(self):
        d = make_patrol()
        self.addCleanup(shutil.rmtree, d, True)
        (d / "sensors" / "http_probes.py").write_text(
            "import sys; print('a.example.net: 500, expected 200'); sys.exit(1)\n"
        )
        patrol(d)
        txt = (d / "ALERT").read_text()
        self.assertIn("== HTTP PROBES ==", txt)
        self.assertIn("a.example.net: 500", txt)
        (d / "sensors" / "http_probes.py").write_text("import sys; sys.exit(0)\n")
        patrol(d)
        self.assertFalse((d / "ALERT").exists())
        (d / "sensors" / "http_probes.py").write_text("import sys; sys.exit(2)\n")
        patrol(d)
        self.assertIn("UNKNOWN: http-probes", (d / "ALERT").read_text())


if __name__ == "__main__":
    unittest.main()
