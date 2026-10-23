import json
import os
import subprocess
import sys
import threading
import time
import unittest

from helpers import SENTINEL, make_event, read_bus, tmpdir, wait_for

import bus  # noqa: E402

BUS_PY = SENTINEL / "bus.py"


class BusBase(unittest.TestCase):
    def setUp(self):
        self.d = tmpdir(self)
        self.env = dict(os.environ, SENTINEL_BUS=str(self.d / "events.jsonl"),
                        SENTINEL_BUS_LOCK=str(self.d / "events.lock"))
        for k, v in self.env.items():
            if k.startswith("SENTINEL_"):
                os.environ[k] = v
                self.addCleanup(os.environ.pop, k, None)

    def cli(self, *args):
        return subprocess.run([sys.executable, str(BUS_PY), *args], env=self.env,
                              capture_output=True, text=True, timeout=20)


class EmitTests(BusBase):
    def test_emit_valid_fills_ts_and_appends(self):
        r = self.cli("emit", "--json", json.dumps(make_event()))
        self.assertEqual(r.returncode, 0, r.stderr)
        evs = read_bus(self.d / "events.jsonl")
        self.assertEqual(len(evs), 1)
        self.assertRegex(evs[0]["ts"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")

    def test_invalid_events_exit_2_and_write_nothing(self):
        bad = [
            "not json",
            json.dumps(make_event(severity="loud")),
            json.dumps(make_event(confidence="sure")),
            json.dumps({k: v for k, v in make_event().items() if k != "what"}),
            json.dumps(make_event(fingerprint="ssh:2026-10-22T10:00:00")),
            json.dumps(make_event(fingerprint="x:12:34")),
            json.dumps(make_event(fingerprint="x:1761120000")),
            json.dumps(make_event(fingerprint="")),
        ]
        for b in bad:
            r = self.cli("emit", "--json", b)
            self.assertEqual(r.returncode, 2, (b, r.stderr))
        self.assertEqual(read_bus(self.d / "events.jsonl"), [])

    def test_digits_inside_a_hex_word_are_not_a_timestamp(self):
        # seen in production: the patrol's section fingerprint carries a 16-hex sha prefix and
        # "224e3684913817bd" holds 10 consecutive digits; the epoch pattern rejected it and the ALERT section never
        # reached the bus ("bus emit failed" in drift.log). A digit run embedded in a longer hex word is not a timestamp.
        ok = [
            "atlas.patrol:ATLAS DRIFT:224e3684913817bd",
            "web.sensitive-hit:1234567890ab:/x",
            "x:ab1234567890",
        ]
        for fp in ok:
            r = self.cli("emit", "--json", json.dumps(make_event(fingerprint=fp)))
            self.assertEqual(r.returncode, 0, (fp, r.stderr))
        self.assertEqual([e["fingerprint"] for e in read_bus(self.d / "events.jsonl")], ok)
        # A bare epoch (not part of a hex word) is still rejected.
        r = self.cli("emit", "--json", json.dumps(make_event(fingerprint="x:1761120000:y")))
        self.assertEqual(r.returncode, 2)

    def test_concurrent_emits_do_not_interleave(self):
        procs = [subprocess.Popen([sys.executable, str(BUS_PY), "emit", "--json",
                                   json.dumps(make_event(fingerprint="c:%d" % i))],
                                  env=self.env) for i in range(12)]
        for p in procs:
            self.assertEqual(p.wait(timeout=20), 0)
        self.assertEqual(len(read_bus(self.d / "events.jsonl")), 12)

    def test_rotation_keeps_three(self):
        os.environ["SENTINEL_BUS_MAX_BYTES"] = "400"
        self.addCleanup(os.environ.pop, "SENTINEL_BUS_MAX_BYTES", None)
        for i in range(40):
            bus.emit(make_event(fingerprint="r:%d" % i))
        names = sorted(p.name for p in self.d.glob("events.jsonl*"))
        self.assertEqual(names, ["events.jsonl", "events.jsonl.1", "events.jsonl.2", "events.jsonl.3"])
        self.assertFalse((self.d / "events.jsonl.4").exists())


class FollowTests(BusBase):
    def _collect(self, **kw):
        got, stop = [], threading.Event()

        def run():
            for ev in bus.follow_events(stop=stop.is_set, poll=0.05, **kw):
                got.append(ev)
        t = threading.Thread(target=run, daemon=True)
        t.start()
        self.addCleanup(t.join, 5)
        self.addCleanup(stop.set)
        return got

    def test_follow_across_rotation_loses_and_duplicates_nothing(self):
        os.environ["SENTINEL_BUS_MAX_BYTES"] = "500"
        self.addCleanup(os.environ.pop, "SENTINEL_BUS_MAX_BYTES", None)
        got = self._collect(from_end=True)
        time.sleep(0.3)
        for i in range(30):
            bus.emit(make_event(fingerprint="f:%d" % i))
            if i % 7 == 0:
                time.sleep(0.1)
        self.assertTrue(wait_for(lambda: len(got) >= 30, 10), len(got))
        self.assertEqual([e["fingerprint"] for e in got], ["f:%d" % i for i in range(30)])
        self.assertTrue((self.d / "events.jsonl.1").exists(), "rotation did not happen")

    def test_from_end_skips_history(self):
        bus.emit(make_event(fingerprint="old:1"))
        got = self._collect(from_end=True)
        time.sleep(0.3)
        bus.emit(make_event(fingerprint="new:1"))
        self.assertTrue(wait_for(lambda: got, 5))
        self.assertEqual([e["fingerprint"] for e in got], ["new:1"])

    def test_without_from_end_reads_history(self):
        bus.emit(make_event(fingerprint="old:1"))
        got = self._collect(from_end=False)
        self.assertTrue(wait_for(lambda: got, 5))
        self.assertEqual(got[0]["fingerprint"], "old:1")

    def test_cli_follow_dedup_min_severity_and_new_fingerprint(self):
        p = subprocess.Popen([sys.executable, str(BUS_PY), "follow", "--min-severity", "alert",
                              "--dedup-seconds", "3600", "--from-end"], env=self.env,
                             stdout=subprocess.PIPE, text=True)
        self.addCleanup(p.kill)
        time.sleep(0.8)
        bus.emit(make_event(fingerprint="dup:1", what="first"))
        bus.emit(make_event(fingerprint="dup:1", what="second"))
        bus.emit(make_event(fingerprint="low:1", severity="info", what="quiet"))
        bus.emit(make_event(fingerprint="dup:2", severity="critical", what="third", sensor="a.b"))
        l1, l2 = p.stdout.readline(), p.stdout.readline()
        self.assertRegex(l1, r"^\d\d:\d\d ALERT test\.sensor: first \[dup:1\]$")
        # the NEW fingerprint must not be suppressed by the dedup of the old one
        self.assertRegex(l2, r"^\d\d:\d\d CRITICAL a\.b: third \[dup:2\]$")


if __name__ == "__main__":
    unittest.main()
