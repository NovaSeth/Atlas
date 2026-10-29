#!/usr/bin/env python3
"""bless and ack leave a trail outside the agent: a bus event and a notice to the human (audit 1c, 6);
check without a baseline is UNKNOWN and never creates one (audit 7). Temp dirs and a notify stub only."""

import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
ATLAS = HERE.parent
sys.path.insert(0, str(HERE))
from test_state_dir import load  # noqa: E402

SNAP = {
    "generated_at": "2026-10-29T10:00:00Z",
    "host": {"kernel": "6.1"},
    "accounts": {"root": {"uid": 0}},
    "vitals": {"measure_errors": {}, "certs_error": "", "silent_unknown": {}},
}
NO_BASELINE = "no baseline yet — review `atlas.py show` and run `bless`"


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="bless-ack-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.notices = self.tmp / "notices.txt"
        stub = self.tmp / "notify-stub"
        stub.write_text('#!/bin/sh\nprintf "%%s\\n%%s\\n==\\n" "$1" "$2" >> "%s"\n' % self.notices)
        stub.chmod(0o755)
        self.env = {
            "SENTINEL_ATLAS": str(self.tmp),
            "SENTINEL_NOTIFY_CMD": str(stub),
            "SENTINEL_EMAIL": "",
            "SENTINEL_LANG": "en",
            "SUDO_USER": "ops",
        }

    def main(self, cmd, snap=None):
        m = load(ATLAS / "atlas.py", "atlas_bless_ack", self.env)
        if snap is not None:
            m.snapshot = lambda: json.loads(json.dumps(snap))
        out, err = io.StringIO(), io.StringIO()
        with (
            mock.patch.dict(os.environ, self.env),
            mock.patch.object(sys, "argv", ["atlas.py", cmd]),
            redirect_stdout(out),
            redirect_stderr(err),
        ):
            rc = m.main()
        return rc, out.getvalue(), err.getvalue()

    def bus(self):
        p = self.tmp / "events.jsonl"
        return [json.loads(ln) for ln in p.read_text().splitlines()] if p.exists() else []

    def notice_list(self):
        return self.notices.read_text().split("==\n")[:-1] if self.notices.exists() else []


class TestNoBaseline(Case):
    def test_check_without_baseline_is_unknown(self):
        rc, _, err = self.main("check", SNAP)
        self.assertEqual(rc, 2)
        self.assertIn(NO_BASELINE, err)
        self.assertFalse((self.tmp / "baseline.json").exists())
        self.assertTrue((self.tmp / "current.json").exists())

    def test_three_checks_never_create_it(self):
        for _ in range(3):
            self.main("check", SNAP)
        self.assertFalse((self.tmp / "baseline.json").exists())


class TestBless(Case):
    def test_first_bless_emits_event_and_notifies(self):
        self.main("snap", SNAP)
        rc, _, _ = self.main("bless")
        self.assertEqual(rc, 0)
        raw = (self.tmp / "baseline.json").read_bytes()
        evs = [e for e in self.bus() if e["sensor"] == "atlas.bless"]
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["severity"], "warning")
        self.assertEqual(evs[0]["evidence"]["who"], "ops")
        self.assertIs(evs[0]["evidence"]["first"], True)
        self.assertEqual(evs[0]["evidence"]["sha256"], hashlib.sha256(raw).hexdigest())
        n = self.notice_list()
        self.assertEqual(len(n), 1)
        self.assertIn("ops", n[0])
        self.assertIn(hashlib.sha256(raw).hexdigest(), n[0])

    def test_second_bless_names_the_changed_sections(self):
        self.main("snap", SNAP)
        self.main("bless")
        changed = json.loads(json.dumps(SNAP))
        changed["host"]["kernel"] = "6.2"
        self.main("snap", changed)
        self.assertEqual(self.main("bless")[0], 0)
        ev = [e for e in self.bus() if e["sensor"] == "atlas.bless"][-1]
        self.assertEqual(ev["evidence"]["sections"], ["host"])
        self.assertIs(ev["evidence"]["first"], False)

    def test_bless_without_a_channel_succeeds_and_queues(self):
        self.env["SENTINEL_NOTIFY_CMD"] = ""
        self.main("snap", SNAP)
        rc, _, err = self.main("bless")
        self.assertEqual(rc, 0)
        self.assertIn("not notified", err)
        self.assertEqual(len(list((self.tmp / "runtime" / "outbox").glob("*.json"))), 1)

    def test_refused_bless_sends_nothing(self):
        bad = json.loads(json.dumps(SNAP))
        bad["vitals"]["measure_errors"] = {"services": "systemctl rc=1"}
        self.main("snap", bad)
        self.assertEqual(self.main("bless")[0], 2)
        self.assertEqual((self.bus(), self.notice_list()), ([], []))


class TestMalformedChannel(Case):
    """A channel that cannot be parsed never breaks bless/ack: exit codes unchanged, the notice is queued."""

    def test_bless_survives_and_queues(self):
        self.env["SENTINEL_NOTIFY_CMD"] = "'"
        self.main("snap", SNAP)
        rc, _, err = self.main("bless")
        self.assertEqual(rc, 0)
        self.assertIn("not notified", err)
        self.assertEqual(len(list((self.tmp / "runtime" / "outbox").glob("*.json"))), 1)

    def test_ack_survives_and_queues(self):
        self.env["SENTINEL_NOTIFY_CMD"] = "'"
        (self.tmp / "ALERT").write_bytes(b"2026-10-29T10:00:00Z\n== ATLAS DRIFT ==\n  x\n")
        rc, _, err = self.main("ack")
        self.assertEqual(rc, 0)
        self.assertIn("not notified", err)
        self.assertEqual(len(list((self.tmp / "runtime" / "outbox").glob("*.json"))), 1)

    def test_notify_crash_never_escapes(self):
        self.main("snap", SNAP)
        m = load(ATLAS / "atlas.py", "atlas_notify_crash", self.env)
        with (
            mock.patch.object(m.notify, "send_or_queue", side_effect=RuntimeError("boom")),
            mock.patch.dict(os.environ, self.env),
            mock.patch.object(sys, "argv", ["atlas.py", "bless"]),
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()) as err,
        ):
            rc = m.main()
        self.assertEqual(rc, 0)
        self.assertIn("not notified", err.getvalue())


class TestAck(Case):
    BODY = b"== ATLAS DRIFT ==\n  + ADDED accounts.bob\n"

    def write_alert(self, body=BODY):
        (self.tmp / "ALERT").write_bytes(b"2026-10-29T10:00:00Z\n" + body)

    def test_ack_writes_the_content_sha_and_notifies(self):
        self.write_alert()
        rc, _, _ = self.main("ack")
        self.assertEqual(rc, 0)
        ack = self.tmp / "ALERT.acked"
        self.assertEqual(ack.read_text().split()[0], hashlib.sha256(self.BODY).hexdigest())
        self.assertGreaterEqual(ack.stat().st_mtime, (self.tmp / "ALERT").stat().st_mtime)
        ev = [e for e in self.bus() if e["sensor"] == "atlas.ack"]
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["evidence"]["sections"], ["ATLAS DRIFT"])
        self.assertEqual(len(self.notice_list()), 1)

    def test_ack_without_alert_is_1(self):
        self.assertEqual(self.main("ack")[0], 1)
        self.assertFalse((self.tmp / "ALERT.acked").exists())

    def test_ack_race_invalidates_the_ack(self):
        self.write_alert()
        m = load(ATLAS / "atlas.py", "atlas_ack_race", self.env)
        orig = m.atomic_write_text

        def write_then_patrol_rewrites(path, text):
            orig(path, text)
            if path.endswith("ALERT.acked"):
                later = time.time() + 5
                (self.tmp / "ALERT").write_bytes(b"2026-10-29T11:00:00Z\n== CRON JOBS ==\nnew\n")
                os.utime(self.tmp / "ALERT", (later, later))

        with (
            mock.patch.object(m, "atomic_write_text", side_effect=write_then_patrol_rewrites),
            mock.patch.dict(os.environ, self.env),
            mock.patch.object(sys, "argv", ["atlas.py", "ack"]),
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()),
        ):
            rc = m.main()
        self.assertEqual(rc, 3)
        self.assertLess((self.tmp / "ALERT.acked").stat().st_mtime, (self.tmp / "ALERT").stat().st_mtime)
        self.assertEqual([e for e in self.bus() if e["sensor"] == "atlas.ack"], [])

    def test_entry_changes_to_the_state_dir(self):
        m = load(ATLAS / "atlas.py", "atlas_entry", self.env)
        with (
            mock.patch.object(m.os, "chdir") as ch,
            mock.patch.object(m, "main", return_value=0),
            self.assertRaises(SystemExit),
        ):
            m.entry()
        ch.assert_called_once_with(m.BASE)


if __name__ == "__main__":
    unittest.main()
