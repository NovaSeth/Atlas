"""Notifier with an outbox: a notice that cannot go out now waits in <runtime>/outbox and the escalation timer
delivers it (audit items 1c, 6, 10; RF1)."""

import json
import os
import stat
import subprocess
import time
import unittest
from unittest import mock

from helpers import SENTINEL, make_event, notify_calls, stub_notify, tmpdir

import notify  # noqa: E402
import router  # noqa: E402

ESC = SENTINEL / "escalation.sh"


class Outbox(unittest.TestCase):
    def setUp(self):
        self.d = tmpdir(self)
        p = mock.patch.dict(
            os.environ, {"SENTINEL_ATLAS": str(self.d), "SENTINEL_NOTIFY_CMD": "", "SENTINEL_EMAIL": ""}
        )
        p.start()
        self.addCleanup(p.stop)
        os.environ.pop("SENTINEL_STATE_DIR", None)
        self.outbox = self.d / "runtime" / "outbox"

    def entries(self):
        return sorted(self.outbox.glob("*.json")) if self.outbox.exists() else []

    def test_queues_when_no_channel_works(self):
        self.assertEqual(notify.send_or_queue("subj", "body", "bless"), "queued")
        files = self.entries()
        self.assertEqual(len(files), 1)
        e = json.loads(files[0].read_text())
        self.assertEqual((e["v"], e["kind"], e["subject"], e["body"]), (1, "bless", "subj", "body"))
        self.assertEqual(stat.S_IMODE(files[0].stat().st_mode), 0o640)

    def test_malformed_channel_is_a_failed_send_and_queues(self):
        for bad in ("'", "/nonexistent/notify-cmd"):
            with mock.patch.dict(os.environ, {"SENTINEL_NOTIFY_CMD": bad}):
                self.assertEqual(notify.send_or_queue("s", "b", "ack"), "queued")
        self.assertEqual(len(self.entries()), 2)

    def test_sends_when_the_channel_works(self):
        stub = stub_notify(self.d)
        with mock.patch.dict(os.environ, {"SENTINEL_NOTIFY_CMD": str(stub)}):
            self.assertEqual(notify.send_or_queue("s", "b", "ack"), "sent")
        self.assertEqual(notify_calls(self.d), ["s b"])
        self.assertEqual(self.entries(), [])

    def test_drain_delivers_and_removes(self):
        notify.send_or_queue("s1", "b1", "router")
        stub = stub_notify(self.d)
        with mock.patch.dict(os.environ, {"SENTINEL_NOTIFY_CMD": str(stub)}):
            self.assertEqual(notify.drain(), {"sent": 1, "failed": 0, "dropped": 0})
        self.assertEqual(self.entries(), [])

    def test_drain_keeps_what_still_fails(self):
        notify.send_or_queue("s1", "b1", "router")
        self.assertEqual(notify.drain()["failed"], 1)
        self.assertEqual(len(self.entries()), 1)

    def test_outbox_is_bounded_and_counts_drops(self):
        for i in range(notify.OUTBOX_MAX + 5):
            notify.send_or_queue("s%d" % i, "b", "x")
        self.assertEqual(len(self.entries()), notify.OUTBOX_MAX)

    def test_router_default_path_queues_and_records(self):
        ev = make_event(severity="critical", fingerprint="t.crit:one")
        state = self.d / "runtime" / "router-sent.json"
        self.assertTrue(router.route(ev, state_path=state, presence=lambda: False, now=1000.0))
        self.assertEqual(len(self.entries()), 1)
        self.assertFalse(router.route(ev, state_path=state, presence=lambda: False, now=1001.0))
        self.assertEqual(len(self.entries()), 1)

    def test_default_notify_is_still_send_only(self):
        self.assertFalse(router.default_notify("s", "b"))
        self.assertEqual(self.entries(), [])


class EscalationDrain(unittest.TestCase):
    def test_escalation_delivers_the_outbox_with_mail(self):
        d = tmpdir(self)
        atlas, binp = d / "atlas", d / "bin"
        atlas.mkdir()
        binp.mkdir()
        mails = d / "mails.txt"
        for n, body in (
            ("mail", 'echo "MAIL $*" >> %s; cat >/dev/null' % mails),
            ("screen", "exit 0"),
            ("systemctl", "exit 0"),
        ):
            (binp / n).write_text("#!/bin/bash\n%s\n" % body)
            (binp / n).chmod(0o755)
        (atlas / "heartbeat.log").write_text("x ok\n")
        with mock.patch.dict(
            os.environ, {"SENTINEL_ATLAS": str(atlas), "SENTINEL_NOTIFY_CMD": "", "SENTINEL_EMAIL": ""}
        ):
            os.environ.pop("SENTINEL_STATE_DIR", None)
            notify.send_or_queue("queued subject", "queued body", "router")
        env = dict(
            os.environ,
            SENTINEL_ATLAS=str(atlas),
            SENTINEL_EMAIL="nobody@example.com",
            SENTINEL_NOTIFY_CMD="",
            SENTINEL_LANG="en",
            SENTINEL_RESIDENT_UNIT="",
            SENTINEL_RESIDENT_SCREEN="",
            PATH="%s:%s" % (binp, os.environ["PATH"]),
        )
        for k in ("SENTINEL_STATE", "SENTINEL_STATE_DIR", "SENTINEL_STREAM_HEARTBEAT"):
            env.pop(k, None)
        subprocess.run(["bash", str(ESC)], env=env, capture_output=True, text=True, timeout=90)
        self.assertIn("queued subject", mails.read_text())
        self.assertEqual(list((atlas / "runtime" / "outbox").glob("*.json")), [])
        self.assertIn("outbox: sent=1", (atlas / "runtime" / "escalation.log").read_text())


class DrainBudget(unittest.TestCase):
    """Review r1 F2: drain stays inside its time budget, also when each send is slow."""

    def setUp(self):
        self.d = tmpdir(self)
        p = mock.patch.dict(
            os.environ, {"SENTINEL_ATLAS": str(self.d), "SENTINEL_NOTIFY_CMD": "", "SENTINEL_EMAIL": ""}
        )
        p.start()
        self.addCleanup(p.stop)
        os.environ.pop("SENTINEL_STATE_DIR", None)

    def test_slow_channel_cannot_exceed_the_budget(self):
        notify.send_or_queue("s1", "b", "router")
        notify.send_or_queue("s2", "b", "router")
        slow = self.d / "slow-stub"
        slow.write_text("#!/bin/sh\nexec sleep 20\n")
        slow.chmod(0o755)
        t0 = time.monotonic()
        with mock.patch.dict(os.environ, {"SENTINEL_NOTIFY_CMD": str(slow)}):
            r = notify.drain(max_seconds=2)
        self.assertLess(time.monotonic() - t0, 6)
        self.assertEqual((r["sent"], r["failed"]), (0, 2))
        self.assertEqual(len(list((self.d / "runtime" / "outbox").glob("*.json"))), 2)

    def test_each_send_gets_the_remaining_budget(self):
        notify.send_or_queue("s1", "b", "router")
        seen = []

        def fake(subject, body, timeout=notify.NOTIFY_TIMEOUT):
            seen.append(timeout)
            return True

        with mock.patch.object(notify, "send", fake):
            notify.drain(max_seconds=5)
        self.assertEqual(len(seen), 1)
        self.assertLessEqual(seen[0], 5)


class DrainDiagnostics(unittest.TestCase):
    """Review r1 F1: an unusable outbox is visible in the CLI result and in the escalation log."""

    def test_cli_reports_an_unusable_outbox(self):
        d = tmpdir(self)
        rt = d / "runtime"
        (rt / "outbox").mkdir(parents=True, mode=0o750)
        (rt / "outbox").chmod(0o777)
        env = dict(os.environ, SENTINEL_ATLAS=str(d))
        env.pop("SENTINEL_STATE_DIR", None)
        r = subprocess.run(
            ["python3", str(SENTINEL / "notify.py"), "drain"], env=env, capture_output=True, text=True, timeout=30
        )
        self.assertEqual(r.returncode, 1)
        self.assertIn("outbox: unusable", r.stdout)

    def test_escalation_logs_a_failed_drain(self):
        d = tmpdir(self)
        atlas, binp = d / "atlas", d / "bin"
        (atlas / "runtime" / "outbox").mkdir(parents=True, mode=0o750)
        (atlas / "runtime" / "outbox").chmod(0o777)
        binp.mkdir()
        for n in ("mail", "screen", "systemctl"):
            (binp / n).write_text("#!/bin/bash\ncat >/dev/null\nexit 0\n")
            (binp / n).chmod(0o755)
        (atlas / "heartbeat.log").write_text("x ok\n")
        env = dict(
            os.environ,
            SENTINEL_ATLAS=str(atlas),
            SENTINEL_EMAIL="nobody@example.com",
            SENTINEL_NOTIFY_CMD="",
            SENTINEL_LANG="en",
            SENTINEL_RESIDENT_UNIT="",
            SENTINEL_RESIDENT_SCREEN="",
            PATH="%s:%s" % (binp, os.environ["PATH"]),
        )
        for k in ("SENTINEL_STATE", "SENTINEL_STATE_DIR", "SENTINEL_STREAM_HEARTBEAT"):
            env.pop(k, None)
        subprocess.run(["bash", str(ESC)], env=env, capture_output=True, text=True, timeout=90)
        log = (atlas / "runtime" / "escalation.log").read_text()
        self.assertIn("outbox drain failed", log)
        self.assertIn("unusable", log)
