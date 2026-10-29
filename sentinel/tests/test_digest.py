"""Daily digest for the human (audit 1b): agent-account sudo, blesses, acks and forged sudo lines of the last 24 h."""
import json
import os
import subprocess
import time
import unittest
from unittest import mock

from helpers import SENTINEL, make_event, notify_calls, stub_notify, tmpdir  # isort: skip

import bus  # noqa: E402
import digest  # noqa: E402


def ev(sensor, what, ts, **evidence):
    return make_event(sensor=sensor, severity="info", what=what, fingerprint="%s:%s" % (sensor, what[:8]),
                      ts=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)), evidence=evidence)


class Digest(unittest.TestCase):
    def setUp(self):
        self.d = tmpdir(self)
        p = mock.patch.dict(os.environ, {"SENTINEL_ATLAS": str(self.d), "SENTINEL_LANG": "en"})
        p.start()
        self.addCleanup(p.stop)
        self.now = time.time()   # the CLI test below uses the real clock
        for e in (ev("auth.sudo.command", 'sudo by "ops": "/usr/bin/systemctl restart apache2"', self.now - 3600, digest=True),
                  ev("auth.sudo.command", 'sudo by "root": "/usr/bin/ls"', self.now - 3600),
                  ev("atlas.bless", "baseline blessed by ops", self.now - 7200),
                  ev("auth.sudo.command", "old", self.now - 2 * 86400, digest=True)):
            bus.emit(e)

    def test_collect_takes_the_window_and_the_marked_events(self):
        got = [e["sensor"] + ":" + e["what"][:12] for e in digest.collect(self.now)]
        self.assertEqual(got, ["atlas.bless:baseline ble", 'auth.sudo.command:sudo by "ops'])

    def test_render_names_every_event(self):
        subject, body = digest.render(digest.collect(self.now), self.now)
        self.assertIn("2 agent action", subject)
        self.assertIn("/usr/bin/systemctl restart apache2", body)
        self.assertNotIn('"/usr/bin/ls"', body)

    def test_nothing_to_report_is_none(self):
        self.assertIsNone(digest.render([], self.now))

    def test_cli_sends_through_the_notify_command(self):
        stub = stub_notify(self.d)
        # Record one JSON line per invocation, including the multiline digest body.
        stub.write_text('#!/usr/bin/env python3\nimport json, sys\n'
                        'with open(%r, "a") as f: f.write(json.dumps(sys.argv[1:]) + "\\n")\n'
                        % str(self.d / "notify.calls"))
        env = dict(os.environ, SENTINEL_NOTIFY_CMD=str(stub), SENTINEL_EMAIL="")
        r = subprocess.run(["python3", str(SENTINEL / "digest.py"), "send"], env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(notify_calls(self.d)), 1)


    def test_rotations_validation_dedup_and_boundaries(self):
        stamp = int(self.now)
        events = [ev(sensor, sensor, stamp - age) for sensor, age in
                  (("atlas.ack", 86400), ("auth.sudo.forged", 30), ("atlas.bless", -60))]
        path = self.d / "slice"
        rotated = self.d / "slice.1"
        path.write_text("\n".join(json.dumps(e) for e in events) + '\nnull\n{}\ninvalid\n')
        rotated.write_text(json.dumps(events[1]) + "\n" + json.dumps(dict(events[0], ts="invalid")))
        got = digest.collect(stamp, paths=[path, rotated, self.d / "missing"])
        self.assertEqual([e["sensor"] for e in got], ["atlas.ack", "auth.sudo.forged"])

    def test_only_literal_true_marks_an_event(self):
        path = self.d / "slice"
        path.write_text(json.dumps(ev("test.sensor", "not marked", self.now - 10, digest=1)))
        self.assertEqual(digest.collect(self.now, paths=[path]), [])

    def test_render_caps_events_and_counts_rendered_lines(self):
        events = [ev("atlas.ack", "ack", self.now - 10)] * (digest.DIGEST_MAX_LINES + 5)
        subject, body = digest.render(events, self.now)
        self.assertIn("200 agent action", subject)
        self.assertEqual(body.count("atlas.ack ack"), 200)
        self.assertIn("5 more", body)

    def test_cli_delivery_results_and_empty_silence(self):
        for result, code in (("sent", 0), ("queued", 0), ("lost", 1)):
            with self.subTest(result=result), mock.patch.object(digest.notify, "send_or_queue", return_value=result) as send:
                self.assertEqual(digest.main(["send"]), code)
                self.assertEqual(send.call_args.kwargs, {"kind": "digest"})
        with mock.patch.object(digest, "collect", return_value=[]), mock.patch.object(digest.notify, "send_or_queue") as send:
            self.assertEqual(digest.main(["send"]), 0)
            send.assert_not_called()

    def test_read_failure_is_not_success(self):
        with mock.patch.object(digest, "collect", side_effect=PermissionError("denied")):
            self.assertEqual(digest.main(["send"]), 1)


class EscalationTrigger(unittest.TestCase):
    def test_once_per_day_after_the_hour(self):
        d = tmpdir(self)
        atlas, binp = d / "atlas", d / "bin"
        atlas.mkdir()
        binp.mkdir()
        mails = d / "mails.txt"
        for n, body in (("mail", 'echo "MAIL $*" >> %s; cat >/dev/null' % mails), ("screen", "exit 0"), ("systemctl", "exit 0")):
            (binp / n).write_text("#!/bin/bash\n%s\n" % body)
            (binp / n).chmod(0o755)
        (atlas / "heartbeat.log").write_text("x ok\n")
        with mock.patch.dict(os.environ, {"SENTINEL_ATLAS": str(atlas)}):
            bus.emit(ev("auth.sudo.command", 'sudo by "ops": "/usr/bin/id"', time.time() - 60, digest=True))
        hb = d / "hb"
        env = dict(os.environ, SENTINEL_ATLAS=str(atlas), SENTINEL_STATE=str(d / "st"), SENTINEL_STREAM_HEARTBEAT=str(hb),
                   SENTINEL_EMAIL="nobody@example.com", SENTINEL_NOTIFY_CMD="", SENTINEL_LANG="en",
                   SENTINEL_RESIDENT_UNIT="", SENTINEL_RESIDENT_SCREEN="", SENTINEL_DIGEST_HOUR="0",
                   PATH="%s:%s" % (binp, os.environ["PATH"]))
        for _ in range(2):
            hb.touch()
            subprocess.run(["bash", str(SENTINEL / "escalation.sh")], env=env, capture_output=True, text=True, timeout=90)
        self.assertEqual(mails.read_text().count("daily digest"), 1)
        self.assertTrue(list((d / "st").glob("digest-*")))

    def test_hour_empty_queue_and_retry(self):
        d = tmpdir(self)
        atlas, binp, state = d / "atlas", d / "bin", d / "runtime"
        atlas.mkdir()
        binp.mkdir()
        state.mkdir(mode=0o750)
        (atlas / "heartbeat.log").touch()
        hb = d / "hb"
        hb.touch()
        date = binp / "date"
        date.write_text('#!/bin/sh\nif [ "$*" = "-u +%H" ]; then echo 08; else exec /bin/date "$@"; fi\n')
        date.chmod(0o755)
        notify = binp / "notify"
        notify.write_text('#!/bin/sh\nexit 1\n')
        notify.chmod(0o755)
        env = dict(os.environ, SENTINEL_ATLAS=str(atlas), SENTINEL_STATE=str(state),
                   SENTINEL_STATE_DIR=str(state), SENTINEL_STREAM_HEARTBEAT=str(hb),
                   SENTINEL_NOTIFY_CMD=str(notify), SENTINEL_EMAIL="", SENTINEL_RESIDENT_UNIT="",
                   SENTINEL_RESIDENT_SCREEN="", SENTINEL_LANG="en", SENTINEL_DIGEST_HOUR="9",
                   PATH="%s:%s" % (binp, os.environ["PATH"]))

        def run():
            result = subprocess.run(["bash", str(SENTINEL / "escalation.sh")], env=env,
                                    capture_output=True, text=True, timeout=90)
            self.assertEqual(result.returncode, 0, result.stderr)

        run()
        self.assertEqual(list(state.glob("digest-*")), [])
        env["SENTINEL_DIGEST_HOUR"] = "8"
        run()
        markers = list(state.glob("digest-*"))
        self.assertEqual(len(markers), 1)
        self.assertNotIn("digest", (state / "escalation.log").read_text())
        self.assertFalse((state / "outbox").exists())
        markers[0].unlink()
        with mock.patch.dict(os.environ, {"SENTINEL_ATLAS": str(atlas)}):
            bus.emit(ev("atlas.ack", "ack", time.time() - 60))
        (state / "outbox").write_text("blocks queue")
        run()
        self.assertEqual(list(state.glob("digest-*")), [])
        self.assertIn("digest failed", (state / "escalation.log").read_text())
        (state / "outbox").unlink()
        (state / "digest-2000-01-01").touch()
        run()
        self.assertEqual(len(list(state.glob("digest-*"))), 1)
        self.assertFalse((state / "digest-2000-01-01").exists())
        self.assertEqual(len(list((state / "outbox").glob("*-digest.json"))), 1)
