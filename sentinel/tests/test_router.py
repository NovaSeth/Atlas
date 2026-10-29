import os
import unittest
from unittest import mock

from helpers import make_event, notify_calls, stub_notify, tmpdir

import router  # noqa: E402


class RouterTests(unittest.TestCase):
    def setUp(self):
        self.d = tmpdir(self)
        self.notify = stub_notify(self.d)
        self.state = self.d / "router-sent.json"

    def route(self, ev, present, now=1000.0):
        return router.route(ev, state_path=self.state, notify=str(self.notify), presence=lambda: present, now=now)

    def test_critical_resident_absent_notifies_once_per_6h(self):
        ev = make_event(severity="critical", message="Login from an unknown IP", fingerprint="s:1")
        self.assertTrue(self.route(ev, False, 1000.0))
        self.assertFalse(self.route(ev, False, 1000.0 + 5 * 3600))
        self.assertEqual(len(notify_calls(self.d)), 1)
        self.assertIn("[sentinel] critical: something happened", notify_calls(self.d)[0])  # subject
        self.assertIn("Login from an unknown IP [s:1]", notify_calls(self.d)[0])  # body
        self.assertTrue(self.route(ev, False, 1000.0 + 6 * 3600 + 1))
        self.assertEqual(len(notify_calls(self.d)), 2)

    def test_new_fingerprint_is_not_suppressed(self):
        self.route(make_event(severity="critical", fingerprint="s:1"), False)
        self.route(make_event(severity="critical", fingerprint="s:2"), False)
        self.assertEqual(len(notify_calls(self.d)), 2)

    def test_resident_present_never_notifies(self):
        self.assertFalse(self.route(make_event(severity="critical"), True))
        self.assertEqual(notify_calls(self.d), [])

    def test_below_critical_never_notifies(self):
        for sev in ("info", "warning", "alert"):
            self.route(make_event(severity=sev, fingerprint="x:" + sev), False)
        self.assertEqual(notify_calls(self.d), [])

    def test_falls_back_to_what_without_message(self):
        self.route(make_event(severity="critical", what="plain english"), False)
        self.assertIn("plain english", notify_calls(self.d)[0])

    def test_old_field_name_message_pl_still_read(self):
        self.route(make_event(severity="critical", message_pl="stara nazwa pola"), False)
        self.assertIn("stara nazwa pola", notify_calls(self.d)[0])

    def test_notify_failure_is_not_recorded_as_sent(self):
        bad = self.d / "bad-notify"
        bad.write_text("#!/bin/sh\nexit 3\n")
        bad.chmod(0o755)
        ev = make_event(severity="critical")
        self.assertFalse(router.route(ev, state_path=self.state, notify=str(bad), presence=lambda: False, now=1.0))
        self.assertTrue(self.route(ev, False, 2.0))

    def test_default_channel_is_notify_cmd_then_mail(self):
        mails = self.d / "mails.txt"
        mail = self.d / "mail-stub"
        mail.write_text('#!/bin/sh\necho "MAIL $*" >> %s\ncat >> %s\n' % (mails, mails))
        mail.chmod(0o755)
        env = {"SENTINEL_NOTIFY_CMD": "", "SENTINEL_EMAIL": "ops@example.com", "SENTINEL_MAIL_CMD": str(mail)}
        with mock.patch.dict(os.environ, env):
            self.assertTrue(router.default_notify("subj", "body text"))
        self.assertIn("MAIL -s subj ops@example.com", mails.read_text())
        self.assertIn("body text", mails.read_text())
        with mock.patch.dict(os.environ, dict(env, SENTINEL_NOTIFY_CMD=str(self.notify))):
            self.assertTrue(router.default_notify("subj2", "body2"))
        self.assertEqual(notify_calls(self.d), ["subj2 body2"])
        self.assertEqual(mails.read_text().count("MAIL"), 1)  # notify command replaces mail here
        with mock.patch.dict(os.environ, {"SENTINEL_NOTIFY_CMD": "", "SENTINEL_EMAIL": ""}):
            self.assertFalse(router.default_notify("s", "b"))  # nobody configured: not delivered


class PresenceTests(unittest.TestCase):
    def setUp(self):
        self.d = tmpdir(self)

    def p(self, screen_out="", unit_active=False, resident_off=False, screen_name="agent", unit=""):
        atlas = self.d / "atlas"
        atlas.mkdir(exist_ok=True)
        off = atlas / "RESIDENT-OFF"
        if resident_off:
            off.write_text("")
        elif off.exists():
            off.unlink()
        return router.resident_present(
            atlas_dir=atlas, screen_out=screen_out, unit_active=unit_active, screen_name=screen_name, unit=unit
        )

    def test_screen_session_alive(self):
        self.assertTrue(self.p("\t123.agent\t(Detached)\n"))

    def test_dead_screen_session_is_a_corpse(self):
        self.assertFalse(self.p("\t123.agent\t(Dead ???)\n"))

    def test_other_session_name_does_not_count(self):
        self.assertFalse(self.p("\t123.other\t(Detached)\n"))

    def test_unit_active_counts(self):
        self.assertTrue(self.p("", unit_active=True, screen_name="", unit="agent.service"))
        self.assertFalse(self.p("", unit_active=False, screen_name="", unit="agent.service"))

    def test_resident_off_means_absent_even_if_alive(self):
        self.assertFalse(self.p("\t123.agent\t(Detached)\n", unit_active=True, resident_off=True, unit="agent.service"))

    def test_nobody(self):
        self.assertFalse(self.p("No Sockets found.\n"))

    def test_no_resident_configured_is_absent(self):
        self.assertFalse(self.p("\t123.agent\t(Detached)\n", unit_active=True, screen_name="", unit=""))

    def test_configuration_comes_from_env(self):
        atlas = self.d / "atlas"
        atlas.mkdir(exist_ok=True)
        with mock.patch.dict(os.environ, {"SENTINEL_RESIDENT_SCREEN": "agent", "SENTINEL_RESIDENT_UNIT": ""}):
            self.assertTrue(router.resident_present(atlas_dir=atlas, screen_out="\t9.agent\t(Attached)\n"))
        with mock.patch.dict(os.environ, {"SENTINEL_RESIDENT_SCREEN": "", "SENTINEL_RESIDENT_UNIT": ""}):
            self.assertFalse(router.resident_present(atlas_dir=atlas, screen_out="\t9.agent\t(Attached)\n"))


if __name__ == "__main__":
    unittest.main()
