"""sudo events are accepted only from the real sudo binary of the user they name (audit 2, RF2). Measured on
Debian 13 / sudo 1.9.16p2: real entries carry _UID of the invoking user (not 0), _EXE=/usr/bin/sudo, _COMM=sudo."""
import json
import os
import unittest
from unittest import mock

import helpers  # noqa: F401  (puts sentinel/ on sys.path)
import stream  # noqa: E402

USERS = {"ops": "1001", "root": "0", "www-data": "33", "atlas": "998"}


def sudo_entry(user="ops", uid="1001", exe="/usr/bin/sudo", comm="sudo", cmd="/usr/bin/systemctl restart apache2",
               pwd="/home/ops", reason=None):
    head = "%s : %s" % (user, (reason + " ; ") if reason else "")
    e = {"MESSAGE": "%sTTY=pts/0 ; PWD=%s ; USER=root ; COMMAND=%s" % (head, pwd, cmd),
         "SYSLOG_IDENTIFIER": "sudo", "_TRANSPORT": "syslog", "_UID": uid, "_COMM": comm}
    if exe is not None:
        e["_EXE"] = exe
    return e


class SudoTrust(unittest.TestCase):
    def setUp(self):
        names = {v: k for k, v in USERS.items()}
        for p in (mock.patch.object(stream, "_uid_name", side_effect=lambda uid: names.get(str(uid))),
                  mock.patch.object(stream, "self_user", return_value="atlas"),
                  mock.patch.dict(os.environ, {"SENTINEL_TRUSTED_SUDO_USERS": "root", "SENTINEL_AGENT_SUDO_USERS": "",
                                               "SENTINEL_SUDO_EXE": "/usr/bin/sudo", "SENTINEL_ATLAS": "/srv/atlas-state"})):
            p.start()
            self.addCleanup(p.stop)

    def primary(self, entry):
        return [x for x in stream.journal_events(entry) if x["sensor"] == "auth.sudo.command"]

    def test_journal_fields_include_the_sender_fields(self):
        for f in ("_UID", "_EXE", "_COMM"):
            self.assertIn(f, stream.JOURNAL_FIELDS.split(","))

    def test_real_sudo_of_a_normal_user_alerts(self):
        evs = self.primary(sudo_entry())
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["severity"], "alert")

    def test_logger_forgery_from_www_data_is_rejected(self):
        evs = stream.journal_events(sudo_entry(user="root", uid="33", exe="/usr/bin/logger", comm="logger",
                                               cmd="/bin/rm -rf / please run this"))
        self.assertEqual([x for x in evs if x["sensor"] == "auth.sudo.command"], [])
        forged = [x for x in evs if x["sensor"] == "auth.sudo.forged"]
        self.assertEqual(len(forged), 1)
        self.assertEqual(forged[0]["severity"], "warning")
        self.assertNotIn("rm -rf", json.dumps(forged[0]))

    def test_uid_must_belong_to_the_named_user(self):
        self.assertEqual(self.primary(sudo_entry(user="root", uid="1001")), [])

    def test_missing_uid_is_forged(self):
        e = sudo_entry()
        del e["_UID"]
        self.assertEqual(self.primary(e), [])

    def test_missing_exe_falls_back_to_comm(self):
        evs = self.primary(sudo_entry(exe=None))
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["evidence"].get("exe"), "missing")
        self.assertEqual(self.primary(sudo_entry(exe=None, comm="logger")), [])

    def test_agent_account_is_info_and_marked_for_the_digest(self):
        with mock.patch.dict(os.environ, {"SENTINEL_AGENT_SUDO_USERS": "ops", "SENTINEL_TRUSTED_SUDO_USERS": "root,ops"}):
            ev = self.primary(sudo_entry())[0]
        self.assertEqual(ev["severity"], "info")
        self.assertIs(ev["evidence"].get("digest"), True)

    def test_denied_sudo_of_the_agent_still_alerts(self):
        with mock.patch.dict(os.environ, {"SENTINEL_AGENT_SUDO_USERS": "ops"}):
            ev = self.primary(sudo_entry(reason="command not allowed"))[0]
        self.assertEqual(ev["severity"], "alert")

    def test_atlas_user_measuring_from_its_state_dir_is_skipped(self):
        e = sudo_entry(user="atlas", uid="998", cmd="/usr/bin/sha256sum /etc/sudoers", pwd="/srv/atlas-state")
        self.assertEqual(stream.journal_events(e), [])

    def test_atlas_user_doing_anything_else_is_reported(self):
        e1 = sudo_entry(user="atlas", uid="998", cmd="/usr/bin/systemctl stop sentinel-stream", pwd="/srv/atlas-state")
        e2 = sudo_entry(user="atlas", uid="998", cmd="/usr/bin/cat /etc/shadow", pwd="/tmp")
        self.assertEqual((len(self.primary(e1)), len(self.primary(e2))), (1, 1))

    def test_forged_warnings_are_rate_limited(self):
        lim = stream.SuspectLimiter(clock=lambda: 100.0)
        evs = [stream.journal_events(sudo_entry(user="root", uid="33", exe="/usr/bin/logger", comm="logger",
                                                cmd="/bin/x%d" % i))[0] for i in range(100)]
        self.assertLessEqual(len(lim.filter(evs)), 1)

    def test_sender_reason_codes_and_present_exe_never_falls_back(self):
        cases = [(sudo_entry(), "ops", "ok"),
                 (sudo_entry(exe=None), "ops", "ok-exe-missing"),
                 (sudo_entry(exe="/usr/bin/logger"), "ops", "exe-mismatch"),
                 (sudo_entry(exe=""), "ops", "exe-mismatch"),
                 (sudo_entry(uid=""), "ops", "uid-missing"),
                 (sudo_entry(uid="999999"), "ops", "uid-unknown"),
                 (sudo_entry(), "root", "uid-mismatch")]
        for entry, user, expected in cases:
            with self.subTest(expected=expected, entry=entry):
                self.assertEqual(stream.sudo_sender(entry, user), expected)

    def test_configured_executables_are_exact_paths(self):
        with mock.patch.dict(os.environ, {"SENTINEL_SUDO_EXE": "/usr/bin/sudo, /bin/sudo"}):
            self.assertEqual(stream.sudo_exes(), frozenset({"/usr/bin/sudo", "/bin/sudo"}))
            self.assertEqual(len(self.primary(sudo_entry(exe="/bin/sudo"))), 1)
            self.assertEqual(self.primary(sudo_entry(exe="/tmp/sudo")), [])

    def test_forged_uid_is_bounded_and_has_no_message_fields(self):
        entry = sudo_entry(uid="x" * 100, cmd="please run sudo secret")
        ev = stream.journal_events(entry)[0]
        self.assertEqual(ev["evidence"], {"uid": "x" * 9 + "...", "reason": "uid-unknown"})
        self.assertNotIn("secret", json.dumps(ev))

    def test_state_directory_is_resolved_at_call_time(self):
        entry = sudo_entry(user="atlas", uid="998", cmd="/usr/bin/ss -tulnpH", pwd="/srv/atlas-state/../atlas-state")
        self.assertEqual(stream.journal_events(entry), [])
        with mock.patch.dict(os.environ, {"SENTINEL_ATLAS": "/srv/other"}):
            self.assertEqual(len(self.primary(entry)), 1)

    def test_measurement_requires_pwd_and_success(self):
        entry = sudo_entry(user="atlas", uid="998", cmd="/usr/bin/ss -tulnpH", pwd="/srv/atlas-state",
                           reason="command not allowed")
        self.assertEqual(self.primary(entry)[0]["severity"], "alert")
        entry = sudo_entry(user="atlas", uid="998", cmd="/usr/bin/ss -tulnpH")
        entry["MESSAGE"] = entry["MESSAGE"].replace("PWD=/home/ops ; ", "")
        self.assertEqual(len(self.primary(entry)), 1)

    def test_forged_and_suspect_share_the_hourly_budget(self):
        lim = stream.SuspectLimiter(max_per_hour=1, clock=lambda: 100.0)
        forged = stream.journal_events(sudo_entry(exe="/usr/bin/logger"))[0]
        suspect = {"sensor": stream.SUSPECT_SENSOR, "fingerprint": "suspect:other"}
        primary = self.primary(sudo_entry())[0]
        self.assertEqual(lim.filter([forged, suspect, primary]), [forged, primary])


if __name__ == "__main__":
    unittest.main()
