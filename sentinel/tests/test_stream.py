import json
import os
import socket
import subprocess
import sys
import time
import unittest

from unittest import mock

from helpers import SENTINEL, notify_calls, read_bus, stub_notify, tmpdir, wait_for

import stream  # noqa: E402

STREAM_PY = SENTINEL / "stream.py"

SSH_NEW_IP = {"MESSAGE": "Accepted publickey for ops from 203.0.113.7 port 51234 ssh2: ED25519 SHA256:abc",
              "_SYSTEMD_UNIT": "ssh.service", "SYSLOG_IDENTIFIER": "sshd"}
SSH_TRAP = {"MESSAGE": "userauth_pubkey: key type ssh-rsa not in PubkeyAcceptedAlgorithms [preauth]",
            "_SYSTEMD_UNIT": "ssh.service", "SYSLOG_IDENTIFIER": "sshd"}


class ClassifyTests(unittest.TestCase):
    def setUp(self):
        self.d = tmpdir(self)
        self.known = self.d / "known-ips.txt"
        self.known.write_text("# known\n198.51.100.9  # home\n")

    def cj(self, entry):
        return stream.classify_journal(entry, known_ips_path=self.known)

    def test_ssh_unknown_ip_is_critical_with_message(self):
        with mock.patch.dict(os.environ, {"SENTINEL_LANG": "en"}):
            ev = self.cj(SSH_NEW_IP)
        self.assertEqual(ev["sensor"], "auth.ssh.accepted-login")
        self.assertEqual(ev["severity"], "critical")
        self.assertEqual(ev["confidence"], "measured")
        self.assertIn("203.0.113.7", ev["message"])
        self.assertIn("unknown address", ev["message"])
        self.assertNotIn("message_pl", ev)
        self.assertEqual(ev["evidence"]["ip"], "203.0.113.7")
        with mock.patch.dict(os.environ, {"SENTINEL_LANG": "pl"}):
            self.assertIn("nieznanego adresu 203.0.113.7", self.cj(SSH_NEW_IP)["message"])

    def test_ssh_known_ip_is_info(self):
        e = dict(SSH_NEW_IP, MESSAGE="Accepted publickey for ops from 198.51.100.9 port 22 ssh2")
        self.assertEqual(self.cj(e)["severity"], "info")

    def test_ssh_bare_line_without_port(self):
        e = dict(SSH_NEW_IP, MESSAGE="Accepted publickey for ops from 203.0.113.7")
        self.assertEqual(self.cj(e)["severity"], "critical")

    def test_pubkey_accepted_algorithms_trap_yields_nothing(self):
        self.assertIsNone(self.cj(SSH_TRAP))
        e = dict(SSH_TRAP, MESSAGE="rejected: PubkeyAcceptedAlgorithms Accepted publickey for x from 198.51.100.4")
        self.assertIsNone(self.cj(e))

    def test_ssh_message_from_other_unit_is_ignored(self):
        e = dict(SSH_NEW_IP, _SYSTEMD_UNIT="cron.service")
        self.assertIsNone(self.cj(e))

    def test_ipv6_fingerprint_is_valid_for_the_bus(self):
        import bus
        e = dict(SSH_NEW_IP, MESSAGE="Accepted publickey for ops from 2001:db8:12:34::1 port 22 ssh2")
        self.assertEqual(bus.validate(self.cj(e) | {"ts": "x"}), [])

    def test_sudo_by_untrusted_user_is_alert_trusted_is_info(self):
        base = {"SYSLOG_IDENTIFIER": "sudo"}
        ops = dict(base, MESSAGE="ops : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/ls /root")
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SENTINEL_TRUSTED_SUDO_USERS", None)   # default: root only
            a = self.cj(dict(base, MESSAGE="mallory : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/id"))
            self.assertEqual((a["sensor"], a["severity"]), ("auth.sudo.command", "alert"))
            self.assertEqual(self.cj(ops)["severity"], "alert")
            r = self.cj(dict(base, MESSAGE="root : PWD=/ ; USER=root ; COMMAND=/usr/bin/ls"))
            self.assertEqual(r["severity"], "info")
        with mock.patch.dict(os.environ, {"SENTINEL_TRUSTED_SUDO_USERS": "root, ops"}):
            self.assertEqual(self.cj(ops)["severity"], "info")

    def test_unit_failed_fingerprint_per_unit(self):
        e = {"MESSAGE": "foo.service: Failed with result 'exit-code'.", "_PID": "1", "UNIT": "foo.service"}
        ev = self.cj(e)
        self.assertEqual((ev["sensor"], ev["severity"]), ("systemd.unit-failed", "alert"))
        self.assertIn("foo.service", ev["fingerprint"])
        self.assertNotEqual(ev["fingerprint"], self.cj(dict(e, UNIT="bar.service"))["fingerprint"])
        # not PID 1 -> spoofable text, ignored
        self.assertIsNone(self.cj(dict(e, _PID="4242")))

    def test_oom_kill(self):
        e = {"MESSAGE": "Out of memory: Killed process 4242 (mysqld) total-vm:1kB", "_TRANSPORT": "kernel"}
        ev = self.cj(e)
        self.assertEqual((ev["sensor"], ev["severity"]), ("kernel.oom-kill", "alert"))
        self.assertIsNone(self.cj(dict(e, _TRANSPORT="syslog")))

    def test_web_sensitive_hit_severity(self):
        line = '2026-10-22T10:00:00 www.example.com 198.51.100.50 %s %s "GET /wp-config.php HTTP/1.1"'
        self.assertEqual(stream.classify_web(line % (200, 512))["severity"], "critical")
        self.assertEqual(stream.classify_web(line % (200, 0))["severity"], "warning")
        self.assertEqual(stream.classify_web(line % (404, 300))["severity"], "info")
        self.assertEqual(stream.classify_web(line % (403, 0))["severity"], "info")
        ev = stream.classify_web(line % (200, 512))
        self.assertEqual(ev["sensor"], "web.sensitive-hit")
        self.assertIn("wp-config.php", ev["fingerprint"])
        self.assertIsNone(stream.classify_web("garbage"))

    def test_web_bare_status_bytes_request_form(self):
        ev = stream.classify_web('200 512 "GET /wp-config.php HTTP/1.1"')
        self.assertEqual(ev["severity"], "critical")

    def test_web_fingerprint_survives_date_in_path(self):
        import bus
        line = '2026-10-22T10:00:00 a.example.com 198.51.100.4 200 99 "GET /dump-2026-10-22.sql HTTP/1.1"'
        ev = stream.classify_web(line)
        self.assertEqual(bus.validate(ev | {"ts": "x"}), [])


class LiveSourceOutageTests(unittest.TestCase):
    def test_unreadable_while_process_alive_alerts_then_recovers(self):
        import threading
        os.environ["SENTINEL_STABLE_SECS"] = "0"
        self.addCleanup(os.environ.pop, "SENTINEL_STABLE_SECS", None)
        state = {"ok": True}
        stop = threading.Event()
        src = stream.Source("web", lambda: ["sleep", "30"], lambda l: None, stop,
                            readable=lambda: state["ok"])
        src.start()
        self.addCleanup(lambda: (stop.set(), src.terminate()))
        wait_for(lambda: src.up_since is not None)
        time.sleep(0.05)
        self.assertIsNone(src.check_health(0.2))
        state["ok"] = False
        self.assertIsNone(src.check_health(0.2))  # outage clock starts now
        time.sleep(0.3)
        ev = src.check_health(0.2)
        self.assertIsNotNone(ev)
        self.assertEqual(ev["confidence"], "unknown")
        self.assertIsNone(src.check_health(0.2))  # alerts once
        state["ok"] = True
        self.assertIsNone(src.check_health(0.2))
        time.sleep(0.3)
        self.assertIsNone(src.check_health(0.2))
        self.assertIsNone(src.fail_since)


class DaemonBase(unittest.TestCase):
    def setUp(self):
        self.d = tmpdir(self)
        self.atlas = self.d / "atlas"
        self.atlas.mkdir()
        self.state = self.d / "state"
        (self.atlas / "known-ips.txt").write_text("198.51.100.9\n")
        self.notify = stub_notify(self.d)
        self.bus = self.d / "events.jsonl"
        self.env = dict(
            os.environ,
            SENTINEL_BUS=str(self.bus), SENTINEL_BUS_LOCK=str(self.d / "events.lock"),
            SENTINEL_ATLAS=str(self.atlas), SENTINEL_KNOWN_IPS=str(self.atlas / "known-ips.txt"),
            SENTINEL_STATE_DIR=str(self.state), SENTINEL_NOTIFY_CMD=str(self.notify),
            SENTINEL_SCREEN_CMD="true", SENTINEL_SYSTEMCTL_CMD="false",
            SENTINEL_RESIDENT_SCREEN="agent", SENTINEL_RESIDENT_UNIT="agent.service",
            SENTINEL_WEB_LOG=str(self.d / "sensitive.log"),
            SENTINEL_RESTART_DELAY="0.2", SENTINEL_STABLE_SECS="1",
        )
        self.procs = []

    def start(self, **env):
        e = dict(self.env, **env)
        e.pop("NOTIFY_SOCKET", None) if "NOTIFY_SOCKET" not in env else None
        p = subprocess.Popen([sys.executable, str(STREAM_PY)], env=e,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.procs.append(p)
        self.addCleanup(self._kill, p)
        return p

    @staticmethod
    def _kill(p):
        p.terminate()
        try:
            p.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()
            p.communicate()

    def feed_cmd(self, path, content):
        """A source command that prints the file once and then idles (a quiet live source)."""
        path.write_text(content)
        return "sh -c 'cat %s; sleep 3600'" % path


class DaemonTests(DaemonBase):
    def test_criterion1_unknown_ssh_login_reaches_the_bus_within_30s(self):
        lines = json.dumps(SSH_NEW_IP) + "\n" + json.dumps(SSH_TRAP) + "\n"
        t0 = time.time()
        self.start(SENTINEL_JOURNAL_CMD=self.feed_cmd(self.d / "journal.json", lines),
                   SENTINEL_WEB_CMD="sleep 3600")
        evs = wait_for(lambda: [e for e in read_bus(self.bus) if e["sensor"] == "auth.ssh.accepted-login"], 30)
        self.assertTrue(evs, "no event on the bus")
        self.assertLess(time.time() - t0, 30)
        self.assertEqual(evs[0]["severity"], "critical")
        time.sleep(1)
        self.assertEqual(len([e for e in read_bus(self.bus) if e["sensor"] == "auth.ssh.accepted-login"]), 1,
                         "the PubkeyAcceptedAlgorithms trap line must not produce an event")

    def test_web_lines_critical_and_warning(self):
        web = ('2026-10-22T10:00:00 m.example.com 198.51.100.50 200 512 "GET /wp-config.php HTTP/1.1"\n'
               '2026-10-22T10:00:01 m.example.com 198.51.100.50 200 0 "GET /.env HTTP/1.1"\n')
        self.start(SENTINEL_JOURNAL_CMD="sleep 3600",
                   SENTINEL_WEB_CMD=self.feed_cmd(self.d / "web.txt", web))
        evs = wait_for(lambda: [e for e in read_bus(self.bus) if e["sensor"] == "web.sensitive-hit"]
                       if len([e for e in read_bus(self.bus) if e["sensor"] == "web.sensitive-hit"]) >= 2 else None, 15)
        self.assertEqual(sorted(e["severity"] for e in evs), ["critical", "warning"])

    def test_router_in_daemon_notifies_when_resident_absent(self):
        (self.atlas / "RESIDENT-OFF").write_text("")
        lines = json.dumps(SSH_NEW_IP) + "\n"
        self.start(SENTINEL_JOURNAL_CMD=self.feed_cmd(self.d / "journal.json", lines),
                   SENTINEL_WEB_CMD="sleep 3600")
        self.assertTrue(wait_for(lambda: notify_calls(self.d), 30), "the human was not notified")
        time.sleep(1)
        self.assertEqual(len(notify_calls(self.d)), 1)

    def test_no_resident_configured_notifies_the_human(self):
        lines = json.dumps(SSH_NEW_IP) + "\n"
        self.start(SENTINEL_RESIDENT_SCREEN="", SENTINEL_RESIDENT_UNIT="",
                   SENTINEL_JOURNAL_CMD=self.feed_cmd(self.d / "journal.json", lines),
                   SENTINEL_WEB_CMD="sleep 3600")
        self.assertTrue(wait_for(lambda: notify_calls(self.d), 30), "no resident, yet nobody was notified")

    def test_resident_present_not_notified(self):
        # screen stub prints a live resident session
        scr = self.d / "screen-stub"
        scr.write_text("#!/bin/sh\necho '\t1.agent\t(Detached)'\n")
        scr.chmod(0o755)
        lines = json.dumps(SSH_NEW_IP) + "\n"
        self.start(SENTINEL_SCREEN_CMD=str(scr),
                   SENTINEL_JOURNAL_CMD=self.feed_cmd(self.d / "journal.json", lines),
                   SENTINEL_WEB_CMD="sleep 3600")
        self.assertTrue(wait_for(lambda: read_bus(self.bus), 30))
        time.sleep(1.5)
        self.assertEqual(notify_calls(self.d), [])

    def test_source_exiting_is_restarted(self):
        line = json.dumps(SSH_NEW_IP)
        self.start(SENTINEL_JOURNAL_CMD="echo '%s'" % line, SENTINEL_WEB_CMD="sleep 3600")
        self.assertTrue(wait_for(lambda: len([e for e in read_bus(self.bus)
                                              if e["sensor"] == "auth.ssh.accepted-login"]) >= 3, 20),
                        "source was not restarted after EOF")

    def test_unreadable_source_raises_unknown_alert(self):
        self.start(SENTINEL_JOURNAL_CMD="false", SENTINEL_WEB_CMD="sleep 3600",
                   SENTINEL_UNREADABLE_SECS="1")
        evs = wait_for(lambda: [e for e in read_bus(self.bus) if e["sensor"] == "stream.source-unreadable"], 20)
        self.assertTrue(evs, "no unknown event")
        self.assertEqual((evs[0]["confidence"], evs[0]["severity"]), ("unknown", "alert"))
        self.assertIn("journal", evs[0]["fingerprint"])
        time.sleep(1.5)
        self.assertEqual(len([e for e in read_bus(self.bus) if e["sensor"] == "stream.source-unreadable"]), 1,
                         "must alert once per outage, not on every tick")

    def test_missing_web_log_is_unreadable_too(self):
        # default web command is tail -F; a log that does not exist/cannot be read is a failing source
        self.start(SENTINEL_JOURNAL_CMD="sleep 3600", SENTINEL_UNREADABLE_SECS="1")
        evs = wait_for(lambda: [e for e in read_bus(self.bus) if e["sensor"] == "stream.source-unreadable"], 20)
        self.assertTrue(evs)
        self.assertIn("web", evs[0]["fingerprint"])

    def test_heartbeat_and_watchdog(self):
        sock_path = str(self.d / "notify.sock")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        s.bind(sock_path)
        s.settimeout(1)
        self.addCleanup(s.close)
        self.start(SENTINEL_JOURNAL_CMD="sleep 3600", SENTINEL_WEB_CMD="sleep 3600",
                   SENTINEL_HEARTBEAT_SECS="1", SENTINEL_WATCHDOG_SECS="1", NOTIFY_SOCKET=sock_path)
        hb = self.state / "stream.heartbeat"
        self.assertTrue(wait_for(hb.exists, 10))
        m1 = hb.stat().st_mtime
        self.assertTrue(wait_for(lambda: hb.stat().st_mtime > m1, 10), "heartbeat not refreshed")
        got = []
        end = time.time() + 10
        while time.time() < end and got.count(b"WATCHDOG=1") < 2:
            try:
                got.append(s.recv(100))
            except socket.timeout:
                pass
        self.assertIn(b"READY=1", got)
        self.assertGreaterEqual(got.count(b"WATCHDOG=1"), 2)

    def test_default_intervals_match_the_spec(self):
        self.assertEqual(stream.DEFAULT_HEARTBEAT_SECS, 60)
        self.assertEqual(stream.DEFAULT_WATCHDOG_SECS, 30)
        self.assertEqual(stream.DEFAULT_UNREADABLE_SECS, 300)


if __name__ == "__main__":
    unittest.main()
