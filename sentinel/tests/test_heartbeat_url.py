"""Optional external heartbeat (audit 5, D4): empty URL = no network call; set = one GET per clean run; the URL
is never logged."""

import http.server
import os
import socket
import subprocess
import threading
import unittest

# helpers puts sentinel/ on sys.path: it must be imported before the modules below
from helpers import SENTINEL, tmpdir
import notify  # noqa: E402

ESC = SENTINEL / "escalation.sh"


class Server:
    def __init__(self):
        self.paths = []
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                outer.paths.append(self.path)
                self.send_response(200)
                self.end_headers()

            def log_message(self, *a):
                pass

        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()


class Heartbeat(unittest.TestCase):
    def setUp(self):
        self.d = tmpdir(self)
        self.srv = Server()
        self.addCleanup(self.srv.close)
        self.atlas, self.bin = self.d / "atlas", self.d / "bin"
        self.atlas.mkdir()
        self.bin.mkdir()
        for n, body in (("mail", "cat >/dev/null"), ("screen", "exit 0"), ("systemctl", "exit 0")):
            (self.bin / n).write_text("#!/bin/bash\n%s\n" % body)
            (self.bin / n).chmod(0o755)
        (self.atlas / "heartbeat.log").write_text("x ok\n")
        self.hb = self.d / "hb"

    def run_esc(self, url):
        self.hb.touch()
        env = dict(
            os.environ,
            SENTINEL_ATLAS=str(self.atlas),
            SENTINEL_STATE=str(self.d / "st"),
            SENTINEL_STREAM_HEARTBEAT=str(self.hb),
            SENTINEL_EMAIL="nobody@example.com",
            SENTINEL_NOTIFY_CMD="",
            SENTINEL_LANG="en",
            SENTINEL_RESIDENT_UNIT="",
            SENTINEL_RESIDENT_SCREEN="",
            SENTINEL_HEARTBEAT_URL=url,
            PATH="%s:%s" % (self.bin, os.environ["PATH"]),
        )
        r = subprocess.run(["bash", str(ESC)], env=env, capture_output=True, text=True, timeout=90)
        return r.returncode, (self.d / "st" / "escalation.log").read_text()

    def test_empty_url_makes_no_request(self):
        rc, log = self.run_esc("")
        self.assertEqual(rc, 0)
        self.assertEqual(self.srv.paths, [])
        self.assertNotIn("external heartbeat", log)

    def test_url_gets_one_get_per_clean_run_and_is_never_logged(self):
        rc, log = self.run_esc("http://127.0.0.1:%d/ping/secret-token-123" % self.srv.port)
        self.assertEqual(rc, 0)
        self.assertEqual(self.srv.paths, ["/ping/secret-token-123"])
        self.assertIn("external heartbeat: sent", log)
        self.assertNotIn("secret-token-123", log)

    def test_problem_run_does_not_ping(self):
        (self.atlas / "heartbeat.log").unlink()
        rc, _ = self.run_esc("http://127.0.0.1:%d/ping/x" % self.srv.port)
        self.assertEqual(rc, 1)
        self.assertEqual(self.srv.paths, [])

    def test_failed_ping_is_logged_and_not_fatal(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        rc, log = self.run_esc("http://127.0.0.1:%d/x" % port)
        self.assertEqual(rc, 0)
        self.assertIn("external heartbeat: FAILED", log)

    def test_only_http_schemes(self):
        for url in ("file:///etc/passwd", "ftp://127.0.0.1/x", "http:///nohost", "not a url"):
            self.assertFalse(notify.ping(url), url)


class PingContract(unittest.TestCase):
    """Socket-free contract checks also run in the implementer sandbox."""

    def test_empty_and_invalid_urls_never_open(self):
        from unittest import mock

        with (
            mock.patch.dict(os.environ, {"SENTINEL_HEARTBEAT_URL": ""}),
            mock.patch("urllib.request.OpenerDirector.open") as opened,
        ):
            for url in (None, "", "file:///etc/passwd", "ftp://localhost/x", "http:///nohost", "http://["):
                self.assertFalse(notify.ping(url))
            opened.assert_not_called()

    def test_get_header_timeout_and_status(self):
        from unittest import mock

        response = mock.MagicMock()
        response.__enter__.return_value = response
        with mock.patch("urllib.request.OpenerDirector.open", return_value=response) as opened:
            for status in (200, 204, 299, 300, 500):
                response.status = status
                self.assertEqual(notify.ping("https://example.com/token", timeout=3), 200 <= status < 300)
            request = opened.call_args.args[0]
            self.assertEqual(request.get_method(), "GET")
            self.assertEqual(request.get_header("User-agent"), "atlas-escalation")
            self.assertEqual(opened.call_args.kwargs["timeout"], 3)

    def test_environment_failure_and_cli_are_quiet(self):
        import contextlib
        import io
        from unittest import mock

        output = io.StringIO()
        with (
            mock.patch.dict(os.environ, {"SENTINEL_HEARTBEAT_URL": "https://example.com/secret"}),
            mock.patch("urllib.request.OpenerDirector.open", side_effect=OSError("secret")),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(output),
        ):
            self.assertFalse(notify.ping())
            self.assertEqual(notify.main(["ping"]), 1)
        self.assertEqual(output.getvalue(), "")
        with mock.patch.object(notify, "ping", return_value=True):
            self.assertEqual(notify.main(["ping"]), 0)


class EscalationPingContract(unittest.TestCase):
    """Exercise shell wiring with a ping stub; other Python helpers remain real."""

    run_esc = Heartbeat.run_esc

    def setUp(self):
        import shlex
        import sys

        self.d = tmpdir(self)
        self.atlas, self.bin = self.d / "atlas", self.d / "bin"
        self.atlas.mkdir()
        self.bin.mkdir()
        self.calls = self.d / "ping-calls"
        self.result = self.d / "ping-result"
        self.result.write_text("0")
        bodies = (
            ("mail", "cat >/dev/null"),
            ("screen", "exit 0"),
            ("systemctl", "exit 0"),
            (
                "python3",
                'if [ "$1" = -I ] && [ "$3" = ping ]; then\n'
                'echo ping >> %s\nexit "$(cat %s)"\nfi\nexec %s "$@"'
                % (shlex.quote(str(self.calls)), shlex.quote(str(self.result)), shlex.quote(sys.executable)),
            ),
        )
        for name, body in bodies:
            stub = self.bin / name
            stub.write_text("#!/bin/bash\n%s\n" % body)
            stub.chmod(0o755)
        (self.atlas / "heartbeat.log").write_text("x ok\n")
        self.hb = self.d / "hb"

    def test_empty_and_problem_runs_never_invoke_ping(self):
        rc, log = self.run_esc("")
        self.assertEqual(rc, 0)
        self.assertFalse(self.calls.exists())
        self.assertNotIn("external heartbeat", log)
        (self.atlas / "heartbeat.log").unlink()
        rc, _ = self.run_esc("https://example.com/secret")
        self.assertEqual(rc, 1)
        self.assertFalse(self.calls.exists())

    def test_clean_run_invokes_once_and_failure_stays_nonfatal(self):
        for result, message in (("0", "sent"), ("1", "FAILED")):
            self.result.write_text(result)
            rc, log = self.run_esc("https://example.com/secret")
            self.assertEqual(rc, 0)
            lines = log.splitlines()
            self.assertIn("ok (", lines[-2])
            self.assertIn("external heartbeat: " + message, lines[-1])
            self.assertNotIn("secret", log)
        self.assertEqual(self.calls.read_text().splitlines(), ["ping", "ping"])
