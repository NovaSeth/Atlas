#!/usr/bin/env python3
"""Alert mails: multipart text + HTML, escaped untrusted text, one mail path. Temp dirs and stub binaries only."""

import json
import os
import re
import stat
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from helpers import SENTINEL, tmpdir

sys.path.insert(0, str(SENTINEL))
import mailfmt  # noqa: E402
import notify  # noqa: E402

ROOT = SENTINEL.parent
HOSTILE = '<script>alert(1)</script> <img src=x onerror=alert(2)> "><b>bold</b> & more'
DRIFT = "\n".join(
    [
        "== PACKAGES ==",
        "+ evil-pkg 1.0",
        "- old-pkg 2.0",
        "~ kernel 6.1 -> 6.2",
        "== FILES ==",
        "+ /home/" + HOSTILE + "/x",
        "plain paragraph line",
    ]
)
ENV = {"SENTINEL_EMAIL": "human@example.org", "SENTINEL_LANG": "en"}


def html_of(msg):
    return msg.get_body(preferencelist=("html",)).get_content()


def stub(d, name, script):
    p = d / name
    p.write_text("#!/bin/bash\n" + script + "\n")
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return p


class Structure(unittest.TestCase):
    def build(self, subject="[atlas] drift", body=DRIFT, kind="router", lang="en"):
        with mock.patch.dict(os.environ, ENV):
            return mailfmt.build(subject, body, kind, lang)

    def test_multipart_alternative_text_first_then_html(self):
        msg = self.build()
        self.assertEqual(msg.get_content_type(), "multipart/alternative")
        parts = list(msg.iter_parts())
        self.assertEqual([p.get_content_type() for p in parts], ["text/plain", "text/html"])

    def test_plain_part_is_the_exact_body(self):
        msg = self.build()
        self.assertEqual(msg.get_body(preferencelist=("plain",)).get_content().rstrip("\n"), DRIFT)

    def test_headers(self):
        msg = self.build()
        self.assertEqual(msg["To"], "human@example.org")
        self.assertRegex(msg["From"], r"^Atlas <atlas@[^>]+>$")
        self.assertTrue(msg["Date"])
        self.assertTrue(msg["Message-ID"])
        self.assertEqual(msg["Subject"], "[atlas] drift")

    def test_from_override(self):
        with mock.patch.dict(os.environ, dict(ENV, SENTINEL_MAIL_FROM="Box <box@example.org>")):
            msg = mailfmt.build("s", "b", "router", "en")
        self.assertIn("box@example.org", msg["From"])

    def test_hostile_text_is_escaped_in_html(self):
        msg = self.build(subject=HOSTILE, body=DRIFT)
        h = html_of(msg)
        for raw in ("<script", "<img", "onerror=alert(2)>", '"><b>bold', "<b>bold"):
            self.assertNotIn(raw, h)
        self.assertIn("&lt;script&gt;", h)
        self.assertIn("&quot;&gt;&lt;b&gt;", h)

    def test_hostile_host_name_is_escaped(self):
        with mock.patch.object(mailfmt, "_host", return_value="<i>h</i>"):
            h = html_of(self.build())
        self.assertNotIn("<i>h", h)
        self.assertIn("&lt;i&gt;h", h)

    def test_no_active_content(self):
        h = html_of(self.build()).lower()
        for bad in ("<script", "<style", "<img", "http://", "https://", "javascript:", "<link"):
            self.assertNotIn(bad, h)

    def test_sections_and_drift_lines_recognised(self):
        h = html_of(self.build())
        self.assertIn("PACKAGES", h)
        self.assertIn('data-kind="section"', h)
        self.assertEqual(len(re.findall('data-kind="added"', h)), 2)
        self.assertEqual(h.count('data-kind="removed"'), 1)
        self.assertEqual(h.count('data-kind="changed"'), 1)
        self.assertIn('data-kind="para"', h)

    def test_footer_keys_exist_in_both_languages(self):
        for lang in ("en", "pl"):
            cat = json.loads((ROOT / "i18n" / ("%s.json" % lang)).read_text())
            for key in mailfmt.I18N_KEYS:
                self.assertIn(key, cat, (lang, key))
        pl = html_of(self.build(lang="pl"))
        self.assertIn("atlas.py ack", pl)
        self.assertIn("LLM-free alert path", html_of(self.build(lang="en")))

    def test_severity_mapping_covers_every_kind_in_the_code(self):
        used = set()
        for path in [p for p in (ROOT / "sentinel").glob("*.py") if p.name != "mailfmt.py"]:
            text = path.read_text()
            used |= set(re.findall(r'send_or_queue\([^)]*?,\s*"([\w.-]+)"\)', text))
            used |= set(re.findall(r'kind="([\w.-]+)"', text))
        atlas_py = (ROOT / "atlas/atlas.py").read_text()
        used |= set(re.findall(r'\n\s+"([\w.]+)",\n    \)\n', atlas_py))
        esc = (ROOT / "sentinel/escalation.sh").read_text()
        used |= set(re.findall(r"add_problem ([\w-]+)", esc))
        used -= {"x"}
        self.assertTrue({"router", "wake-limit", "digest", "atlas.bless", "atlas.ack", "resident-dead"} <= used, used)
        for kind in sorted(used | {"unsafe-state", "ack-unrecorded"}):
            self.assertIn(kind, mailfmt.SEVERITY, kind)
        self.assertEqual(mailfmt.severity("resident-dead", "s"), "critical")
        self.assertEqual(mailfmt.severity("digest", "s"), "info")
        self.assertEqual(mailfmt.severity("no-such-kind", "s"), "alert")
        self.assertEqual(mailfmt.severity("router", "[sentinel] critical: x"), "critical")


class Sending(unittest.TestCase):
    def setUp(self):
        self.d = tmpdir(self)
        self.out = self.d / "out.bin"
        self.env = dict(ENV)

    def msg(self):
        with mock.patch.dict(os.environ, ENV):
            return mailfmt.build("subj", "body line\n== S ==\n", "router", "en")

    def test_send_mail_pipes_bytes_to_sendmail(self):
        sm = stub(self.d, "sendmail", 'echo "$@" > %s.args; cat > %s' % (self.out, self.out))
        env = dict(self.env, SENTINEL_SENDMAIL_CMD=str(sm))
        with mock.patch.dict(os.environ, env):
            m = self.msg()
            ok, err = mailfmt.send_mail(m)
        self.assertTrue(ok, err)
        self.assertEqual(Path(str(self.out) + ".args").read_text().strip(), "-t -oi")
        self.assertEqual(self.out.read_bytes(), m.as_bytes())

    def test_sendmail_failure_is_reported_without_the_message(self):
        sm = stub(self.d, "sendmail", "cat >/dev/null; echo SECRETLOG >&2; exit 75")
        with mock.patch.dict(os.environ, dict(self.env, SENTINEL_SENDMAIL_CMD=str(sm))):
            ok, err = mailfmt.send_mail(self.msg())
        self.assertFalse(ok)
        self.assertNotIn("body line", err)
        self.assertNotIn("SECRETLOG", err)

    def test_missing_sendmail_falls_back_to_mail(self):
        mailbin = stub(self.d, "mail", 'echo "MAIL $*" > %s; cat >> %s' % (self.out, self.out))
        env = dict(self.env, SENTINEL_SENDMAIL_CMD=str(self.d / "nope"), PATH="%s:%s" % (self.d, os.environ["PATH"]))
        with mock.patch.dict(os.environ, env):
            ok, err = mailfmt.send_mail(self.msg())
        self.assertTrue(ok, err)
        self.assertIn("MAIL -s subj human@example.org", self.out.read_text())
        self.assertIn("body line", self.out.read_text())
        self.assertTrue(mailbin.exists())

    def test_notify_send_uses_html_mail(self):
        sm = stub(self.d, "sendmail", "cat > %s" % self.out)
        env = dict(ENV, SENTINEL_SENDMAIL_CMD=str(sm))
        env.pop("SENTINEL_NOTIFY_CMD", None)
        with mock.patch.dict(os.environ, env):
            self.assertTrue(notify.send("subj", "hello <b>x</b>"))
        raw = self.out.read_text()
        self.assertIn("multipart/alternative", raw)
        self.assertIn("&lt;b&gt;x", raw)

    def test_notify_cli_mail_mode(self):
        sm = stub(self.d, "sendmail", "cat > %s" % self.out)
        env = dict(os.environ, **ENV, SENTINEL_SENDMAIL_CMD=str(sm))
        r = subprocess.run(
            [sys.executable, str(SENTINEL / "notify.py"), "mail", "resident-dead", "the subject"],
            input="the body\n",
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Subject: the subject", self.out.read_text())
        bad = dict(env, SENTINEL_SENDMAIL_CMD=str(self.d / "nope"), SENTINEL_MAIL_CMD=str(self.d / "nomail"))
        r = subprocess.run(
            [sys.executable, str(SENTINEL / "notify.py"), "mail", "x", "s"],
            input="b\n",
            env=bad,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(r.returncode, 0)


class EscalationUsesOnePath(unittest.TestCase):
    def test_escalation_has_no_direct_mail_calls(self):
        text = (SENTINEL / "escalation.sh").read_text()
        self.assertNotRegex(text, r"mail -s")
        self.assertIn('notify.py" mail', text)


if __name__ == "__main__":
    unittest.main()
