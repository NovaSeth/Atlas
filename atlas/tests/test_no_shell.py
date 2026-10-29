#!/usr/bin/env python3
"""atlas.py runs no shell (audit 12), a failed command is never a value (audit 19), sections come from a registry
with an explicit error collector (audit 18), limits are named (audit 20), main is a table (audit 17)."""
import ast
import importlib.util
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ATLAS = Path(__file__).resolve().parent.parent
ROOT = ATLAS.parent


def load():
    spec = importlib.util.spec_from_file_location("atlas_noshell", ATLAS / "atlas.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    m.MEAS_ERRORS.clear()
    return m


class NoShell(unittest.TestCase):
    def setUp(self):
        self.a = load()

    def test_no_shell_true_in_product_code(self):
        for p in list(ATLAS.glob("*.py")) + list((ATLAS / "sensors").glob("*.py")) + list((ROOT / "sentinel").glob("*.py")):
            self.assertNotIn("shell=True", p.read_text(), p.name)

    def test_run_checked_passes_an_argv_list(self):
        with mock.patch.object(self.a.subprocess, "run") as r:
            r.return_value = mock.Mock(returncode=0, stdout="x\n", stderr="")
            self.assertEqual(self.a.run_checked("sudo ss -tulnpH"), (0, "x", ""))
        args, kw = r.call_args
        self.assertEqual(args[0], ["sudo", "ss", "-tulnpH"])
        self.assertFalse(kw.get("shell", False))

    def test_shell_operators_are_refused(self):
        with mock.patch.object(self.a.subprocess, "run") as r:
            for cmd in ("ls | wc -l", "a && b", "x; y", "cat x > /tmp/f", "echo $(id)", "echo `id`"):
                rc, out, _ = self.a.run_checked(cmd)
                self.assertIsNone(rc, cmd)
                self.assertTrue(out.startswith("__ERROR__"), cmd)
            r.assert_not_called()

    def test_interpolated_names_stay_one_argument(self):
        seen = []

        def fake(cmd, timeout=25):
            seen.append(self.a.argv_of(cmd))
            if cmd == "sudo ls /etc/sudoers.d":
                return 0, "evil name;rm -rf ~", ""
            return 0, "0123456789abcdef  x", ""

        with mock.patch.object(self.a, "run_checked", side_effect=fake):
            self.a.sudoers()
        self.assertIn(["sudo", "sha256sum", "/etc/sudoers.d/name;rm"], seen)
        self.assertTrue(all(len(a) == 3 for a in seen), seen)

    def test_run_returns_none_on_failure(self):
        with mock.patch.object(self.a.subprocess, "run", side_effect=OSError("boom")):
            self.assertIsNone(self.a.run("uname -r"))

    def test_host_failure_is_unknown_not_a_value(self):
        errs = {}
        with mock.patch.object(self.a, "run_checked", return_value=(None, "__ERROR__ timeout", "")):
            h = self.a.host_info(errors=errs)
        self.assertNotIn("__ERROR__", repr(h))
        self.assertIn("host", errs)

    def test_vitals_failure_is_a_question_mark_with_a_reason(self):
        with mock.patch.object(self.a, "run", return_value=None), \
                mock.patch.object(self.a, "silent_failures_checked", return_value=({}, {})):
            v = self.a.vitals()
        self.assertEqual(v["disk_used_pct"], "?")
        self.assertIn("disk", v["vitals_errors"])

    def test_sections_registry_keeps_the_order(self):
        self.assertEqual(list(self.a.SECTIONS), ["services", "timers", "listeners", "containers", "accounts",
                                                 "sudoers", "vhosts", "crontabs", "packages", "setuid",
                                                 "sensitive_files", "firewall", "apt_sources", "vitals"])

    def test_explicit_error_collector(self):
        errs = {}
        with mock.patch.object(self.a, "run_checked", return_value=(1, "", "sudo: a password is required")):
            self.a.sudoers(errors=errs)
        self.assertIn("sudoers", errs)
        self.assertNotIn("sudoers", self.a.MEAS_ERRORS)

    def test_main_is_a_dispatch_table_and_unknown_runs_check(self):
        self.assertEqual(set(self.a.COMMANDS), {"bless", "ack", "thresholds", "silent", "snap", "show", "check"})
        with mock.patch.dict(self.a.COMMANDS, {"check": lambda: 7}), mock.patch.object(sys, "argv", ["atlas.py", "nonsense"]):
            self.assertEqual(self.a.main(), 7)

    def test_named_limits_only(self):
        src = (ATLAS / "atlas.py").read_text()
        for pat in (r"\[:220\]", r"\[:16\]", r"\[:70\]", r"\[:200\]", r"timeout=\d"):
            self.assertIsNone(re.search(pat, src), pat)

    def test_functions_are_short(self):
        tree = ast.parse((ATLAS / "atlas.py").read_text())
        long_ = [(n.name, n.end_lineno - n.lineno + 1) for n in ast.walk(tree)
                 if isinstance(n, ast.FunctionDef) and n.end_lineno - n.lineno + 1 > 50]
        self.assertEqual(long_, [])


class SshSensorNoShell(unittest.TestCase):
    def test_journal_command_is_not_a_shell_line(self):
        d = Path(tempfile.mkdtemp(prefix="ssh-noshell-"))
        canary = d / "canary"
        (d / "known.txt").write_text("198.51.100.4\n")
        env = dict(os.environ, SSH_JOURNAL_CMD="cat %s; touch %s" % (d / "j.log", canary),
                   SSH_KNOWN_IPS=str(d / "known.txt"))
        r = subprocess.run([sys.executable, str(ATLAS / "sensors" / "ssh_logins.py")], env=env,
                           capture_output=True, text=True, timeout=30)
        self.assertFalse(canary.exists())
        self.assertEqual(r.returncode, 2)
