#!/usr/bin/env python3
"""/etc/sudoers is read through sudo; a failing sudo is a measurement error, never a value."""

import importlib.util
import unittest
from pathlib import Path
from unittest import mock

ATLAS = Path(__file__).resolve().parent.parent


def load_atlas():
    spec = importlib.util.spec_from_file_location("atlas_mod_sudoers", ATLAS / "atlas.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class SudoersRead(unittest.TestCase):
    def setUp(self):
        self.a = load_atlas()
        self.a.MEAS_ERRORS.clear()

    def test_hashes_sudoers_through_sudo(self):
        calls = []

        def fake(cmd, timeout=25):
            calls.append(cmd)
            if cmd == "sudo sha256sum /etc/sudoers":
                return 0, "0123456789abcdef0123  /etc/sudoers\n", ""
            if cmd == "sudo ls /etc/sudoers.d":
                return 0, "", ""
            return 1, "", "unexpected"

        with mock.patch.object(self.a, "run_checked", side_effect=fake):
            res = self.a.sudoers()
        self.assertIn("sudo sha256sum /etc/sudoers", calls)
        self.assertEqual(res["/etc/sudoers"], "0123456789abcdef")
        self.assertNotIn("sudoers", self.a.MEAS_ERRORS)

    def test_failing_sudo_is_error_not_value(self):
        with mock.patch.object(self.a, "run_checked", return_value=(1, "", "sudo: a password is required")):
            res = self.a.sudoers()
        self.assertNotIn("/etc/sudoers", res)
        self.assertIn("sudoers", self.a.MEAS_ERRORS)


if __name__ == "__main__":
    unittest.main()
