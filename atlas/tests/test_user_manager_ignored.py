#!/usr/bin/env python3
"""A23: the per-login user@<uid>.service manager must not show up as drift in services.running."""

import importlib.util
import unittest
from pathlib import Path
from unittest import mock

ATLAS = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("atlas_mod", ATLAS / "atlas.py")
atlas = importlib.util.module_from_spec(spec)
spec.loader.exec_module(atlas)

RUNNING = (
    "ssh.service loaded active running OpenBSD Secure Shell server\n"
    "user@1000.service loaded active running User Manager for UID 1000\n"
    "user@0.service loaded active running User Manager for UID 0\n"
    "user-runtime-dir@1000.service loaded active exited User Runtime Directory /run/user/1000\n"
    "user@abc.service loaded active running not a uid\n"
    "user.service loaded active running something else\n"
    "userd@1000.service loaded active running lookalike\n"
    "user@1000.service.bak loaded active running lookalike\n"
)


def fake_measure(section, cmd, **kw):
    return RUNNING if "--state=running" in cmd else "ssh.service enabled enabled\n"


class TestUserManagerIgnored(unittest.TestCase):
    def test_predicate_exact_shape(self):
        f = atlas.is_per_login_unit
        self.assertTrue(f("user@1000.service"))
        self.assertTrue(f("user@0.service"))
        for n in ("user@.service", "user@abc.service", "user.service", "userd@1000.service", "user@1000.service.bak"):
            self.assertFalse(f(n), n)

    def test_collector_filters_only_user_manager(self):
        with mock.patch.object(atlas, "measure", fake_measure):
            running = atlas.services()["running"]
        self.assertEqual(
            running,
            sorted(
                [
                    "ssh.service",
                    "user-runtime-dir@1000.service",
                    "user@abc.service",
                    "user.service",
                    "userd@1000.service",
                    "user@1000.service.bak",
                ]
            ),
        )

    def test_old_baseline_is_normalized(self):
        old = {"services": {"running": ["ssh.service", "user@1000.service"], "enabled": ["ssh.service"]}, "x": 1}
        new = {"services": {"running": ["ssh.service"], "enabled": ["ssh.service"]}, "x": 1}
        self.assertEqual(atlas.diff(atlas.without_per_login_units(old), new), [])
        self.assertEqual(atlas.changed_sections(atlas.without_per_login_units(old), new), [])
        self.assertIn("user@1000.service", old["services"]["running"])  # input not mutated

    def test_normalize_tolerates_odd_shapes(self):
        for snap in ({}, {"services": None}, {"services": {}}, {"services": {"running": "x"}}):
            self.assertEqual(atlas.without_per_login_units(snap), snap)


if __name__ == "__main__":
    unittest.main()
