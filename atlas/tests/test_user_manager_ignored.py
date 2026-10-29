#!/usr/bin/env python3
"""A23: the per-login user@<uid>.service manager must not show up as drift in services.running."""

import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

ATLAS = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("atlas_mod", ATLAS / "atlas.py")
atlas = importlib.util.module_from_spec(spec)
spec.loader.exec_module(atlas)


def at(prefix, rest):
    """prefix@rest, assembled so no literal looks like a mail address (tests/test_product_rules.py)."""
    return prefix + "@" + rest


RUNNING = "".join(
    [
        "ssh.service loaded active running OpenBSD Secure Shell server\n",
        at("user", "1000.service") + " loaded active running User Manager for UID 1000\n",
        at("user", "0.service") + " loaded active running User Manager for UID 0\n",
        at("user-runtime-dir", "1000.service") + " loaded active exited User Runtime Directory\n",
        at("user", "abc.service") + " loaded active running not a uid\n",
        "user.service loaded active running something else\n",
        at("userd", "1000.service") + " loaded active running lookalike\n",
        at("user", "1000.service.bak") + " loaded active running lookalike\n",
    ]
)


def fake_measure(section, cmd, **kw):
    return RUNNING if "--state=running" in cmd else "ssh.service enabled enabled\n"


class TestUserManagerIgnored(unittest.TestCase):
    def test_predicate_exact_shape(self):
        f = atlas.is_per_login_unit
        self.assertTrue(f(at("user", "1000.service")))
        self.assertTrue(f(at("user", "0.service")))
        for n in (
            at("user", ".service"),
            at("user", "abc.service"),
            "user.service",
            at("userd", "1000.service"),
            at("user", "1000.service.bak"),
        ):
            self.assertFalse(f(n), n)

    def test_collector_filters_only_user_manager(self):
        with mock.patch.object(atlas, "measure", fake_measure):
            running = atlas.services()["running"]
        self.assertEqual(
            running,
            sorted(
                [
                    "ssh.service",
                    at("user-runtime-dir", "1000.service"),
                    at("user", "abc.service"),
                    "user.service",
                    at("userd", "1000.service"),
                    at("user", "1000.service.bak"),
                ]
            ),
        )

    def test_old_baseline_is_normalized(self):
        old = {"services": {"running": ["ssh.service", at("user", "1000.service")], "enabled": ["ssh.service"]}, "x": 1}
        new = {"services": {"running": ["ssh.service"], "enabled": ["ssh.service"]}, "x": 1}
        self.assertEqual(atlas.diff(atlas.without_per_login_units(old), new), [])
        self.assertEqual(atlas.changed_sections(atlas.without_per_login_units(old), new), [])
        self.assertIn(at("user", "1000.service"), old["services"]["running"])  # input not mutated

    def test_normalize_tolerates_odd_shapes(self):
        for snap in ({}, {"services": None}, {"services": {}}, {"services": {"running": "x"}}):
            self.assertEqual(atlas.without_per_login_units(snap), snap)

    def test_uid_is_bounded(self):
        self.assertTrue(atlas.is_per_login_unit(at("user", "4294967295.service")))
        self.assertFalse(atlas.is_per_login_unit(at("user", "99999999999999999999.service")))
        self.assertFalse(atlas.is_per_login_unit(at("user", "12345678901.service")))


sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_bless_ack import SNAP, Case  # noqa: E402


def with_running(names):
    snap = json.loads(json.dumps(SNAP))
    snap["services"] = {"running": sorted(names), "enabled": []}
    return snap


UM = at("user", "1000.service")


class TestEndToEnd(Case):
    """cmd_check and cmd_bless through main(), with a stubbed snapshot and a baseline file."""

    def baseline(self, names):
        (self.tmp / "baseline.json").write_text(json.dumps(with_running(names)))

    def test_check_running_user_manager_is_no_drift(self):
        self.baseline(["ssh.service"])
        rc, out, _ = self.main("check", with_running(["ssh.service", UM]))
        self.assertEqual(rc, 0, out)

    def test_check_old_baseline_with_user_manager_is_no_removed(self):
        self.baseline(["ssh.service", UM])
        rc, out, _ = self.main("check", with_running(["ssh.service"]))
        self.assertEqual(rc, 0, out)
        self.assertNotIn("REMOVED", out)

    def test_check_normal_service_drifts_both_ways(self):
        self.baseline(["ssh.service", "old.service"])
        rc, out, _ = self.main("check", with_running(["ssh.service", "new.service", UM]))
        self.assertEqual(rc, 1)
        self.assertIn("ADDED", out)
        self.assertIn("new.service", out)
        self.assertIn("REMOVED", out)
        self.assertIn("old.service", out)
        self.assertNotIn("user@", out)

    def test_bless_old_baseline_with_user_manager_names_no_section(self):
        self.baseline(["ssh.service", UM])
        self.main("snap", with_running(["ssh.service"]))
        self.assertEqual(self.main("bless")[0], 0)
        ev = [e for e in self.bus() if e["sensor"] == "atlas.bless"][-1]
        self.assertEqual(ev["evidence"]["sections"], [])

    def test_bless_normal_service_change_names_services(self):
        self.baseline(["ssh.service", UM])
        self.main("snap", with_running(["ssh.service", "new.service"]))
        self.assertEqual(self.main("bless")[0], 0)
        ev = [e for e in self.bus() if e["sensor"] == "atlas.bless"][-1]
        self.assertEqual(ev["evidence"]["sections"], ["services"])


if __name__ == "__main__":
    unittest.main()
