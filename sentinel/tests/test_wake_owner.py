"""A35: the wake budget lives where the session user can write; an unusable budget never hides alerts."""

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import bus  # noqa: E402


class WakeOwnerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.atlas = self.tmp / "atlas"
        self.atlas.mkdir()
        (self.atlas / "runtime").mkdir(mode=0o750)
        self.home = self.tmp / "home"
        self.home.mkdir()
        self.xdg = self.tmp / "xdg"
        self.xdg.mkdir()
        env = {k: v for k, v in os.environ.items() if k not in ("SENTINEL_STATE_DIR", "SENTINEL_ATLAS")}
        env.update(HOME=str(self.home), XDG_STATE_HOME=str(self.xdg))
        p = mock.patch.dict(os.environ, env, clear=True)
        p.start()
        self.addCleanup(p.stop)
        self.bus_file = self.atlas / "events.jsonl"

    def foreign(self):
        return mock.patch("os.geteuid", return_value=os.geteuid() + 1)

    def test_a_foreign_runtime_falls_back_to_the_resident_dir(self):
        with self.foreign():
            self.assertEqual(bus.wake_state_dir(self.bus_file), self.xdg / "atlas-resident" / "wake")

    def test_b_budget_persists_in_the_fallback_dir(self):
        d = None
        with self.foreign():
            d = bus.wake_state_dir(self.bus_file)
        a = bus.SharedWakeBudget(2, d)
        self.assertTrue(a.admit("s"))
        b = bus.SharedWakeBudget(2, d)
        self.assertTrue(b.admit("s"))
        self.assertFalse(bus.SharedWakeBudget(2, d).admit("s"))
        self.assertEqual(a.take_problem(), "")
        self.assertEqual(d.parent.stat().st_mode & 0o777, 0o700)

    def test_c_unusable_state_fails_open_bounded(self):
        real = self.tmp / "real"
        real.mkdir()
        link = self.tmp / "link"
        link.symlink_to(real)
        w = bus.SharedWakeBudget(2, link)
        self.assertEqual([w.admit("s"), w.admit("s"), w.admit("s")], [True, True, False])
        p = w.take_problem()
        self.assertIn("symlink", p)
        self.assertIn("kept in memory", p)
        self.assertEqual(w.take_problem(), "")

    def test_c2_group_writable_dir_fails_open(self):
        d = self.tmp / "gw"
        d.mkdir()
        os.chmod(d, 0o770)
        w = bus.SharedWakeBudget(1, d)
        self.assertTrue(w.admit("s"))
        self.assertFalse(w.admit("s"))
        self.assertIn("group-or-other-writable", w.take_problem())

    def test_d_owned_runtime_is_still_used(self):
        self.assertEqual(bus.wake_state_dir(self.bus_file), self.atlas / "runtime")

    def test_e_no_home_means_in_memory(self):
        env = {k: v for k, v in os.environ.items() if k not in ("HOME", "XDG_STATE_HOME")}
        with mock.patch.dict(os.environ, env, clear=True):
            with self.foreign():
                d = bus.wake_state_dir(self.bus_file)
            w = bus.SharedWakeBudget(1, d)
            self.assertTrue(w.admit("s"))
            self.assertFalse(w.admit("s"))
            self.assertIn("kept in memory", w.take_problem())


if __name__ == "__main__":
    unittest.main()
