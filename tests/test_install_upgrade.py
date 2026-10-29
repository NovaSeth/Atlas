#!/usr/bin/env python3
"""Installer: refuses paths that would break sed/systemd rendering (audit 21), creates and migrates the runtime state
(audit 8) and restarts the stream on upgrade. Dry runs only: no root, no system change."""
import os
import pwd
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / "install.sh"
ME = pwd.getpwuid(os.getuid()).pw_name


class InstallUpgrade(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="atlas-upgrade-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.state = self.tmp / "state"

    def dry(self, *args, code="/opt/atlas", user="atlas-test-nobody", env=None):
        e = dict(os.environ, **(env or {}))
        return subprocess.run(["bash", str(INSTALL), "--dry-run", "--code", code, "--state", str(self.state),
                               "--user", user, *args], capture_output=True, text=True, timeout=120, env=e)

    def test_odd_characters_in_paths_are_refused_before_any_action(self):
        for bad in ("/opt/at las", "/opt/a|b", "/opt/a&b", "/opt/a%b", "/opt/a\\b"):
            r = self.dry(code=bad)
            self.assertEqual(r.returncode, 2, bad)
            self.assertIn("may contain only", r.stderr)
            self.assertNotIn("[dry-run]", r.stdout)

    def test_bad_user_name_is_refused(self):
        r = self.dry(user="Atlas;rm")
        self.assertEqual(r.returncode, 2)

    def test_runtime_dir_is_created(self):
        r = self.dry()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("install -d -m 0750 -o atlas-test-nobody", r.stdout)
        self.assertIn("%s/runtime" % self.state, r.stdout)

    def test_legacy_state_owned_by_the_atlas_user_is_migrated(self):
        legacy = self.tmp / "legacy"
        legacy.mkdir()
        (legacy / "escalation.log").write_text("x\n")
        (legacy / "sent-patrol-silent").write_text("")
        r = self.dry(user=ME, env={"ATLAS_LEGACY_STATE": str(legacy)})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("mv %s/escalation.log %s/runtime/escalation.log" % (legacy, self.state), r.stdout)
        self.assertIn("rm -rf --one-file-system %s" % legacy, r.stdout)
        self.assertTrue((legacy / "escalation.log").exists())

    def test_foreign_or_symlinked_legacy_state_is_left_alone(self):
        real = self.tmp / "real"
        real.mkdir()
        link = self.tmp / "legacy"
        link.symlink_to(real)
        r = self.dry(user=ME, env={"ATLAS_LEGACY_STATE": str(link)})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("not migrated", r.stderr)
        self.assertNotIn("rm -rf --one-file-system %s" % link, r.stdout)

    def test_stream_is_restarted_after_the_units(self):
        out = self.dry().stdout
        self.assertIn("systemctl try-restart sentinel-stream.service", out)
        self.assertLess(out.index("systemctl daemon-reload"), out.index("systemctl try-restart sentinel-stream.service"))

    def _overlap(self, legacy, state=None, code="/opt/atlas"):
        legacy.mkdir(parents=True, exist_ok=True)
        (legacy / "escalation.log").write_text("x\n")
        if state is not None:
            self.state = state
        r = self.dry(user=ME, code=code, env={"ATLAS_LEGACY_STATE": str(legacy)})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("rm -rf --one-file-system %s" % legacy, r.stdout)
        self.assertNotIn("mv %s/" % legacy, r.stdout)
        self.assertIn("overlaps", r.stderr)

    def test_legacy_equal_to_state_is_never_removed(self):
        self._overlap(self.tmp / "legacy", state=self.tmp / "legacy")

    def test_state_inside_legacy_is_never_removed(self):
        legacy = self.tmp / "legacy"
        self._overlap(legacy, state=legacy / "st")

    def test_legacy_inside_state_is_never_removed(self):
        self._overlap(self.state / "old")

    def test_legacy_overlapping_code_is_never_removed(self):
        legacy = self.tmp / "legacy"
        self._overlap(legacy, code=str(legacy / "code"))
        self._overlap(self.tmp / "legacy2", code=str(self.tmp))

    def test_legacy_reached_through_a_symlinked_state_is_never_removed(self):
        legacy = self.tmp / "legacy"
        legacy.mkdir()
        link = self.tmp / "lnk"
        link.symlink_to(legacy)
        self._overlap(legacy, state=link)


if __name__ == "__main__":
    unittest.main()
