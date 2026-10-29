#!/usr/bin/env python3
"""install.sh --resident-user / --permission-mode / --resident-name: the trust level is the operator's explicit
choice; the installer renders the resident files but never enables or starts the unit. uninstall.sh removes them."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / "install.sh"
UNINSTALL = ROOT / "uninstall.sh"


class InstallResident(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="atlas-install-res-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.state = self.tmp / "state"
        self.etc = self.tmp / "etc" / "atlas"  # private config dir: tests never read the real /etc

    def run_install(self, *args):
        return subprocess.run(
            [
                "bash",
                str(INSTALL),
                "--dry-run",
                "--code",
                "/opt/atlas",
                "--state",
                str(self.state),
                "--user",
                "atlas-test-nobody",
                *args,
            ],
            capture_output=True,
            text=True,
            timeout=120,
            stdin=subprocess.DEVNULL,
            env={**os.environ, "ATLAS_ETC_DIR": str(self.etc)},
        )

    def test_resident_user_without_mode_is_refused(self):
        r = self.run_install("--resident-user", "ops-test")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        for word in ("--permission-mode", "default", "acceptEdits", "plan", "bypassPermissions"):
            self.assertIn(word, r.stderr)
        self.assertNotIn("[dry-run]", r.stdout)

    def test_resident_user_without_mode_is_refused_even_with_yes(self):
        r = self.run_install("--resident-user", "ops-test", "--yes")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)

    def test_invalid_mode_is_refused(self):
        r = self.run_install("--resident-user", "ops-test", "--permission-mode", "yolo")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("bypassPermissions", r.stderr)

    def test_invalid_resident_name_is_refused(self):
        r = self.run_install("--resident-user", "ops-test", "--permission-mode", "default", "--resident-name", "a b|c")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)

    def test_dry_run_renders_both_files(self):
        r = self.run_install(
            "--resident-user", "ops-test", "--permission-mode", "acceptEdits", "--resident-name", "atlas-box"
        )
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        out = r.stdout
        self.assertRegex(out, r"install -m 0644 -o root -g root \S+ \S*/atlas/resident\.env")
        self.assertRegex(out, r"install -m 0644 \S+ /etc/systemd/system/atlas-resident\.service")
        self.assertIn('RESIDENT_PERMISSION_MODE="acceptEdits"', out)
        self.assertIn('RESIDENT_NAME="atlas-box"', out)
        self.assertIn('SENTINEL_ATLAS="%s"' % self.state, out)
        self.assertIn('ATLAS_CODE="/opt/atlas"', out)
        self.assertIn("User=ops-test", out)
        self.assertIn("ExecStart=/opt/atlas/examples/resident/start-resident.sh", out)
        self.assertIn("<home of ops-test>/.local/bin:/usr/local/bin", out)
        self.assertNotIn("/ho" + "me/ops-test", out)
        self.assertNotRegex(out, r"@[A-Z_]+@")
        self.assertNotIn("--allow-dangerously-skip-permissions", out)
        self.assertNotRegex(
            out, r"\[dry-run\].*sed.*SENTINEL_RESIDENT_UNIT"
        )  # set after the enable step (first_run tests)
        # never enabled or started by the installer
        self.assertNotRegex(out, r"\[dry-run\].*(enable|start).*atlas-resident")
        self.assertIn("claude auth login", out)
        self.assertIn("systemctl enable --now atlas-resident", out)

    def test_model_and_effort_are_rendered_and_summarised(self):
        r = self.run_install(
            "--resident-user", "ops-test", "--permission-mode", "plan", "--model", "claude-opus-5-5", "--effort", "high"
        )
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('RESIDENT_MODEL="claude-opus-5-5"', r.stdout)
        self.assertIn('RESIDENT_EFFORT="high"', r.stdout)
        self.assertIn("model claude-opus-5-5", r.stdout)
        self.assertIn("effort high", r.stdout)

    def test_without_model_and_effort_summary_says_account_default(self):
        r = self.run_install("--resident-user", "ops-test", "--permission-mode", "plan")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("model account default", r.stdout)
        self.assertIn("effort account default", r.stdout)

    def test_bad_effort_and_model_are_refused(self):
        for flag, bad in (("--effort", "ultra"), ("--model", "Bad Model")):
            r = self.run_install("--resident-user", "ops-test", "--permission-mode", "plan", flag, bad)
            self.assertEqual(r.returncode, 2, flag)
            self.assertIn(flag, r.stderr)

    def test_model_and_effort_need_resident_user(self):
        for flag, val in (("--effort", "high"), ("--model", "opus")):
            r = self.run_install(flag, val)
            self.assertEqual(r.returncode, 2, flag)

    def test_existing_env_upgrade_prints_how_to_change_keys(self):
        self.etc.mkdir(parents=True)
        (self.etc / "resident.env").write_text("RESIDENT_PERMISSION_MODE=plan\n")
        r = self.run_install("--resident-user", "ops-test", "--permission-mode", "plan")
        self.assertIn("RESIDENT_MODEL", r.stdout)
        self.assertIn("RESIDENT_EFFORT", r.stdout)

    def test_docs_name_both_keys(self):
        root = Path(__file__).resolve().parents[1]
        for f in ("docs/resident.md", "docs/quickstart.md"):
            t = (root / f).read_text()
            self.assertIn("RESIDENT_MODEL", t, f)
            self.assertIn("RESIDENT_EFFORT", t, f)
        readme = (root / "README.md").read_text()
        self.assertIn("--model", readme)
        self.assertIn("--effort", readme)
        self.assertIn("## Model and effort", (root / "docs/resident.md").read_text())

    def test_upgrade_without_resident_user_reports_configured_resident(self):
        self.etc.mkdir(parents=True)
        env = self.etc / "resident.env"
        env.write_text('RESIDENT_PERMISSION_MODE="plan"\nRESIDENT_MODEL="opus"\nRESIDENT_EFFORT=\n')
        before = env.read_text()
        r = self.run_install()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(
            f"AI resident: configured (trust level plan, model opus, effort account default); edit {env} to change",
            r.stdout,
        )
        self.assertNotIn("not set up", r.stdout)
        self.assertEqual(env.read_text(), before)

    def test_existing_resident_env_is_kept(self):
        self.etc.mkdir(parents=True)
        (self.etc / "resident.env").write_text("RESIDENT_PERMISSION_MODE=plan\n")
        r = self.run_install("--resident-user", "ops-test", "--permission-mode", "acceptEdits")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(f"keeping existing {self.etc}/resident.env", r.stdout)
        self.assertNotRegex(r.stdout, r"install -m 0644 -o root -g root \S+ \S*/atlas/resident\.env")

    def test_bypass_adds_allow_flag_and_warning(self):
        r = self.run_install("--resident-user", "ops-test", "--permission-mode", "bypassPermissions")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('RESIDENT_EXTRA_ARGS="--allow-dangerously-skip-permissions"', r.stdout)
        self.assertIn("WITHOUT asking", r.stdout + r.stderr)

    def test_without_resident_user_prints_hint_and_no_files(self):
        r = self.run_install()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("AI resident (optional)", r.stdout)
        self.assertIn("quickstart.md", r.stdout)
        self.assertNotIn("atlas-resident", r.stdout.replace("AI resident (optional)", ""))
        self.assertNotIn("resident.env", r.stdout.split("AI resident (optional)")[0])

    def broken_tree(self, template_text):
        """A copy of the installer with its examples, and the resident.env template replaced (None = removed)."""
        tree = self.tmp / "tree"
        shutil.copytree(ROOT / "examples", tree / "examples")
        shutil.copytree(ROOT / "sentinel", tree / "sentinel", ignore=shutil.ignore_patterns("tests", "__pycache__"))
        shutil.copy(INSTALL, tree / "install.sh")
        env = tree / "examples" / "resident" / "resident.env"
        env.unlink(missing_ok=True)
        if template_text is not None:
            env.write_text(template_text)
        return tree

    def run_tree(self, tree):
        return subprocess.run(
            [
                "bash",
                str(tree / "install.sh"),
                "--dry-run",
                "--code",
                "/opt/atlas",
                "--state",
                str(self.state),
                "--user",
                "atlas-test-nobody",
                "--resident-user",
                "ops-test",
                "--permission-mode",
                "default",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            stdin=subprocess.DEVNULL,
            env={**os.environ, "ATLAS_ETC_DIR": str(self.etc)},
        )

    def test_missing_template_is_refused(self):
        r = self.run_tree(self.broken_tree(None))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("resident.env", r.stderr)

    def test_template_without_permission_line_is_refused(self):
        r = self.run_tree(self.broken_tree("RESIDENT_NAME=x\n"))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("RESIDENT_PERMISSION_MODE", r.stderr)

    def test_empty_template_is_refused(self):
        r = self.run_tree(self.broken_tree(""))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)

    def test_uninstall_removes_resident_unit_and_env(self):
        r = subprocess.run(
            ["bash", str(UNINSTALL), "--dry-run", "--state", str(self.state), "--user", "atlas-test-nobody"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("atlas-resident.service", r.stdout)
        self.assertRegex(r.stdout, r"rm -f \S*/atlas/resident\.env")


if __name__ == "__main__":
    unittest.main()
