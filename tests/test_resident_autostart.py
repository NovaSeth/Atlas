#!/usr/bin/env python3
"""The resident start script and its unit (A28): the agent session comes back after a reboot, and refuses
loudly when a login is gone. No root, no real claude or screen: stub executables on PATH."""

import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "examples" / "resident" / "start-resident.sh"
ENVTPL = ROOT / "examples" / "resident" / "resident.env"
UNIT = ROOT / "examples" / "systemd" / "atlas-resident.service"


def stub(path, body="exit 0"):
    path.write_text("#!/bin/sh\n" + body + "\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class StartScript(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.state = self.tmp / "state"
        self.state.mkdir()
        self.work = self.tmp / "work"
        self.work.mkdir()
        self.trace = self.tmp / "trace"
        stub(self.bin / "curl")
        stub(
            self.bin / "claude",
            f'echo "claude $*" >> {self.trace}\n[ "$1" = auth ] && exit ${{CLAUDE_AUTH_RC:-0}}\nexit 0',
        )
        stub(self.bin / "screen", f'echo "screen $*" >> {self.trace}\nexit ${{SCREEN_LS_RC:-1}}')
        stub(self.bin / "codex", "echo SECRET-ACCOUNT-DATA; exit 1")
        stub(self.bin / "sleep")
        self.env_file = self.tmp / "resident.env"
        self.write_env()

    def write_env(self, extra=""):
        self.env_file.write_text(
            f"RESIDENT_DIR={self.work}\nRESIDENT_SESSION=claude\nRESIDENT_NAME=atlas-server\n"
            f"RESIDENT_CLAUDE={self.bin}/claude\nSENTINEL_ATLAS={self.state}\nATLAS_CODE=/opt/atlas\n{extra}"
        )

    def run_script(self, *args, **env):
        e = {"PATH": f"{self.bin}:/usr/bin:/bin", "RESIDENT_ENV": str(self.env_file), "HOME": str(self.tmp)}
        e.update(env)
        return subprocess.run(
            ["bash", str(SCRIPT), *args], env=e, capture_output=True, text=True, timeout=30, cwd=self.tmp
        )

    def test_off_switch_exits_zero_without_exec(self):
        (self.state / "RESIDENT-OFF").write_text("")
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("off switch present", r.stderr)
        self.assertFalse(self.trace.exists())

    def test_existing_session_exits_zero(self):
        stub(self.bin / "screen", 'echo "\t123.claude\t(Detached)"; exit 0')
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("already exists", r.stderr)
        self.assertFalse(self.trace.exists())

    def test_network_down_exits_one(self):
        stub(self.bin / "curl", "exit 6")
        r = self.run_script()
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("network", r.stderr)

    def test_not_logged_in_exits_three_with_message(self):
        r = self.run_script(CLAUDE_AUTH_RC="1")
        self.assertEqual(r.returncode, 3, r.stderr)
        self.assertIn("agent not logged in: run `claude auth login` as", r.stderr)
        self.assertFalse((self.state / "BOOT").exists())

    def test_extra_check_failure_names_check_and_hides_output(self):
        self.write_env('RESIDENT_AUTH_CHECKS="codex login status"\n')
        r = self.run_script()
        self.assertEqual(r.returncode, 3, r.stderr)
        self.assertIn("codex login status", r.stderr)
        self.assertNotIn("SECRET-ACCOUNT-DATA", r.stdout + r.stderr)

    def test_happy_path_dry_run_prints_argv(self):
        r = self.run_script("--dry-run")
        self.assertEqual(r.returncode, 0, r.stderr)
        out = r.stdout
        for part in ("--remote-control", "-n", "atlas-server", "--permission-mode", "default", "-DmS"):
            self.assertIn(part, out)
        for part in ("AGENTS.md", "BOOT", "AFTER-REBOOT.md", "/opt/atlas/sentinel/session-sensor.sh"):
            self.assertIn(part, out)
        self.assertIn(f"SENTINEL_ATLAS={self.state}", out)
        self.assertNotIn("screen -DmS", self.trace.read_text() if self.trace.exists() else "")

    def test_real_run_writes_boot_and_execs_screen(self):
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stderr)
        boot = (self.state / "BOOT").read_text()
        self.assertIn("Kernel:", boot)
        self.assertIn("screen -DmS claude", self.trace.read_text())

    def test_permission_mode_is_configurable(self):
        self.write_env("RESIDENT_PERMISSION_MODE=plan\n")
        r = self.run_script("--dry-run")
        self.assertIn("plan", r.stdout)

    def test_default_env_path_is_etc_atlas(self):
        self.assertIn("/etc/atlas/resident.env", SCRIPT.read_text())


class Templates(unittest.TestCase):
    def test_unit_template(self):
        t = UNIT.read_text()
        for needle in (
            "@ATLAS_CODE@",
            "@ATLAS_STATE@",
            "@RESIDENT_USER@",
            "User=@RESIDENT_USER@",
            "Type=exec",
            "Restart=on-failure",
            "RestartSec=60",
            "StartLimitIntervalSec=3600",
            "StartLimitBurst=5",
            "After=network-online.target",
            "Environment=RESIDENT_ENV=/etc/atlas/resident.env",
            "ExecStart=@ATLAS_CODE@/examples/resident/start-resident.sh",
            "SENTINEL_RESIDENT_UNIT=atlas-resident.service",
        ):
            self.assertIn(needle, t)
        body = "\n".join(ln for ln in t.splitlines() if not ln.startswith("#"))
        self.assertNotRegex(body, r"/(opt|home|var)/")

    def test_env_template_keys(self):
        t = ENVTPL.read_text()
        for k in (
            "RESIDENT_DIR=/home/ops/resident",
            "RESIDENT_SESSION=",
            "RESIDENT_NAME=",
            "RESIDENT_PERMISSION_MODE=default",
            "RESIDENT_CLAUDE=",
            "RESIDENT_AUTH_CHECKS=",
            "SENTINEL_ATLAS=/var/lib/atlas",
            "ATLAS_CODE=/opt/atlas",
            "codex login status",
            "bypassPermissions",
        ):
            self.assertIn(k, t)

    @unittest.skipUnless(shutil.which("shellcheck"), "shellcheck not installed")
    def test_shellcheck(self):
        r = subprocess.run(["shellcheck", "-x", str(SCRIPT)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)


class Docs(unittest.TestCase):
    def read(self, p):
        return (ROOT / p).read_text()

    def test_resident_doc_logins_section(self):
        t = self.read("docs/resident.md")
        self.assertIn("Logins and restarts", t)
        for needle in (
            ".claude/.credentials.json",
            "claude auth status",
            ".codex/auth.json",
            "codex login status",
            "codex login --device-auth",
            "ANTHROPIC_API_KEY",
            "SENTINEL_RESIDENT_UNIT=atlas-resident.service",
            "systemctl restart atlas-resident",
        ):
            self.assertIn(needle, t)

    def test_quickstart_uses_shipped_files(self):
        t = self.read("docs/quickstart.md")
        for needle in (
            "examples/systemd/atlas-resident.service",
            "examples/resident/resident.env",
            "examples/resident/start-resident.sh",
            "SENTINEL_RESIDENT_UNIT=atlas-resident.service",
            "not an official Claude Code feature",
            "screen -ls",
        ):
            self.assertIn(needle, t)
        self.assertNotIn("agent.service", t)

    def test_readme_links_logins_section(self):
        self.assertRegex(self.read("README.md"), r"docs/resident\.md#[a-z0-9-]*logins-and-restarts")

    def test_agent_docs_after_a_restart(self):
        for p in ("AGENTS.md", "agent/claude-code/skills/atlas-resident/SKILL.md"):
            t = self.read(p)
            self.assertIn("After a restart", t, p)
            self.assertIn("AFTER-REBOOT.md", t, p)
            m = re.search(r"After a restart", t)
            end = t.find("<!-- alert-procedure:end -->")
            start = t.find("<!-- alert-procedure:start -->")
            self.assertFalse(start < m.start() < end, p)

    def test_security_mentions_boot_agent(self):
        t = self.read("docs/security.md")
        self.assertIn("atlas-resident", t)
        self.assertIn("standing privilege", t)


if __name__ == "__main__":
    os.environ.setdefault("LC_ALL", "C")
    unittest.main()
