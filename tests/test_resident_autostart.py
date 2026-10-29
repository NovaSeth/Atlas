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
        stub(self.bin / "screen", f'echo "screen $*" >> {self.trace}\n[ "$1" = -ls ] && exit 1\nexit 0')
        stub(self.bin / "codex", "echo SECRET-ACCOUNT-DATA; exit 1")
        stub(self.bin / "sleep")
        self.env_file = self.tmp / "resident.env"
        self.write_env()

    def write_env(self, extra=""):
        self.env_file.write_text(
            f"RESIDENT_DIR={self.work}\nRESIDENT_SESSION=claude\nRESIDENT_NAME=atlas-server\nRESIDENT_PERMISSION_MODE=default\n"
            f"RESIDENT_CLAUDE={self.bin}/claude\nSENTINEL_ATLAS={self.state}\nATLAS_CODE=/opt/atlas\n{extra}"
        )

    def run_script(self, *args, **env):
        e = {
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "RESIDENT_ENV": str(self.env_file),
            "HOME": str(self.tmp),
            "RESIDENT_ENV_TRUSTED_UID": str(os.getuid()),  # test harness only
        }
        e.update(env)
        e = {k: v for k, v in e.items() if v is not None}
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

    def test_env_file_writable_by_others_is_refused(self):
        self.env_file.chmod(0o666)
        r = self.run_script("--dry-run")
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("must be owned by root and not group/other-writable", r.stderr)

    def test_env_file_owned_by_agent_is_refused_by_default(self):
        r = self.run_script("--dry-run", RESIDENT_ENV_TRUSTED_UID=None)
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("must be owned by root", r.stderr)

    def test_env_file_cannot_raise_its_own_trust(self):
        self.write_env("RESIDENT_ENV_TRUSTED_UID=%d\n" % os.getuid())
        r = self.run_script("--dry-run", RESIDENT_ENV_TRUSTED_UID=None)
        self.assertEqual(r.returncode, 2, r.stderr)

    def test_trusted_uid_accepts_owned_file(self):
        r = self.run_script("--dry-run")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_mode_0666_refused_with_default_trusted_uid_too(self):
        self.env_file.chmod(0o666)
        r = self.run_script("--dry-run", RESIDENT_ENV_TRUSTED_UID=None)
        self.assertEqual(r.returncode, 2, r.stderr)

    @unittest.skipUnless(os.geteuid() == 0, "needs root to create a file owned by someone else")
    def test_env_file_of_another_owner_is_refused(self):
        os.chown(self.env_file, 12345, 12345)
        r = self.run_script("--dry-run")
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("must be owned by root", r.stderr)

    def test_missing_claude_binary_exits_four(self):
        self.write_env(f"RESIDENT_CLAUDE={self.tmp}/nonexistent\n")
        r = self.run_script("--dry-run")
        self.assertEqual(r.returncode, 4, r.stderr)
        self.assertIn(f"claude not found at {self.tmp}/nonexistent", r.stderr)

    def test_non_executable_claude_exits_four(self):
        (self.tmp / "noexec").write_text("x")
        self.write_env(f"RESIDENT_CLAUDE={self.tmp}/noexec\n")
        r = self.run_script("--dry-run")
        self.assertEqual(r.returncode, 4, r.stderr)

    def test_unset_resident_dir_exits_two_with_prefix(self):
        self.env_file.write_text(
            f"RESIDENT_PERMISSION_MODE=default\nRESIDENT_CLAUDE={self.bin}/claude\nSENTINEL_ATLAS={self.state}\n"
        )
        r = self.run_script("--dry-run")
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("start-resident: RESIDENT_DIR", r.stderr)

    def test_missing_resident_dir_exits_two(self):
        self.write_env(f"RESIDENT_DIR={self.tmp}/gone\n")
        r = self.run_script("--dry-run")
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("start-resident: RESIDENT_DIR", r.stderr)

    def test_network_log_states_real_maximum(self):
        stub(self.bin / "curl", "exit 6")
        r = self.run_script()
        self.assertIn("150 s", r.stderr)
        self.assertNotIn("60 s", r.stderr)

    def test_unit_state_dir_wins_over_env_file(self):
        other = self.tmp / "other"
        other.mkdir()
        (other / "RESIDENT-OFF").write_text("")
        r = self.run_script("--dry-run", SENTINEL_ATLAS=str(other))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("off switch present", r.stderr)
        self.assertIn(str(other), r.stderr)

    def test_extra_args_in_order_before_prompt(self):
        self.write_env("RESIDENT_EXTRA_ARGS='--allow-dangerously-skip-permissions --effort high'\n")
        r = self.run_script("--dry-run")
        self.assertEqual(r.returncode, 0, r.stderr)
        out = r.stdout
        i = out.index("--allow-dangerously-skip-permissions")
        self.assertLess(out.index("--permission-mode"), i)
        self.assertLess(i, out.index("--effort"))
        self.assertLess(out.index("--effort"), out.index("high"))
        self.assertLess(out.index("high"), out.index("machine"))

    def test_empty_extra_args_add_nothing(self):
        self.write_env("RESIDENT_EXTRA_ARGS=\n")
        r = self.run_script("--dry-run")
        self.assertNotIn("--effort", r.stdout)
        self.assertNotIn("--allow-dangerously", r.stdout)

    def test_extra_args_with_newline_refused(self):
        self.write_env("RESIDENT_EXTRA_ARGS='--effort high\n--evil'\n")
        r = self.run_script("--dry-run")
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("RESIDENT_EXTRA_ARGS", r.stderr)

    def test_empty_permission_mode_is_refused(self):
        self.write_env("RESIDENT_PERMISSION_MODE=\n")
        r = self.run_script("--dry-run")
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("choose a permission mode: set RESIDENT_PERMISSION_MODE in", r.stderr)
        self.assertIn("(see docs/resident.md)", r.stderr)

    def test_unknown_permission_mode_is_refused(self):
        self.write_env("RESIDENT_PERMISSION_MODE=yolo\n")
        r = self.run_script("--dry-run")
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("choose a permission mode", r.stderr)

    def test_every_valid_permission_mode_reaches_argv(self):
        for mode in ("default", "acceptEdits", "plan", "bypassPermissions"):
            self.write_env(f"RESIDENT_PERMISSION_MODE={mode}\n")
            r = self.run_script("--dry-run")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn(f"--permission-mode {mode} ", r.stdout)

    def test_default_env_path_is_etc_atlas(self):
        self.assertIn("/etc/atlas/resident.env", SCRIPT.read_text())


class Templates(unittest.TestCase):
    def test_unit_template(self):
        t = UNIT.read_text()
        for needle in (
            "@ATLAS_CODE@",
            "@ATLAS_STATE@",
            "@RESIDENT_USER@",
            "@RESIDENT_HOME@",
            "Environment=TERM=xterm-256color",
            "Environment=PATH=@RESIDENT_HOME@/.local/bin:/usr/local/bin:/usr/bin:/bin",
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
            "RESIDENT_DIR=~/resident",
            "RESIDENT_SESSION=",
            "RESIDENT_NAME=",
            "RESIDENT_PERMISSION_MODE=\n",
            "acceptEdits",
            "choose",
            "RESIDENT_CLAUDE=",
            "RESIDENT_AUTH_CHECKS=",
            "RESIDENT_EXTRA_ARGS=",
            "--allow-dangerously-skip-permissions",
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
            "RESIDENT_EXTRA_ARGS",
            "--allow-dangerously-skip-permissions",
        ):
            self.assertIn(needle, t)

    def test_quickstart_uses_shipped_files(self):
        t = self.read("docs/quickstart.md")
        for needle in (
            "examples/systemd/atlas-resident.service",
            "examples/resident/resident.env",
            "examples/resident/start-resident.sh",
            "@RESIDENT_HOME@",
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
