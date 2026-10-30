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
        self.notes = self.tmp / "notes"
        self.write_env()

    def write_env(self, extra=""):
        self.env_file.write_text(
            f"RESIDENT_DIR={self.work}\nRESIDENT_SESSION=claude\nRESIDENT_NAME=atlas-server\nRESIDENT_PERMISSION_MODE=default\n"
            f"RESIDENT_CLAUDE={self.bin}/claude\nSENTINEL_ATLAS={self.state}\nATLAS_CODE=/opt/atlas\nRESIDENT_NOTES_DIR={self.notes}\n{extra}"
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
            [shutil.which("bash"), str(SCRIPT), *args], env=e, capture_output=True, text=True, timeout=30, cwd=self.tmp
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
        # D-KR-23 (T-KR-33, P4): BOOT moved from the Atlas state dir to the resident's notes dir; the state dir
        # is read-only for the resident, so it is made read-only here too. Every assertion is kept.
        self.state.chmod(0o550)
        self.addCleanup(self.state.chmod, 0o750)
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stderr)
        boot = (self.notes / "BOOT").read_text()
        self.assertIn("Kernel:", boot)
        self.assertIn("screen -DmS claude", self.trace.read_text())
        self.assertEqual(os.listdir(self.state), [], "nothing may be written under the state dir")

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
        self.write_env('RESIDENT_EXTRA_ARGS="--allow-dangerously-skip-permissions --effort high"\n')
        r = self.run_script("--dry-run")
        self.assertEqual(r.returncode, 0, r.stderr)
        out = r.stdout
        i = out.index("--allow-dangerously-skip-permissions")
        self.assertLess(out.index("--permission-mode"), i)
        self.assertLess(i, out.index("--effort"))
        self.assertLess(out.index("--effort"), out.index("high"))
        self.assertLess(out.index("high"), out.index("machine"))

    def test_env_unquoted_multiword_value_is_refused_and_not_executed(self):
        marker = self.tmp / "marker"
        stub(self.bin / "login", f"touch {marker}")
        stub(self.bin / "--chrome", f"touch {marker}")
        for line in ("RESIDENT_AUTH_CHECKS=codex login status", "RESIDENT_EXTRA_ARGS=--allow-x --chrome"):
            self.write_env(line + "\n")
            r = self.run_script("--dry-run")
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertIn("line 8", r.stderr)
            self.assertIn("quote values with spaces", r.stderr)
            self.assertFalse(marker.exists())

    def test_env_quoted_multiword_values_split_into_argv(self):
        self.write_env('RESIDENT_EXTRA_ARGS="--allow-x --chrome"\nRESIDENT_AUTH_CHECKS="true now"\n')
        stub(self.bin / "true", "exit 0")
        r = self.run_script("--dry-run")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertLess(r.stdout.index("--allow-x"), r.stdout.index("--chrome"))
        self.assertIn("auth check ok: true now", r.stderr)

    def test_env_shell_syntax_in_value_is_refused(self):
        marker = self.tmp / "marker"
        for v in (f"$(touch {marker})", f"`touch {marker}`", f"a;touch {marker}", '"a $HOME"', '"x;y\\z"'):
            self.write_env(f"RESIDENT_EXTRA_ARGS={v}\n")
            r = self.run_script("--dry-run")
            self.assertEqual(r.returncode, 2, (v, r.stderr))
            self.assertFalse(marker.exists())

    def test_env_unknown_key_and_bad_line_are_refused(self):
        for line in ("FOO=bar", "lower=x", "just words"):
            self.write_env(line + "\n")
            r = self.run_script("--dry-run")
            self.assertEqual(r.returncode, 2, (line, r.stderr))
            self.assertIn("line 8", r.stderr)

    def test_env_comments_blank_lines_and_tilde(self):
        self.write_env("\n# a comment\n   \nRESIDENT_DIR=~/w\n")
        (self.tmp / "w").mkdir()
        r = self.run_script("--dry-run")
        self.assertEqual(r.returncode, 0, r.stderr)

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

    def minimal_path(self, *omit):
        """A PATH holding only what the script needs, without the programs named in omit."""
        d = self.tmp / "minbin"
        d.mkdir(exist_ok=True)
        for name in ("stat", "id", "grep", "seq", "cut", "date", "uname", "uptime", "cat"):
            real = shutil.which(name)
            if real and not (d / name).exists():
                (d / name).symlink_to(real)
        for name in ("claude", "curl", "screen", "sleep"):
            if name not in omit and not (d / name).exists():
                (d / name).symlink_to(self.bin / name)
        return str(d)

    def test_missing_screen_exits_four(self):
        r = self.run_script("--dry-run", PATH=self.minimal_path("screen"))
        self.assertEqual(r.returncode, 4, r.stderr)
        self.assertIn("screen", r.stderr)
        self.assertIn("not found", r.stderr)

    def test_missing_curl_exits_four_not_network_down(self):
        r = self.run_script("--dry-run", PATH=self.minimal_path("curl"))
        self.assertEqual(r.returncode, 4, r.stderr)
        self.assertIn("curl", r.stderr)

    def test_minimal_path_otherwise_works(self):
        r = self.run_script("--dry-run", PATH=self.minimal_path())
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_default_env_path_is_etc_atlas(self):
        self.assertIn("/etc/atlas/resident.env", SCRIPT.read_text())

    def test_model_and_effort_follow_permission_mode_before_extra_args(self):
        self.write_env('RESIDENT_MODEL=claude-opus-5-5\nRESIDENT_EFFORT=high\nRESIDENT_EXTRA_ARGS="--verbose"\n')
        r = self.run_script("--dry-run")
        self.assertEqual(r.returncode, 0, r.stderr)
        out = r.stdout
        names = ("--permission-mode", "--model", "claude-opus-5-5", "--effort", "high", "--verbose")
        order = [out.index(x) for x in names]
        self.assertEqual(order, sorted(order))

    def test_model_and_effort_empty_add_nothing(self):
        self.write_env("RESIDENT_MODEL=\nRESIDENT_EFFORT=\n")
        r = self.run_script("--dry-run")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("--model", r.stdout)
        self.assertNotIn("--effort", r.stdout)

    def test_valid_model_ids_and_aliases_are_accepted(self):
        for model in ("opus", "sonnet", "claude-sonnet-5-5", "claude-fable-5-1", "claude-opus-4-1[1m]"):
            self.write_env(f'RESIDENT_MODEL="{model}"\n')
            r = self.run_script("--dry-run")
            self.assertEqual(r.returncode, 0, model + r.stderr)
            self.assertIn("--model", r.stdout)

    def test_invalid_model_is_refused_naming_the_key(self):
        for model in ("-x", "a", "Opus", "bad model", "x/y", "a" * 65):
            self.write_env(f'RESIDENT_MODEL="{model}"\n')
            r = self.run_script("--dry-run")
            self.assertEqual(r.returncode, 2, model)
            self.assertIn("RESIDENT_MODEL", r.stderr)

    def test_effort_levels(self):
        for level in ("low", "medium", "high", "xhigh", "max"):
            self.write_env(f"RESIDENT_EFFORT={level}\n")
            r = self.run_script("--dry-run")
            self.assertEqual(r.returncode, 0, level + r.stderr)
            self.assertIn("--effort", r.stdout)

    def test_invalid_effort_is_refused_naming_the_key(self):
        for level in ("ultra", "HIGH", "hi gh"):
            self.write_env(f'RESIDENT_EFFORT="{level}"\n')
            r = self.run_script("--dry-run")
            self.assertEqual(r.returncode, 2, level)
            self.assertIn("RESIDENT_EFFORT", r.stderr)
            self.assertIn("low|medium|high|xhigh|max", r.stderr)

    def test_template_has_both_keys_empty(self):
        t = ENVTPL.read_text()
        self.assertRegex(t, r"(?m)^RESIDENT_MODEL=$")
        self.assertRegex(t, r"(?m)^RESIDENT_EFFORT=$")

    # T-KR-33: the resident's notes live in its own dir, never in the (read-only) Atlas state dir.
    def test_s1_boot_written_to_notes_dir_with_read_only_state(self):
        self.state.chmod(0o550)
        self.addCleanup(self.state.chmod, 0o750)
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Kernel:", (self.notes / "BOOT").read_text())
        self.assertEqual(stat.S_IMODE(self.notes.stat().st_mode), 0o700)
        self.assertNotIn("could not write BOOT", r.stderr)

    def test_s2_prompt_names_notes_paths_and_no_legacy_sentence(self):
        r = self.run_script("--dry-run")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f"{self.notes}/BOOT", r.stdout.replace("\\", ""))
        self.assertIn(f"{self.notes}/AFTER-REBOOT.md", r.stdout.replace("\\", ""))
        self.assertIn(f"would write {self.notes}/BOOT", r.stderr)
        self.assertNotIn("legacy note", r.stdout)
        self.assertFalse(self.notes.exists(), "a dry run created the notes dir")

    def test_s2_legacy_note_is_named_when_present(self):
        (self.state / "AFTER-REBOOT.md").write_text("old note\n")
        r = self.run_script("--dry-run")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("legacy note", r.stdout)
        self.assertIn(f"{self.state}/AFTER-REBOOT.md", r.stdout.replace("\\", ""))

    def test_legacy_note_is_not_touched_by_a_real_run(self):
        legacy = self.state / "AFTER-REBOOT.md"
        legacy.write_text("old note\n")
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(legacy.read_text(), "old note\n")
        self.assertFalse((self.state / "BOOT").exists())

    def test_bad_notes_dir_exits_two(self):
        for bad in ("relative/dir", "~/", "/a/../b", '"$(id)"', '"/tmp/a`id`"'):
            with self.subTest(bad=bad):
                self.write_env(f"RESIDENT_NOTES_DIR={bad}\n")
                r = self.run_script("--dry-run")
                self.assertEqual(r.returncode, 2, r.stderr)
                self.assertIn("RESIDENT_NOTES_DIR", r.stderr)

    def test_tilde_notes_dir_is_expanded(self):
        self.write_env("RESIDENT_NOTES_DIR=~/mynotes\n")
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue((self.tmp / "mynotes" / "BOOT").is_file())

    def test_default_notes_dir_follows_xdg_state_home(self):
        self.write_env()
        text = self.env_file.read_text().replace(f"RESIDENT_NOTES_DIR={self.notes}\n", "")
        self.env_file.write_text(text)
        xdg = self.tmp / "xdg"
        r = self.run_script(XDG_STATE_HOME=str(xdg))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue((xdg / "atlas-resident" / "BOOT").is_file())

    def test_uncreatable_notes_dir_exits_two(self):
        (self.tmp / "afile").write_text("x")
        self.write_env(f"RESIDENT_NOTES_DIR={self.tmp}/afile/sub\n")
        r = self.run_script()
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("RESIDENT_NOTES_DIR", r.stderr)

    def test_template_documents_the_key(self):
        text = ENVTPL.read_text()
        self.assertRegex(text, r"(?m)^RESIDENT_NOTES_DIR=\s*$")
        self.assertIn("atlas-resident", text)


class Templates(unittest.TestCase):
    def test_env_template_is_tracked_by_git(self):
        r = subprocess.run(
            ["git", "ls-files", "--error-unmatch", "examples/resident/resident.env"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(r.returncode, 0, "resident.env is ignored or untracked: " + r.stderr)

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

    def test_docs_name_the_notes_dir_not_the_state_dir(self):  # S5
        for name in ("AGENTS.md", "agent/claude-code/skills/atlas-resident/SKILL.md", "docs/resident.md"):
            text = (ROOT / name).read_text()
            self.assertIn("RESIDENT_NOTES_DIR", text, name)
            for old in ("<state>/BOOT", "$SENTINEL_ATLAS/BOOT", "<state>/AFTER-REBOOT.md"):
                self.assertNotIn(old, text, f"{name} still names {old}")


if __name__ == "__main__":
    os.environ.setdefault("LC_ALL", "C")
    unittest.main()
