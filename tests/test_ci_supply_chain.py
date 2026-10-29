#!/usr/bin/env python3
"""CI supply chain (audit 14) and the commit convention guard (audit 23)."""

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WF = ROOT / ".github" / "workflows" / "tests.yml"
CHECK = ROOT / ".github" / "check-commits.sh"


class Workflow(unittest.TestCase):
    def test_every_action_is_pinned_to_a_sha(self):
        uses = re.findall(r"uses:\s*(\S+)", WF.read_text())
        self.assertTrue(uses)
        for u in uses:
            self.assertRegex(u, r"@[0-9a-f]{40}$", u)
        # D-KR-16: any full SHA with its version comment, so Dependabot bumps pass; the SHA form is the guard.
        for name in ("actions/checkout", "actions/setup-python"):
            self.assertRegex(WF.read_text(), re.escape(name) + r"@[0-9a-f]{40} # v\d+\.\d+\.\d+")

    def test_coverage_gate(self):
        text = WF.read_text()
        self.assertIn("--cov-fail-under=60", text)
        self.assertIn("pytest-cov==5.0.0", text)
        self.assertIn("omit = */tests/*", (ROOT / ".github" / "coveragerc").read_text())

    def test_dependabot_watches_actions(self):
        text = (ROOT / ".github" / "dependabot.yml").read_text()
        self.assertIn("package-ecosystem: github-actions", text.replace('"', ""))

    def test_verify_tag_fetches_the_annotated_tag_first(self):
        # actions/checkout leaves a lightweight tag at the commit; verify-tag needs the tag object.
        text = WF.read_text()
        job = text[text.index("verify-tag:"):]
        fetch = job.find("git fetch --force origin \"refs/tags/${GITHUB_REF_NAME}:refs/tags/${GITHUB_REF_NAME}\"")
        self.assertGreater(fetch, 0)
        self.assertLess(fetch, job.index("verify-tag \"$GITHUB_REF_NAME\""))

    def test_tags_are_verified(self):
        self.assertIn("verify-tag", WF.read_text())
        self.assertTrue((ROOT / ".github" / "allowed_signers").exists())


class CommitCheck(unittest.TestCase):
    def repo(self, subjects):
        d = Path(tempfile.mkdtemp(prefix="cc-"))
        self.addCleanup(shutil.rmtree, d, True)
        env = dict(
            os.environ,
            GIT_AUTHOR_NAME="t",
            GIT_AUTHOR_EMAIL="t@example.com",
            GIT_COMMITTER_NAME="t",
            GIT_COMMITTER_EMAIL="t@example.com",
        )
        subprocess.run(["git", "init", "-q", str(d)], check=True)
        subprocess.run(["git", "-C", str(d), "commit", "-q", "--allow-empty", "-m", "base"], check=True, env=env)
        base = subprocess.run(["git", "-C", str(d), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        for s in subjects:
            subprocess.run(["git", "-C", str(d), "commit", "-q", "--allow-empty", "-m", s], check=True, env=env)
        return d, base

    def check(self, d, base):
        return subprocess.run(["bash", str(CHECK), base, "HEAD"], cwd=str(d), capture_output=True, text=True)

    def test_conventional_subjects_pass(self):
        d, base = self.repo(["feat(gate): x", "fix: y", "test(atlas): z (RED)", "docs!: w"])
        self.assertEqual(self.check(d, base).returncode, 0)

    def test_style_subject_passes(self):
        d, base = self.repo(["style: ruff format", "style(gate): wrap"])
        self.assertEqual(self.check(d, base).returncode, 0)

    def test_other_subjects_fail_and_are_named(self):
        d, base = self.repo(["feat: ok", "Journal: old style"])
        r = self.check(d, base)
        self.assertEqual(r.returncode, 1)
        self.assertIn("Journal: old style", r.stdout + r.stderr)


class CommitCheckEdges(unittest.TestCase):
    repo = CommitCheck.repo
    check = CommitCheck.check

    def test_empty_and_zero_base_check_head_only(self):
        d, _ = self.repo(["old subject", "fix: current"])
        for base in ("", "0" * 40):
            with self.subTest(base=base):
                self.assertEqual(self.check(d, base).returncode, 0)
        d, _ = self.repo(["fix: previous", "invalid current"])
        self.assertEqual(self.check(d, "0" * 40).returncode, 1)

    def test_base_is_excluded(self):
        d, base = self.repo([])
        self.assertEqual(self.check(d, base).returncode, 0)

    def test_all_offenders_are_printed(self):
        d, base = self.repo(["first invalid", "fix: fine", "second invalid"])
        result = self.check(d, base)
        self.assertEqual(result.returncode, 1)
        self.assertIn("first invalid", result.stdout)
        self.assertIn("second invalid", result.stdout)

    def test_bad_scope_and_missing_description_fail(self):
        for subject in ("fix(UPPER): x", "fix: ", "unknown: x"):
            with self.subTest(subject=subject):
                d, base = self.repo([subject])
                self.assertEqual(self.check(d, base).returncode, 1)

    def test_invalid_revision_fails(self):
        d, _ = self.repo(["fix: fine"])
        self.assertNotEqual(self.check(d, "missing-revision").returncode, 0)

    def test_merge_subject_is_excluded(self):
        d, base = self.repo(["fix: parent"])
        parent = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=d, text=True).strip()
        env = dict(
            os.environ,
            GIT_AUTHOR_NAME="t",
            GIT_AUTHOR_EMAIL="t@example.com",
            GIT_COMMITTER_NAME="t",
            GIT_COMMITTER_EMAIL="t@example.com",
        )
        tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=d, text=True).strip()
        merge = subprocess.check_output(
            ["git", "commit-tree", tree, "-p", parent, "-p", base, "-m", "Merge branch"], cwd=d, env=env, text=True
        ).strip()
        subprocess.run(["git", "update-ref", "HEAD", merge], cwd=d, check=True)
        self.assertEqual(self.check(d, base).returncode, 0)

    def test_initial_merge_ref_does_not_walk_parents(self):
        d, base = self.repo(["invalid parent"])
        parent = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=d, text=True).strip()
        tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=d, text=True).strip()
        env = dict(
            os.environ,
            GIT_AUTHOR_NAME="t",
            GIT_AUTHOR_EMAIL="t@example.com",
            GIT_COMMITTER_NAME="t",
            GIT_COMMITTER_EMAIL="t@example.com",
        )
        merge = subprocess.check_output(
            ["git", "commit-tree", tree, "-p", parent, "-p", base, "-m", "Merge branch"], cwd=d, env=env, text=True
        ).strip()
        subprocess.run(["git", "update-ref", "HEAD", merge], cwd=d, check=True)
        self.assertEqual(self.check(d, "0" * 40).returncode, 0)
