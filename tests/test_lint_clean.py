#!/usr/bin/env python3
"""The tree is ruff- and shellcheck-clean with the committed configuration (audit 14). Skipped where the tools
are missing; CI installs them."""

import os
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CFG = ROOT / ".github" / "ruff.toml"


def ruff():
    return shutil.which("ruff") or (
        os.path.expanduser("~/.local/bin/ruff") if os.path.exists(os.path.expanduser("~/.local/bin/ruff")) else None
    )


class Lint(unittest.TestCase):
    @unittest.skipUnless(ruff(), "ruff not installed")
    def test_ruff_check(self):
        r = subprocess.run([ruff(), "check", "--config", str(CFG), "."], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout[-3000:])

    @unittest.skipUnless(ruff(), "ruff not installed")
    def test_ruff_format(self):
        r = subprocess.run(
            [ruff(), "format", "--config", str(CFG), "--check", "."], cwd=ROOT, capture_output=True, text=True
        )
        self.assertEqual(r.returncode, 0, r.stdout[-3000:])

    @unittest.skipUnless(shutil.which("shellcheck"), "shellcheck not installed")
    def test_shellcheck(self):
        files = subprocess.run(["git", "ls-files", "*.sh"], cwd=ROOT, capture_output=True, text=True).stdout.split()
        r = subprocess.run(["shellcheck", "-x", *files], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout[-3000:])
