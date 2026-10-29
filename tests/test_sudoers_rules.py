#!/usr/bin/env python3
"""sudoers rules mean what the docs say (audit 11) and the agent example is narrow (audit 1a). sudo's ^...$
arguments are POSIX EREs; the classes used here behave the same in Python's re."""
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ATLAS = ROOT / "examples" / "sudoers.d" / "atlas"
RESIDENT = ROOT / "examples" / "sudoers.d" / "atlas-resident"


def rules(path):
    return "\n".join(l for l in path.read_text().splitlines() if not l.lstrip().startswith("#"))


def ak_patterns():
    return [m.group(1) for m in re.finditer(r"(\^-[sl]f? /\S*authorized_keys\$)", rules(ATLAS))]


def visudo():
    for p in ("/usr/sbin/visudo", "/sbin/visudo", shutil.which("visudo") or ""):
        if p and os.path.exists(p):
            return p
    return None


class AuthorizedKeysRules(unittest.TestCase):
    def test_both_rules_found(self):
        self.assertEqual(len(ak_patterns()), 2)

    def test_dot_dot_never_matches(self):
        for pat in ak_patterns():
            flag = pat.split()[0].lstrip("^")
            for bad in ("/home/../root/.ssh/authorized_keys", "/home/./ops/.ssh/authorized_keys",
                        "//.ssh/authorized_keys", "/home/ops/../../etc/.ssh/authorized_keys"):
                self.assertIsNone(re.fullmatch(pat, "%s %s" % (flag, bad)), (pat, bad))

    def test_real_homes_still_match(self):
        for pat in ak_patterns():
            flag = pat.split()[0].lstrip("^")
            for good in ("/home/ops/.ssh/authorized_keys", "/root/.ssh/authorized_keys",
                         "/var/lib/git-user/.ssh/authorized_keys", "/home/a.b/.ssh/authorized_keys"):
                self.assertIsNotNone(re.fullmatch(pat, "%s %s" % (flag, good)), (pat, good))

    def test_no_class_mixes_dot_and_slash(self):
        self.assertNotRegex(rules(ATLAS), r"\[[^\]]*\.[^\]]*/[^\]]*\]|\[[^\]]*/[^\]]*\.[^\]]*\]")


class ResidentExample(unittest.TestCase):
    def rendered(self):
        return (RESIDENT.read_text().replace("@RESIDENT_USER@", "ops").replace("@ATLAS_USER@", "atlas")
                .replace("@ATLAS_CODE@", "/opt/atlas").replace("@ATLAS_STATE@", "/var/lib/atlas"))

    def test_is_narrow(self):
        r = rules(RESIDENT)
        self.assertNotRegex(r, r"NOPASSWD:\s*ALL\b")
        self.assertNotIn("ALL=(ALL)", r)
        self.assertNotIn("*", r)
        for bad in ("/bash", "/sh ", "/sh,", "/vi", "/less", "/tee", "/cp ", "chmod", "chown", "-exec", "/su "):
            self.assertNotIn(bad, r)

    def test_atlas_commands_run_as_the_atlas_user_only(self):
        self.assertRegex(rules(RESIDENT), r"(?m)^@RESIDENT_USER@ ALL=\(@ATLAS_USER@\) NOPASSWD: RESIDENT_ATLAS$")

    @unittest.skipUnless(visudo(), "visudo not installed")
    def test_rendered_example_parses(self):
        d = Path(tempfile.mkdtemp(prefix="sudoers-res-"))
        self.addCleanup(shutil.rmtree, d, True)
        f = d / "atlas-resident"
        f.write_text(self.rendered())
        r = subprocess.run([visudo(), "-cf", str(f)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
