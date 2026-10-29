#!/usr/bin/env python3
"""Rules that bind the whole product (audit plan 2026-10, GC1/GC2) and the shared contract later tasks use.

GC1: no host data in tracked files (documentation IPs, example mail domains, fake home directories only).
GC2: the runtime is stdlib-only: every import in product code is the standard library or an own module.
Shared contract (A1): catalog keys in both languages, sentinel.env keys, ignored runtime directory.
"""
import ast
import ipaddress
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TRACKED = subprocess.run(["git", "-C", str(ROOT), "ls-files"], capture_output=True, text=True,
                         check=True).stdout.split()
DOC_NETS = [ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "127.0.0.0/8", "0.0.0.0/32", "1.2.3.4/32")]
FAKE_HOMES = {"tester", "mallory", "ops", "newuser", "alice", "bob", "user"}
MAIL_OK = re.compile(r"@(example\.(com|org|net)|[a-z0-9-]+\.example)$")
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
MAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
HOME = re.compile(r"/home/([A-Za-z0-9_][A-Za-z0-9._-]*)")
PRODUCT_DIRS = ("atlas/", "sentinel/", "agent/claude-code/hooks/", "agent/claude-code/bin/")
NEW_KEYS = ("atlas.no_baseline", "atlas.bless_subject", "atlas.bless_body", "atlas.bless_first",
            "atlas.ack_subject", "atlas.ack_body", "atlas.ack_nothing", "atlas.ack_raced",
            "atlas.notify_not_sent", "esc.ack_unrecorded_subject", "esc.ack_unrecorded",
            "esc.unsafe_state_subject", "esc.unsafe_state", "router.wake_limit_subject",
            "router.wake_limit_body", "digest.subject", "digest.header", "digest.more")
NEW_ENV = ("SENTINEL_AGENT_SUDO_USERS", "SENTINEL_DIGEST_HOUR", "SENTINEL_SUDO_EXE",
           "SENTINEL_WAKE_MAX_PER_HOUR", "SENTINEL_HEARTBEAT_URL")


def texts():
    for rel in TRACKED:
        try:
            yield rel, (ROOT / rel).read_text(encoding="utf-8")
        except (UnicodeDecodeError, IsADirectoryError, FileNotFoundError):
            continue


class Privacy(unittest.TestCase):
    def test_ipv4_literals_are_documentation_addresses(self):
        bad = []
        for rel, text in texts():
            for m in IPV4.finditer(text):
                try:
                    ip = ipaddress.ip_address(m.group(0))
                except ValueError:
                    continue
                if not any(ip in n for n in DOC_NETS):
                    bad.append("%s: %s" % (rel, ip))
        self.assertEqual(bad, [])

    def test_mail_addresses_use_example_domains(self):
        bad = ["%s: %s" % (rel, m.group(0)) for rel, text in texts() for m in MAIL.finditer(text)
               if not MAIL_OK.search(m.group(0).lower())]
        self.assertEqual(bad, [])

    def test_home_directories_are_fake(self):
        bad = ["%s: /home/%s" % (rel, m.group(1)) for rel, text in texts() for m in HOME.finditer(text)
               if m.group(1) not in FAKE_HOMES]
        self.assertEqual(bad, [])


class StdlibOnly(unittest.TestCase):
    def test_product_imports_are_stdlib_or_own_modules(self):
        own = {Path(p).stem for p in TRACKED if p.endswith(".py")}
        allowed = set(sys.stdlib_module_names) | set(sys.builtin_module_names) | own
        bad = []
        for rel in TRACKED:
            if not rel.startswith(PRODUCT_DIRS) or "/tests/" in rel:
                continue
            text = (ROOT / rel).read_text(encoding="utf-8", errors="replace")
            if not (rel.endswith(".py") or text.startswith("#!/usr/bin/env python3")):
                continue
            for node in ast.walk(ast.parse(text, rel)):
                names = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    names = [node.module]
                bad += ["%s: %s" % (rel, n) for n in names if n.split(".")[0] not in allowed]
        self.assertEqual(bad, [])


class SharedContract(unittest.TestCase):
    def catalog(self, lang):
        return json.loads((ROOT / "i18n" / ("%s.json" % lang)).read_text(encoding="utf-8"))

    def test_new_catalog_keys_exist_in_both_languages(self):
        en, pl = self.catalog("en"), self.catalog("pl")
        for k in NEW_KEYS:
            self.assertIn(k, en, k)
            self.assertIn(k, pl, k)
        self.assertEqual(en["atlas.no_baseline"], "no baseline yet — review `atlas.py show` and run `bless`")

    def test_new_env_keys_are_documented_in_the_template(self):
        text = (ROOT / "examples" / "sentinel.env").read_text(encoding="utf-8")
        keys = {l.split("=", 1)[0] for l in text.splitlines() if l and not l.startswith("#") and "=" in l}
        for k in NEW_ENV:
            self.assertIn(k, keys, k)
        self.assertRegex(text, r"(?m)^SENTINEL_HEARTBEAT_URL=$")
        self.assertRegex(text, r"(?m)^SENTINEL_WAKE_MAX_PER_HOUR=12$")

    def test_runtime_dir_next_to_the_code_is_ignored(self):
        r = subprocess.run(["git", "-C", str(ROOT), "check-ignore", "atlas/runtime/escalation.log"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
