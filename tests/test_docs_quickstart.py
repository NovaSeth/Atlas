#!/usr/bin/env python3
"""docs/quickstart.md matches the code it describes: headings, installer flags, atlas.py subcommands,
plugin and marketplace names, the monitor command, and the README pointer."""

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUIDE_PATH = ROOT / "docs" / "quickstart.md"
HEADINGS = [
    "## Before you start",
    "## 1. Prepare the server",
    "## 2. Get Atlas",
    "## 3. Install Atlas",
    "## 4. Install Claude Code",
    "## 5. Log in with your subscription",
    "## 6. Add the Atlas resident plugin",
    "## 7. Start the resident session with Remote Control",
    "## 8. Talk to it from your phone",
    "## 9. Keep it running",
    "## 10. Test that the alarm path works",
    "## Uninstall",
]


def guide():
    return GUIDE_PATH.read_text()


def code_lines(text):
    out, inside = [], False
    for ln in text.splitlines():
        if ln.startswith("```"):
            inside = not inside
        elif inside:
            out.append(ln)
    return out


class QuickstartGuide(unittest.TestCase):
    def test_headings_exist_in_order(self):
        lines = guide().splitlines()
        pos = -1
        for h in HEADINGS:
            self.assertIn(h, lines, h)
            self.assertGreater(lines.index(h), pos, h)
            pos = lines.index(h)

    def test_installer_flags_exist(self):
        install = (ROOT / "install.sh").read_text()
        uninstall = (ROOT / "uninstall.sh").read_text()
        seen = 0
        for ln in code_lines(guide()):
            m = re.search(r"(?<![\w.-])\./(un)?install\.sh\b(.*)", ln)
            if not m:
                continue
            src = uninstall if m.group(1) else install
            for flag in re.findall(r"(?<![\w-])--[a-z][a-z-]*", m.group(2)):
                seen += 1
                self.assertIn(flag, src, ln)
        self.assertGreater(seen, 0)

    def test_atlas_subcommands_exist(self):
        src = (ROOT / "atlas" / "atlas.py").read_text()
        table = re.search(r"COMMANDS = \{(.*?)\n\}", src, re.S).group(1)
        known = set(re.findall(r'"(\w+)":', table))
        used = set()
        for ln in code_lines(guide()):
            used.update(re.findall(r"atlas\.py (\w+)", ln))
        self.assertTrue({"show", "bless", "ack", "check"} <= used, used)
        self.assertTrue(used <= known, used - known)

    def test_plugin_and_marketplace_names(self):
        mp = json.loads((ROOT / "agent" / ".claude-plugin" / "marketplace.json").read_text())
        text = guide()
        self.assertIn(f"{mp['plugins'][0]['name']}@{mp['name']}", text)
        self.assertIn("claude plugin marketplace add", text)
        self.assertIn("claude plugin list", text)

    def test_monitor_command_equals_agents_md(self):
        cmd = "SENTINEL_ATLAS=/var/lib/atlas /opt/atlas/sentinel/session-sensor.sh"
        self.assertIn(cmd, (ROOT / "AGENTS.md").read_text())
        self.assertIn(cmd, guide())

    def test_claude_code_facts(self):
        text = guide()
        for needle in (
            "curl -fsSL https://claude.ai/install.sh | bash",
            "claude doctor",
            "claude auth status",
            "unset ANTHROPIC_API_KEY",
            "claude --remote-control",
            "setup-token",
            "docs/security.md",
            "Threat model",
        ):
            self.assertIn(needle, text, needle)

    def test_no_polling_and_no_bare_touch_ack(self):
        text = guide()
        self.assertNotRegex(text, r"touch \S*ALERT\.acked")
        self.assertIn("atlas.py ack", text)

    def test_readme_points_to_guide(self):
        readme = (ROOT / "README.md").read_text()
        self.assertGreaterEqual(readme.count("docs/quickstart.md"), 2)


if __name__ == "__main__":
    unittest.main()
