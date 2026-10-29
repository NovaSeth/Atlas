#!/usr/bin/env python3
"""Operator docs match the shipped behaviour of the audit plan (items 1, 4, 5, 7-10, 14, 23)."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = {
    n: (ROOT / n).read_text()
    for n in (
        "README.md",
        "AGENTS.md",
        "docs/resident.md",
        "docs/configuration.md",
        "agent/claude-code/skills/atlas-resident/SKILL.md",
    )
}
NEW_ENV = (
    "SENTINEL_AGENT_SUDO_USERS",
    "SENTINEL_DIGEST_HOUR",
    "SENTINEL_SUDO_EXE",
    "SENTINEL_WAKE_MAX_PER_HOUR",
    "SENTINEL_HEARTBEAT_URL",
)


class OperatorDocs(unittest.TestCase):
    def test_no_bare_touch_acknowledgement(self):
        for name, text in DOCS.items():
            self.assertIsNone(re.search(r"touch \S*ALERT\.acked", text), name)
        for name in ("README.md", "AGENTS.md", "docs/resident.md", "agent/claude-code/skills/atlas-resident/SKILL.md"):
            self.assertIn("atlas.py ack", DOCS[name], name)

    def test_agent_account_is_not_trusted(self):
        self.assertNotRegex(DOCS["docs/resident.md"], r"SENTINEL_TRUSTED_SUDO_USERS=\S*ops")
        self.assertIn("SENTINEL_AGENT_SUDO_USERS", DOCS["docs/resident.md"])
        self.assertIn("atlas-resident", DOCS["docs/resident.md"])
        self.assertNotIn("planned for the plugin", DOCS["docs/resident.md"])

    def test_configuration_documents_new_keys_and_runtime(self):
        for k in NEW_ENV:
            self.assertIn(k, DOCS["docs/configuration.md"], k)
        self.assertIn("runtime/", DOCS["docs/configuration.md"])
        self.assertNotIn("/var/tmp/sentinel", DOCS["docs/configuration.md"])

    def test_readme_install_from_a_signed_tag_and_contributing(self):
        r = DOCS["README.md"]
        self.assertIn("verify-tag", r)
        self.assertIn("Conventional Commits", r)
        self.assertNotIn("Subagent calls are not gated", r)
