#!/usr/bin/env python3
"""Security and architecture docs carry the threat model (audit 13), C4 diagrams with trust boundaries (audit 24)
and the compatibility matrix (audit 22)."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEC = (ROOT / "docs" / "security.md").read_text()
ARCH = (ROOT / "docs" / "architecture.md").read_text()
FENCE = "`" * 3


class Docs(unittest.TestCase):
    def test_threat_model(self):
        self.assertIn("## Threat model", SEC)
        tm = SEC.split("## Threat model", 1)[1]
        for word in (
            "root",
            "notification channel",
            "host failure",
            "Atlas account",
            "model provider",
            "IP addresses",
            "user names",
            "GDPR",
            "pseudonymisation",
        ):
            self.assertIn(word, tm, word)

    def test_c4_diagrams_with_boundaries(self):
        for kind in ("C4Context", "C4Container"):
            block = re.search(FENCE + r"mermaid\s*\n%s\n(.*?)" % kind + FENCE, ARCH, re.S)
            self.assertTrue(block, kind)
            self.assertGreaterEqual(block.group(1).count("Boundary("), 3, kind)

    def test_layer_table_names_the_heartbeat(self):
        self.assertIn("SENTINEL_HEARTBEAT_URL", ARCH.split("## When a layer dies", 1)[1])

    def test_compatibility_matrix(self):
        text = (ROOT / "docs" / "compatibility.md").read_text()
        for word in ("2.1.306", "agent_id", "promptSource", "queued_command", "transcript-format-unknown", "_EXE"):
            self.assertIn(word, text, word)


class DocsSweepA27(unittest.TestCase):
    """A27: the docs follow A21-A26 and carry no limit that those tasks fixed."""

    @staticmethod
    def _doc(*parts):
        return ROOT.joinpath(*parts).read_text()

    def _all(self):
        docs = [self._doc("README.md"), self._doc("AGENTS.md")]
        docs += [p.read_text() for p in sorted((ROOT / "docs").glob("*.md"))]
        docs.append(self._doc("agent", "claude-code", "skills", "atlas-resident", "SKILL.md"))
        return docs

    def test_user_manager_filter_is_documented(self):
        text = self._doc("docs", "configuration.md") + self._doc("docs", "architecture.md")
        self.assertIn("user@<uid>.service", text)
        self.assertIn("4294967294", text)

    def test_force_push_fallback_is_documented(self):
        contributing = self._doc("README.md").split("## Contributing", 1)[1]
        self.assertIn("force-push", contributing)
        self.assertIn("merge base", contributing)

    def test_wake_summary_is_once_per_closed_window(self):
        for name in ("architecture.md", "resident.md", "configuration.md"):
            self.assertIn("after the window closes", self._doc("docs", name), name)
        for text in self._all():
            self.assertNotIn("when an hour closes with suppressed events", text)
            self.assertNotIn("Over the limit the sensor prints one", text)

    def test_origin_rule_is_consistent(self):
        self.assertIn("explicit null", self._doc("docs", "compatibility.md"))
        readme = self._doc("README.md")
        self.assertIn("`origin`", readme.split("Only a **verified human message**", 1)[1][:700])

    def test_release_example_verifies_and_repo_is_public(self):
        self.assertIn("verify-tag v0.3.1", self._doc("README.md"))
        self.assertNotIn("**Private repository?**", self._doc("docs", "quickstart.md"))


if __name__ == "__main__":
    unittest.main()
