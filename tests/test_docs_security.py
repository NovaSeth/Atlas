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


if __name__ == "__main__":
    unittest.main()
