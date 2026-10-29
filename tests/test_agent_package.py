"""The agent package: AGENTS.md (any harness) and the Claude Code plugin under agent/claude-code/."""

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "agent" / "claude-code"
AGENTS_MD = ROOT / "AGENTS.md"
SKILL_MD = PLUGIN / "skills" / "atlas-resident" / "SKILL.md"
LOG_READER = PLUGIN / "agents" / "log-reader.md"
START, END = "<!-- alert-procedure:start -->", "<!-- alert-procedure:end -->"


def frontmatter(path):
    text = path.read_text()
    m = re.match(r"---\n(.*?)\n---\n", text, re.S)
    if not m:
        return {}
    out = {}
    for line in m.group(1).splitlines():
        k, sep, v = line.partition(":")
        if sep and not line.startswith(" "):
            out[k.strip()] = v.strip()
    return out


def procedure(path):
    text = path.read_text()
    a, b = text.find(START), text.find(END)
    return text[a + len(START) : b].strip() if 0 <= a < b else ""


class PluginManifestTests(unittest.TestCase):
    def test_plugin_json_is_valid_with_required_fields(self):
        data = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text())
        self.assertEqual(data["name"], "atlas-resident")
        self.assertEqual(data["version"], "0.2.0")
        self.assertTrue(data.get("description", "").strip())
        self.assertNotIn("@", json.dumps(data.get("author", "")))  # no personal e-mail address


class SkillAndAgentTests(unittest.TestCase):
    def test_skill_frontmatter(self):
        fm = frontmatter(SKILL_MD)
        self.assertEqual(fm.get("name"), "atlas-resident")
        desc = fm.get("description", "")
        for word in ("Atlas", "ALERT", "bless"):
            self.assertIn(word, desc)

    def test_log_reader_has_exactly_read_grep_glob(self):
        fm = frontmatter(LOG_READER)
        self.assertEqual(fm.get("name"), "log-reader")
        self.assertTrue(fm.get("description"))
        tools = sorted(t.strip() for t in fm.get("tools", "").split(","))
        self.assertEqual(tools, ["Glob", "Grep", "Read"])

    def test_log_reader_output_contract(self):
        text = LOG_READER.read_text()
        for key in (
            "source",
            "window",
            "counts",
            "top_ips",
            "status_codes",
            "paths",
            "user_agent_classes",
            "injection_suspected",
            "injection_examples_redacted",
        ):
            self.assertIn(key, text)
        self.assertIn("untrusted", text.lower())


class ProcedureTests(unittest.TestCase):
    def test_agents_md_and_skill_share_one_procedure(self):
        a, s = procedure(AGENTS_MD), procedure(SKILL_MD)
        self.assertTrue(a, "AGENTS.md has no marked alert procedure")
        self.assertEqual(a, s, "AGENTS.md and SKILL.md must carry the same alert procedure")

    def test_procedure_has_verify_by_probing_step(self):
        for p in (AGENTS_MD, SKILL_MD):
            body = procedure(p).lower()
            self.assertIn("verify by probing", body, p)
            self.assertIn("log-reader", body, p)
            self.assertIn("alert.acked", body, p)
            self.assertIn("bless", body, p)

    def test_agents_md_is_short(self):
        self.assertLessEqual(len(AGENTS_MD.read_text().splitlines()), 160)


class NoRawJournalInAgentDocsTests(unittest.TestCase):
    """`systemctl status` prints recent journal lines (raw, untrusted log text) into the agent's context."""

    DOCS = [AGENTS_MD, SKILL_MD, ROOT / "docs" / "resident.md", ROOT / "README.md"]

    def test_no_bare_systemctl_status(self):
        for p in self.DOCS:
            for line in p.read_text().splitlines():
                for m in re.finditer(r"systemctl status([^`\n]*)", line):
                    with self.subTest(doc=p.name, line=line):
                        self.assertRegex(m.group(1), r"--lines=0|-n ?0\b")

    def test_procedure_recommends_systemctl_show(self):
        for p in (AGENTS_MD, SKILL_MD):
            body = procedure(p)
            self.assertIn("systemctl show -p ActiveState,SubState,Result,ExecMainStatus,ActiveEnterTimestamp", body)
            self.assertIn("is-failed", body)


if __name__ == "__main__":
    unittest.main()
