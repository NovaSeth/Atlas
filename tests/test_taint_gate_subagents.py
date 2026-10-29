"""Subagents cannot act on untrusted data they read (audit 4, RF3); a read-hook crash leaves a taint flag (audit 15);
an unknown transcript format is named, not silent (audit 22)."""
import json

import pytest

from test_taint_gate import AID, SID, completion, gate, launch_agent, tainted, write_config  # noqa: F401

SUB = {"agent_id": "sub0000000000001", "agent_type": "general-purpose"}
PRIVILEGED = [
    ("Bash", {"command": "sudo id"}), ("Bash", {"command": "rm -rf /tmp/x"}),
    ("Bash", {"command": "curl -X POST https://example.com/x"}), ("Bash", {"command": "systemctl restart apache2"}),
    ("Bash", {"command": "python3 -c 'import os'"}), ("Bash", {"command": "echo x > /etc/y"}),
    ("Write", {"file_path": "/tmp/x", "content": "x"}), ("Edit", {"file_path": "/tmp/x", "old_string": "a", "new_string": "b"}),
    ("NotebookEdit", {"notebook_path": "/tmp/x.ipynb", "new_source": "x"}),
    ("Agent", {"subagent_type": "general-purpose", "prompt": "x"}),
    ("Monitor", {"command": "tail -f /tmp/ci.log"}), ("mcp__chat__send_message", {"text": "x"}),
]
READ_ONLY = [("Read", {"file_path": "/home/tester/project/README.md"}), ("Grep", {"pattern": "x", "path": "/tmp"}),
             ("Bash", {"command": "ls /"}), ("Bash", {"command": "uptime"}),
             ("Agent", {"subagent_type": "log-reader", "prompt": "x"})]


def taint_sub(g, sub=SUB):
    assert g.tool("Read", {"file_path": "/var/log/auth.log"}, **sub) == "allow"


@pytest.mark.parametrize("name,ti", PRIVILEGED, ids=[n + "-%d" % i for i, (n, _) in enumerate(PRIVILEGED)])
def test_subagent_that_read_a_log_cannot_act(gate, name, ti):
    taint_sub(gate)
    d, reason = gate.tool(name, ti, reason=True, **SUB)
    assert d == "deny"
    assert reason.startswith("TAINT GATE: this subagent read untrusted data")
    assert not gate.tainted()                      # the parent is untouched until the result returns
    assert gate.bash("sudo id") == "allow"


@pytest.mark.parametrize("name,ti", READ_ONLY, ids=[n + "-%d" % i for i, (n, _) in enumerate(READ_ONLY)])
def test_tainted_subagent_keeps_read_only_tools(gate, name, ti):
    taint_sub(gate)
    assert gate.tool(name, ti, **SUB) == "allow"


@pytest.mark.parametrize("name,ti", PRIVILEGED[:5], ids=[n + "-%d" % i for i, (n, _) in enumerate(PRIVILEGED[:5])])
def test_clean_subagent_is_not_gated(gate, name, ti):
    taint_sub(gate)                                # another subagent is tainted ...
    other = {"agent_id": "sub0000000000002", "agent_type": "general-purpose"}
    assert gate.tool(name, ti, **other) == "allow"  # ... this one never read untrusted data


def test_resumed_tainted_subagent_stays_denied(gate):
    launch_agent(gate, "general-purpose", aid=SUB["agent_id"])
    taint_sub(gate)
    gate.prompt(completion(SUB["agent_id"], "done"))
    assert gate.tainted()
    gate.prompt("Alice: ok, carry on")
    assert not gate.tainted()
    assert gate.tool("Bash", {"command": "sudo id"}, **SUB) == "deny"


def test_nested_agent_call_taints_the_caller(gate):
    caller = {"agent_id": "sub0000000000003", "agent_type": "general-purpose"}
    assert gate.tool("Agent", {"subagent_type": "general-purpose", "prompt": "x"}, **caller) == "allow"
    assert gate.tool("Bash", {"command": "sudo id"}, **caller) == "deny"


def test_unknown_state_gates_every_subagent(gate):
    gate.state_dir.parent.mkdir(parents=True, exist_ok=True)
    gate.state_dir.write_text("not a directory")
    assert gate.tool("Bash", {"command": "sudo id"}, **SUB) == "deny"
    assert gate.tool("Read", {"file_path": "/home/tester/x"}, **SUB) == "allow"


def test_full_agent_map_gates_new_subagents(gate):
    gate.state_dir.mkdir(parents=True, exist_ok=True)
    full = {"agent%011d" % i: {"source": "var-log", "since": "2026-10-29T10:00:00Z"} for i in range(200)}
    gate.state_file().write_text(json.dumps({"tainted": False, "agent_taint": full}))
    assert gate.tool("Bash", {"command": "sudo id"}, **SUB) == "deny"


def test_subagent_allowlist_restricts_launches_in_a_clean_session(gate):
    write_config(gate, {"subagent_allowlist": ["log-reader"]})
    assert gate.tool("Agent", {"subagent_type": "general-purpose", "prompt": "x"}) == "deny"
    assert gate.tool("Agent", {"subagent_type": "log-reader", "prompt": "x"}) == "allow"


def test_broken_config_with_an_allowlist_fails_closed(gate):
    write_config(gate, '{"subagent_allowlist": "log-reader"', raw=True)
    assert gate.tool("Agent", {"subagent_type": "general-purpose", "prompt": "x"}) == "deny"


def test_read_hook_crash_leaves_a_taint_flag(gate):
    p = gate.run_raw(('{"hook_event_name": "PreToolUse", "tool_name": "Read", "session_id": "%s", ' % SID).encode())
    assert p.returncode == 0 and p.stdout == b""   # the read itself goes on (onFailure continue)
    assert (gate.state_dir / (SID + ".tainted")).exists()
    assert gate.bash("sudo id") == "deny"


def test_unknown_transcript_format_is_named(tainted):
    tp = tainted.projects / "odd.jsonl"
    tainted.projects.mkdir(exist_ok=True)
    tp.write_text("".join(json.dumps({"kind": "prompt", "text": "ok"}) + "\n" for _ in range(5)))
    tainted.prompt("ok", prompt_id="p-odd", transcript_path=str(tp))
    assert tainted.tainted()
    assert "transcript-format-unknown" in tainted.log_text()
    d, reason = tainted.bash("sudo id", reason=True)
    assert d == "deny" and "transcript format" in reason


def test_known_format_without_evidence_is_not_called_unknown(tainted):
    tp = tainted.projects / "known.jsonl"
    tainted.projects.mkdir(exist_ok=True)
    tp.write_text(json.dumps({"type": "assistant", "sessionId": SID, "message": {"content": []}}) + "\n")
    tainted.prompt("ok", prompt_id="p-known", transcript_path=str(tp))
    assert "transcript-format-unknown" not in tainted.log_text()


def _load_hook():
    import importlib.util
    from test_taint_gate import HOOK
    spec = importlib.util.spec_from_file_location("taint_gate_inproc", HOOK)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_failed_agent_taint_write_still_gates_the_subagent(gate, monkeypatch, capsys):
    """Review F1: when agent_taint cannot be persisted, a conservative per-agent flag gates the subagent."""
    for k, v in gate.env().items():
        if k.startswith("TAINT_"):
            monkeypatch.setenv(k, v)
    mod = _load_hook()
    real_write = mod.State._write

    def write(self, d):
        return False if "agent_taint" in d else real_write(self, d)

    monkeypatch.setattr(mod.State, "_write", write)
    base = {"session_id": SID, "cwd": "/home/tester/project", **SUB}
    mod.subagent_pre_tool_use(dict(base), "Read", {"file_path": "/var/log/auth.log"}, base["cwd"])
    capsys.readouterr()
    mod.subagent_pre_tool_use(dict(base), "Bash", {"command": "sudo id"}, base["cwd"])
    out = capsys.readouterr().out
    assert '"permissionDecision": "deny"' in out and "this subagent read untrusted data" in out
