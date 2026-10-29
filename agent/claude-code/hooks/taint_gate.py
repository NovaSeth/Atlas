#!/usr/bin/env python3
"""Taint gate: deterministic defense against prompt injection through untrusted data.

Part of the optional Atlas taint gate (see the README, "Taint gate (optional)").

A stdlib entry and six modules for three hook events, dispatched by `hook_event_name`:
- PreToolUse: when the MAIN agent reads an untrusted source (logs, journal, web, mail, other agents)
  the session becomes tainted and the call is recorded as pending; while tainted every tool call
  outside a read-only allowlist is denied. A subagent (input carries `agent_id`) is gated the same way once it has itself read untrusted data (`agent_taint`).
- PostToolUse: when an untrusted call completes, the taint is marked again (a human message may have
  cleared it while the call ran). Never prints.
- UserPromptSubmit: a human prompt clears the taint (pending calls stay); task notifications, system
  envelopes and loop ticks do not (R2). Never prints (stdout would become model context).

Allowed calls print nothing (normal permission flow; the gate never auto-approves).
A denial prints the PreToolUse deny JSON and exits 0.
Internal errors follow P3: Read/Grep/Glob are allowed, everything else is denied.
The gate never stores untrusted text (G1): state and log hold fixed source codes and times only.
"""

import os
import sys

SUBMODULES = ("tg_core", "tg_lexer", "tg_classify", "tg_state", "tg_provenance", "tg_hooks")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
for m in SUBMODULES:
    sys.modules.pop(m, None)

import _signal as signal  # noqa: E402 - sys.path is set above
import json  # noqa: E402 - sys.path is set above
import re  # noqa: E402 - sys.path is set above

_import_error = None
tg_core = tg_lexer = tg_state = tg_classify = tg_hooks = None
_loaded = []
for _module_name in ("tg_core", "tg_lexer", "tg_state", "tg_classify", "tg_hooks"):
    try:
        _module = __import__(_module_name)
        globals()[_module_name] = _module
        _loaded.append(_module)
    except BaseException:
        _import_error = _module_name
        break

for _module in sorted(_loaded, key=lambda module: SUBMODULES.index(module.__name__)):
    for _name in vars(_module):
        if not _name.startswith("__") and _name not in (
            "_CONFIG",
            "_ARTIFACTS",
            "_ARTIFACTS_FULL",
            "_LATENT",
            "_LATENT_FULL",
        ):
            globals()[_name] = getattr(_module, _name)


def __getattr__(name):
    if name in ("_CONFIG", "_ARTIFACTS", "_ARTIFACTS_FULL", "_LATENT", "_LATENT_FULL"):
        return getattr(tg_state, name)
    import tg_provenance

    return getattr(tg_provenance, name)


def raw_event(raw):
    m = re.search(rb'"hook_event_name"\s*:\s*"([A-Za-z]+)"', raw)
    return m.group(1).decode() if m else None


def raw_tool(raw):
    m = re.search(rb'"tool_name"\s*:\s*"([A-Za-z0-9_.-]+)"', raw)
    return m.group(1).decode() if m else None


def raw_session(raw):
    m = re.search(rb'"session_id"\s*:\s*"([A-Za-z0-9_-]{1,128})"', raw)
    return m.group(1).decode() if m else None


def _deadline(signum, frame):
    raise tg_core.GateError("deadline")


def _import_failure(raw, module):
    """P3/P13 fallback independent of every split module, including state."""
    event, tool, sid = raw_event(raw), raw_tool(raw), raw_session(raw)
    if event == "PostToolUse" or (event == "PreToolUse" and tool in {"Read", "Grep", "Glob"}):
        try:
            if not sid:
                raise ValueError("no-session")
            directory = os.environ.get("TAINT_STATE_DIR") or os.path.expanduser("~/.claude/taint")
            os.makedirs(directory, mode=0o700, exist_ok=True)
            fd = os.open(os.path.join(directory, sid + ".tainted"), os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        except BaseException:
            # Reads retain onFailure semantics; a broken install still denies every write.
            pass
    elif event != "UserPromptSubmit":
        sys.stdout.write(
            json.dumps(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": "TAINT GATE: gate error: import-" + module,
                    }
                }
            )
        )
        sys.stdout.flush()


def _check_imports():
    if _import_error:
        return _import_error
    # Validate the last module on execution, keeping compatibility-only loads lazy.
    # Its stdlib dependencies are already loaded by state/hooks; no heavy new imports.
    try:
        __import__("tg_provenance")
    except BaseException:
        return "tg_provenance"
    return None


def main():
    raw = b""
    event = tool = None
    broken = _check_imports()
    if broken:
        _import_failure(sys.stdin.buffer.read(4 * 1024 * 1024), broken)
        return
    try:
        signal.signal(signal.SIGALRM, _deadline)
        signal.setitimer(signal.ITIMER_REAL, tg_core.INTERNAL_DEADLINE_S)
        raw = sys.stdin.buffer.read(4 * 1024 * 1024)
        try:
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, dict):
                raise ValueError
        except (ValueError, UnicodeDecodeError):
            raise tg_core.GateError("malformed-input")  # noqa: B904 - the gate reports a fixed code, never the chained cause
        event = data.get("hook_event_name")
        tool = data.get("tool_name")
        if event == "UserPromptSubmit":
            tg_hooks.user_prompt_submit(data)
        elif event == "PreToolUse":
            tg_hooks.pre_tool_use(data)
        elif event == "PostToolUse":
            tg_hooks.post_tool_use(data)
        else:
            raise tg_core.GateError("unknown-event")
    except BaseException as e:  # P3: any internal failure ends in a decision, never a crash
        _handle_error(e, raw, event, tool)
    finally:
        try:
            signal.setitimer(signal.ITIMER_REAL, 0)
        except BaseException:
            pass
    sys.exit(0)


def _handle_error(e, raw, event, tool):
    code = str(e) if isinstance(e, tg_core.GateError) else "internal-" + type(e).__name__
    code = tg_state.safe_token(code, 40).lower()
    event = event if isinstance(event, str) else raw_event(raw)
    tool = tool if isinstance(tool, str) else raw_tool(raw)
    try:
        tg_state.log(None, event or "unknown", tool or "-", "error", code)
    except BaseException:
        pass
    if event == "UserPromptSubmit":
        pass  # never print here; taint stays as it was
    elif event == "PostToolUse":
        # cannot tell whether the result was untrusted: keep the session tainted (fail closed)
        try:
            if raw_session(raw):
                tg_state.State(raw_session(raw))._touch_flag()
        except BaseException:
            pass
    elif tool in tg_core.ALWAYS_READ_ONLY:
        # P13: the read goes on, but we cannot tell whether it read untrusted data: leave a taint flag
        try:
            if raw_session(raw) and tg_state.State(raw_session(raw))._touch_flag():
                tg_state.log(raw_session(raw), event or "unknown", tool, "taint", "error-read-flagged")
        except BaseException:
            pass
    else:
        tg_hooks.deny_internal(code)


if __name__ == "__main__":
    main()
