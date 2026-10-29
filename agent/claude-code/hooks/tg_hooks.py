"""Hook decisions and subagent bookkeeping; human evidence is resolved lazily."""
import json
import os
import sys
import time
import tg_core
import tg_classify
import tg_state


def deny(reason):
    sys.stdout.write(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "deny",
        "permissionDecisionReason": reason}}))
    sys.stdout.flush()


def deny_internal(code):
    deny(tg_core.DENY_TEXT.format(source="gate error: " + code, since=tg_core.now_iso()))


def format_hint_active(state):
    """True while an unreadable transcript format was seen less than 24 h ago (P14)."""
    at = state.data.get("format_unknown_at") if state.unknown is None else None
    if not (isinstance(at, str) and tg_state.ISO_TIME.fullmatch(at)):
        return False
    try:
        import calendar
        age = time.time() - calendar.timegm(time.strptime(at, "%Y-%m-%dT%H:%M:%SZ"))
    except (ValueError, OverflowError):
        return False
    return -60 <= age < tg_core.FORMAT_HINT_TTL_S


def deny_state(state):
    src, since = state.source_and_since()
    deny(tg_core.DENY_TEXT.format(source=src, since=since) + (tg_core.FORMAT_HINT if format_hint_active(state) else ""))


def launch_allowed(tool, ti):
    """Config `subagent_allowlist`: when non-empty, Agent/Task may launch only the listed types (any state)."""
    if tool not in ("Agent", "Task"):
        return True  # no config read on the hot path of every other tool
    allowed = tg_state.config()["subagent_allowlist"]
    if not allowed:
        return True
    kind = ti.get("subagent_type") if isinstance(ti, dict) else None
    return isinstance(kind, str) and kind in allowed


def is_subagent(data):
    agent_id = data.get("agent_id")
    return isinstance(agent_id, str) and bool(agent_id)


def pre_tool_use(data):
    sid = data.get("session_id")
    tool = data.get("tool_name")
    if not isinstance(tool, str):
        raise tg_core.GateError("no-tool")
    ti = data.get("tool_input")
    cwd = data.get("cwd")
    tuid = data.get("tool_use_id") if isinstance(data.get("tool_use_id"), str) else None
    if tg_state.switch_on():
        tg_state.log(sid, "PreToolUse", tool, "allow", "switch-off")
        return
    if not launch_allowed(tool, ti):
        tg_state.log(sid, "PreToolUse", tool, "deny", "subagent-not-allowed")
        deny(tg_core.SUBAGENT_LAUNCH_DENY_TEXT.format(allowed=", ".join(tg_state.safe_token(x, 64) for x in
                                                               tg_state.config()["subagent_allowlist"])))
        return
    if is_subagent(data):
        subagent_pre_tool_use(data, tool, ti, cwd)
        return  # a subagent is gated by its own reads (agent_taint), not by the parent's taint
    if tool == "Monitor" and isinstance(ti, dict) and tg_classify.tool_source(tool, ti, cwd):
        # Round 2, D2: a monitored untrusted stream keeps delivering after any human clear.
        tg_state.log(sid, "PreToolUse", tool, "deny", "monitor-untrusted")
        deny(tg_core.MONITOR_DENY_TEXT)
        return
    state = tg_state.State(sid)
    _resolve_pending(state, sid, "PreToolUse")
    if not isinstance(ti, dict):
        if state.gated and tool not in tg_core.ALWAYS_READ_ONLY:
            tg_state.log(sid, "PreToolUse", tool, "deny", "bad-input")
            deny_state(state)
        return
    allowed = tg_classify.tainted_allows(tool, ti) if state.gated else True
    if not allowed:
        tg_state.log(sid, "PreToolUse", tool, "deny", "unknown-" + state.unknown if state.unknown
            else "tainted")
        deny_state(state)
        return
    latent = []
    source = tg_classify.tool_source(tool, ti, cwd, latent)
    if latent and state.path is not None:
        with state:
            if not state.add_latent(latent):
                source = source or "latent-unrecorded"  # a script we cannot remember: treat it as a read
    if source:
        _mark_source(state, sid, tool, ti, cwd, tuid, source)
        return
    after_allowed_call(state, data, tool, ti, cwd)
    if state.gated:
        tg_state.log(sid, "PreToolUse", tool, "allow", "allowlisted")


def _resolve_pending(state, sid, event):
    if state.gated and state.unknown is None and state.data.get("pending_human"):
        import tg_provenance
        with state:
            tg_provenance.resolve_pending_human(state, sid, event)


def _mark_source(state, sid, tool, ti, cwd, tuid, source):
    unrecorded = []
    with state:
        ok = state.mark(source, pending_id=tuid)
        if ok and tool in ("Bash", "Monitor"):
            targets = tg_classify.write_targets(ti.get("command") or "", cwd)
            if targets:
                state.add_artifacts(targets)
                unrecorded = [t for t in targets if tg_classify.is_artifact(os.path.realpath(t)) != "artifact"
                              and tg_classify.is_artifact(t) != "artifact"]
    if ok and unrecorded:
        # a copy of untrusted data whose destination cannot be remembered would lose its provenance
        tg_state.log(sid, "PreToolUse", tool, "deny", "artifact-registry-full")
        deny(tg_core.DENY_TEXT.format(source=source + " (copy destination cannot be recorded: registry full)",
                              since=tg_core.now_iso()))
        return
    if ok:
        tg_state.log(sid, "PreToolUse", tool, "taint", source)
    else:
        tg_state.log(sid, "PreToolUse", tool, "taint-failed", source)
        if tool not in tg_core.ALWAYS_READ_ONLY:  # never deliver untrusted data we cannot remember
            deny(tg_core.DENY_TEXT.format(source=source + " (taint not persisted)", since=tg_core.now_iso()))


def post_tool_use(data):
    """Re-mark taint when an untrusted call completes: a human message may have cleared
    the session while the call was running, and its result is about to reach the model."""
    sid = data.get("session_id")
    tool = data.get("tool_name")
    if not isinstance(tool, str) or tg_state.switch_on() or is_subagent(data):
        return
    ti = data.get("tool_input")
    cwd = data.get("cwd")
    tuid = data.get("tool_use_id") if isinstance(data.get("tool_use_id"), str) else None
    state = tg_state.State(sid)
    if state.path is None:
        return
    with state:
        if state.gated and state.unknown is None and state.data.get("pending_human"):
            import tg_provenance
            tg_provenance.resolve_pending_human(state, sid, "PostToolUse")
        src = state.pending().get(tuid) if tuid else None
        src = src or (tg_classify.tool_source(tool, ti, cwd) if isinstance(ti, dict) else None)
        if src:
            ok = state.mark(src, settle_id=tuid)
            tg_state.log(sid, "PostToolUse", tool, "retaint" if ok else "taint-failed", src)
        post_bookkeeping(state, data, tool, ti)


def after_allowed_call(state, data, tool, ti, cwd):
    return None


AGENT_ID = tg_core.Lazy(r"[A-Za-z0-9_-]{1,64}")


NOTIFICATION_HEAD = tg_core.Lazy(r"\s*<task-notification>\s*<task-id>([A-Za-z0-9_-]{1,64})</task-id>")


def _agent_flag(state, aid):
    return "%s.agent-%s.tainted" % (state.path[:-len(".json")], aid)


def _touch_agent_flag(state, aid):
    """Fallback when agent_taint cannot be written: an empty per-agent flag file (needs no data blocks)."""
    if state.path is None or os.environ.get("TAINT_FAIL_WRITES") == "all":
        return False
    try:
        os.close(os.open(_agent_flag(state, aid), os.O_WRONLY | os.O_CREAT, 0o600))
        return True
    except OSError:
        return False


def agent_tainted(state, aid):
    """(source, since) when this subagent read untrusted data, else None. An unknown state or a full map
    (a new subagent cannot be remembered) gates every subagent: ("state unknown", now)."""
    if state.path is None or state.unknown is not None:
        return "state unknown", tg_core.now_iso()
    if os.path.lexists(_agent_flag(state, aid)):
        return "taint-not-persisted", tg_core.now_iso()  # fallback flag of a failed agent_taint write
    m = state.data.get("agent_taint")
    if m is None:
        return None
    if not isinstance(m, dict):
        return "state unknown", tg_core.now_iso()
    if aid in m:
        e = m[aid] if isinstance(m[aid], dict) else {}
        since = e.get("since")
        return (tg_state.safe_token(e.get("source"), 32),
                since if isinstance(since, str) and tg_state.ISO_TIME.fullmatch(since) else "unknown time")
    if len(m) >= tg_core.AGENT_TAINT_MAX:
        return "state unknown", tg_core.now_iso()
    return None


def mark_agent(state, aid, source):
    """Remember that subagent `aid` read untrusted data (inside `with state:`). False = not persisted."""
    m = state.data.get("agent_taint")
    m = dict(m) if isinstance(m, dict) else {}
    if aid in m:
        return True
    if len(m) >= tg_core.AGENT_TAINT_MAX:
        return False
    m[aid] = {"source": source, "since": tg_core.now_iso()}
    return state.update(agent_taint=m)


def subagent_pre_tool_use(data, tool, ti, cwd):
    """A subagent that read untrusted data is gated like a tainted session for the rest of its run (also
    after a resume); its reads are remembered for its parent. A clean subagent is not gated."""
    sid = data.get("session_id")
    agent_id = tg_state.safe_token(data.get("agent_id"), 64)
    state = tg_state.State(sid)
    bad = not isinstance(ti, dict)
    tainted = agent_tainted(state, agent_id)
    if tainted is not None:
        if not (tool in tg_core.ALWAYS_READ_ONLY if bad else tg_classify.tainted_allows(tool, ti)):
            tg_state.log(sid, "PreToolUse", tool, "deny", "subagent-tainted")
            deny(tg_core.SUBAGENT_DENY_TEXT.format(source=tainted[0], since=tainted[1]))
            return
    if bad:
        return
    src = tg_classify.tool_source(tool, ti, cwd)
    nested = tool in ("Agent", "Task")
    if not (src or nested):
        return
    ok = True
    if state.path is not None:
        with state:
            if src:
                agents = dict(state.data.get("agents") or {})
                if agents.get(agent_id) is None:
                    agents[agent_id] = src
                    if not state.update(agents=agents):
                        state._touch_flag()  # cannot remember it: taint the parent now (fail closed)
            ok = mark_agent(state, agent_id, src or "nested-agent")
            if not ok and _touch_agent_flag(state, agent_id):
                ok = True  # remembered by the fallback flag: the subagent stays gated
    if src:
        tg_state.log(sid, "PreToolUse", tool, "agent-read", src)
    else:
        tg_state.log(sid, "PreToolUse", tool, "agent-nested", "nested-agent")
    if not ok:
        tg_state.log(sid, "PreToolUse", tool, "taint-failed", src or "nested-agent")
        if tool not in tg_core.ALWAYS_READ_ONLY:  # never run what we cannot remember
            deny(tg_core.SUBAGENT_DENY_TEXT.format(source=(src or "nested-agent") + " (not persisted)", since=tg_core.now_iso()))


def post_bookkeeping(state, data, tool, ti):
    if tool not in ("Agent", "Task") or not isinstance(ti, dict):
        return
    resp = data.get("tool_response")
    aid = resp.get("agentId") if isinstance(resp, dict) else None
    out_file = resp.get("outputFile") if isinstance(resp, dict) else None
    if isinstance(out_file, str) and out_file.startswith("/"):
        state.add_artifacts([os.path.normpath(out_file)])  # the subagent's raw transcript
    if not (isinstance(aid, str) and AGENT_ID.fullmatch(aid)):
        aid = None
    if aid:
        types = dict(state.data.get("agent_types") or {})
        types[aid] = tg_state.safe_token(ti.get("subagent_type"), 64)
        state.update(agent_types=types)
    asynchronous = isinstance(resp, dict) and (resp.get("isAsync") is True
                                               or resp.get("status") == "async_launched")
    if not asynchronous:
        judge_agent_result(state, data.get("session_id"), aid, None, "PostToolUse")


def judge_agent_result(state, sid, aid, out_file, event):
    """Taint the parent when a subagent that read untrusted data hands back its reply (inside
    `with state:`). No exemption, the log-reader's included : a schema cannot keep
    instructions out of the strings it allows, and the parent sees the original reply anyway."""
    agents = dict(state.data.get("agents") or {})
    types = state.data.get("agent_types") or {}
    src = agents.pop(aid, None) if aid else None
    if src is None:
        unmatched = [a for a in agents if a not in types]
        if not unmatched:
            return  # this subagent read nothing untrusted
        src = "subagent-unmatched"  # reads under an id we cannot pair with a launch: assume this one
        for a in unmatched:
            agents.pop(a, None)
    state.data = dict(state.data, agents=agents)
    ok = state.mark("subagent")
    if out_file:
        state.add_artifacts([out_file])  # D5: the raw transcript named by the completion
    tg_state.log(sid, event, "Agent", "taint" if ok else "taint-failed", "subagent")


OUTPUT_FILE = tg_core.Lazy(r"<output-file>(/[^<\x00-\x1f]{1,4095})</output-file>")


def notification_agent(prompt):
    """(agent id, output file or None) of a completion notification, else (None, None). Both come
    from the envelope head, before any <result> (where data from the agent begins)."""
    m = NOTIFICATION_HEAD.match(prompt)
    if not m:
        return None, None
    head_end = prompt.find("<result>", m.end())
    head = prompt[m.end():head_end if head_end >= 0 else len(prompt)]
    f = OUTPUT_FILE.search(head)
    return m.group(1), (os.path.normpath(f.group(1)) if f else None)


TRANSCRIPT_CHUNK = 1024 * 1024


TRANSCRIPT_MAX_SCAN = 16 * 1024 * 1024


TRANSCRIPT_TRIES = 2  # one retry; the harness writes a turn-start prompt after the hook, the deferred path covers it


PENDING_HUMAN_MAX = 4


TRANSCRIPT_WAIT_S = 0.2


def user_prompt_submit(data):
    """Clear the taint ONLY on verified, fresh, unused human evidence ; judge agent completions."""
    import tg_provenance
    sid = data.get("session_id")
    if tg_state.switch_on():
        tg_state.log(sid, "UserPromptSubmit", "-", "keep", "switch-off")
        return
    state = tg_state.State(sid)
    prompt = data.get("prompt")
    aid, out_file = notification_agent(prompt) if isinstance(prompt, str) else (None, None)
    if aid and state.path is not None:
        with state:
            judge_agent_result(state, sid, aid, out_file, "UserPromptSubmit")
    if not state.gated:
        _consume_clean_prompt(state, data, prompt, aid)
        return
    after = state.data.get("marked_at") if state.unknown is None else None
    used = frozenset(e for e in (state.data.get("used_evidence") or []) if isinstance(e, str)) \
        if state.unknown is None else frozenset()
    origin, eid, ts = tg_provenance.transcript_origin(data, after, used) if isinstance(prompt, str) else (None, None, None)
    if origin == "format-unknown":
        tg_state.log(sid, "UserPromptSubmit", "-", "keep", "transcript-format-unknown")
        if state.path is not None and state.unknown is None:
            with state:
                state.update(format_unknown_at=tg_core.now_iso())
        origin = None  # no evidence either way: the deferred path below still applies
    if origin != "human":  # verified human provenance wins, even over notification-shaped text
        if _defer_prompt(state, data, sid, prompt, aid, origin):
            return
        tg_state.log(sid, "UserPromptSubmit", "-", "keep",
            "not-human" if origin == "other" or aid else "unverified-origin")
        return
    if state.path is None:
        tg_state.log(sid, "UserPromptSubmit", "-", "keep", "unknown-" + (state.unknown or "x"))
        return
    with state:
        latest = state.data.get("marked_at") if state.unknown is None else None
        if latest and not (isinstance(ts, str) and ts > latest):
            ok = False  # an untrusted read landed after the evidence while we were looking it up
            reason = "evidence-older-than-taint"
        else:
            ok = state.clear(eid)
            reason = "cleared-by-human-verified" if ok else "clear-failed"
    tg_state.log(sid, "UserPromptSubmit", "-", "clear" if ok else "keep", reason)


def _consume_clean_prompt(state, data, prompt, aid):
    import tg_provenance
    # Consume this human message's own evidence even in a clean session, so the record cannot later
    # authenticate an automated prompt with identical text (single lookup, no retries).
    if isinstance(prompt, str) and state.path is not None and state.unknown is None and not aid:
        used0 = frozenset(e for e in (state.data.get("used_evidence") or []) if isinstance(e, str))
        o, eid0, _ = tg_provenance._consume_lookup(data, used0)
        if o == "human" and eid0 and eid0.startswith("q:"):  # promptId evidence is unique per prompt
            with state:
                used = [e for e in (state.data.get("used_evidence") or []) if isinstance(e, str)]
                if eid0 not in used:
                    used.append(eid0)
                    state.update(used_evidence=used[-tg_core.EVIDENCE_MAX:])


def _defer_prompt(state, data, sid, prompt, aid, origin):
    import tg_provenance
    if origin is None and not aid and isinstance(prompt, str):
        real = tg_provenance._transcript_real(data.get("transcript_path"))
        pid = data.get("prompt_id")
        if real and isinstance(pid, str) and pid and state.path is not None and state.unknown is None:
            with state:
                if state.unknown is None and state.tainted:
                    items = [i for i in (state.data.get("pending_human") or []) if isinstance(i, dict)]
                    items.append({"pid": pid, "sha256": tg_provenance._text_hash(prompt), "transcript": real,
                                  "at": tg_core.now_iso_ms()})
                    if state.update(pending_human=items[-PENDING_HUMAN_MAX:]):
                        tg_state.log(sid, "UserPromptSubmit", "-", "keep", "unverified-origin")
                        tg_state.log(sid, "UserPromptSubmit", "-", "keep", "deferred-human-pending")
                        return True
    return False

