"""Human transcript evidence: fresh, session-bound and consumed once; imported only when needed."""

import hashlib
import json
import os
import re
import time

import tg_core
import tg_hooks
import tg_state


def _lines_reversed(real):
    """Complete transcript lines, newest first, reading backwards in chunks; a record longer than a chunk is
    assembled from its fragments with one join (linear work), up to TRANSCRIPT_MAX_SCAN bytes."""
    with open(real, "rb") as f:
        f.seek(0, 2)
        pos, scanned, carry = f.tell(), 0, []  # carry: fragments of the record being assembled, oldest first
        while pos > 0 and scanned < tg_hooks.TRANSCRIPT_MAX_SCAN:
            n = min(tg_hooks.TRANSCRIPT_CHUNK, pos)
            pos -= n
            f.seek(pos)
            chunk = f.read(n)
            scanned += n
            idx = chunk.rfind(b"\n")
            if idx == -1:
                carry.insert(0, chunk)
                continue
            line = chunk[idx + 1 :] + b"".join(carry)
            if line:
                yield line
            inner = chunk[:idx].split(b"\n")
            carry = [inner[0]]
            for line in reversed(inner[1:]):
                if line:
                    yield line
        if pos == 0:
            line = b"".join(carry)
            if line:
                yield line


def _origin_kind(d):
    o = d.get("origin")
    return o.get("kind") if isinstance(o, dict) else o


def _human_content(c):
    """A prompt typed by a person: a string, or content blocks of text/image only (an attachment)."""
    if isinstance(c, str):
        return True
    return (
        isinstance(c, list) and bool(c) and all(isinstance(x, dict) and x.get("type") in ("text", "image") for x in c)
    )


def _content_text(c):
    if isinstance(c, str):
        return c
    return "".join(x.get("text", "") for x in c if isinstance(x, dict) and x.get("type") == "text")


ISO_MS = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")


ABSORB_WINDOW_S = 10  # a mid-turn message is absorbed when its UserPromptSubmit fires; older absorptions are history


def _iso_ms_ago(seconds):
    t = time.time() - seconds
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + ".%03dZ" % int((t % 1) * 1000)


def _fresh(ts, after):
    """Evidence must be newer than the latest untrusted read. Both are fixed-width UTC millisecond ISO strings
    written on this host (one clock), so string order is time order; any other format is rejected."""
    return isinstance(ts, str) and bool(ISO_MS.match(ts)) and (not after or ts > after)


FORMAT_PROBE_LINES = 200


def _is_record(line):
    """A transcript line the gate can recognise: a JSON object with a string `type`."""
    try:
        d = json.loads(line)
    except ValueError:
        return False
    return isinstance(d, dict) and isinstance(d.get("type"), str)


def _transcript_lookup(real, pid, sid, prompt, after=None, used=()):
    """Find fresh human evidence; unknown formats fail closed (P14)."""
    key = pid.encode("utf-8", "replace") if pid else None
    seen, recognized = 0, False
    absorbed = {}  # deliveryId -> timestamp of its mid-turn absorption (newer lines are seen first)
    recent = _iso_ms_ago(ABSORB_WINDOW_S)
    try:
        for line in _lines_reversed(real):
            if seen < FORMAT_PROBE_LINES:
                seen += 1
                recognized = recognized or _is_record(line)
            d = _matching_record(line, key, sid)
            if d is None:
                continue
            if d.get("type") == "queue-operation":
                if d.get("operation") == "remove" and isinstance(d.get("deliveryId"), str):
                    absorbed.setdefault(d["deliveryId"], d.get("timestamp"))
                continue
            att = d.get("attachment")
            if b'"queued_command"' in line and isinstance(att, dict) and att.get("type") == "queued_command":
                found = _queued_evidence(d, att, line, prompt, after, used, absorbed, recent)
                if found is not None:
                    return found
                continue
            if d.get("type") != "user" or d.get("promptId") != pid:
                continue
            msg = d.get("message")
            c = msg.get("content") if isinstance(msg, dict) else None
            if not _human_content(c):
                continue  # tool results and other non-prompt user entries
            same_text = isinstance(prompt, str) and _content_text(c) == prompt
            if d.get("promptSource") in ("typed", "queued") and _origin_kind(d) in (None, "human"):
                eid, ts = "p:" + pid, d.get("timestamp")
                if eid in used or not _fresh(ts, after):
                    continue
                return "human", eid, ts
            if same_text:
                return "other", None, None
    except OSError:
        return None, None, None
    if seen and not recognized:
        return "format-unknown", None, None
    return None, None, None


def _queued_evidence(d, att, line, prompt, after, used, absorbed, recent):
    """Match queued text only with a fresh absorption of this human delivery."""
    if not (isinstance(prompt, str) and att.get("prompt") == prompt):
        return None
    did = att.get("delivery_id")
    eid = "q:%s" % (did or att.get("source_uuid") or d.get("uuid") or hashlib.sha256(line).hexdigest()[:32])
    ts = att.get("timestamp") or d.get("timestamp")
    if not (
        _origin_kind(att) == "human" and att.get("humanTurn") is True and att.get("commandMode", "prompt") == "prompt"
    ):
        return "other", None, None
    if eid in used or not _fresh(ts, after):
        return None
    # bound to THIS submission: the harness writes the absorption of this delivery when the message is
    # handed to the model, i.e. now; an older, unconsumed record of the same text is history, not evidence
    absorbed_at = absorbed.get(did) if isinstance(did, str) else None
    if not (isinstance(absorbed_at, str) and ISO_MS.match(absorbed_at) and absorbed_at >= recent):
        return None
    return "human", eid, ts


def _matching_record(line, key, sid):
    """Decode relevant records and reject records belonging to a different session."""
    is_pid = key is not None and key in line
    is_queued = b'"queued_command"' in line
    is_qop = b'"queue-operation"' in line
    if not (is_pid or is_queued or is_qop):
        return None
    try:
        d = json.loads(line)
    except ValueError:
        return None
    if not isinstance(d, dict):
        return None
    if "sessionId" in d and d.get("sessionId") != sid:
        return None
    return d


def transcript_origin(data, after=None, used=()):
    """(verdict, evidence id, timestamp): verdict 'human', 'other' or None (no evidence), from the harness's
    own transcript (the hook input has no promptSource). Transcript lines are JSON written by the harness, so
    data inside them cannot forge a separate record. The record may be written just after the hook starts, so
    the lookup is retried once (200 ms); later evidence is verified by the deferred path (pending_human)."""
    tp, pid, sid = data.get("transcript_path"), data.get("prompt_id"), data.get("session_id")
    if not (isinstance(tp, str) and isinstance(pid, str) and pid):
        return None, None, None
    root = os.environ.get("TAINT_TRANSCRIPT_ROOT") or tg_core.TRANSCRIPT_ROOT
    real = os.path.realpath(tp)
    if not real.startswith(root.rstrip("/") + "/"):
        return None, None, None
    for attempt in range(tg_hooks.TRANSCRIPT_TRIES):
        found = _transcript_lookup(real, pid, sid, data.get("prompt"), after, used)
        if found[0] is not None:
            return found
        if attempt + 1 < tg_hooks.TRANSCRIPT_TRIES:
            time.sleep(tg_hooks.TRANSCRIPT_WAIT_S)
    return None, None, None


def _consume_lookup(data, used):
    """One transcript lookup (no retries) for consuming a clean-session human message's evidence."""
    tp, pid, sid = data.get("transcript_path"), data.get("prompt_id"), data.get("session_id")
    if not (isinstance(tp, str) and isinstance(pid, str) and pid):
        return None, None, None
    root = os.environ.get("TAINT_TRANSCRIPT_ROOT") or tg_core.TRANSCRIPT_ROOT
    real = os.path.realpath(tp)
    if not real.startswith(root.rstrip("/") + "/"):
        return None, None, None
    return _transcript_lookup(real, pid, sid, data.get("prompt"), None, used)


def _transcript_real(tp):
    """The realpath of a transcript path inside the transcript root, else None."""
    if not isinstance(tp, str) or not tp or "\x00" in tp:
        return None
    root = os.environ.get("TAINT_TRANSCRIPT_ROOT") or tg_core.TRANSCRIPT_ROOT
    real = os.path.realpath(tp)
    return real if real.startswith(root.rstrip("/") + "/") else None


def _text_hash(text):
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _pending_lookup(item, sid, after, used):
    """One lookup (no sleeps) for a deferred prompt: 'human' (verified), 'drop' (this prompt is not human, or its
    evidence is stale or consumed and can never become fresh again) or None (not written yet)."""
    real = _transcript_real(item.get("transcript"))
    pid, want = item.get("pid"), item.get("sha256")
    if real is None or not (isinstance(pid, str) and pid and isinstance(want, str)):
        return "drop"
    key = pid.encode("utf-8", "replace")
    try:
        for line in _lines_reversed(real):
            if key not in line:
                continue
            try:
                d = json.loads(line)
            except ValueError:
                continue
            if not isinstance(d, dict) or d.get("type") != "user" or d.get("promptId") != pid:
                continue
            if "sessionId" in d and d.get("sessionId") != sid:
                continue
            msg = d.get("message")
            c = msg.get("content") if isinstance(msg, dict) else None
            if not _human_content(c):
                continue
            if not (d.get("promptSource") in ("typed", "queued") and _origin_kind(d) in (None, "human")):
                return "drop"
            if _text_hash(_content_text(c)) != want:
                continue  # not the text the hook was shown
            if ("p:" + pid) in used or not _fresh(d.get("timestamp"), after):
                return "drop"
            return "human"
    except OSError:
        return None
    return None


def resolve_pending_human(state, sid, event):
    """Inside `with state:`. Verify prompts whose transcript entry did not exist at UserPromptSubmit; the first
    verified one clears the taint (the entry must be newer than the latest untrusted read)."""
    if not state.gated or state.unknown is not None:
        return
    items = state.data.get("pending_human")
    if not (isinstance(items, list) and items):
        return
    after = state.data.get("marked_at")
    used = frozenset(e for e in (state.data.get("used_evidence") or []) if isinstance(e, str))
    keep, verified = [], None
    for item in reversed(items):  # newest first
        if not isinstance(item, dict):
            continue
        verdict = _pending_lookup(item, sid, after, used)
        if verdict == "human":
            verified = item
            break
        if verdict is None:
            keep.append(item)
    if verified is None:
        if len(keep) != len(items):
            state.update(pending_human=list(reversed(keep)))
        return
    ok = state.clear("p:" + verified["pid"])  # clear() also drops pending_human
    tg_state.log(
        sid, event, "-", "clear" if ok else "keep", "cleared-by-human-verified-deferred" if ok else "clear-failed"
    )
