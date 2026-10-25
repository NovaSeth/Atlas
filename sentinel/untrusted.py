#!/usr/bin/env python3
"""Untrusted text: request paths, SSH user names, sudo command lines, process names, URLs.

Anything an outsider (or a local user) can write ends up in log lines, and log lines end up on the
bus, in ALERT and in front of an AI agent. Two jobs, stdlib only:

  clean(text, limit)  printable ASCII only, whitespace collapsed, at most `limit` characters
  quote(text, limit)  clean() wrapped in double quotes with `"` and `\\` escaped: the text is shown
                      as DATA, and a reader can see where it starts and ends
  suspicious(text)    rule ids of a small heuristic set that flags instruction-like text

suspicious() is a SIGNAL, not a defense. Keyword heuristics and classifiers are evadable (published
research on prompt injection through log fields shows persona and context payloads slip past them);
the defense is structural: an AI agent reads raw logs only through a quarantined reader without
write tools, and never acts on instructions found in data. The rules favour precision over recall:
a false alarm on every scanner request would train everyone to ignore the warning.

Rules (ids are stable; they appear in events and fingerprints):
  override          "ignore / disregard / forget ... previous|prior|above ..." instructions
  persona           role markers ("system:", "assistant:", "<|im_start|>", "[INST]"),
                    "you are now", "from now on you", "pretend to be"
  new-instructions  "new / updated / real ... instructions|directives|prompt"
  addressed         text addressed to an AI ("dear AI", "note to the agent", "AI agent, please delete")
  run-command       "please run|execute <command word>", "run the following command"
  context           context manipulation: "the admin has authorized", "this alert is a false
                    positive", "do not report", "end of log"
  base64            a base64 run of >= 40 characters that decodes to mostly printable text
  invisible         zero-width or bidi control characters (raw, Apache \\xHH or %HH encoded)
  classifier        only when ATLAS_INJECTION_CLASSIFIER_CMD is set (see below)

Matching runs on a normalised copy: Apache `\\xHH` escapes and URL `%HH` encoding are decoded,
the text is lower-cased and every separator (`-`, `_`, `/`, `+`, `.`, ...) becomes a space, so
"/ignore-previous-instructions" and "ignore%20previous%20instructions" match the same rule.

Optional extra signal: if ATLAS_INJECTION_CLASSIFIER_CMD is set, it is run for every text (stdin =
the raw text, exit 1 = suspicious, 2 s timeout, any other outcome ignored). Off by default; no
network, no model unless the operator installs one locally.
"""
import base64
import binascii
import os
import re
import shlex
import signal
import subprocess
import urllib.parse

DEFAULT_LIMIT = 80
# Only a bounded prefix is inspected: a megabyte request line must not stall a follower on 1 vCPU.
SCAN_PREFIX = 4096
CLASSIFIER_TIMEOUT = 2.0

_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|\x1b[@-_]?")
_WS = re.compile(r"\s+")
_NON_PRINTABLE = re.compile(r"[^\x20-\x7e]")

# Zero-width and bidi controls: invisible to a human reading a terminal, visible to a model.
INVISIBLE = frozenset(
    [chr(c) for c in range(0x200B, 0x2010)]      # ZWSP, ZWNJ, ZWJ, LRM, RLM
    + [chr(c) for c in range(0x202A, 0x202F)]    # LRE, RLE, PDF, LRO, RLO
    + [chr(c) for c in range(0x2060, 0x2065)]    # WJ, invisible operators
    + [chr(c) for c in range(0x2066, 0x206A)]    # LRI, RLI, FSI, PDI
    + ["\ufeff", "\u061c", "\u180e"])

_AI = r"(?:ai|llm|assistant|agent|model|bot|claude|gpt|chatgpt|copilot|gemini|resident)"
_CMD_WORD = (r"(?:sudo|su|curl|wget|bash|sh|zsh|rm|chmod|chown|python3?|perl|nc|ncat|socat|systemctl|"
             r"crontab|ssh|scp|touch|echo|cat|dd|mkfs|useradd|usermod|passwd|iptables|ufw|atlas|bless)")

RULES = {
    "override": [
        r"\b(?:ignore|disregard|forget|override|bypass|skip)\s+(?:(?:all|any|the|your|of|these|those)\s+)*"
        r"(?:previous|prior|above|earlier|preceding|existing|system|safety|original)\b",
        r"\b(?:forget|ignore|disregard)\s+(?:everything|all)\s+(?:you|instructions|rules|above|before)\b",
    ],
    "persona": [
        r"(?:^|\s)(?:system|assistant|developer)\s*:",
        r"\byou\s+are\s+now\b",
        r"\bfrom\s+now\s+on\s+you\b",
        r"\bpretend\s+(?:to\s+be|you\s+are)\b",
        r"<\|\s*(?:im\s+start|im\s+end|system|endoftext)",
        r"\[\s*/?\s*inst\s*\]",
    ],
    "new-instructions": [
        r"\b(?:new|updated|revised|real|actual|additional|hidden)\s+(?:system\s+)?"
        r"(?:instructions?|directives?|prompt)\b",
    ],
    "addressed": [
        r"\b(?:dear|hey|hello|attention|(?:note|message|instructions?)\s+(?:to|for)(?:\s+the)?)\s+"
        + _AI + r"\b",
        r"\b(?:ai|llm)\s+(?:agent|assistant|model)s?\s*[:,]?\s+(?:please\s+)?"
        r"(?:run|execute|delete|remove|send|ignore|disable|stop|reveal|print|install|create|add|write|"
        r"bless|ack|acknowledge)\b",
    ],
    "run-command": [
        r"\bplease\s+(?:run|execute|exec)\s+(?:\S+\s+){0,2}?" + _CMD_WORD + r"\b",
        r"\b(?:run|execute)\s+(?:the\s+following|this)\s+(?:command|script|code)\b",
    ],
    "context": [
        r"\b(?:admin|administrator|owner|operator|sysadmin|security\s+team|it\s+department)\s+"
        r"(?:has\s+|have\s+)?(?:authori[sz]ed|approved|requested|instructed|allowed|permitted)\b",
        r"\b(?:authori[sz]ed|approved|sanctioned)\s+(?:security\s+|penetration\s+|pen\s+)?"
        r"(?:test|testing|scan|maintenance|change)\b",
        r"\b(?:this|the)\s+(?:alert|alarm|event|request|warning|incident)\s+is\s+(?:a\s+)?"
        r"(?:false\s+positive|expected|safe|benign|harmless|authori[sz]ed)\b",
        r"\bdo\s+not\s+(?:report|alert|escalate|notify|flag|mention|tell)\b",
        r"\bend\s+of\s+(?:log|logs|data|input|context)\b",
    ],
}
_COMPILED = {rid: [re.compile(p) for p in pats] for rid, pats in RULES.items()}
RULES["base64"] = [r"[A-Za-z0-9+/]{40,}={0,2} decoding to >= 80% printable ASCII"]
RULES["invisible"] = ["zero-width / bidi control characters"]

_B64_RUN = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_APACHE_ESC = re.compile(r"(?:\\x[0-9a-fA-F]{2})+")
_SEPARATORS = re.compile(r"[^a-z0-9:|<>\[\]]+")


def _text(text):
    if text is None:
        return ""
    return text if isinstance(text, str) else str(text)


def clean(text, limit=DEFAULT_LIMIT):
    """Printable ASCII (0x20-0x7E) only: ANSI escape sequences and every other character become `?`,
    whitespace runs become one space, the result is at most `limit` characters (cut with `...`)."""
    s = _ANSI.sub("?", _text(text))
    s = _WS.sub(" ", s).strip()
    s = _NON_PRINTABLE.sub("?", s)
    if len(s) > limit:
        s = s[:limit - 3] + "..." if limit > 3 else s[:limit]
    return s


def quote(text, limit=DEFAULT_LIMIT):
    """clean(text) as a quoted string; `"` and `\\` are escaped. The text between the quotes is at most
    `limit` characters, escapes included, and never ends in a dangling backslash."""
    c = clean(text, limit=max(limit, len(_text(text)) + 1))
    esc = c.replace("\\", "\\\\").replace('"', '\\"')
    if len(esc) > limit:
        out, n, budget = [], 0, max(limit - 3, 0)
        for ch in c:
            piece = "\\" + ch if ch in '"\\' else ch
            if n + len(piece) > budget:
                break
            out.append(piece)
            n += len(piece)
        esc = "".join(out) + "..."
    return '"' + esc + '"'


def _decode(raw):
    s = _APACHE_ESC.sub(lambda m: bytes.fromhex(m.group(0).replace("\\x", "")).decode("utf-8", "replace"), raw)
    for _ in range(2):  # double URL encoding (%2520) is a classic filter evasion
        if "%" not in s:
            break
        s = urllib.parse.unquote(s, errors="replace")
    return s


def _base64_text(s):
    for m in _B64_RUN.finditer(s):
        # a path separator often precedes the payload ("/aWdub3Jl..."): try every alignment
        run = m.group(0).strip("/").rstrip("=")
        for off in range(4):
            part = run[off:]
            part = part[: len(part) - len(part) % 4]
            if len(part) < 40:
                break
            try:
                data = base64.b64decode(part, validate=True)
            except (binascii.Error, ValueError):
                continue
            if sum(32 <= b < 127 or b in (9, 10, 13) for b in data) >= 0.8 * len(data):
                return True
    return False


def _classifier(raw):
    cmd = os.environ.get("ATLAS_INJECTION_CLASSIFIER_CMD")
    if not cmd:
        return False
    try:
        p = subprocess.Popen(shlex.split(cmd), stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True)
    except (OSError, ValueError):
        return False
    try:
        p.communicate(raw.encode("utf-8", "replace"), timeout=CLASSIFIER_TIMEOUT)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(p.pid, signal.SIGKILL)  # the whole group: a shell's children must not linger
        except OSError:
            pass
        p.wait()
        return False
    except OSError:
        p.wait()
        return False
    return p.returncode == 1


def suspicious(text):
    """Rule ids (see the module docstring) that match `text`; [] for ordinary text. A signal only."""
    raw = _text(text)[:SCAN_PREFIX]
    if not raw:
        return []
    decoded = _decode(raw)
    # ANSI sequences are cut out first: "\x1b[2Jyou are now" must read as "you are now"
    words = " " + _SEPARATORS.sub(" ", _ANSI.sub(" ", decoded).lower()) + " "
    hits = [rid for rid, pats in _COMPILED.items() if any(p.search(words) for p in pats)]
    if _base64_text(decoded):
        hits.append("base64")
    if any(ch in INVISIBLE for ch in decoded):
        hits.append("invisible")
    if _classifier(raw):
        hits.append("classifier")
    return hits
