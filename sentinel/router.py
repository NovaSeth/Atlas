#!/usr/bin/env python3
"""Sentinel router: delivers critical events to the human when the AI resident is absent.

Stdlib only, no LLM. The only side effect is one notification per (fingerprint, window):
SENTINEL_NOTIFY_CMD called as <cmd> "<subject>" "<body>" when configured, otherwise
`mail -s <subject> $SENTINEL_EMAIL`. With neither configured nothing is sent and the event is not
recorded as delivered (the next critical event retries).

Resident detection is configuration, not code: SENTINEL_RESIDENT_SCREEN (a screen session name) and
SENTINEL_RESIDENT_UNIT (a systemd unit). Both empty = there is no resident, so every critical event
goes to the human. The human's switch $SENTINEL_ATLAS/RESIDENT-OFF also means absent.

Overridable by env (tests): SENTINEL_STATE_DIR, SENTINEL_ATLAS, SENTINEL_SCREEN_CMD (default
"screen"), SENTINEL_SYSTEMCTL_CMD (default "systemctl"), SENTINEL_MAIL_CMD (default "mail").
"""
import fcntl
import json
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "atlas"))
from i18n import t  # noqa: E402

import bus  # noqa: E402
import notify as _notify  # noqa: E402

default_notify = _notify.send  # alias kept for callers and tests

# 6 h: the human is woken at most 4 times a day for the same fingerprint.
HUMAN_WINDOW_SECS = int(os.environ.get("SENTINEL_HUMAN_WINDOW_SECS") or 6 * 3600)
NOTIFY_TIMEOUT = 60


def state_dir():
    return bus.runtime_dir()


def default_state_path():
    return state_dir() / "router-sent.json"


def _atlas():
    return Path(os.environ.get("SENTINEL_ATLAS") or Path(__file__).resolve().parent.parent / "atlas")


def _run(cmd_env, default, args):
    cmd = shlex.split(os.environ.get(cmd_env) or default) + args
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None


def resident_present(atlas_dir=None, screen_out=None, unit_active=None, screen_name=None, unit=None):
    """Two independent signs (one may lie): a live screen session or an active systemd unit, as
    configured. A session reported as (Dead ???) is a corpse. RESIDENT-OFF (the human's switch) or
    no resident configured = absent."""
    atlas_dir = Path(atlas_dir) if atlas_dir else _atlas()
    screen_name = os.environ.get("SENTINEL_RESIDENT_SCREEN", "") if screen_name is None else screen_name
    unit = os.environ.get("SENTINEL_RESIDENT_UNIT", "") if unit is None else unit
    if (atlas_dir / "RESIDENT-OFF").exists():
        return False
    if not screen_name and not unit:
        return False
    if screen_name:
        if screen_out is None:
            r = _run("SENTINEL_SCREEN_CMD", "screen", ["-ls"])
            screen_out = (r.stdout if r else "") or ""
        pat = re.compile(r"\d+\.%s\s" % re.escape(screen_name))
        for line in screen_out.splitlines():
            if pat.search(line) and "dead" not in line.lower():
                return True
    if unit:
        if unit_active is None:
            r = _run("SENTINEL_SYSTEMCTL_CMD", "systemctl", ["is-active", "--quiet", unit])
            unit_active = bool(r and r.returncode == 0)
        return bool(unit_active)
    return False


def _load(path):
    try:
        data = json.loads(Path(path).read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _command_notifier(cmd):
    """A notifier for an explicit command (path or command line), used by tests and callers."""
    def notify(subject, body):
        try:
            r = subprocess.run(shlex.split(cmd) + [subject, body], capture_output=True, text=True,
                               timeout=NOTIFY_TIMEOUT)
            return r.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False
    return notify


def route(event, state_path=None, notify=None, presence=None, now=None):
    """Route one event. Returns True when the human was notified. Presence is checked at routing
    time, so a resident that died between events is noticed. A new fingerprint is never suppressed.
    `notify` is a callable (subject, body) -> bool or a command string; default: default_notify."""
    if event.get("severity") != "critical":
        return False
    presence = presence or resident_present
    if presence():
        return False  # the resident wakes through `bus.py follow`
    now = time.time() if now is None else now
    state_path = Path(state_path) if state_path else default_state_path()
    if notify is None:
        def notify(subject, body):
            # sent or queued (the escalation timer delivers the outbox) counts as handed off
            return _notify.send_or_queue(subject, body, "router") in ("sent", "queued")
    elif isinstance(notify, (str, os.PathLike)):
        notify = _command_notifier(str(notify))
    fp = event["fingerprint"]
    try:
        if state_path.parent == state_dir():
            bus.ensure_private_dir(state_path.parent)
        else:
            state_path.parent.mkdir(parents=True, exist_ok=True)
    except bus.UnsafeStateDir as e:
        # No trusted place for the dedup state: notify without dedup rather than stay silent.
        print("sentinel-router: unsafe runtime directory %s (%s)" % (e.path, e.code), file=sys.stderr, flush=True)
        text = event.get("message") or event.get("message_pl") or event.get("what", "")
        return bool(notify(t("router.subject", what=event.get("what", "")[:120]), "%s [%s]" % (text, fp)))
    with open(str(state_path) + ".lock", "a") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        state = _load(state_path)
        if fp in state and now - float(state[fp]) < HUMAN_WINDOW_SECS:
            return False
        # `message` is the field name; `message_pl` (its name before the catalog existed) is still
        # read for one release so that events written by an older patrol keep their text.
        text = event.get("message") or event.get("message_pl") or event.get("what", "")
        body = "%s [%s]" % (text, fp)
        subject = t("router.subject", what=event.get("what", "")[:120])
        if not notify(subject, body):
            return False  # not recorded as sent: the next critical event retries
        state = {k: v for k, v in state.items() if now - float(v) < HUMAN_WINDOW_SECS}
        state[fp] = now
        tmp = str(state_path) + ".tmp"
        Path(tmp).write_text(json.dumps(state))
        os.replace(tmp, state_path)
        return True
