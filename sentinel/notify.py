#!/usr/bin/env python3
"""Sentinel notifier: send a notice to the human, or queue it in an outbox for the escalation timer.

Stdlib only, no LLM. The stream runs without privileges for a setuid MTA, so a notice it cannot send is
written to <runtime>/outbox/ and delivered by the next escalation run (`notify.py drain`).

    notify.py drain      deliver queued notices; prints "outbox: sent=N failed=M dropped=K" only when non-zero

Channels (same as the router): SENTINEL_NOTIFY_CMD called as <cmd> "<subject>" "<body>", otherwise
`mail -s <subject> $SENTINEL_EMAIL` (SENTINEL_MAIL_CMD overrides `mail`).
"""
import fcntl
import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bus  # noqa: E402

OUTBOX_MAX = 200
OUTBOX_MAX_AGE_S = 7 * 86400
NOTIFY_TIMEOUT = 60
DROPPED_FILE = ".dropped"  # count of entries lost to the size/age bound, reported by the next drain


def outbox_dir():
    return bus.runtime_dir() / "outbox"


def send(subject, body, timeout=NOTIFY_TIMEOUT):
    """Send one notification; True when a channel accepted it. `timeout` bounds one attempt (seconds)."""
    env = dict(os.environ)
    cmd = os.environ.get("SENTINEL_NOTIFY_CMD", "").strip()
    try:
        if cmd:
            r = subprocess.run(shlex.split(cmd) + [subject, body], capture_output=True, text=True,
                               timeout=timeout, env=env)
            return r.returncode == 0
        to = os.environ.get("SENTINEL_EMAIL", "").strip()
        if not to:
            print("sentinel-router: no recipient configured (SENTINEL_EMAIL and SENTINEL_NOTIFY_CMD empty)",
                  file=sys.stderr, flush=True)
            return False
        mail = shlex.split(os.environ.get("SENTINEL_MAIL_CMD") or "mail")
        r = subprocess.run(mail + ["-s", subject, to], input=body + "\n", capture_output=True, text=True,
                           timeout=timeout, env=env)
        return r.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _ensure_outbox():
    bus.ensure_private_dir(bus.runtime_dir())
    return bus.ensure_private_dir(outbox_dir())


def _entries(box):
    def key(p):
        try:
            return int(p.name.split("-", 1)[0])
        except ValueError:
            return 0
    return sorted(box.glob("*.json"), key=key)


def _count_dropped(box, n):
    if n <= 0:
        return
    f = box / DROPPED_FILE
    try:
        cur = int(f.read_text().strip() or 0)
    except (OSError, ValueError):
        cur = 0
    try:
        f.write_text(str(cur + n))
    except OSError:
        pass


def _queue(subject, body, kind):
    box = _ensure_outbox()
    lock = os.open(str(box / ".lock"), os.O_CREAT | os.O_RDWR, 0o640)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        files = _entries(box)
        extra = len(files) - OUTBOX_MAX + 1
        if extra > 0:  # bound: the oldest notices go first, and they are counted
            dropped = 0
            for f in files[:extra]:
                try:
                    f.unlink()
                    dropped += 1
                except OSError:
                    pass
            _count_dropped(box, dropped)
        safe_kind = "".join(c for c in kind if c.isalnum() or c in "._") or "x"
        name = "%d-%s.json" % (time.time_ns(), safe_kind)
        tmp = box / (name + ".tmp")
        data = {"v": 1, "kind": kind, "subject": subject, "body": body, "created": time.time()}
        fd = os.open(str(tmp), os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o640)
        with os.fdopen(fd, "w") as fh:
            fh.write(json.dumps(data))
        os.chmod(tmp, 0o640)
        os.replace(tmp, box / name)
    finally:
        os.close(lock)


def send_or_queue(subject, body, kind):
    """'sent' when a channel accepted the notice, 'queued' when it waits in the outbox, 'lost' when neither."""
    if send(subject, body):
        return "sent"
    try:
        _queue(subject, body, kind)
        return "queued"
    except (OSError, bus.UnsafeStateDir) as e:
        print("sentinel-notify: notice lost (%s): %s" % (kind, e), file=sys.stderr, flush=True)
        return "lost"


def drain(max_seconds=60.0):
    """Deliver queued notices, oldest first; a delivered one is removed. Stops at the first failure
    (the channel is down; the rest stays queued and counts as failed) or when the time is up. The whole
    call, lock wait and every send included, stays inside `max_seconds`."""
    return _drain(max_seconds)[0]


def _drain(max_seconds):
    """(counts, error): `error` is a short text when the outbox could not be used at all, else ''."""
    result = {"sent": 0, "failed": 0, "dropped": 0}
    end = time.monotonic() + max_seconds
    box = outbox_dir()
    try:
        bus.ensure_private_dir(bus.runtime_dir())
        if not box.is_dir():
            return result, ""
        bus.ensure_private_dir(box)
        lock = os.open(str(box / ".lock"), os.O_CREAT | os.O_RDWR, 0o640)
    except (OSError, bus.UnsafeStateDir) as e:
        print("sentinel-notify: outbox unusable: %s" % e, file=sys.stderr, flush=True)
        return result, str(e)
    error = ""
    try:
        while True:  # bounded lock wait: a stuck holder must not eat the whole budget
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() >= end:
                    print("sentinel-notify: outbox lock busy", file=sys.stderr, flush=True)
                    return result, "lock busy"
                time.sleep(0.1)
        files = _entries(box)
        for i, f in enumerate(files):
            try:
                e = json.loads(f.read_text())
                if not isinstance(e, dict):
                    raise ValueError("not an object")
                expired = time.time() - float(e.get("created", 0)) > OUTBOX_MAX_AGE_S
            except (OSError, ValueError, TypeError):
                e, expired = None, True  # unreadable entry: drop it, counted
            if expired:
                try:
                    f.unlink()
                    result["dropped"] += 1
                except OSError:
                    result["failed"] += 1
                continue
            left = end - time.monotonic()
            if left <= 0 or not send(str(e.get("subject", "")), str(e.get("body", "")),
                                     timeout=min(NOTIFY_TIMEOUT, left)):
                result["failed"] += len(files) - i
                break
            try:
                f.unlink()
            except OSError:
                pass
            result["sent"] += 1
        d = box / DROPPED_FILE
        try:
            result["dropped"] += int(d.read_text().strip() or 0)
            d.unlink()
        except (OSError, ValueError):
            pass
    finally:
        os.close(lock)
    return result, error


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] != ["drain"]:
        print("usage: notify.py drain", file=sys.stderr)
        return 2
    r, error = _drain(60.0)
    if error:
        print("outbox: unusable (%s)" % error)
        return 1
    if r["sent"] or r["failed"] or r["dropped"]:
        print("outbox: sent=%d failed=%d dropped=%d" % (r["sent"], r["failed"], r["dropped"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
