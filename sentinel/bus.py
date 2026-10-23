#!/usr/bin/env python3
"""Sentinel event bus: one JSON object per line in atlas/events.jsonl (stdlib only, no LLM).

    bus.py emit --json '<event>'                      exit 0 ok, 2 invalid
    bus.py follow --min-severity alert --dedup-seconds 3600 [--from-end]

Every path is overridable by env (tests never touch production):
    SENTINEL_ATLAS (dir), SENTINEL_BUS, SENTINEL_BUS_LOCK, SENTINEL_BUS_MAX_BYTES
"""
import argparse
import fcntl
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

SEVERITIES = ["info", "warning", "alert", "critical"]
CONFIDENCES = ["measured", "inferred", "unknown"]
REQUIRED = ["sensor", "severity", "confidence", "what", "fingerprint"]
KEEP = 3  # rotated generations: events.jsonl.1 .. .3 (about 20 MB worst case on a small disk)
# 5 MB: ~20k events of ~250 B - days of history for the resident, bounded disk use.
DEFAULT_MAX_BYTES = 5 * 1024 * 1024
FOLLOW_POLL = 0.5  # seconds; a tail-like poll, never a busy loop (1 vCPU host, G8)

# A fingerprint identifies WHAT happened, never WHEN: a timestamp in it would make every
# repeat a new fingerprint and defeat dedup. Patterns: ISO date, HH:MM, 10-13 digit epoch.
# The epoch pattern is bounded by non-hex characters, not non-digits: a sha prefix such as
# "224e3684913817bd" holds 10 consecutive digits and is not a timestamp (seen in production).
_TS_PATTERNS = [
    re.compile(r"\d{4}-\d{2}-\d{2}"),
    re.compile(r"(?<!\d)\d{1,2}:\d{2}(?::\d{2})?(?!\d)"),
    re.compile(r"(?<![0-9a-fA-F])\d{10,13}(?![0-9a-fA-F])"),
]


def atlas_dir():
    return Path(os.environ.get("SENTINEL_ATLAS") or Path(__file__).resolve().parent.parent / "atlas")


def bus_path():
    return Path(os.environ.get("SENTINEL_BUS") or atlas_dir() / "events.jsonl")


def lock_path():
    return Path(os.environ.get("SENTINEL_BUS_LOCK") or atlas_dir() / "events.lock")


def max_bytes():
    return int(os.environ.get("SENTINEL_BUS_MAX_BYTES") or DEFAULT_MAX_BYTES)


def sanitize_fp(text):
    """Make a string safe as a fingerprint fragment (replace timestamp-looking parts)."""
    for pat in _TS_PATTERNS:
        text = pat.sub("N", text)
    return text


def validate(ev):
    """Return a list of problems (empty = valid)."""
    if not isinstance(ev, dict):
        return ["event is not a JSON object"]
    errs = []
    for k in REQUIRED:
        if not isinstance(ev.get(k), str) or not ev[k].strip():
            errs.append("missing or empty key: %s" % k)
    if ev.get("severity") not in SEVERITIES:
        errs.append("severity must be one of %s" % SEVERITIES)
    if ev.get("confidence") not in CONFIDENCES:
        errs.append("confidence must be one of %s" % CONFIDENCES)
    fp = ev.get("fingerprint")
    if isinstance(fp, str) and any(p.search(fp) for p in _TS_PATTERNS):
        errs.append("fingerprint contains a timestamp-looking fragment")
    if "evidence" in ev and not isinstance(ev["evidence"], dict):
        errs.append("evidence must be an object")
    # The optional sentence for the human is `message`. Its old name `message_pl` is still accepted
    # for one release (events from an older patrol or sensor); drop it in the release after that.
    for k in ("message", "message_pl"):
        if k in ev and not isinstance(ev[k], str):
            errs.append("%s must be a string" % k)
    return errs


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _rotate(path):
    # rename (not copytruncate): a follower holding the old inode drains it completely.
    for i in range(KEEP, 1, -1):
        src = Path("%s.%d" % (path, i - 1))
        if src.exists():
            os.replace(src, "%s.%d" % (path, i))
    os.replace(path, "%s.1" % path)


def emit(event, path=None):
    """Validate and append one event under flock. Raises ValueError when invalid."""
    ev = dict(event)
    ev.setdefault("ts", now_iso())
    errs = validate(ev)
    if errs:
        raise ValueError("; ".join(errs))
    path = Path(path) if path else bus_path()
    lock = lock_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    line = (json.dumps(ev, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    with open(lock, "a") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            if path.exists() and path.stat().st_size >= max_bytes():
                _rotate(path)
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
            try:
                os.write(fd, line)  # one write() of one line: never interleaved
            finally:
                os.close(fd)
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)
    return ev


def _parse(line):
    try:
        ev = json.loads(line)
    except ValueError:
        return None
    return ev if isinstance(ev, dict) else None


class _Reader:
    """Reads complete lines from one open file, keeping a partial tail in a buffer."""

    def __init__(self, f):
        self.f, self.buf = f, b""

    def lines(self):
        chunk = self.f.read()
        if chunk:
            self.buf += chunk
        out = []
        while b"\n" in self.buf:
            raw, self.buf = self.buf.split(b"\n", 1)
            if raw.strip():
                out.append(raw.decode("utf-8", "replace"))
        return out


def _open(path):
    try:
        return open(path, "rb")
    except FileNotFoundError:
        return None


def follow_events(from_end=False, stop=lambda: False, poll=FOLLOW_POLL, path=None, on_ready=None):
    """Yield parsed events as they are appended, tail -F style across rotation.

    Rotation is a rename, so we keep reading the old inode to EOF, then read every rotated
    generation that is newer than ours (a second rotation may happen while we lag), then
    switch to the fresh file from offset 0: nothing lost, nothing read twice.
    """
    path = Path(path) if path else bus_path()
    f = _open(path)
    if f is not None and from_end:
        f.seek(0, os.SEEK_END)
    if on_ready:
        on_ready()  # positioned: events appended from now on will be seen
    while f is None and not stop():
        time.sleep(poll)
        f = _open(path)  # created after we started: everything in it is new, read from 0
    if f is None:
        return
    rd = _Reader(f)
    while not stop():
        for line in rd.lines():
            ev = _parse(line)
            if ev:
                yield ev
        try:
            cur = os.stat(path)
        except FileNotFoundError:
            cur = None
        mine = os.fstat(rd.f.fileno())
        if cur is not None and (cur.st_ino, cur.st_dev) != (mine.st_ino, mine.st_dev):
            # rotated: drain what was written to the old inode before the rename
            for line in rd.lines():
                ev = _parse(line)
                if ev:
                    yield ev
            newer = []
            for i in range(1, KEEP + 1):
                rp = Path("%s.%d" % (path, i))
                try:
                    st = os.stat(rp)
                except FileNotFoundError:
                    continue
                if (st.st_ino, st.st_dev) == (mine.st_ino, mine.st_dev):
                    break
                newer.append(rp)
            else:
                newer = []  # our generation fell off the end: do not guess, resume at the live file
            rd.f.close()
            for rp in reversed(newer):  # oldest of the newer generations first
                g = _open(rp)
                if g is None:
                    continue
                with g:
                    for line in _Reader(g).lines():
                        ev = _parse(line)
                        if ev:
                            yield ev
            rd = _Reader(_open(path) or open(os.devnull, "rb"))
            continue
        if cur is not None and cur.st_size < rd.f.tell():  # truncated in place
            rd.f.seek(0)
            rd.buf = b""
            continue
        time.sleep(poll)
    rd.f.close()


def cmd_emit(args):
    try:
        ev = json.loads(args.json)
    except ValueError as e:
        print("bus emit: invalid JSON: %s" % e, file=sys.stderr)
        return 2
    try:
        emit(ev)
    except ValueError as e:
        print("bus emit: invalid event: %s" % e, file=sys.stderr)
        return 2
    return 0


def format_line(ev):
    try:
        hhmm = datetime.strptime(ev["ts"], "%Y-%m-%dT%H:%M:%SZ").strftime("%H:%M")
    except (KeyError, ValueError):
        hhmm = "--:--"
    return "%s %s %s: %s [%s]" % (hhmm, ev["severity"].upper(), ev["sensor"], ev["what"], ev["fingerprint"])


def cmd_follow(args):
    floor = SEVERITIES.index(args.min_severity)
    last = {}  # fingerprint -> monotonic time last printed; a NEW fingerprint is never suppressed
    for ev in follow_events(from_end=args.from_end):
        if validate(ev) or SEVERITIES.index(ev["severity"]) < floor:
            continue
        now = time.monotonic()
        fp = ev["fingerprint"]
        if fp in last and now - last[fp] < args.dedup_seconds:
            continue
        last[fp] = now
        if len(last) > 5000:  # bounded memory: drop expired entries
            last = {k: v for k, v in last.items() if now - v < args.dedup_seconds}
        print(format_line(ev), flush=True)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("emit")
    e.add_argument("--json", required=True)
    f = sub.add_parser("follow")
    f.add_argument("--min-severity", default="alert", choices=SEVERITIES)
    # 3600 s: the resident is woken at most once per hour per fingerprint (success criterion 3)
    f.add_argument("--dedup-seconds", type=int, default=3600)
    f.add_argument("--from-end", action="store_true")
    args = ap.parse_args(argv)
    try:
        return {"emit": cmd_emit, "follow": cmd_follow}[args.cmd](args)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
