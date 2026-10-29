#!/usr/bin/env python3
"""Daily digest of agent actions, delivered through the notifier outbox."""
import argparse
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "atlas"))
import bus  # noqa: E402
import notify  # noqa: E402

from i18n import t  # noqa: E402

DIGEST_SENSORS = frozenset({"atlas.bless", "atlas.ack", "auth.sudo.forged"})
DIGEST_MAX_LINES = 200
DIGEST_WINDOW_S = 86400


def _timestamp(value):
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp()


def collect(now: float, window_s: int = 86400, paths: list | None = None) -> list[dict]:
    """Read valid selected events in the window, oldest first, across bus rotations.

    Missing generations are normal; other read errors propagate so a failed collection
    cannot be mistaken for an empty day.
    """
    if paths is None:
        base = bus.bus_path()
        paths = [base] + [Path("%s.%d" % (base, n)) for n in range(1, bus.KEEP + 1)]
    found = {}
    for path in paths:
        try:
            source = open(path, encoding="utf-8", errors="replace")
        except FileNotFoundError:
            continue
        with source:
            for line in source:
                try:
                    event = json.loads(line)
                    if bus.validate(event):
                        continue
                    stamp = _timestamp(event["ts"])
                except (ValueError, TypeError, KeyError):
                    continue
                if not now - window_s <= stamp <= now:
                    continue
                if event.get("evidence", {}).get("digest") is not True and event["sensor"] not in DIGEST_SENSORS:
                    continue
                found.setdefault((event["ts"], event["fingerprint"]), event)
    return sorted(found.values(), key=lambda event: event["ts"])


def render(events: list[dict], now: float) -> tuple[str, str] | None:
    """Render up to the line limit; event text is already quoted by its producer."""
    if not events:
        return None
    shown = events[:DIGEST_MAX_LINES]
    since = time.strftime("%Y-%m-%d %H:%M", time.gmtime(now - DIGEST_WINDOW_S))
    until = time.strftime("%Y-%m-%d %H:%M", time.gmtime(now))
    lines = [t("digest.header", since=since, until=until)]
    lines.extend("%s %s %s" % (event["ts"][11:16], event["sensor"], event["what"]) for event in shown)
    if len(events) > len(shown):
        lines.append(t("digest.more", count=len(events) - len(shown)))
    return t("digest.subject", count=len(shown)), "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["send"])
    parser.parse_args(argv)
    try:
        now = time.time()
        notice = render(collect(now), now)
        if notice is None:
            return 0
        return 1 if notify.send_or_queue(*notice, kind="digest") == "lost" else 0
    except (OSError, bus.UnsafeStateDir) as exc:
        print("sentinel-digest: collection failed: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
