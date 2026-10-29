#!/usr/bin/env bash
# Event sensor for the LLM session. Emits a line ONLY when the state CHANGES to bad
# or when it returns to good. Silence = nothing changed.
#
# Why this exists: a patrol loop INSIDE an AI session re-reads the whole session context on
# every tick. Measured once: a context of ~800k tokens times ~130 ticks = about 100 million input
# tokens in one day, for a patrol that found nothing in 99% of cases. Polling was replaced by
# listening: run this script under the agent's Monitor-like tool; it costs 0 while nothing happens.
#
# NOTE: this sensor's silence is NOT proof of health - if it dies itself, it is silent
# just the same. That is what sentinel-escalation.timer is for (systemd, independent of this
# session), which mails the human when the patrol or the resident goes quiet.
set -uo pipefail
# Code location comes from this script's own path, never from the state dir.
SDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ATLAS=${SENTINEL_ATLAS:-$SDIR/../atlas}
# shellcheck source=../atlas/lib.sh
. "$SDIR/../atlas/lib.sh"
atlas_load_env "$ATLAS"
ESCALATION_LOG=${SENTINEL_ESCALATION_LOG:-${SENTINEL_STATE:-$ATLAS/runtime}/escalation.log}
# Interval overridable ONLY for tests; 120 s in production.
INTERVAL=${SENTINEL_INTERVAL:-120}
# Real-time bus events: `bus.py follow` runs as a child of this script and writes
# straight to our stdout, so both streams reach the Monitor through ONE pipe. Each side emits whole
# lines (python flushed via PYTHONUNBUFFERED, bash echo), and a line below PIPE_BUF is atomic,
# so lines never interleave mid-line.
# --min-severity alert: info/warning events must not wake the session. --dedup-seconds 3600: the
# same fingerprint at most once an hour (a new fingerprint always passes). --from-end: no replay of
# old events on every restart.
# When bus.py is absent the sensor works exactly as before. SENTINEL_BUS_CMD overrides it (tests).
REPO_ROOT=$(cd "$SDIR/.." && pwd)
BUS_CMD=${SENTINEL_BUS_CMD:-"python3 $REPO_ROOT/sentinel/bus.py"}
if [ -n "${SENTINEL_BUS_CMD:-}" ] || [ -f "$REPO_ROOT/sentinel/bus.py" ]; then
    MAIN_PID=$$
    BUS_FILE=${SENTINEL_BUS_FILE:-$ATLAS/events.jsonl}
    STATE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/session-sensor.XXXXXX")
    SEEN="$STATE_DIR/seen"   # "<epoch> <fingerprint>" of every bus line printed (live or replayed)
    : > "$SEEN"
    # Replays the bus lines appended since byte offset $1 (inode $2 of the file at the time; a
    # different inode or a shorter file = rotation: replay from the start) through the same filter
    # as the follower: severity >= alert, a fingerprint at most once per hour (shared via $SEEN).
    replay_gap() {
        python3 -I -c '
import json, os, sys, time
path, off, ino, seen = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
try:
    st = os.stat(path)
except OSError:
    sys.exit(0)
if st.st_ino != ino or st.st_size < off:
    off = 0
now = time.time()
done = {}
for l in open(seen).read().splitlines():
    t, _, fp = l.partition(" ")
    done[fp] = float(t)
with open(path, "rb") as f:
    f.seek(off)
    data = f.read()
data = data[: data.rfind(b"\n") + 1]
for l in data.decode("utf-8", "replace").splitlines():
    try:
        e = json.loads(l)
        if e["severity"] not in ("alert", "critical"):
            continue
        fp = str(e["fingerprint"])
        if now - done.get(fp, 0) < 3600:
            continue
        done[fp] = now
        with open(seen, "a") as s:
            s.write("%d %s\n" % (now, fp))
        print("%s %s %s: %s [%s]" % (str(e.get("ts", ""))[11:16], e["severity"].upper(), e["sensor"], e["what"], fp), flush=True)
    except (ValueError, KeyError, TypeError):
        continue
' "$BUS_FILE" "$1" "$2" "$SEEN" 2>/dev/null
    }
    # Records every printed follower line's fingerprint (the trailing [..]) so a replay after a
    # restart does not print it again.
    track_seen() {
        local line fp
        while IFS= read -r line; do
            printf '%s\n' "$line"
            fp=${line##*\[}; fp=${fp%\]*}
            printf '%s %s\n' "$(date +%s)" "$fp" >> "$SEEN"
        done
    }
    (
        # A follower that exits (crash, EOF) is restarted after 30 s: a dead follower would be silence
        # that looks like health. 30 s keeps a crash loop from burning CPU on 1 vCPU.
        # --from-end alone would lose everything emitted during that gap, so the size and inode of the
        # bus file are recorded when each follower starts; the next one first replays what was
        # appended since (bus.py is not changed for this). The first start has nothing to replay.
        start_off=""; start_ino=""
        while kill -0 "$MAIN_PID" 2>/dev/null; do
            cur_ino=$(stat -c %i "$BUS_FILE" 2>/dev/null || echo 0)
            cur_off=$(stat -c %s "$BUS_FILE" 2>/dev/null || echo 0)
            if [ -n "$start_off" ]; then
                replay_gap "$start_off" "$start_ino"
            fi
            start_off=$cur_off; start_ino=$cur_ino
            # shellcheck disable=SC2086  # BUS_CMD is deliberately word-split
            PYTHONUNBUFFERED=1 $BUS_CMD follow --min-severity alert --dedup-seconds 3600 --from-end > >(track_seen) &
            FPID=$!
            # Orphan guard: when this script is killed (even SIGKILL, which runs no trap), the
            # follower must not live on. Poll the parent every 2 s; cheap, no busy loop.
            while kill -0 "$MAIN_PID" 2>/dev/null && kill -0 "$FPID" 2>/dev/null; do sleep 2; done
            kill "$FPID" 2>/dev/null
            wait "$FPID" 2>/dev/null
            kill -0 "$MAIN_PID" 2>/dev/null && sleep "${SENTINEL_FOLLOW_RETRY:-30}"
        done
        rm -rf "$STATE_DIR"
    ) &
fi
# Change detection compares KEYS (full content hashes / normalised text); only the DISPLAYED
# text is truncated. prev holds the key of the last state.
prev=""
while true; do
    cur=""   # displayed text
    key=""   # state key for change detection
    # We compare the alert CONTENT without the first line (timestamp of first appearance):
    # otherwise the same content would wake the session on every patrol run (SENTINEL anti-
    # pattern: a timestamp inside compared text). The content itself (from ALERT) is for the human.
    # An acknowledgement is valid only if ALERT.acked is at least as new as ALERT - exactly the
    # rule of escalation.sh; an older ack must not silence a newer alert.
    if [ -f "$ATLAS/ALERT" ]; then
        acked=0
        [ -f "$ATLAS/ALERT.acked" ] && \
            [ "$(stat -c %Y "$ATLAS/ALERT.acked" 2>/dev/null || echo 0)" -ge "$(stat -c %Y "$ATLAS/ALERT" 2>/dev/null || echo 0)" ] && acked=1
        if [ "$acked" -eq 0 ]; then
            body=$(tail -n +2 "$ATLAS/ALERT")
            # ANSI sequences, control and format characters (zero-width, bidi overrides) from untrusted
            # text in ALERT must not reach the terminal or the agent reading this line; letters in any
            # language stay (SENTINEL_LANG=pl). 300 characters, newlines become spaces.
            cur="ATLAS ALERT: $(printf '%s' "$body" | python3 -I "$SDIR/untrusted.py" clean-unicode 300)"
            key="alert:$(printf '%s' "$body" | sha256sum | cut -d' ' -f1)"
        fi
    fi
    if [ -f "$ATLAS/REPORT-TO-SEND" ]; then
        cur="${cur:+$cur | }REPORT waiting to be sent (REPORT-TO-SEND)"
        key="${key:+$key | }report"
    fi
    last=$(tail -1 "$ESCALATION_LOG" 2>/dev/null || true)
    if [ -n "$last" ] && ! printf '%s' "$last" | grep -q ' ok ('; then
        cur="${cur:+$cur | }ESCALATION REPORTS: $last"
        # the leading ISO timestamp differs on every run: compare the rest only
        key="${key:+$key | }escalation:${last#* }"
    fi
    if [ "$key" != "$prev" ]; then
        if [ -n "$cur" ]; then
            echo "$(date '+%H:%M') $cur"
        else
            echo "$(date '+%H:%M') clear — previous event has subsided"
        fi
    fi
    prev="$key"
    sleep "$INTERVAL"
done
