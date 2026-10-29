#!/usr/bin/env bash
# SENTINEL - escalation to a human BYPASSING the LLM.
#
# Why it exists: when the alarm channel runs THROUGH the AI session, a host that goes down (a
# provider maintenance reboot, a crash) takes the session and the means to shout about it at the
# same time. The only symptom is silence, and a human has to notice it. This script is the path
# that does not depend on the session.
#
# PRINCIPLE: this script knows nothing about an LLM. It does not import its libraries, does not read
# its configuration, does not call it. Its only job is to write to a human when SILENCE lasts too
# long. If a model call ever appears here - the goal is lost.
#
# Configuration ($SENTINEL_ATLAS/sentinel.env, the environment wins):
#   SENTINEL_EMAIL          mail recipient
#   SENTINEL_NOTIFY_CMD     notify channel, called as <cmd> "<subject>" "<body>"
#                           (both empty = "no recipient configured", exit 2 (UNKNOWN), never ok)
#   SENTINEL_RESIDENT_UNIT  systemd unit of the AI resident (empty = no resident: check skipped)
#   SENTINEL_RESIDENT_SCREEN  screen session name of the AI resident (empty = not checked)
#   SENTINEL_LANG           language of the mail texts (en default, pl available)
# State: $SENTINEL_ATLAS/runtime (SENTINEL_STATE overrides, for tests), SENTINEL_STREAM_HEARTBEAT.
set -uo pipefail

# Testability is a feature, not a hack: a script whose alarm branch nobody ever ran is a hope,
# not a safeguard. Every path can be redirected to a temp dir and every command to a stub.
SDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ATLAS=${SENTINEL_ATLAS:-$SDIR/../atlas}
# shellcheck source=../atlas/lib.sh
. "$SDIR/../atlas/lib.sh"
atlas_load_env "$ATLAS"
HUMAN=${SENTINEL_EMAIL:-}
NOTIFY_CMD=${SENTINEL_NOTIFY_CMD:-}
RES_UNIT=${SENTINEL_RESIDENT_UNIT:-}
RES_SCREEN=${SENTINEL_RESIDENT_SCREEN:-}
STATE=${SENTINEL_STATE:-$ATLAS/runtime}
LOG=$STATE/escalation.log

# The runtime directory holds throttle markers, the log and the notifier outbox: it must belong to this
# user, must not be a symlink and must not be group- or other-writable. Prints the problem code, or nothing
# (a missing directory is created 0750; its parent is not).
state_dir_problem() {
    local d=$1 mode
    if [ -L "$d" ]; then echo symlink; return 0; fi
    if [ ! -e "$d" ]; then
        mkdir -m 0750 "$d" 2>/dev/null || echo cannot-create
        return 0
    fi
    if [ ! -d "$d" ]; then echo not-a-directory; return 0; fi
    if [ "$(stat -c %u "$d")" != "$(id -u)" ]; then echo foreign-owner; return 0; fi
    mode=$(stat -c %a "$d")
    if [ $(( 8#$mode & 8#022 )) -ne 0 ]; then echo group-or-other-writable; fi
    return 0
}

# Thresholds. The patrol runs every 30 min - 45 min leaves one full cycle of slack.
MAX_PATROL_AGE=45        # minutes
MAX_ALERT_AGE=45         # minutes without acknowledgement by the resident
QUIET_BETWEEN_MAILS=6    # hours, per kind - so that a failure does not turn into spam

now=$(date +%s)

# An unsafe runtime directory: no marker or log may be written there. One mail per 6 h (marker in the
# state dir of Atlas itself), a stderr line, exit 2 (UNKNOWN), never ok.
UNSAFE_REASON=$(state_dir_problem "$STATE")
if [ -n "$UNSAFE_REASON" ]; then
    echo "sentinel-escalation: unsafe runtime directory $STATE ($UNSAFE_REASON)" >&2
    unsafe_marker="$ATLAS/escalation-unsafe-state.sent"
    if [ ! -f "$unsafe_marker" ] || [ $(( now - $(stat -c %Y "$unsafe_marker") )) -ge 21600 ]; then
        u_subject=$(t esc.unsafe_state_subject)
        u_body=$(t esc.unsafe_state dir="$STATE" reason="$UNSAFE_REASON" hours=6)
        u_sent=0
        if [ -n "$HUMAN" ] && printf '%s\n' "$u_body" | mail -s "$u_subject" "$HUMAN"; then u_sent=1; fi
        if [ -n "$NOTIFY_CMD" ]; then
            read -r -a u_cmd <<< "$NOTIFY_CMD"
            SENTINEL_EMAIL="$HUMAN" timeout 45 "${u_cmd[@]}" "$u_subject" "$u_body" >/dev/null 2>&1 && u_sent=1
        fi
        [ "$u_sent" -eq 1 ] && touch "$unsafe_marker"
    fi
    exit 2
fi

heartbeat() { echo "$(date -Is) $*" >> "$LOG"; tail -n 500 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"; }

# Notification sent at most once per QUIET_BETWEEN_MAILS hours for a given kind.
# An alarm that arrives every 10 minutes teaches people to filter it - and then it does not exist.
shout() {   # $1=kind  $2=subject  $3=body
    local marker="$STATE/sent-$1" sent=0
    if [ -f "$marker" ] && [ $(( now - $(stat -c %Y "$marker") )) -lt $(( QUIET_BETWEEN_MAILS * 3600 )) ]; then
        heartbeat "quiet: $1 (notified < ${QUIET_BETWEEN_MAILS}h ago)"
        return 0
    fi
    if [ -n "$HUMAN" ]; then
        printf '%s\n' "$3" | mail -s "$2" "$HUMAN" && sent=1 && heartbeat "MAIL SENT: $1"
    fi
    # The optional extra channel supplements mail, it never replaces it:
    #  - `timeout` and no `set -e`: a failing extra channel must NEVER bring escalation down;
    #  - the command gets SENTINEL_EMAIL in its environment, so a channel with its own address
    #    configuration can be pointed at the same (test) recipient - a dry run must not page a human.
    if [ -n "$NOTIFY_CMD" ]; then
        local -a cmd
        read -r -a cmd <<< "$NOTIFY_CMD"
        if SENTINEL_EMAIL="$HUMAN" timeout 45 "${cmd[@]}" "$2" "$3" >/dev/null 2>&1; then
            sent=1; heartbeat "NOTIFY: passed on"
        else
            heartbeat "NOTIFY: failed (mail is independent)"
        fi
    fi
    [ "$sent" -eq 1 ] && touch "$marker"
    return 0
}

declare -A PTEXT=()   # kind -> problem text (for the mail); one throttle marker per kind
KINDS=""           # machine-readable problem kinds (English) for the log
NOTES=""           # machine-readable notes for the ok heartbeat
add_problem() {    # $1=kind  $2=text
    KINDS+="${KINDS:+,}$1"
    PTEXT[$1]+="$2"
}

# --- 1. Is the patrol (the LLM-independent layer) alive at all ---
# The heartbeat is written on EVERY patrol run, also when an alarm stands - otherwise a dead
# patrol would look identical to a live patrol with a standing alarm.
if [ -f "$ATLAS/heartbeat.log" ]; then
    age=$(( (now - $(stat -c %Y "$ATLAS/heartbeat.log")) / 60 ))
    if [ "$age" -gt "$MAX_PATROL_AGE" ]; then
        add_problem patrol-silent "$(t esc.patrol_silent age="$age" limit="$MAX_PATROL_AGE" last="$(tail -2 "$ATLAS/heartbeat.log" 2>/dev/null)")"
    fi
else
    add_problem patrol-missing "$(t esc.patrol_missing)"
fi

# --- 2. Is the resident (the AI agent) alive ---
# Two independent signs, one may lie: a screen session and a systemd unit. Either one configured
# is enough; with neither configured there is no resident to check (said so in the heartbeat).
if [ -z "$RES_UNIT" ] && [ -z "$RES_SCREEN" ]; then
    NOTES="no resident configured"
else
    alive=no
    # A screen session reported as "(Dead ???)" is a corpse, not a resident.
    if [ -n "$RES_SCREEN" ] && screen -ls 2>/dev/null | grep -E "[0-9]+\.${RES_SCREEN}[[:space:]]" | grep -qiv 'dead'; then
        alive=yes
    fi
    if [ -n "$RES_UNIT" ] && systemctl is-active --quiet "$RES_UNIT"; then
        alive=yes
    fi
    if [ "$alive" = "no" ]; then
        # The human's off switch is not a failure.
        if [ -f "$ATLAS/RESIDENT-OFF" ]; then
            heartbeat "resident switched off deliberately (RESIDENT-OFF) - not alarming"
        else
            signs=""; revive=""
            [ -n "$RES_SCREEN" ] && signs=$(t esc.sign_screen screen="$RES_SCREEN")
            [ -n "$RES_UNIT" ] && signs+="${signs:+$(t esc.sign_and)}$(t esc.sign_unit unit="$RES_UNIT")" \
                && revive=$(t esc.revive unit="$RES_UNIT")
            add_problem resident-dead "$(t esc.resident_dead signs="$signs" revive="$revive")"
        fi
    fi
fi

# --- 3. An alarm stands and the resident has not acknowledged it ---
# This is the heart of it: an alarm with no recipient. Acknowledge with `touch ALERT.acked`.
if [ -f "$ATLAS/ALERT" ]; then
    # Age = time since the alert FIRST appeared in this continuous episode (ALERT.since, written
    # by the patrol when ALERT is created from nothing, removed with ALERT). The mtime of ALERT
    # moves with every body change, so an alert whose text changes every run would never age.
    # Without ALERT.since (older patrol) fall back to the mtime of ALERT.
    since_ref="$ATLAS/ALERT.since"
    [ -f "$since_ref" ] || since_ref="$ATLAS/ALERT"
    alert_age=$(( (now - $(stat -c %Y "$since_ref")) / 60 ))
    acked=0
    [ -f "$ATLAS/ALERT.acked" ] && \
        [ "$(stat -c %Y "$ATLAS/ALERT.acked")" -ge "$(stat -c %Y "$ATLAS/ALERT")" ] && acked=1
    if [ "$alert_age" -gt "$MAX_ALERT_AGE" ] && [ "$acked" -eq 0 ]; then
        add_problem alert-unacked "$(t esc.alert_unacked age="$alert_age" body="$(cat "$ATLAS/ALERT" 2>/dev/null)")"
    fi
fi

# --- 4. Is the real-time stream daemon alive ---
# The daemon touches the heartbeat every 60 s; 5 min = five missed beats, enough slack for a
# restart or a busy 1 vCPU, short enough that a dead stream is not silent for a patrol cycle.
# A missing file counts as silent (the daemon never started). The human's off switch is the file
# pauses/sentinel-stream (it carries a reason): a deliberate stop is not a failure.
STREAM_HB=${SENTINEL_STREAM_HEARTBEAT:-${SENTINEL_STATE_DIR:-$ATLAS/runtime}/stream.heartbeat}
MAX_STREAM_AGE=5   # minutes
if [ -f "$ATLAS/pauses/sentinel-stream" ]; then
    heartbeat "stream daemon paused deliberately (pauses/sentinel-stream) - not alarming"
elif [ ! -f "$STREAM_HB" ]; then
    add_problem stream-silent "$(t esc.stream_missing file="$STREAM_HB")"
else
    stream_age=$(( (now - $(stat -c %Y "$STREAM_HB")) / 60 ))
    if [ $(( now - $(stat -c %Y "$STREAM_HB") )) -gt $(( MAX_STREAM_AGE * 60 )) ]; then
        add_problem stream-silent "$(t esc.stream_silent age="$stream_age" limit="$MAX_STREAM_AGE")"
    fi
fi

# --- 5. Deliver notices the stream or the router could not send (outbox) ---
# Escalation runs without NoNewPrivileges, so a setuid MTA works here. The line goes to the log BEFORE the
# result line (the recipient test reads the last one).
DRAIN_OUT=$(SENTINEL_ATLAS="$ATLAS" SENTINEL_STATE_DIR="${SENTINEL_STATE_DIR:-$STATE}" SENTINEL_EMAIL="$HUMAN" \
    SENTINEL_NOTIFY_CMD="$NOTIFY_CMD" timeout 70 python3 "$SDIR/notify.py" drain 2>&1)
DRAIN_RC=$?
# A failed drain (unusable outbox, timeout, crash) is logged with its diagnostics, never swallowed.
if [ "$DRAIN_RC" -ne 0 ]; then
    heartbeat "outbox drain failed (rc=$DRAIN_RC): $(printf '%s' "$DRAIN_OUT" | tr '\n' ' ' | cut -c1-300)"
elif [ -n "$DRAIN_OUT" ]; then
    heartbeat "$DRAIN_OUT"
fi

# --- Result ---
# A throttle marker lives only while ITS kind is a problem: a marker for a healthy kind is removed,
# a marker for a kind that is still failing stays (and keeps throttling just that kind).
for m in "$STATE"/sent-*; do
    [ -e "$m" ] || continue
    [ -n "${PTEXT[${m##*/sent-}]+x}" ] || rm -f "$m"
done

if [ "${#PTEXT[@]}" -gt 0 ]; then
    hints=""
    [ -n "$RES_UNIT" ] && hints+=$(t esc.hint_unit unit="$RES_UNIT")
    [ -n "$RES_SCREEN" ] && hints+=$(t esc.hint_screen screen="$RES_SCREEN")
    for kind in "${!PTEXT[@]}"; do
        shout "$kind" "$(t esc.subject kind="$kind")" "$(t esc.body problem="${PTEXT[$kind]}" \
            host="$(hostname)" uptime="$(uptime -p 2>/dev/null)" \
            disk="$(df -h / | tail -1 | awk '{print $5}')" ram="$(free -m | awk '/Mem:/{print $7}')" \
            time="$(date -Is)" state="$ATLAS" hints="$hints")"
    done
fi

# No recipient = nobody can be told: that is never "ok", whatever the checks found.
# A configured notify command is a recipient too (a phone push, a chat webhook); only both empty is UNKNOWN.
if [ -z "$HUMAN" ] && [ -z "$NOTIFY_CMD" ]; then
    heartbeat "UNKNOWN: no recipient configured (SENTINEL_EMAIL and SENTINEL_NOTIFY_CMD are empty)${KINDS:+; PROBLEM: $KINDS}"
    exit 2
fi
if [ "${#PTEXT[@]}" -gt 0 ]; then
    heartbeat "PROBLEM: $KINDS"
    exit 1
fi

# Silence on the problems side = health. But we write the heartbeat ALWAYS.
heartbeat "ok (patrol alive, ${NOTES:-resident alive}, stream alive, no unacknowledged alerts)"
exit 0
