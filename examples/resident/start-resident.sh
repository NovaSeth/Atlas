#!/usr/bin/env bash
# Starts the AI resident session in `screen` after a (re)boot. Run by atlas-resident.service
# (examples/systemd/atlas-resident.service); not an official Claude Code feature.
#
# Config: an env file (RESIDENT_ENV, default /etc/atlas/resident.env), see examples/resident/resident.env.
# Exit codes: 0 = started, or nothing to do (off switch, session already running);
#             1 = network down / bad setup; 2 = no env file; 3 = a login is missing (human must log in).
# Exit 3 makes systemd mark the unit failed; Atlas's escalation (SENTINEL_RESIDENT_UNIT=atlas-resident.service)
# then reports the resident dead to the human.
# --dry-run prints every decision and the final command line instead of executing (used by the tests).
set -uo pipefail

DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1

log() { echo "start-resident: $*" >&2; }

ENV_FILE="${RESIDENT_ENV:-/etc/atlas/resident.env}"
if [ ! -r "$ENV_FILE" ]; then
    log "env file $ENV_FILE not readable"
    exit 2
fi
# shellcheck disable=SC1090
. "$ENV_FILE"

RESIDENT_SESSION="${RESIDENT_SESSION:-claude}"
RESIDENT_NAME="${RESIDENT_NAME:-atlas-server}"
RESIDENT_PERMISSION_MODE="${RESIDENT_PERMISSION_MODE:-default}"
RESIDENT_CLAUDE="${RESIDENT_CLAUDE:-claude}"
RESIDENT_AUTH_CHECKS="${RESIDENT_AUTH_CHECKS:-}"
SENTINEL_ATLAS="${SENTINEL_ATLAS:-/var/lib/atlas}"
ATLAS_CODE="${ATLAS_CODE:-/opt/atlas}"

# a. Off switch for the human.
if [ -e "$SENTINEL_ATLAS/RESIDENT-OFF" ]; then
    log "off switch present ($SENTINEL_ATLAS/RESIDENT-OFF): not starting"
    exit 0
fi

# b. Never two sessions.
if screen -ls 2>/dev/null | grep -qE "[0-9]+\.${RESIDENT_SESSION}[[:space:]]"; then
    log "session '$RESIDENT_SESSION' already exists: not starting a second one"
    exit 0
fi

# c. Network: without it claude starts and dies on the API.
up=0
for _ in $(seq 1 30); do
    if curl -s -o /dev/null --max-time 3 https://api.anthropic.com/; then
        up=1
        break
    fi
    sleep 2
done
if [ "$up" != 1 ]; then
    log "network still down after 60 s: giving up (exit 1)"
    exit 1
fi
log "network up"

# d. Login check. Output is discarded: it can hold account data.
if ! "$RESIDENT_CLAUDE" auth status >/dev/null 2>&1; then
    log "agent not logged in: run \`claude auth login\` as $(id -un) over SSH"
    exit 3
fi
log "claude login ok"

# e. Extra providers: ';'-separated commands, each must exit 0. Never print their output.
IFS=';' read -ra checks <<<"$RESIDENT_AUTH_CHECKS"
for c in "${checks[@]}"; do
    [ -n "${c// /}" ] || continue
    read -ra argv <<<"$c"
    if ! "${argv[@]}" >/dev/null 2>&1; then
        log "auth check failed: $c (log in again over SSH as $(id -un))"
        exit 3
    fi
    log "auth check ok: $c"
done

if ! cd "${RESIDENT_DIR:?RESIDENT_DIR is not set}"; then
    log "cannot enter RESIDENT_DIR=$RESIDENT_DIR"
    exit 1
fi

# f. A trace for the session: when and how the machine came up. No log text.
if [ "$DRY" = 1 ]; then
    log "dry run: would write $SENTINEL_ATLAS/BOOT"
else
    {
        date -u +%Y-%m-%dT%H:%M:%SZ
        echo "Machine came up after a restart. Uptime when the resident started: $(uptime -p 2>/dev/null || cut -d' ' -f1 /proc/uptime)"
        echo "Kernel: $(uname -r)"
    } >"$SENTINEL_ATLAS/BOOT" || log "could not write BOOT (continuing)"
fi

# g. Fresh session (no --continue): cheap and predictable; context comes from the note files.
PROMPT="The machine (re)started and I was started automatically by atlas-resident.service. Follow $ATLAS_CODE/AGENTS.md.
Read $SENTINEL_ATLAS/BOOT and, if it exists, $SENTINEL_ATLAS/AFTER-REBOOT.md (a note the previous session left) and carry it out.
Check Atlas: the stream is active, the heartbeat is fresh, and \`python3 $ATLAS_CODE/atlas/atlas.py check\` is clean.
Arm your monitor tool (persistent) on exactly: SENTINEL_ATLAS=$SENTINEL_ATLAS $ATLAS_CODE/sentinel/session-sensor.sh
Report a short result to the human. Never start a polling loop."

cmd=(screen -DmS "$RESIDENT_SESSION" "$RESIDENT_CLAUDE" --remote-control "$RESIDENT_NAME" -n "$RESIDENT_NAME"
    --permission-mode "$RESIDENT_PERMISSION_MODE" "$PROMPT")

if [ "$DRY" = 1 ]; then
    log "dry run: would exec:"
    printf '%q ' "${cmd[@]}"
    echo
    exit 0
fi
log "starting session '$RESIDENT_SESSION' (remote-control '$RESIDENT_NAME', permission mode '$RESIDENT_PERMISSION_MODE')"
exec "${cmd[@]}"
