#!/usr/bin/env bash
# Starts the AI resident session in `screen` after a (re)boot. Run by atlas-resident.service
# (examples/systemd/atlas-resident.service); not an official Claude Code feature.
#
# Config: an env file (RESIDENT_ENV, default /etc/atlas/resident.env), see examples/resident/resident.env.
# Exit codes: 0 = started, or nothing to do (off switch, session already running);
#             1 = network down; 2 = bad setup (env file, RESIDENT_DIR, RESIDENT_EXTRA_ARGS);
#             3 = a login is missing (human must log in); 4 = claude binary missing.
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
# The file is parsed (never executed) and sets the trust level (RESIDENT_PERMISSION_MODE, RESIDENT_EXTRA_ARGS): the
# agent account must never be able to raise its own trust level. So only a regular file owned by the trusted uid
# (root, 0) that nobody else can write is accepted. RESIDENT_ENV_TRUSTED_UID is read from this script's own
# environment BEFORE anything is sourced, so the env file cannot change it; it is set only by a test harness,
# never in the env file or the unit.
if [ ! -f "$ENV_FILE" ] || [ -L "$ENV_FILE" ]; then
    log "env file $ENV_FILE must be owned by root and not group/other-writable (it is not a regular file)"
    exit 2
fi
read -r env_uid env_mode < <(stat -c '%u %a' "$ENV_FILE")
if [ "$env_uid" != "${RESIDENT_ENV_TRUSTED_UID:-0}" ] || [ $((8#$env_mode & 8#022)) -ne 0 ]; then
    log "env file $ENV_FILE must be owned by root and not group/other-writable"
    exit 2
fi
# A SENTINEL_ATLAS from the unit wins over the one in the env file.
unit_atlas="${SENTINEL_ATLAS:-}"
# The env file is PARSED, never executed: one KEY=VALUE per line, a known key, and a value that is either a bare
# word or a "double-quoted string" without $, backtick, backslash or inner quote. Anything else is refused.
env_bad() {
    log "env file $ENV_FILE line $1: $2"
    exit 2
}
lineno=0
while IFS= read -r line || [ -n "$line" ]; do
    lineno=$((lineno + 1))
    line="${line%"${line##*[![:space:]]}"}"
    line="${line#"${line%%[![:space:]]*}"}"
    case "$line" in '' | '#'*) continue ;; esac
    if [[ ! $line =~ ^([A-Z_][A-Z0-9_]*)=(.*)$ ]]; then
        env_bad "$lineno" "not a KEY=VALUE line (quote values with spaces: KEY=\"a b\")"
    fi
    key="${BASH_REMATCH[1]}"
    val="${BASH_REMATCH[2]}"
    case "$key" in
    RESIDENT_DIR | RESIDENT_SESSION | RESIDENT_NAME | RESIDENT_PERMISSION_MODE | RESIDENT_CLAUDE | SENTINEL_ATLAS | ATLAS_CODE | RESIDENT_EXTRA_ARGS | RESIDENT_AUTH_CHECKS | RESIDENT_MODEL | RESIDENT_EFFORT | RESIDENT_NOTES_DIR) ;;
    *) env_bad "$lineno" "unknown key $key" ;;
    esac
    if [[ $val =~ ^\"([^\"\$\`\\]*)\"$ ]]; then
        val="${BASH_REMATCH[1]}"
    elif [[ ! $val =~ ^[^[:space:]\$\`\\\;\|\&\<\>\(\)\"\']*$ ]]; then
        env_bad "$lineno" "value of $key is not a bare word or a plain double-quoted string (quote values with spaces: $key=\"a b\"; no \$, backtick, backslash, ; | & < > ( ) or inner quotes)"
    fi
    case "$key" in RESIDENT_DIR | RESIDENT_CLAUDE | RESIDENT_NOTES_DIR) [[ $val == \~/* ]] && val="$HOME/${val#\~/}" ;; esac
    printf -v "$key" '%s' "$val"
done <"$ENV_FILE"
[ -n "$unit_atlas" ] && SENTINEL_ATLAS="$unit_atlas"

RESIDENT_SESSION="${RESIDENT_SESSION:-claude}"
RESIDENT_NAME="${RESIDENT_NAME:-atlas-server}"
RESIDENT_PERMISSION_MODE="${RESIDENT_PERMISSION_MODE:-}"
RESIDENT_CLAUDE="${RESIDENT_CLAUDE:-claude}"
RESIDENT_AUTH_CHECKS="${RESIDENT_AUTH_CHECKS:-}"
RESIDENT_EXTRA_ARGS="${RESIDENT_EXTRA_ARGS:-}"
RESIDENT_MODEL="${RESIDENT_MODEL:-}"
RESIDENT_EFFORT="${RESIDENT_EFFORT:-}"
RESIDENT_NOTES_DIR="${RESIDENT_NOTES_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/atlas-resident}"
SENTINEL_ATLAS="${SENTINEL_ATLAS:-/var/lib/atlas}"
ATLAS_CODE="${ATLAS_CODE:-/opt/atlas}"

# a. Off switch for the human.
if [ -e "$SENTINEL_ATLAS/RESIDENT-OFF" ]; then
    log "off switch present ($SENTINEL_ATLAS/RESIDENT-OFF): not starting"
    exit 0
fi

# Prerequisites: a missing program must not look like a down network or a missing session.
for prog in screen curl; do
    if ! command -v "$prog" >/dev/null 2>&1; then
        log "required program not found: $prog (install it, e.g. apt-get install $prog)"
        exit 4
    fi
done

# b. Never two sessions.
if screen -ls 2>/dev/null | grep -qE "[0-9]+\.${RESIDENT_SESSION}[[:space:]]"; then
    log "session '$RESIDENT_SESSION' already exists: not starting a second one"
    exit 0
fi

# Setup checks before any waiting, each with its own result.
# The trust level is the human's explicit choice: no default.
case "$RESIDENT_PERMISSION_MODE" in
default | acceptEdits | plan | bypassPermissions) ;;
*)
    log "choose a permission mode: set RESIDENT_PERMISSION_MODE in $ENV_FILE (see docs/resident.md)"
    exit 2
    ;;
esac
model_re='^[a-z0-9][]a-z0-9.[-]{1,63}$'
if [ -n "$RESIDENT_MODEL" ] && [[ ! $RESIDENT_MODEL =~ ${model_re} ]]; then
    log "RESIDENT_MODEL '$RESIDENT_MODEL' is not a model id: allowed form ^[a-z0-9][a-z0-9.[]-]{1,63}$, e.g. claude-opus-5-5 or opus (see docs/resident.md)"
    exit 2
fi
case "$RESIDENT_EFFORT" in
'' | low | medium | high | xhigh | max) ;;
*)
    log "RESIDENT_EFFORT '$RESIDENT_EFFORT' is not an effort level: allowed values low|medium|high|xhigh|max (or empty)"
    exit 2
    ;;
esac
# The resident's own notes (BOOT, AFTER-REBOOT.md) live in a directory the resident owns, never in the Atlas state
# dir, which is read-only for the resident. An absolute path without a ".." part.
notes_bad() {
    log "RESIDENT_NOTES_DIR '$RESIDENT_NOTES_DIR' must be an absolute path (or ~/<dir>) below the home directory: no '.' or '..' part, not / and not the home itself"
    exit 2
}
NOTES="$RESIDENT_NOTES_DIR"
while [ "${#NOTES}" -gt 1 ] && [ "${NOTES%/}" != "$NOTES" ]; do NOTES="${NOTES%/}"; done
case "$NOTES" in
*$'\n'* | *[\$\`\(\)\;\|\&\<\>\*]*) notes_bad ;;
/*) ;;
*) notes_bad ;;
esac
IFS=/ read -ra parts <<<"$NOTES"
for part in "${parts[@]}"; do
    [ "$part" = "." ] || [ "$part" = ".." ] && notes_bad
done
# Compare canonical paths, not strings: repeated separators and symlinks must not reach the home directory.
if ! command -v realpath >/dev/null 2>&1; then
    log "realpath (GNU coreutils) not found: cannot validate RESIDENT_NOTES_DIR"
    exit 2
fi
canon=$(realpath -m -- "$NOTES")
lexical=$(realpath -m -s -- "$NOTES")
home_canon=$(realpath -m -- "$HOME")
if [ -z "$canon" ] || [ -z "$lexical" ] || [ -z "$home_canon" ]; then
    log "RESIDENT_NOTES_DIR '$RESIDENT_NOTES_DIR' cannot be resolved"
    exit 2
fi
if [ "$canon" != "$lexical" ]; then
    log "RESIDENT_NOTES_DIR '$RESIDENT_NOTES_DIR' goes through a symlink (resolves to $canon): name the real directory"
    exit 2
fi
if [ "$canon" = "/" ] || [ "$canon" = "$home_canon" ] || [[ $home_canon == "$canon"/* ]]; then
    notes_bad
fi
NOTES="$canon"
case "$RESIDENT_EXTRA_ARGS" in
*$'\n'*)
    log "RESIDENT_EXTRA_ARGS must not contain a newline"
    exit 2
    ;;
esac
if [ -z "${RESIDENT_DIR:-}" ] || [ ! -d "$RESIDENT_DIR" ]; then
    log "RESIDENT_DIR '${RESIDENT_DIR:-}' is not set or not a directory"
    exit 2
fi
case "$RESIDENT_CLAUDE" in
*/*) [ -x "$RESIDENT_CLAUDE" ] && [ -f "$RESIDENT_CLAUDE" ] && found=1 || found=0 ;;
*) command -v "$RESIDENT_CLAUDE" >/dev/null 2>&1 && found=1 || found=0 ;;
esac
if [ "$found" != 1 ]; then
    log "claude not found at $RESIDENT_CLAUDE"
    exit 4
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
    log "network still down after up to 150 s of trying: giving up (exit 1)"
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

if ! cd "$RESIDENT_DIR"; then
    log "cannot enter RESIDENT_DIR=$RESIDENT_DIR"
    exit 1
fi

# f. A trace for the session: when and how the machine came up. No log text.
if [ "$DRY" = 1 ]; then
    log "dry run: notes dir $NOTES"
    log "dry run: would write $NOTES/BOOT"
else
    if ! mkdir -p "$NOTES" || ! chmod 0700 "$NOTES"; then
        log "RESIDENT_NOTES_DIR $NOTES cannot be created or protected (0700)"
        exit 2
    fi
    {
        date -u +%Y-%m-%dT%H:%M:%SZ
        echo "Machine came up after a restart. Uptime when the resident started: $(uptime -p 2>/dev/null || cut -d' ' -f1 /proc/uptime)"
        echo "Kernel: $(uname -r)"
    } >"$NOTES/BOOT" || log "could not write BOOT (continuing)"
fi

# g. Fresh session (no --continue): cheap and predictable; context comes from the note files.
legacy=""
[ -r "$SENTINEL_ATLAS/AFTER-REBOOT.md" ] && legacy=" A legacy note also exists at $SENTINEL_ATLAS/AFTER-REBOOT.md (read it; you cannot delete it)."
PROMPT="The machine (re)started and I was started automatically by atlas-resident.service. Follow $ATLAS_CODE/AGENTS.md.
Read $NOTES/BOOT and, if it exists, $NOTES/AFTER-REBOOT.md (a note the previous session left) and carry it out.$legacy
Check Atlas: the stream is active, the heartbeat is fresh, and \`python3 $ATLAS_CODE/atlas/atlas.py check\` is clean.
Arm your monitor tool (persistent) on exactly: SENTINEL_ATLAS=$SENTINEL_ATLAS $ATLAS_CODE/sentinel/session-sensor.sh
Report a short result to the human. Never start a polling loop."

# Extra claude flags: split on whitespace only (no eval, no globbing).
set -f
read -r -a extra <<<"$RESIDENT_EXTRA_ARGS"
set +f
# Model and effort: the operator's choice (docs/resident.md), right after --permission-mode; empty = account default.
chosen=()
[ -n "$RESIDENT_MODEL" ] && chosen+=(--model "$RESIDENT_MODEL")
[ -n "$RESIDENT_EFFORT" ] && chosen+=(--effort "$RESIDENT_EFFORT")
cmd=(screen -DmS "$RESIDENT_SESSION" "$RESIDENT_CLAUDE" --remote-control "$RESIDENT_NAME" -n "$RESIDENT_NAME"
    --permission-mode "$RESIDENT_PERMISSION_MODE" "${chosen[@]}" "${extra[@]}" "$PROMPT")

if [ "$DRY" = 1 ]; then
    log "dry run: would exec:"
    printf '%q ' "${cmd[@]}"
    echo
    exit 0
fi
log "starting session '$RESIDENT_SESSION' (remote-control '$RESIDENT_NAME', permission mode '$RESIDENT_PERMISSION_MODE')"
exec "${cmd[@]}"
