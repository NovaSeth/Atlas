#!/usr/bin/env bash
# Atlas patrol: the periodic tripwire, independent of any AI session. Run from cron every 30 min.
# Collects sensor results (atlas check, job contracts, SSH, resource/cert thresholds, HTTP probes,
# silent failures), writes drift to drift.log and raises the ALERT flag, which the session sensor reads
# cheaply. Report bridges ($SENTINEL_ATLAS/bridges.d/*) can hand a report to the human (REPORT-TO-SEND).
# The baseline is changed ONLY by a human or the resident, deliberately (atlas.py bless) - never here.
# Zero LLM: nothing here depends on a live session.
set -uo pipefail
# The whole run goes under nice -n 10: the patrol must not push services out (1 vCPU).
# Re-exec before cd, because $0 may be a relative path.
if [ -z "${PATROL_NICE:-}" ]; then
    export PATROL_NICE=1
    exec nice -n 10 bash "$0" "$@"
fi
# CODE = where this script lives (sensors are called by absolute path); STATE = where every file the
# patrol writes lives (SENTINEL_ATLAS, default: next to the code). The state dir is created when missing:
# a fresh deploy must not fail silently.
CODE=$(cd "$(dirname "$0")" && pwd) || exit 1
STATE=${SENTINEL_ATLAS:-$CODE}
mkdir -p "$STATE" || exit 1
cd "$STATE" || exit 1
export SENTINEL_ATLAS="$STATE"
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$CODE/lib.sh"
atlas_load_env "$STATE"     # $STATE/sentinel.env; variables already in the environment win

# Time limits for EACH sensor (s). A healthy full run takes about 30 s on one vCPU. The limit protects
# against a hung sensor that would block the whole patrol (and the heartbeat): exceeding it = "unknown",
# not silence.
T_CHECK=${PATROL_T_CHECK:-100}
T_JOBS=${PATROL_T_JOBS:-30}
T_SSH=${PATROL_T_SSH:-40}
T_THRESHOLDS=${PATROL_T_THRESHOLDS:-30}
T_SILENT=${PATROL_T_SILENT:-$T_THRESHOLDS}
T_REPORT=${PATROL_T_REPORT:-20}
# 10 vhosts x 10 s fetch timeout would be 100 s worst case; healthy runs take ~2 s. 90 s keeps the
# patrol well inside its 30 min cadence and turns a hang into "unknown".
T_HTTP=${PATROL_T_HTTP:-90}

STAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
SECTIONS=""    # alert body (no timestamps!); texts come from the i18n catalog (SENTINEL_LANG)
ALARMS=""      # names of sensors in alarm (for the heartbeat)
UNKNOWN=""     # names of sensors that could not judge
SEC_NAMES=()   # one entry per ALERT section (bus events are emitted per section)
SEC_BODIES=()

# Report bridges: every executable file in $STATE/bridges.d/ (sorted, each under the T_REPORT limit)
# may print a report that must reach the human through the session. Non-empty stdout becomes one
# section of REPORT-TO-SEND, which the session sensor announces. A bridge keeps its own "already
# reported" marker in $SENTINEL_ATLAS (exported above). Silent or failing bridges add nothing.
REPORTS=""
if [ -d "$STATE/bridges.d" ]; then
    for bridge in "$STATE"/bridges.d/*; do
        if [ ! -f "$bridge" ] || [ ! -x "$bridge" ]; then continue; fi
        bname=${bridge##*/}; bname=${bname%.*}
        out=$(timeout "$T_REPORT" "$bridge" 2>/dev/null)
        [ -n "$out" ] || continue
        { echo "=== $STAMP NEW REPORT ($bname) ==="; echo "$out"; } >> drift.log
        REPORTS+="${REPORTS:+$'\n'}$(t patrol.report_header bridge="$bname")"$'\n'"$out"
    done
fi
if [ -n "$REPORTS" ]; then
    # temp file + mv: the session sensor polls this file and must never see it half written
    { echo "$STAMP"; echo "$REPORTS"; } > REPORT-TO-SEND.tmp && mv -f REPORT-TO-SEND.tmp REPORT-TO-SEND
fi

# Sensor contract: 0 clean, 1 event, 2 unknown. Breaking the contract
# (any other code, timeout) is also "unknown" - NEVER "clean".
# $1 name  $2 limit-s  $3 section-header  rest: command
run_sensor() {
    local name="$1" t="$2" header="$3" out err rc
    shift 3
    err=$(mktemp)
    out=$(timeout "$t" "$@" 2>"$err"); rc=$?
    local errt; errt=$(tr '\n' ' ' < "$err" | head -c 300); rm -f "$err"
    case $rc in
        0) ;;
        1) ALARMS+="${ALARMS:+, }$name"; SECTIONS+="${SECTIONS:+$'\n'}== $header =="$'\n'"$out"
           SEC_NAMES+=("$header"); SEC_BODIES+=("$out") ;;
        124) UNKNOWN+="${UNKNOWN:+, }$name"; SECTIONS+="${SECTIONS:+$'\n'}$(t patrol.unknown_timeout name="$name" limit="$t")"
             SEC_NAMES+=("UNKNOWN: $name"); SEC_BODIES+=("timeout ${t} s") ;;
        *) UNKNOWN+="${UNKNOWN:+, }$name"; SECTIONS+="${SECTIONS:+$'\n'}$(t patrol.unknown_code name="$name" rc="$rc" stderr="$errt")"
           SEC_NAMES+=("UNKNOWN: $name"); SEC_BODIES+=("code $rc") ;;
    esac
}
# Works for a sensor that, on exit 2, says why on stderr (atlas.py thresholds, ssh).
# Section headers are fixed English identifiers (they are part of the bus fingerprint), not catalog texts.
run_sensor 'atlas-drift' "$T_CHECK" 'ATLAS DRIFT' python3 "$CODE/atlas.py" check
run_sensor 'cron-jobs' "$T_JOBS" 'CRON JOBS' "$CODE/jobs.sh"
run_sensor 'ssh-logins' "$T_SSH" 'SSH: LOGINS FROM UNKNOWN IP' python3 "$CODE/sensors/ssh_logins.py" --text
run_sensor 'thresholds' "$T_THRESHOLDS" 'RESOURCE AND CERTIFICATE THRESHOLDS' python3 "$CODE/atlas.py" thresholds

# HTTP probes: every vhost answers with the expected first status code; optional extra URLs answer 200.
run_sensor 'http-probes' "$T_HTTP" 'HTTP PROBES' python3 "$CODE/sensors/http_probes.py"

# Silent failures live in `vitals`, which by design is NOT diffed (it changes
# every run). The diff will not catch them, so we ask about them directly - knowing about a failure
# without reporting it to anyone is an ornament. Same contract as every sensor: 0 clean,
# 1 failures (stdout), 2 cannot judge (stderr says why), timeout/other = unknown.
run_sensor 'silent-failures' "$T_SILENT" 'SILENT FAILURES (timer services ending in error)' python3 "$CODE/atlas.py" silent

# The heartbeat must be INDEPENDENT of whether things are healthy: every run leaves a trace,
# and its CONTENT says in what state: ok / alarm (...) / unknown (...).
heartbeat() {
    echo "$STAMP $*" >> heartbeat.log
    tail -n 500 heartbeat.log > heartbeat.log.tmp && mv heartbeat.log.tmp heartbeat.log
}

# We change ALERT ONLY when the CONTENT changed (everything except the first line). The first
# line = time the content FIRST appeared. Reason: escalation.sh computes the alert age from the
# file's mtime and compares it with ALERT.acked; rewriting on every run reset the age (an alert
# with no recipient never escalated) and invalidated the acknowledgement.
# Implementation: a bash function (one text comparison, no extra file/language).
write_alert() {
    if [ -f ALERT ] && [ "$(tail -n +2 ALERT)" = "$1" ]; then
        return 0
    fi
    { echo "=== $STAMP ALERT CHANGED ==="; echo "$1"; } >> drift.log
    # A new continuous episode starts when ALERT is created from nothing. escalation.sh measures
    # the alert age from ALERT.since, so a body that changes every run still escalates.
    [ -f ALERT ] || : > ALERT.since
    # Atomic: temp file in the SAME directory, then mv (rename). A `>` truncation shows readers an
    # empty ALERT for a moment (seen in practice: the session sensor read it empty).
    { echo "$STAMP"; echo "$1"; } > ALERT.tmp && mv -f ALERT.tmp ALERT
}

# --- Bus wiring: one event per ALERT section that is NEW or CHANGED ---
# Only the CLI of sentinel/bus.py is used (emit --json). SENTINEL_BUS_CMD overrides it for tests.
# Fingerprint = section name + first 16 hex of sha256(body): no timestamps, and a changed
# body is a different fingerprint, so the bus dedup cannot swallow a real change.
# State file bus-sections.state holds the fingerprints already emitted successfully. A section
# whose emit failed is not recorded, so the next run retries it. State is rebuilt from the
# sections present now, so a cleared section that comes back emits again.
# Emit failures NEVER affect the patrol: at most one line in drift.log per run.
REPO_ROOT=$(cd "$CODE/.." && pwd)
BUS_CMD=${SENTINEL_BUS_CMD:-"python3 $REPO_ROOT/sentinel/bus.py"}
bus_available() {
    [ -n "${SENTINEL_BUS_CMD:-}" ] || [ -f "$REPO_ROOT/sentinel/bus.py" ]
}
section_json() {   # $1=name $2=fingerprint $3=body $4=confidence $5=message for the human
    python3 -c '
import json, sys
name, fp, body, conf, msg = sys.argv[1:6]
print(json.dumps({"sensor": "atlas.patrol", "severity": "alert", "confidence": conf,
                  "what": "ALERT section: " + name, "message": msg,
                  "evidence": {"section": name, "body": body[:500]},
                  "command": "bash atlas/patrol.sh", "fingerprint": fp}))' "$1" "$2" "$3" "$4" "$5"
}
emit_sections() {
    local i name body fp conf json failed=0 newstate="" prev=""
    [ -f bus-sections.state ] && prev=$(cat bus-sections.state)
    if ! bus_available; then
        echo "$STAMP bus unavailable (no sentinel/bus.py): ALERT section events not emitted" >> drift.log
        return 0
    fi
    for i in "${!SEC_NAMES[@]}"; do
        name=${SEC_NAMES[$i]}; body=${SEC_BODIES[$i]}
        fp="atlas.patrol:${name}:$(printf '%s' "$body" | sha256sum | cut -c1-16)"
        if printf '%s\n' "$prev" | grep -qxF -- "$fp"; then
            newstate+="$fp"$'\n'
            continue
        fi
        conf=measured; case $name in UNKNOWN:*) conf=unknown ;; esac
        json=$(section_json "$name" "$fp" "$body" "$conf" "$(t patrol.section_message section="$name")") || { failed=1; continue; }
        # shellcheck disable=SC2086  # BUS_CMD is deliberately word-split (command + script path)
        if timeout 20 $BUS_CMD emit --json "$json" >/dev/null 2>&1; then
            newstate+="$fp"$'\n'
        else
            failed=1
        fi
    done
    [ "$failed" -eq 1 ] && echo "$STAMP bus emit failed for at least one ALERT section (retry next run)" >> drift.log
    printf '%s' "$newstate" > bus-sections.state.tmp && mv -f bus-sections.state.tmp bus-sections.state
    return 0
}

if [ -n "$SECTIONS" ]; then
    write_alert "$SECTIONS"
    emit_sections || true
    if [ -n "$UNKNOWN" ]; then
        heartbeat "unknown ($UNKNOWN)${ALARMS:+; alarm ($ALARMS)}"
    else
        heartbeat "alarm ($ALARMS)"
    fi
    exit 1
fi

# An alarm must be able to GO OUT. An alarm that does not go out on its own is the same problem
# as an alarm that burns for a week: it teaches that red means nothing.
if [ -f ALERT ]; then
    echo "$STAMP alert cleared (clean run)" >> drift.log
    rm -f ALERT ALERT.since bus-sections.state
fi
heartbeat "ok"
exit 0
