#!/usr/bin/env bash
# Health contracts for scheduled jobs (cron, scripts) that systemd knows nothing about.
#
# atlas.py notices a TIMER service that ends in error. A job started from cron that fails, or never
# starts, leaves no trace in systemd - only its own log knows. So every job gets a CONTRACT: a log
# file, the maximum age of its last entry and a pattern that MUST be there. A missing fresh log is as
# suspicious as a log with an error: a job that did not start leaves no error behind.
#
# This file is a generic runner. It holds NO contract. It defines the helpers below and then sources
# every $SENTINEL_ATLAS/jobs.d/*.sh in sorted order (examples: examples/jobs.d/). A contract file is
# plain bash that calls the helpers:
#
#   check <name> <logfile> <max_hours> <success-regex>
#       the log exists, changed within max_hours, and one of its last 40 lines matches the regex
#   check_last_line <name> <logfile> <max_minutes> <regex>
#       the log exists, changed within max_minutes, and its LAST line matches the regex
#   check_last_match <name> <logfile> <max_minutes> <regex>
#       the newest line matching the regex starts with a timestamp (date -d) younger than max_minutes
#   paused <id>          true when $SENTINEL_ATLAS/pauses/<id> exists (a deliberate, reviewable silence)
#   problem <text>       add one problem line in your own words
#   unknown <text>       the contract cannot judge (exit 2): never reads as clean
#
# Exit contract (same as every sensor): 0 clean (no output), 1 problems (one line each on stdout),
# 2 cannot judge (stderr says why). Messages come from the i18n catalog (SENTINEL_LANG).
# Test overrides: JOBS_PAUSE_DIR (pause directory), JOBS_D (contract directory).
# shellcheck disable=SC2317  # the job functions below are called by name from the contract files
set -uo pipefail
JOBS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$JOBS_DIR/lib.sh"
STATE=${SENTINEL_ATLAS:-$JOBS_DIR}
atlas_load_env "$STATE"
PAUSE_DIR=${JOBS_PAUSE_DIR:-$STATE/pauses}
CONTRACTS=${JOBS_D:-$STATE/jobs.d}
PROBLEMS=""
UNKNOWNS=""

paused() { [ -e "$PAUSE_DIR/$1" ]; }
problem() { PROBLEMS+="  $1"$'\n'; }
unknown() { UNKNOWNS+="  $1"$'\n'; }
_age_min() { echo $(( ( $(date +%s) - $(stat -c %Y "$1") ) / 60 )); }

check() {   # $1 name  $2 file  $3 max_hours  $4 success-regex
    local name="$1" file="$2" hours="$3" pattern="$4" age
    if [ ! -f "$file" ]; then
        problem "$(t jobs.no_log name="$name" file="$file")"; return
    fi
    age=$(( $(_age_min "$file") / 60 ))
    if [ "$age" -gt "$hours" ]; then
        problem "$(t jobs.stale_hours name="$name" age="$age" limit="$hours")"; return
    fi
    if ! tail -40 "$file" | grep -qE "$pattern"; then
        problem "$(t jobs.no_success name="$name" pattern="$pattern")"
    fi
}

check_last_line() {   # $1 name  $2 file  $3 max_minutes  $4 regex
    local name="$1" file="$2" limit="$3" pattern="$4" age last
    if [ ! -f "$file" ]; then
        problem "$(t jobs.no_log name="$name" file="$file")"; return
    fi
    age=$(_age_min "$file")
    last=$(tail -n 1 "$file")
    if [ "$age" -gt "$limit" ]; then
        problem "$(t jobs.stale_minutes name="$name" age="$age" limit="$limit")"
    elif ! printf '%s' "$last" | grep -qE "$pattern"; then
        problem "$(t jobs.last_line_bad name="$name" line="${last:0:120}" file="$file")"
    fi
}

check_last_match() {   # $1 name  $2 file  $3 max_minutes  $4 regex (the matching line starts with a timestamp)
    local name="$1" file="$2" limit="$3" pattern="$4" ts epoch age
    [ -f "$file" ] || return 0      # a missing log is check/check_last_line's job; do not report it twice
    ts=$(grep -E "$pattern" "$file" | tail -n 1 | cut -d' ' -f1)
    epoch=""
    [ -n "$ts" ] && epoch=$(date -d "$ts" +%s 2>/dev/null)
    if [ -z "$epoch" ]; then
        problem "$(t jobs.no_success_ever name="$name" pattern="$pattern")"; return
    fi
    age=$(( ( $(date +%s) - epoch ) / 60 ))
    if [ "$age" -gt "$limit" ]; then
        problem "$(t jobs.success_too_old name="$name" age="$age" limit="$limit")"
    fi
}

if [ -d "$CONTRACTS" ]; then
    LC_COLLATE=C
    for f in "$CONTRACTS"/*.sh; do
        [ -e "$f" ] || continue
        if ! bash -n "$f" 2>/dev/null; then
            unknown "$(t jobs.syntax file="${f##*/}")"
            continue
        fi
        # shellcheck disable=SC1090
        . "$f"
    done
fi

if [ -n "$UNKNOWNS" ]; then printf '%s%s' "$UNKNOWNS" "$PROBLEMS" >&2; exit 2; fi
if [ -n "$PROBLEMS" ]; then printf '%s' "$PROBLEMS"; exit 1; fi
exit 0
