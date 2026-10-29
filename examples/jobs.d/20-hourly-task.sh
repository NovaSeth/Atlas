# shellcheck shell=bash
# Example contract: an hourly job that writes exactly one line per run, "<timestamp> <OUTCOME>",
# for example "2026-01-01T10:17:00 OK pushed", "... SKIPPED busy" or "... FAILED <reason>".
# Copy to $SENTINEL_ATLAS/jobs.d/ and adapt. Sourced by atlas/jobs.sh, which provides the helpers.
#
# Thresholds: hourly cadence + one missed run of slack = 120 min for the log to change, and the LAST
# line must be OK or a single SKIPPED (a skip while another run holds the lock is fine). Repeated
# skips keep the log fresh forever, so the last SUCCESSFUL run is checked on its own: 180 min =
# hourly cadence + two missed or skipped runs.
HOURLY_TASK_LOG=${HOURLY_TASK_LOG:-/var/log/hourly-task.log}
if ! paused hourly-task; then
    check_last_line  "hourly task" "$HOURLY_TASK_LOG" 120 '^[^ ]+ (OK|SKIPPED busy)( |$)'
    check_last_match "hourly task" "$HOURLY_TASK_LOG" 180 '^[^ ]+ OK( |$)'
fi
