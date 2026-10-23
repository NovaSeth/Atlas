# Example contract: a nightly job that appends to its own log (log-freshness contract).
# Copy to $SENTINEL_ATLAS/jobs.d/ and adapt. Sourced by atlas/jobs.sh, which provides the helpers.
#
# "nightly backup" must have written to its log within the last 26 hours (daily cadence + 2 h of
# slack), and one of the last 40 lines must contain "backup: OK". A log that did not change is
# reported as well: a job that never started leaves no error behind.
#
# Pause it deliberately with:  printf 'reason\nwho, date\n' > $SENTINEL_ATLAS/pauses/nightly-backup
if ! paused nightly-backup; then
    check "nightly backup" "${NIGHTLY_BACKUP_LOG:-/var/log/nightly-backup.log}" 26 "backup: OK"
fi
