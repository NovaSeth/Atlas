# Report bridges (`$SENTINEL_ATLAS/bridges.d/`)

A bridge hands a report from some other system to the human, through the AI session, when that
system's own delivery failed or does not exist. `atlas/patrol.sh` runs every **executable** file in
`$SENTINEL_ATLAS/bridges.d/` on each run, in sorted order, each under the `PATROL_T_REPORT` time
limit (20 s by default).

Contract:

- Print the report to stdout **only when there is something new** to tell. Empty output = nothing
  to report; a failing or timed-out bridge is ignored (it must never break the patrol).
- Remember what you already reported yourself, in a marker file under `$SENTINEL_ATLAS` (the
  patrol exports it), so the same report is not announced twice.
- Read-only towards the system you bridge; no network calls to the human (the session or the
  escalation path does the delivery).

What the patrol does with non-empty output:

- appends it to `drift.log` under `=== <time> NEW REPORT (<name>) ===`;
- writes `REPORT-TO-SEND` (atomically) with a header per bridge,
  `NEW REPORT (<name>) - to be sent to the human:`, followed by the output;
- the session sensor announces `REPORT waiting to be sent`, and the resident delivers it and then
  deletes `REPORT-TO-SEND`.

`<name>` is the file name without its extension (`daily-report.sh` -> `daily-report`).

Minimal example (`$SENTINEL_ATLAS/bridges.d/daily-report.sh`, `chmod 755`):

```bash
#!/usr/bin/env bash
# Announce a new line of /var/lib/myapp/outbox.log that the app could not deliver itself.
set -uo pipefail
LOG=/var/lib/myapp/outbox.log
MARKER="$SENTINEL_ATLAS/daily-report.marker"
[ -f "$LOG" ] || exit 0
last=$(cat "$MARKER" 2>/dev/null || echo 0)
total=$(wc -l < "$LOG")
[ "$total" -gt "$last" ] || exit 0
echo "$total" > "$MARKER"
tail -n +"$((last + 1))" "$LOG" | grep 'delivered=no' || true
```
