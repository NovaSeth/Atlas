# Connecting an AI resident (optional)

Atlas works without any AI: it detects, and it calls the human. A *resident* - an AI agent session that watches
the server (for example a coding agent with shell access, running in `screen` or as a systemd service) - makes it
complete: it is woken within seconds, investigates, fixes what it is allowed to fix, accepts deliberate changes and
gives the human a verdict instead of a raw alarm.

The resident is never on the alarm path. If it dies, the router and the escalation timer notify the human anyway.

## 1. Tell Atlas how to see the resident

In `$SENTINEL_ATLAS/sentinel.env`, one or both:

```
SENTINEL_RESIDENT_UNIT=agent.service       # a systemd unit that runs the session
SENTINEL_RESIDENT_SCREEN=agent             # or a screen session name
SENTINEL_TRUSTED_SUDO_USERS=root,ops       # the account the agent works under uses sudo all day
```

Either sign alive = present. A screen session listed as `(Dead ???)` does not count. `touch $SENTINEL_ATLAS/RESIDENT-OFF`
when you stop the resident on purpose: escalation then does not report it dead, and critical events go to you.

## 2. Wake on events, never poll

Run the session sensor under the agent's monitor tool (any facility that runs a long-lived command and turns each
output line into a notification for the agent):

```bash
SENTINEL_ATLAS=/var/lib/atlas /opt/atlas/sentinel/session-sensor.sh
```

It prints a line only when something **changes**:

- `ATLAS ALERT: <first 300 characters>` - a new or changed, unacknowledged ALERT;
- `HH:MM ALERT|CRITICAL <sensor>: <what> [<fingerprint>]` - a bus event of severity `alert` or higher (each
  fingerprint at most once an hour);
- `REPORT waiting to be sent (REPORT-TO-SEND)` - a bridge produced a report for the human;
- `ESCALATION REPORTS: <line>` - the escalation path reported a problem;
- `clear — previous event has subsided`.

Silence costs nothing. Do **not** run a periodic "check the server" loop inside the session: every tick re-reads the
whole context (measured once at about 100 million tokens in a day for a patrol that found nothing). If the monitor
tool times out, re-arm it; the sensor's own silence is not proof of health, which is why escalation exists.

## 3. What the resident does with an alarm

1. Read `$SENTINEL_ATLAS/ALERT` and the evidence (`drift.log`, `events.jsonl`, the command in each event).
2. Decide: explained change, real problem, or intrusion.
3. Explained change (the owner or the resident did it): `python3 /opt/atlas/atlas/atlas.py bless`. Bless refuses a
   snapshot that contains failed measurements - fix those first.
4. Real problem: fix it if that is within its mandate, otherwise report to the human with a verdict.
5. Acknowledge: `touch $SENTINEL_ATLAS/ALERT.acked` - only valid for the current content; new content needs a new
   ack. An unacknowledged alert is mailed to the human after 45 minutes.
6. Deliver `REPORT-TO-SEND` to the human, then delete it.

Suggested limits for the resident: it may read, investigate, restart a failed service, bless a change it made
itself; it needs the human for anything destructive or outward-facing; it never silences a sensor (a pause is a
human decision with a written reason) and never edits the baseline by hand.

## 4. After a reboot

Start the resident from a systemd unit (so it comes back by itself) and re-arm the session sensor at the start of
every session. Until the resident is back, the router sends critical events to the human and escalation reports
`resident-dead` (unless `RESIDENT-OFF` exists).
