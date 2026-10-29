# Configuration

Everything that belongs to one installation lives in the **state directory**, selected by `SENTINEL_ATLAS`
(installer default `/var/lib/atlas`; unset = `atlas/` next to the code, which is how the tests run). The code
directory holds no instance data.

```
$SENTINEL_ATLAS/
├── sentinel.env          the one config file (below)
├── known-ips.txt         SSH source addresses that are expected
├── http-expected.json    expected HTTP status per vhost (+ optional extra URLs)
├── jobs.d/*.sh           your job contracts (plugins)
├── bridges.d/*           your report bridges (plugins)
├── pauses/<id>           deliberate silences, each with a reason
├── baseline.json         the accepted identity of the machine (atlas.py bless)
├── runtime/              private runtime state of the stream and escalation (markers, outbox, wake budget, logs)
└── ...                   runtime state: current.json, snapshots/, ALERT*, drift.log, heartbeat.log, events.jsonl
```

## `sentinel.env`

`KEY=VALUE` per line; blank lines and `#` comments are allowed, as are an `export ` prefix and one pair of
surrounding quotes. It is **parsed, never executed** (no `$(...)`, no variable expansion, no inline comments).
It is read by `patrol.sh`, `jobs.sh`, `escalation.sh`, `session-sensor.sh`, `stream.py`, `atlas.py` and the sensors,
and by the systemd units through `EnvironmentFile=`. **A variable already set in the environment wins**, so a
one-off override is `VAR=value command`, and cron needs nothing but `SENTINEL_ATLAS=...`.
`SENTINEL_ATLAS` itself cannot be set in the file: it is what locates the file.

| Variable | Default | Used by | Meaning |
|---|---|---|---|
| `SENTINEL_EMAIL` | *(empty)* | escalation, router | Recipient of mails (`mail -s`). If both this and `SENTINEL_NOTIFY_CMD` are empty, escalation logs `UNKNOWN: no recipient configured` and exits 2 - never a silent "ok". |
| `SENTINEL_NOTIFY_CMD` | *(empty)* | escalation, router | Extra channel, called as `<cmd> "<subject>" "<body>"` (word-split, no shell). Escalation calls it in addition to mail; the router uses it instead of mail. It receives `SENTINEL_EMAIL` in its environment. A failure never stops the mail. |
| `SENTINEL_LANG` | `en` | everything human-facing | `en` or `pl`. A key missing in a catalog falls back to English. |
| `SENTINEL_RESIDENT_UNIT` | *(empty)* | escalation, router | systemd unit of the AI resident (e.g. `agent.service`). |
| `SENTINEL_RESIDENT_SCREEN` | *(empty)* | escalation, router | `screen` session name of the AI resident. A session listed as `(Dead ???)` does not count. With both resident variables empty there is no resident: every `critical` event goes to the human and escalation skips the "resident dead" check (its heartbeat says `no resident configured`). |
| `SENTINEL_TRUSTED_SUDO_USERS` | `root` | stream | Comma/space separated users whose `sudo` is routine (`info`). Anyone else's sudo is an `alert`. Do **not** add the account your resident works under: use `SENTINEL_AGENT_SUDO_USERS`. |
| `SENTINEL_AGENT_SUDO_USERS` | *(empty)* | stream, digest | Comma/space separated account(s) the AI agent works under. Their `sudo` is `info` (never wakes) and is listed in the daily digest; it overrides the trusted list for that purpose. Denied sudo still alerts. Restart `sentinel-stream` after changing it. |
| `SENTINEL_DIGEST_HOUR` | `7` | escalation | UTC hour (0-23) at or after which escalation sends the daily digest, once per UTC day. |
| `SENTINEL_SUDO_EXE` | `/usr/bin/sudo` | stream | Comma/space separated paths of the real `sudo`. A journal line that claims to be sudo from another executable is dropped and reported as a rate-limited `auth.sudo.forged` warning. Set it for a non-default sudo path. |
| `SENTINEL_WAKE_MAX_PER_HOUR` | `12` | session sensor, stream | Most events that wake the agent per hour (after dedup). `0` = no limit. Events over the limit are not printed; one summary line for the agent follows after the window closes (from the first sensor process that runs then), and the human gets one notice. |
| `SENTINEL_HEARTBEAT_URL` | *(empty)* | escalation | Optional `http(s)` URL fetched (one GET, 10 s) after every clean escalation run, for an external dead-man's switch. Empty = no network call (the default). Redirects count as failures; the URL is never logged. |
| `SENTINEL_WEB_LOG` | `/var/log/apache2/sentinel-sensitive.log` | stream | Log written by `sentinel/apache/sentinel-sensitive.conf`. A missing/unreadable log raises an `unknown` alert after 5 minutes. |
| `HTTP_SITES_DIR` | `/etc/apache2/sites-enabled` | HTTP probes, atlas | Where vhosts live. No such directory = no Apache = nothing to probe, zero SSL vhosts. |
| `ATLAS_DISK_PCT` | `90` | atlas thresholds | Alarm when `/` is at least this full (%). |
| `ATLAS_RAM_MB` | `250` | atlas thresholds | Alarm when available RAM is below this (MB). |
| `ATLAS_CERT_DAYS` | `14` | atlas thresholds | Alarm when a certificate has fewer days left (certbot renews at 30, so this means renewal has failed for 16 days). |

Choose thresholds on your own data: after a week, replay `snapshots/*.json` and count how often a candidate value
would have fired. Zero false hits in history and still time to react is the target.

Less common overrides (mostly for tests and unusual layouts): `SENTINEL_STATE` (escalation markers and log,
default `$SENTINEL_ATLAS/runtime/`), `SENTINEL_STATE_DIR` (router/stream state, same default), `SENTINEL_STREAM_HEARTBEAT`,
`SENTINEL_KNOWN_IPS` / `SSH_KNOWN_IPS`, `HTTP_EXPECTED`, `HTTP_EXTRA_URLS_CMD`, `SENTINEL_BUS`, `SENTINEL_BUS_MAX_BYTES`,
`SENTINEL_HUMAN_WINDOW_SECS`, `PATROL_T_*` (per-sensor time limits in seconds: `CHECK` 100, `JOBS` 30, `SSH` 40,
`THRESHOLDS` 30, `SILENT`, `REPORT` 20, `HTTP` 90), `JOBS_D`, `JOBS_PAUSE_DIR`, `ATLAS_I18N_DIR`.

## `known-ips.txt`

One address per line, `#` comments allowed. A successful SSH login from any other address is a `critical` event
(real time) and an ALERT section (patrol, for 24 h or until the address is added). An empty or missing list means
every login alarms (missing = the patrol section is UNKNOWN). Add your addresses before you rely on it.

## `http-expected.json`

```json
{
  "_extra_urls_cmd": "",
  "example.com": [200],
  "www.example.com": [301]
}
```

For every `ServerName` in `HTTP_SITES_DIR` the probe requests `https://<name>/` without following redirects and
compares the **first** status code with the list. A vhost missing from the file is an event ("unknown expectation"):
a new site must be a conscious entry. Reserved names (`.invalid`, `.test`, `.example`, `.localhost`) are skipped.
Sites without any `ServerName` (a fresh Apache with only `000-default.conf`) leave nothing to probe: the probe is
clean and says so; an empty `HTTP_SITES_DIR` is UNKNOWN (it cannot be told from an unreadable one).

`_extra_urls_cmd` (optional): a shell command printing URLs, one per line; each must answer 200. Use it for a path
where breakage hides behind a cached front page, for example the newest published post of a CMS:

```json
"_extra_urls_cmd": "sudo -n -u www-data wp --path=/var/www/example.com post list --post_type=post --post_status=publish --posts_per_page=1 --field=url"
```

The command runs as the Atlas user; grant whatever it needs (here, a sudoers line for `wp` as `www-data`) yourself.
A failing command or no URL in its output makes the section UNKNOWN. Keys starting with `_` are never hosts.

## `jobs.d/` - job contracts

`atlas/jobs.sh` is a runner without contracts. It sources every `$SENTINEL_ATLAS/jobs.d/*.sh` in sorted (C locale)
order; a file with a syntax error is skipped and makes the whole sensor UNKNOWN (exit 2). Helpers:

| Helper | Fires when |
|---|---|
| `check <name> <log> <max_hours> <regex>` | the log is missing, unchanged for more than `max_hours`, or none of its last 40 lines matches |
| `check_last_line <name> <log> <max_minutes> <regex>` | the log is missing, unchanged for more than `max_minutes`, or its last line does not match |
| `check_last_match <name> <log> <max_minutes> <regex>` | the newest matching line (which starts with a `date -d` timestamp) is older than `max_minutes`, or there is none |
| `paused <id>` | (a test) true when `pauses/<id>` exists |
| `problem "<text>"` | always: adds your own line |
| `unknown "<text>"` | always: the contract cannot judge; the sensor exits 2 |

Contracts are plain bash sourced into the runner: keep them short, read-only and fast (the whole runner has 30 s).
Examples: [`examples/jobs.d/10-nightly-backup.sh`](../examples/jobs.d/10-nightly-backup.sh) (log freshness) and
[`examples/jobs.d/20-hourly-task.sh`](../examples/jobs.d/20-hourly-task.sh) (one outcome line per run). A missing
fresh log is as suspicious as a log with an error: a job that did not start leaves no error behind.

## `bridges.d/` - report bridges

Every **executable** file in `$SENTINEL_ATLAS/bridges.d/` runs on each patrol (sorted, 20 s each). Non-empty stdout
becomes a section of `REPORT-TO-SEND` (`NEW REPORT (<name>) - to be sent to the human:`) and a `drift.log` entry;
the session sensor announces it and the resident delivers it. A bridge remembers what it already reported in a
marker under `$SENTINEL_ATLAS`. See [`examples/bridges.d/README.md`](../examples/bridges.d/README.md).

## `pauses/` - deliberate silence

A file `pauses/<id>` silences one contract: `paused <id>` in your `jobs.d/` files, and `pauses/sentinel-stream`
stops escalation about a stopped stream daemon. First line: the reason; then who and when. Delete it to resume.
See `atlas/pauses/README.md`.

## Other switches in the state directory

- `RESIDENT-OFF` - the resident is off on purpose: escalation does not report it dead, the router notifies the human.
- `ALERT.acked` - acknowledges the current ALERT content; written by `atlas.py ack` (the SHA-256 of the content, plus a notice
  to the human), not by `touch`.
- `REPORT-TO-SEND` - delete after delivering it.

A fresh install has no baseline: `atlas.py check` reports `UNKNOWN` until you have reviewed `atlas.py show` and run
`atlas.py bless`. `check` never creates a baseline by itself.

## Notify commands that write files

The systemd units run with strict filesystem hardening. A `SENTINEL_NOTIFY_CMD` that writes outside the state
directory (a log file, a spool) needs its path added with a drop-in, for example
`systemctl edit sentinel-escalation.service` (and the same for `sentinel-stream.service`):

```
[Service]
ReadWritePaths=/var/log/my-notifier
```

A setuid mail program cannot raise its privileges inside the stream unit: a failed notice goes to the outbox in
`runtime/` and is retried by escalation. After changing the units, run `sudo /opt/atlas/sentinel/units/verify-hardening.sh --code /opt/atlas --state /var/lib/atlas --user atlas`
(add `--mail-to <local user>` to test mail under the escalation unit; append `--print` to show the checks without
root).

## Languages (`i18n/`)

`i18n/en.json` and `i18n/pl.json` map keys to templates with `{placeholders}`. Python uses `atlas/i18n.py`
(`t(key, **values)`); bash sources `atlas/lib.sh` and calls `t key name=value ...` (the catalog is loaded once per
run). To add a language, copy `en.json` to `<lang>.json`, translate the values, keep keys and placeholders, and set
`SENTINEL_LANG=<lang>`; `tests/test_i18n_config.py` checks that catalogs agree on keys and placeholders.
Section headers in ALERT stay English in every language: they are part of the event fingerprints.
