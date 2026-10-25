# Atlas

**Atlas is the immune system of one Linux server.** It knows what the machine *should* look like, notices within
minutes when it stops looking like that, and makes sure a human hears about it, with or without an AI agent watching
the server.

Its single job is to tell two kinds of change apart:

- the server changed because **its owner (or the owner's AI agent) changed it**: the change is reviewed and accepted (`bless`);
- the server changed because **someone else changed it**: that is an intrusion, not a glitch.

Everything below runs without a language model: stdlib Python 3 and bash, cron and systemd. An AI agent watching the
server (the *resident*, optional) makes the system complete: it is woken in seconds, investigates, repairs and gives
the human a verdict instead of a raw alarm. Without a resident, Atlas still detects and still calls the human.

Licence: MIT (see LICENSE).

---

## Requirements

- Debian 12+ or Ubuntu 24.04+ (any systemd distribution with the same tools should work), one vCPU is enough.
- systemd and journald, `python3` >= 3.11, `sudo` >= 1.9.10, `ss` (iproute2), cron, `timeout` (coreutils).
- A working `mail` command (bsd-mailx or mailutils plus an MTA) for the escalation mails, and/or any command-line
  notifier you configure as `SENTINEL_NOTIFY_CMD`.
- Optional, used when present: Apache 2.4 (vhost inventory, HTTP probes, sensitive-path log), certbot, ufw,
  fail2ban, Docker, `screen` (if your resident runs in one). A missing optional tool is reported as
  "not present" by `atlas.py show`, never as an alarm.
- `git` to fetch the code. A minimal Debian cloud image lacks `git` and `cron`; on Debian/Ubuntu:
  `sudo apt-get install -y git python3 sudo cron iproute2` (add `apache2` if you serve sites with it).

Tested on: a clean Debian 13 (trixie) genericcloud amd64 image with Apache 2.4, 1 vCPU and 768 MB RAM,
2026-10-25: Quick start as written, then the acceptance checks (units, sudoers drop-in, patrol, drift,
real-time SSH and sensitive-path events, escalation, uninstall and reinstall, Polish texts).

## Quick start

```bash
git clone <this repository> atlas && cd atlas
sudo ./install.sh --dry-run            # see every action first
sudo ./install.sh --with-apache --install-cron
sudoedit /var/lib/atlas/sentinel.env    # set SENTINEL_EMAIL (and whatever else you need)
```

The installer (idempotent; defaults `--code /opt/atlas --state /var/lib/atlas --user atlas`):

1. checks the prerequisites and prints what is missing;
2. creates the unprivileged `atlas` user (groups `adm`, `systemd-journal` for log access);
3. copies the code to `--code` and creates the state directory with `sentinel.env`, `known-ips.txt` and
   `http-expected.json` from `examples/` (an existing file is never overwritten);
4. renders and installs the systemd units (`sentinel-stream.service`, `sentinel-escalation.timer`) and starts them;
5. installs the Apache log snippet only with `--with-apache`;
6. installs a sudoers drop-in limited to the read-only commands Atlas runs (checked with `visudo -cf` first);
7. prints the crontab lines (installs them only with `--install-cron`);
8. takes the first snapshot and asks before accepting it as the baseline (`--yes` skips the question); on a
   reinstall an existing baseline is never replaced: review the drift with `atlas.py check`, then `bless`.

`./uninstall.sh` reverses units, snippet, sudoers and crontab lines; the state directory stays unless `--purge`.

Everyday commands (as the atlas user, `SENTINEL_ATLAS=/var/lib/atlas`):

```bash
cat /var/lib/atlas/ALERT                                   # is there an alarm?
python3 /opt/atlas/atlas/atlas.py show                     # what Atlas sees now
python3 /opt/atlas/atlas/atlas.py bless                    # accept a reviewed change as the new baseline
touch /var/lib/atlas/ALERT.acked                           # acknowledge (stops escalation for this content)
touch /var/lib/atlas/RESIDENT-OFF                          # the resident is off on purpose
```

## Configuration

One file: `$SENTINEL_ATLAS/sentinel.env` (`KEY=VALUE`, no shell code). Every script and unit reads it; a variable
already set in the environment wins. The most important keys:

| Key | Default | Meaning |
|---|---|---|
| `SENTINEL_EMAIL` | *(empty)* | who gets the escalation mails; empty = escalation reports UNKNOWN, never "ok" |
| `SENTINEL_NOTIFY_CMD` | *(empty)* | extra channel, called as `<cmd> "<subject>" "<body>"` |
| `SENTINEL_LANG` | `en` | language of the human-facing texts (`en`, `pl`) |
| `SENTINEL_RESIDENT_UNIT` / `SENTINEL_RESIDENT_SCREEN` | *(empty)* | how to see that the AI resident is alive; empty = no resident |
| `SENTINEL_TRUSTED_SUDO_USERS` | `root` | users whose `sudo` is routine |
| `ATLAS_DISK_PCT` / `ATLAS_RAM_MB` / `ATLAS_CERT_DAYS` | `90` / `250` / `14` | thresholds |

Your own checks plug in without touching the code: job contracts in `jobs.d/`, report bridges in `bridges.d/`,
expected HTTP codes in `http-expected.json`, deliberate silences in `pauses/`.
Full reference: [docs/configuration.md](docs/configuration.md).

---

## Project map

What the repository contains, what the installer turns it into, what runs each part, what each part reads and
writes, and who is told in the end. Solid arrows are "runs" or "writes", dotted arrows are "reads".

```mermaid
flowchart LR
    subgraph REPO["Repository"]
        direction TB
        INST["install.sh / uninstall.sh"]
        CODEA["atlas/<br/>atlas.py · patrol.sh · jobs.sh<br/>sensors/ssh_logins.py · sensors/http_probes.py"]
        CODES["sentinel/<br/>stream.py · router.py · bus.py<br/>escalation.sh · session-sensor.sh"]
        LIB["shared helpers<br/>atlas/lib.sh · envfile.py · i18n.py<br/>i18n/en.json · i18n/pl.json"]
        TPL["templates and examples<br/>sentinel/units/* · sentinel/apache/*<br/>examples/*"]
    end

    subgraph HOST["Installed on the host"]
        direction TB
        CRON["crontab of the atlas user<br/>patrol at :07 and :37"]
        TIMER["sentinel-escalation.timer<br/>every 10 min (UTC)"]
        UNIT["sentinel-stream.service<br/>always on, watchdog"]
        SUDO["/etc/sudoers.d/atlas<br/>read-only commands"]
        APSN["Apache snippet<br/>sensitive-path log"]
        ENV["sentinel.env<br/>one config file"]
    end

    subgraph RUN["Running processes"]
        direction TB
        PATROL["patrol.sh"]
        ATLASPY["atlas.py check / thresholds / silent"]
        JOBS["jobs.sh + jobs.d/*.sh"]
        SENS["ssh_logins.py · http_probes.py"]
        BRIDGES["bridges.d/*"]
        STREAM["stream.py"]
        ROUTER["router.py"]
        ESC["escalation.sh"]
        SSENS["session-sensor.sh + bus.py follow"]
    end

    subgraph INPUT["What is read"]
        direction TB
        SYS["system state<br/>services, ports, accounts, keys,<br/>sudoers, vhosts, crontabs, certs,<br/>setuid files, ufw, packages"]
        JLOGS["job logs"]
        JOURNAL["systemd journal"]
        WEBLOG["Apache sensitive-path log"]
        SITES["your public sites"]
    end

    subgraph STATE["State directory (SENTINEL_ATLAS)"]
        direction TB
        BASE[("baseline.json<br/>current.json · snapshots/")]
        ALERT[("ALERT · ALERT.since<br/>ALERT.acked")]
        LOGS[("heartbeat.log · drift.log<br/>REPORT-TO-SEND")]
        BUS[("events.jsonl<br/>event bus")]
        CONF[("known-ips.txt · http-expected.json<br/>pauses/ · jobs.d/ · bridges.d/")]
    end

    subgraph OUT["Who is told"]
        direction TB
        HUMAN["the human<br/>mail and/or SENTINEL_NOTIFY_CMD"]
        RES["optional AI resident<br/>woken in seconds"]
    end

    INST --> CRON
    INST --> TIMER
    INST --> UNIT
    INST --> SUDO
    INST --> APSN
    INST --> ENV
    TPL -. rendered by .-> INST
    LIB -. used by every entrypoint .-> RUN
    ENV -. loaded by every entrypoint .-> RUN
    CODEA -. installed as .-> PATROL
    CODES -. installed as .-> STREAM

    CRON --> PATROL
    PATROL --> ATLASPY
    PATROL --> JOBS
    PATROL --> SENS
    PATROL --> BRIDGES
    TIMER --> ESC
    UNIT --> STREAM
    STREAM --> ROUTER

    SYS -. via sudo rules .-> ATLASPY
    SUDO -. allows .-> ATLASPY
    JLOGS -.-> JOBS
    JOURNAL -.-> STREAM
    JOURNAL -.-> SENS
    APSN --> WEBLOG
    WEBLOG -.-> STREAM
    SITES -.-> SENS
    CONF -.-> JOBS
    CONF -.-> SENS
    CONF -.-> STREAM
    BASE -. compared with .-> ATLASPY

    PATROL --> ALERT
    PATROL --> LOGS
    PATROL --> BUS
    ATLASPY --> BASE
    STREAM --> BUS
    STREAM --> LOGS

    BUS -.-> SSENS
    ALERT -.-> SSENS
    ALERT -.-> ESC
    LOGS -. heartbeats .-> ESC
    SSENS --> RES
    ROUTER -- "critical, resident absent" --> HUMAN
    ESC -- "silence or unanswered alarm" --> HUMAN
    RES -- "bless, fix, ack" --> BASE
    RES -- "ack" --> ALERT
```

### Files, one line each

```text
install.sh                     installer: prerequisites, state dir, units, sudoers, Apache snippet, crontab, first snapshot (--dry-run)
uninstall.sh                   removes units, snippet and sudoers; keeps the state dir unless --purge
atlas/
  atlas.py                     snapshot of the machine's identity; check (drift vs baseline), bless, show, thresholds, silent failures
  patrol.sh                    one patrol run: every periodic sensor under a time limit -> ALERT, drift.log, heartbeat.log, bus events
  jobs.sh                      runner for job contracts: helpers check / check_last_line / paused, sources STATE/jobs.d/*.sh
  sensors/ssh_logins.py        SSH logins of the last 24 h from IPs outside known-ips.txt
  sensors/http_probes.py       every vhost answers its expected code; optional extra URLs must answer 200
  lib.sh                       bash helpers: load sentinel.env (environment wins), message catalog lookup
  envfile.py                   the same env loading for Python entrypoints (parsed, never executed)
  i18n.py                      message catalog lookup for Python and for bash (via lib.sh)
  pauses/README.md             how a deliberate silence (pauses/<id>) works
sentinel/
  bus.py                       append-only JSONL event bus: emit (validated), follow (tail -F, per-fingerprint dedup), rotation
  stream.py                    daemon: follows the journal and the Apache sensitive-path log, turns lines into events, heartbeat
  router.py                    for critical events: notifies the human when no AI resident is present (once per fingerprint per 6 h)
  escalation.sh                LLM-free path to the human: silent patrol, silent stream, dead resident, unacknowledged alarm
  session-sensor.sh            prints one line per state change for an AI agent's monitor tool (no polling inside the agent)
  units/*.service, *.timer     systemd templates (@ATLAS_CODE@, @ATLAS_STATE@, @ATLAS_USER@), rendered by install.sh
  units/crontab.example        the two cron lines (patrol, snapshot retention)
  apache/sentinel-sensitive.conf   logs requests for .env, .git, wp-config, dumps ... to a separate log for stream.py
i18n/en.json, i18n/pl.json     every human-facing message; SENTINEL_LANG picks the language
examples/                      sentinel.env, http-expected.json, known-ips.txt, jobs.d/, bridges.d/, sudoers.d/atlas
docs/                          architecture, configuration, security, resident (connecting an AI agent)
.github/workflows/tests.yml    CI: tests, shell syntax and an installer dry run on every push
```

---

## The system at a glance

```mermaid
flowchart LR
    subgraph SRC["What is watched"]
        direction TB
        OS["Machine identity<br/>services, ports, accounts, SSH keys,<br/>sudoers, vhosts, crontabs, certs,<br/>setuid files, firewall, packages"]
        JOBS["Scheduled jobs<br/>(your contracts in jobs.d)"]
        JRN["systemd journal<br/>SSH logins, sudo, failed units, OOM"]
        WEB["Apache: requests for<br/>sensitive paths (.env, .git, wp-config)"]
        HTTP["Public sites<br/>expected HTTP codes"]
    end

    subgraph PERIODIC["Every 30 min (cron)"]
        PATROL["patrol.sh<br/>runs all periodic sensors"]
    end

    subgraph REALTIME["Always on (systemd daemon)"]
        STREAM["stream.py<br/>follows journal and Apache log"]
        ROUTER["router.py<br/>who must hear it?"]
    end

    subgraph STATE["State directory"]
        ALERT[("ALERT<br/>current alarm")]
        BUS[("events.jsonl<br/>event bus")]
        BASE[("baseline.json<br/>accepted state")]
        HB[("heartbeat.log and<br/>stream.heartbeat")]
    end

    subgraph WHO["Who reacts"]
        RES["AI resident<br/>(optional agent session)"]
        HUMAN["Human<br/>(mail or notify command)"]
    end

    OS --> PATROL
    JOBS --> PATROL
    HTTP --> PATROL
    BASE -.->|"compared with"| PATROL
    PATROL --> ALERT
    PATROL --> BUS
    PATROL --> HB

    JRN --> STREAM
    WEB --> STREAM
    STREAM --> BUS
    STREAM --> ROUTER
    STREAM --> HB
    ROUTER -->|"critical and<br/>resident absent"| HUMAN

    BUS --> SENSOR["session-sensor.sh<br/>(under the agent's monitor tool)"]
    ALERT --> SENSOR
    SENSOR -->|"wakes in seconds"| RES
    RES -->|"bless, fix, ack"| BASE

    ESC["escalation.sh<br/>every 10 min, no LLM"]
    ALERT --> ESC
    HB --> ESC
    ESC -->|"silence or<br/>unanswered alarm"| HUMAN
```

Three independent paths reach a person, and each one covers the failure of another:

| Path | Latency | Needs the AI? | Covers |
|---|---|---|---|
| Stream → bus → session sensor → resident | seconds | yes | SSH login from an unknown IP, sudo by a stranger, a failed unit, OOM, a leak of a sensitive file |
| Patrol → ALERT → session sensor → resident | ≤ 30 min | yes | any drift of the machine's identity, broken jobs, disk/RAM/certs, sites returning the wrong code |
| Router → notify/mail, Escalation → mail | ≤ 2 min / ≤ 10 min | **no** | the resident is dead or absent (or there is none), an alarm nobody acknowledged, the patrol or the stream went silent |

---

## Modules

```mermaid
flowchart TB
    subgraph A["atlas/ (periodic layer)"]
        direction LR
        ATLASPY["atlas.py<br/>snap, check, bless, show<br/>thresholds, silent"]
        PATROLSH["patrol.sh<br/>one patrol run"]
        JOBSSH["jobs.sh<br/>runner for jobs.d contracts"]
        SENSORS["sensors/<br/>ssh_logins.py, http_probes.py"]
        LIB["lib.sh, envfile.py, i18n.py<br/>config file and messages"]
    end
    subgraph S["sentinel/ (real-time and escalation layer)"]
        direction LR
        BUSPY["bus.py<br/>emit, follow (JSONL bus)"]
        STREAMPY["stream.py<br/>journal and web followers"]
        ROUTERPY["router.py<br/>human when resident absent"]
        ESCSH["escalation.sh<br/>LLM-free path to the human"]
        SENSORSH["session-sensor.sh<br/>wakes the AI session"]
        UNITS["units/, apache/<br/>templates"]
    end
    subgraph ST["state directory (yours)"]
        direction LR
        JD["jobs.d/*.sh"]
        BD["bridges.d/*"]
        CFG["sentinel.env, http-expected.json,<br/>known-ips.txt, pauses/"]
    end
    PATROLSH --> ATLASPY
    PATROLSH --> JOBSSH
    PATROLSH --> SENSORS
    PATROLSH --> BD
    PATROLSH --> BUSPY
    JOBSSH --> JD
    STREAMPY --> BUSPY
    STREAMPY --> ROUTERPY
    SENSORSH --> BUSPY
    LIB -.-> CFG
```

| Module | Runs as | What it does |
|---|---|---|
| `atlas/atlas.py` | CLI, called by the patrol | Takes a JSON snapshot of the machine's identity (`snap`), diffs it against `baseline.json` (`check`), promotes a reviewed snapshot to the baseline (`bless`). Also judges thresholds and "silent failures" (timer services that end in error). Volatile numbers live under `vitals` and are never diffed. A failed measurement is UNKNOWN, never an empty inventory; a tool that is not installed is simply absent. |
| `atlas/patrol.sh` | cron, minutes 7 and 37 | Runs every periodic sensor under a time limit, runs the report bridges, writes `drift.log` and `heartbeat.log`, raises or clears `ALERT`, emits one bus event per new or changed ALERT section. Never touches the baseline. |
| `atlas/jobs.sh` | sensor | Generic runner: provides `check`, `check_last_line`, `check_last_match`, `paused`, `problem`, `unknown` and sources every `jobs.d/*.sh`. |
| `atlas/sensors/ssh_logins.py` | sensor | SSH logins in the last 24 h from IPs outside `known-ips.txt`. |
| `atlas/sensors/http_probes.py` | sensor | Every enabled vhost answers with its expected first status code; optional extra URLs answer 200. |
| `sentinel/bus.py` | library + CLI | Append-only JSONL bus with `flock`, rotation at 5 MB (3 generations), validation, and `follow` with tail -F semantics and per-fingerprint dedup. |
| `sentinel/stream.py` | `sentinel-stream.service` (Type=notify, watchdog 120 s, MemoryMax 80 M) | Follows the journal (`ssh.service`, `sudo`, PID 1, kernel) and the Apache sensitive-path log; turns lines into events; touches a heartbeat every 60 s. |
| `sentinel/router.py` | inside the daemon | For a `critical` event: if the resident is absent (or none is configured), notifies the human at once, at most once per fingerprint per 6 h. |
| `sentinel/escalation.sh` | `sentinel-escalation.timer`, every 10 min | Mails the human (and calls the notify command) when the patrol is silent > 45 min, the resident is dead, an alarm is unacknowledged > 45 min, or the stream heartbeat is older than 5 min. Same kind at most once per 6 h. |
| `sentinel/session-sensor.sh` | the agent session's monitor tool | Prints one line per state change (ALERT appeared or cleared, a bus event `alert`+, an escalation, a report to deliver). Silence costs nothing. |

---

## What happens, step by step

### A stranger logs in over SSH (real-time path)

```mermaid
sequenceDiagram
    autonumber
    participant J as systemd journal
    participant S as stream.py
    participant B as events.jsonl
    participant R as router.py
    participant M as session-sensor.sh
    participant AI as AI resident
    participant H as Human

    J->>S: "Accepted publickey for ops from 203.0.113.7"
    S->>S: IP not in known-ips.txt, severity critical
    S->>B: emit event (fingerprint auth.ssh.accepted-login:ops@IP)
    S->>R: route(event)
    alt resident present
        R-->>R: nothing to do, the resident will see it
        B-->>M: bus.py follow prints the line
        M-->>AI: monitor notification within seconds
        AI->>AI: investigate (who, from where, what next)
        AI->>H: verdict, not a raw alarm
    else resident absent, not configured, or RESIDENT-OFF
        R->>H: notify command or mail at once (one per 6 h per fingerprint)
    end
```

### The machine drifts (periodic path)

```mermaid
sequenceDiagram
    autonumber
    participant C as cron (7 and 37)
    participant P as patrol.sh
    participant A as atlas.py
    participant ST as state directory
    participant M as session-sensor.sh
    participant AI as AI resident
    participant E as escalation.sh
    participant H as Human

    C->>P: start
    P->>A: check (snapshot vs baseline.json)
    A-->>P: "~ CHANGED crontabs.ops.sha ..." (exit 1)
    P->>ST: write ALERT and ALERT.since, drift.log, heartbeat "alarm"
    P->>ST: emit one bus event per ALERT section
    ST-->>M: ALERT appeared
    M-->>AI: wake up
    alt the owner or the resident made the change
        AI->>A: bless (baseline becomes current)
        AI->>ST: touch ALERT.acked
        Note over P,ST: next patrol is clean, ALERT removed
    else nobody can explain it
        AI->>H: intrusion report
    end
    E->>ST: ALERT older than 45 min and not acknowledged?
    E->>H: "alert without a recipient" mail (one per 6 h)
```

### Nobody is home (LLM-free escalation)

```mermaid
flowchart LR
    T["sentinel-escalation.timer<br/>every 10 min"] --> E["escalation.sh"]
    E --> Q1{"patrol heartbeat<br/>older than 45 min?"}
    E --> Q2{"resident configured<br/>and not alive?"}
    E --> Q3{"ALERT older than<br/>45 min, not acked?"}
    E --> Q4{"stream heartbeat<br/>older than 5 min?"}
    Q1 -->|"yes"| MAIL["mail and notify command<br/>(per kind, one per 6 h)"]
    Q2 -->|"yes, and no RESIDENT-OFF"| MAIL
    Q3 -->|"yes"| MAIL
    Q4 -->|"yes, and not paused"| MAIL
    Q1 -->|"no"| OK["heartbeat ok"]
    Q2 -->|"no"| OK
    Q3 -->|"no"| OK
    Q4 -->|"no"| OK
```

---

## Life of an alarm

```mermaid
stateDiagram-v2
    [*] --> Clean
    Clean --> Raised: patrol finds drift or a failing sensor
    Raised --> Raised: body changes (ALERT rewritten, ALERT.since kept)
    Raised --> Acknowledged: resident or human touches ALERT.acked
    Raised --> Escalated: 45 min without ack, mail and notify
    Acknowledged --> Raised: body changes after the ack
    Acknowledged --> Clean: fixed or blessed, next patrol is clean
    Escalated --> Acknowledged: resident or human acks
    Escalated --> Clean: cause removed, next patrol is clean
    Clean --> [*]
```

A sensor that cannot judge (time limit, missing permission, unreadable file) is reported as **UNKNOWN**, never as
clean: silence mistaken for health is the failure mode this whole design exists to prevent.

---

## Timing

```mermaid
gantt
    title One hour of Atlas (minutes after the full hour)
    dateFormat mm
    axisFormat %M
    section cron
    patrol run           :p1, 07, 2m
    patrol run           :p2, 37, 2m
    section systemd timer
    escalation           :e1, 00, 1m
    escalation           :e2, 10, 1m
    escalation           :e3, 20, 1m
    escalation           :e4, 30, 1m
    escalation           :e5, 40, 1m
    escalation           :e6, 50, 1m
    section daemon
    stream heartbeat every 60 s :active, s1, 00, 60m
```

| What | When | Budget |
|---|---|---|
| `patrol.sh` | cron `7,37 * * * *` | each sensor has its own time limit (atlas check 100 s, HTTP probes 90 s ...); a full run takes about 30 s |
| `escalation.sh` | `OnCalendar=*-*-* *:00/10:00 UTC` (UTC, so the autumn DST change cannot skip an hour) | 120 s, 128 MB |
| `stream.py` | always; heartbeat 60 s, systemd watchdog 120 s | 80 MB, 10 % CPU |
| snapshot retention | cron `40 4 * * *` | snapshots older than 30 days are deleted |

---

## Code and state are separate

```mermaid
flowchart LR
    subgraph CODE["/opt/atlas (this repository)"]
        C1["atlas/ sentinel/ i18n/ examples/ docs/"]
    end
    subgraph STATEDIR["/var/lib/atlas (never in git)"]
        S0["sentinel.env (the one config file)"]
        S1["baseline.json, current.json, snapshots/"]
        S2["known-ips.txt, http-expected.json, pauses/"]
        S3["jobs.d/, bridges.d/ (your plugins)"]
        S4["ALERT, ALERT.since, ALERT.acked, REPORT-TO-SEND"]
        S5["drift.log, heartbeat.log, events.jsonl"]
    end
    ENV["SENTINEL_ATLAS=/var/lib/atlas"] --> CODE
    CODE -->|"reads config, writes state only here"| STATEDIR
```

One variable, `SENTINEL_ATLAS`, selects the state directory for every script; code locates itself by its own
path. Unset, state lives next to the code in `atlas/` (that is how the tests run). The units read `sentinel.env`
through `EnvironmentFile=` without the `-` prefix: a missing file fails the unit loudly instead of silently running
unconfigured.

---

## Principles

1. **No LLM on the alarm path.** Detection and escalation are stdlib Python and bash. The AI is a reader and a fixer, never a link in the chain that calls the human.
2. **Silence is not health.** Every layer writes a heartbeat; another layer watches it. A sensor that cannot measure says UNKNOWN.
3. **The baseline changes only by a deliberate `bless`,** after the change is understood.
4. **Events wake the AI; it never polls.** A polling loop inside an AI session once cost about 100 M tokens in a day; the session sensor costs nothing while nothing happens.
5. **One alarm, one recipient, no spam.** Dedup per fingerprint (1 h for the resident, 6 h for the human); mail at most once per 6 h per kind.
6. **Testable alarm branches.** Every path that would mail a human runs in a test with stubs; a branch nobody ever ran is a hope, not a safeguard.

More: [docs/architecture.md](docs/architecture.md) (layers, event format, engineering rules),
[docs/configuration.md](docs/configuration.md), [docs/security.md](docs/security.md) (what Atlas can read),
[docs/resident.md](docs/resident.md) (connecting an AI agent).

## Tests

```bash
python3 -m pytest -q          # needs python3-pytest; about 2 minutes on one vCPU
```

Every test runs on temporary directories with stubbed commands: no root, no mail, no network, no real state.
GitHub Actions runs the same suite on every push and pull request (Python 3.11 and 3.13), plus `bash -n` on every
shell script and an installer dry run: [.github/workflows/tests.yml](.github/workflows/tests.yml).
