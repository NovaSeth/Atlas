# Security model

Atlas reads a lot and writes almost nothing. It runs as an unprivileged user (installer default `atlas`) with a
sudoers drop-in that allows the fixed command lines below, as root, without a password - and no others. The commands
are read-only in effect, but not all of them are content-blind: `cat` of Apache vhost files and `journalctl` return
text, while `sha256sum`, `ls`, `test` and `ssh-keygen -lf` return hashes, names or fingerprints only. Anyone who
controls the Atlas account can run each allowed line with any argument its rule accepts (see *Threat model*).

## What Atlas writes

- Its **state directory** (`SENTINEL_ATLAS`): `baseline.json`, `ALERT*`, `events.jsonl`, logs, and `runtime/`
  (escalation markers, stream heartbeat, router and digest state; owner and mode are checked at use). Installs from before this layout kept
  it in `/var/tmp/sentinel`; the installer moves it into `runtime/` on upgrade. `runtime/outbox/` holds notices
  that could not be delivered at once, one file each, until the next escalation run delivers them
  (`notify.py drain`). Atlas never writes into the code directory, `/etc`, or anything it watches.
- It sends mail (`mail`) and runs `SENTINEL_NOTIFY_CMD` if you configure one.
- **Opt-in heartbeat URL.** When `SENTINEL_HEARTBEAT_URL` is set (empty by default), every clean escalation run makes
  one HTTP GET to that URL (10 s socket timeout, a redirect counts as failure, the URL is never logged). It carries
  no payload, but the receiver learns the host's public IP address and that the escalation timer is alive.
- Apart from that there is no telemetry and no network call except the HTTP probes to your own vhosts. What an AI
  agent you attach sends to its provider is described in *Threat model*; Atlas itself never contacts a provider.
- The **installer** is the exception: run as root, it creates the user, the state directory, the systemd units,
  the optional Apache snippet, the sudoers drop-in and (on request) the crontab lines. `uninstall.sh` removes them.

## Threat model

Atlas is a detector with a narrow privilege, so this section says whom it defends against, whom it cannot, and
what leaves the host.

**In scope**

- *Internet clients.* Anyone who can send a request, an SSH user name or a login attempt controls text that reaches
  the bus (request paths, user names). Defense: the text is cleaned and bounded, the stream requires journald's
  trusted fields, and the session sensor shows attacker-controlled events by sensor name and digest only (see
  *Untrusted input* in [architecture.md](architecture.md#untrusted-input)).
- *Local unprivileged users.* They can write to the journal and run `sudo` with a command line of their choosing.
  A `sudo` log line counts only when the journal entry's sender matches: `_EXE` must be a configured sudo path
  (`SENTINEL_SUDO_EXE`, default `/usr/bin/sudo`) and `_UID` must map to the user named in the message. Only when the
  entry has no `_EXE` does the check fall back to `_COMM` equal to `sudo`, which is weaker (a process can name
  itself `sudo`). A mismatch becomes an `auth.sudo.forged` warning instead of a `sudo` event.
- *A manipulated or compromised agent.* Text from logs can try to steer an attached AI agent. The alerting path
  contains no model, so the human is told regardless. The agent reads raw logs only through a quarantined reader and
  needs a human message before a privileged action once it has read untrusted text (see
  [resident.md](resident.md)); its wake-ups are capped (`SENTINEL_WAKE_MAX_PER_HOUR`, default 12); its own `sudo`
  use (`SENTINEL_AGENT_SUDO_USERS`) is summarised in a daily digest.
- *Forged log lines.* Covered by the two points above: the trusted journald fields decide, never the message text.
- *The boot-time agent service.* The optional `atlas-resident` unit starts an AI with shell access at every boot, with
  nobody watching: a standing privilege, limited only by the rights of the agent account and by the approval mode
  in `resident.env` (`bypassPermissions` removes the human approval step). Its logins are files in that account's
  home (see [resident.md](resident.md#logins-and-restarts)); an expired login stops the start and escalates.

**Out of scope, with reasons**

- *An intruder with root.* Root can stop the daemons, rewrite the baseline and the state directory and forge any
  journal field. Atlas on the same host cannot detect what root hides.
- *Takeover of the MTA or the notification channel.* Escalation is one mail or one `SENTINEL_NOTIFY_CMD`. Whoever
  controls that channel controls whether the human hears anything. Use a channel you monitor independently.
- *The machine itself dying.* A dead host reports nothing (host failure); see [When a layer dies](architecture.md#when-a-layer-dies) for what
  is detected from inside and what needs a check from outside.
- *An attacker with the Atlas account.* That account can edit `sentinel.env` (recipient, notify command), the
  baseline and the pauses, and can run every allowed `sudo` line with any argument its rule accepts. Treat it as a
  service account with a sensitive read role and never give an agent a shell as this account.
- *Authenticity of stored events.* Entries on the bus and files in the state directory are not signed; integrity
  rests on file permissions. HMAC is not implemented.

**What an attached agent sends to its model provider**

Atlas itself sends nothing to a provider. An AI agent attached to it does, as the content of its context: IP
addresses (SSH logins, web clients), user names (SSH, sudo), host configuration read from `ALERT`, `events.jsonl`
and `atlas.py show` (vhost names, listening ports, unit, cron and certificate names), and command lines (sudo
commands, process names). The session sensor shows attacker-controlled bus text as a sensor name and digest, but an
agent that reads `events.jsonl` or `ALERT` directly sees the cleaned text.

IP addresses and login names are personal data under the GDPR. Before you attach an agent you need a legal basis
(for example a documented legitimate interest in securing the system), a data processing agreement with the model
provider, and an assessment of where the provider processes the data. Atlas does not replace addresses or names
with tokens: pseudonymisation is not implemented. Without an agent nothing leaves the host except the notices you
configured and the opt-in heartbeat GET.

## What Atlas reads, and why

Through `sudo` (all listed in `examples/sudoers.d/atlas`):

| Command | Purpose |
|---|---|
| `ss -tulnpH` | listening sockets and their processes |
| `sha256sum` on `/etc/sudoers`, `/etc/sudoers.d/<file>`, `/etc/apache2/conf-enabled/<file>`, unit files under `/etc/systemd/{system,user}` and `/usr/local/lib/systemd/system`, and `ld.so.preload`, `hosts`, `resolv.conf`, `nsswitch.conf`, `pam.d/sshd`, `ssh/sshd_config`, `profile`, `bash.bashrc`, `rc.local`, `environment` in `/etc` | hashes of files attackers use to persist or hide (hashes only, never contents) |
| `cat /etc/apache2/{sites,conf}-enabled/<file>` | vhost names, document roots, proxies, aliases; counting SSL vhosts |
| `ls /etc/sudoers.d`, `ls /var/spool/cron/crontabs`, `ls -1` of `cron.hourly`, `cron.daily`, `profile.d`, `sudoers.d`, `ssh/sshd_config.d`, `apt/apt.conf.d` | a file appearing out of nowhere is a signal |
| `test -d / -e / -s` on the same places and on `~/.ssh/authorized_keys` of accounts with a shell | existence, without reading |
| `ssh-keygen -lf` on `authorized_keys` and the SSH host keys | key **fingerprints** (never key material) |
| `find /usr /bin /sbin /opt -xdev -perm -4000 -type f` | setuid binaries |
| `find <unit dir> -maxdepth 2 -type f ( -name *.service -o ... )` | unit files that wait to be enabled |
| `crontab -u <user> -l` | every account's crontab (hash and line count only) |
| `journalctl -u <unit> --since -14d / -7d`, `journalctl -u ssh --since -24h` | last result of timer services; SSH logins |
| `certbot certificates`, `ufw status numbered`, `fail2ban-client status sshd`, `docker ps --format ...` | certificates, firewall rules, bans, containers (each only if installed) |

Without `sudo`: `systemctl` listings, `dpkg-query`, `df`, `free`, `/proc/loadavg`, `/etc/passwd`, `/etc/apt/sources.list*`,
`/etc/cron.d`, and the journal / Apache logs through the `adm` and `systemd-journal` groups (the stream daemon).
The Docker socket is never used directly: membership in the `docker` group would be equivalent to root.

## Why regular expressions in the sudoers file

A `*` in a sudoers argument also matches spaces and `../`, so `cat /etc/apache2/sites-enabled/*` would let the
account read `/etc/apache2/sites-enabled/../../shadow`. The shipped rules therefore use sudo's `^...$` regular
expressions (sudo >= 1.9.10) with path components that cannot start with a dot, so `..` can never appear, and fixed
command lines everywhere else. The installer refuses to install a file that `visudo -cf` rejects.

Residual exposure, accepted on purpose: `test` can tell whether a path under a home directory exists, and
`sha256sum` can hash any unit file under the systemd directories. Neither reveals contents.

If your sudo is older than 1.9.10, either upgrade it or run Atlas as root (`--user root`), knowing that it then
runs with full privileges.

## Your additions

Commands you add yourself - `_extra_urls_cmd` in `http-expected.json`, `jobs.d/` contracts, `bridges.d/` bridges,
`SENTINEL_NOTIFY_CMD` - run as the Atlas user. If one of them needs privileges, add a narrow rule for exactly that
command in a separate sudoers file; do not widen `atlas`.

## Secrets

The repository contains none and needs none. `sentinel.env` may hold a recipient address and a notify command; keep
it `0640` (the installer does). Never commit a state directory to a public place: `baseline.json` is a detailed map
of your server.
