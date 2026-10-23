# Security model

Atlas reads a lot and writes almost nothing. It runs as an unprivileged user (installer default `atlas`) with a
sudoers drop-in that allows exactly the read-only commands below, as root, without a password - and nothing else.

## What Atlas writes

- Only its **state directory** (`SENTINEL_ATLAS`) and `/var/tmp/sentinel` (escalation markers, stream heartbeat,
  router state). It never writes into the code directory, `/etc`, or anything it watches.
- It sends mail (`mail`) and runs `SENTINEL_NOTIFY_CMD` if you configure one. Nothing else leaves the host; there is
  no telemetry and no network call except the HTTP probes to your own vhosts.
- The **installer** is the exception: run as root, it creates the user, the state directory, the systemd units,
  the optional Apache snippet, the sudoers drop-in and (on request) the crontab lines. `uninstall.sh` removes them.

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
