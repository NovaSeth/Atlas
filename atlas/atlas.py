#!/usr/bin/env python3
"""Atlas - a structural snapshot of this server, and a tripwire for drift.

The point is not monitoring (that is what the patrol does). The point is *identity*:
what this machine IS - which services run, which ports listen, which keys open it,
which vhosts answer, which binaries carry setuid. Anything that changes here changed
because someone changed it. If neither the owner nor the resident did it, it is an intrusion.

    atlas.py snap    write current.json (in the state directory, SENTINEL_ATLAS)
    atlas.py check   snap + diff against baseline.json; prints changes, exit 1 if any;
                     no baseline = UNKNOWN (exit 2), a baseline is never created implicitly
    atlas.py bless   promote current.json to baseline.json (after a reviewed, approved change);
                     leaves a bus event and a notice to the human
    atlas.py ack     acknowledge the current ALERT by its content (ALERT.acked); same trail as bless
    atlas.py show    human-readable map of the house
    atlas.py thresholds   read current.json: disk/RAM/cert thresholds (exit 0 clean, 1 alarm, 2 unknown)
    atlas.py silent       read current.json: print silent failures of timer services

Volatile numbers (disk, RAM, load, ban counts) live under "vitals" and are never diffed.
"""
import contextlib, hashlib, json, os, pwd, re, shlex, shutil, subprocess, sys
from datetime import datetime, timezone

# Code and instance state are separate: SENTINEL_ATLAS selects the state directory (baseline, current,
# snapshots, sentinel.env). Unset = next to the code.
CODE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, CODE_DIR)
import envfile  # noqa: E402
from i18n import t  # noqa: E402
sys.path.insert(0, os.path.join(os.path.dirname(CODE_DIR), "sentinel"))
import bus  # noqa: E402
import notify  # noqa: E402

BASE = os.path.abspath(os.environ.get("SENTINEL_ATLAS") or CODE_DIR)
envfile.load(BASE)   # $BASE/sentinel.env; variables already in the environment win
CURRENT = os.path.join(BASE, "current.json")
BASELINE = os.path.join(BASE, "baseline.json")
SNAPDIR = os.path.join(BASE, "snapshots")


CMD_TIMEOUT = 25         # seconds for an ordinary command
SLOW_CMD_TIMEOUT = 40    # dpkg-query, certbot
SETUID_TIMEOUT = 60      # find over /usr /bin /sbin /opt
ERROR_TEXT_LIMIT = 220   # characters of one recorded measurement error
CMD_PREVIEW = 70         # characters of a command shown in an error
SHA_PREFIX = 16          # characters of a sha256 kept in the snapshot
CERT_ERROR_LIMIT = 200   # characters of a certbot / journal error
DIFF_VALUE_LIMIT = 160   # characters of an added or removed value in a diff line
DIFF_CHANGE_LIMIT = 80   # characters of each side of a changed value in a diff line
OS_RELEASE = "/etc/os-release"
LOADAVG = "/proc/loadavg"
PASSWD = "/etc/passwd"

# A command is a string split into an argument list and run WITHOUT a shell: these tokens (and any token
# made only of shell punctuation, or starting a substitution) are refused instead of being interpreted.
SHELL_OPERATORS = frozenset({"|", "||", "&", "&&", ";", ";;", ">", ">>", "<", "<<", "2>", "2>>", "&>", "2>&1"})
_PUNCTUATION = frozenset("();<>|&")


def argv_of(cmd):
    """Split `cmd` into an argv list. ValueError on a shell operator, a substitution or a broken quote."""
    if "$(" in cmd:
        raise ValueError("shell syntax: command substitution")
    lex = shlex.shlex(cmd, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    argv = list(lex)
    for tok in argv:
        # a lone ( or ) is an ordinary find(1) argument; a substitution is refused by the `$(` check below
        punct = all(c in _PUNCTUATION for c in tok) and tok not in ("(", ")")
        if tok in SHELL_OPERATORS or punct or tok.startswith("`"):
            raise ValueError("shell syntax: %r" % tok)
    if not argv:
        raise ValueError("empty command")
    return argv


def run_checked(cmd, timeout=CMD_TIMEOUT):
    """Run `cmd` as an argv list (no shell). Returns (rc, stdout, stderr).

    rc is None when the command could not run at all (timeout, exec error, shell syntax); stdout then
    starts with "__ERROR__". Use it for every measurement whose EMPTY output is meaningful:
    empty output with rc != 0 is "could not measure", never "nothing found".
    """
    try:
        p = subprocess.run(argv_of(cmd), shell=False, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except ValueError:
        return None, f"__ERROR__ shell syntax not supported: {cmd[:CMD_PREVIEW]}", ""
    except Exception as e:
        return None, f"__ERROR__ {e}", ""


def run(cmd, timeout=CMD_TIMEOUT):
    """Stdout of a command that succeeded; None when it failed. A failure is never a value."""
    rc, out, _ = run_checked(cmd, timeout)
    return out if rc == 0 else None


# Measurement failures of the last snapshot: section -> reason. A collector whose command FAILED
# (sudo denied, timeout, missing binary) must never look like a collector that found NOTHING:
# the failure lands here, `check` reports it (exit 2 = UNKNOWN) and `bless` refuses the snapshot.
MEAS_ERRORS = {}


def sink(errors):
    """The collector a function writes to: its `errors` argument, MEAS_ERRORS when none is given."""
    return MEAS_ERRORS if errors is None else errors


def record(errors, section, text):
    """Record the first failure of a section (kept short; the first reason is the useful one)."""
    sink(errors).setdefault(section, text[:ERROR_TEXT_LIMIT])


def measure(section, cmd, timeout=CMD_TIMEOUT, ok=(0,), errors=None):
    """Run a measurement. Returns stdout, or None when the command failed (recorded in `errors`).

    A non-zero status outside `ok`, or ANY status != 0 together with stderr output (sudo failing),
    is a failure; an empty stdout with a clean status is a real, empty result.
    """
    rc, out, err = run_checked(cmd, timeout)
    if rc is None or rc not in ok or out.startswith("__ERROR__") or (rc != 0 and err):
        record(errors, section, f"{cmd[:CMD_PREVIEW]} rc={rc} {err or out}")
        return None
    return out


def probe(section, test_cmd, errors=None):
    """`sudo test ...` style question: True (rc 0), False (rc 1, silent), None (could not ask)."""
    rc, out, err = run_checked(test_cmd)
    if rc == 0:
        return True
    if rc == 1 and not err and not out:
        return False
    record(errors, section, f"{test_cmd[:CMD_PREVIEW]} rc={rc} {err or out}")
    return None


def sha(path, section="local_files", errors=None):
    """Hash of a local file, or None when it cannot be read (recorded in `errors`).

    A read failure is UNKNOWN, never a value of the snapshot.
    """
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()[:SHA_PREFIX]
    except Exception as e:
        record(errors, section, f"read {path}: {e}")
        return None


def local_isdir(path, section="local_files", errors=None):
    """True/False for a directory that exists/is really absent; None (recorded) when stat fails otherwise."""
    try:
        os.stat(path)
        return os.path.isdir(path)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError as e:
        record(errors, section, f"stat {path}: {e}")
        return None


def local_listdir(path, section="local_files", errors=None):
    """Sorted directory entries; [] for a really absent directory; [] plus a recorded error when unreadable."""
    if not local_isdir(path, section, errors):
        return []
    try:
        return sorted(os.listdir(path))
    except OSError as e:
        record(errors, section, f"list {path}: {e}")
        return []


# Optional tools (docker, ufw, certbot): a tool that is not installed is a real, empty result, not a
# failed measurement. A tool that IS installed and fails is still UNKNOWN.
TOOL_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


OPTIONAL_TOOLS = ("certbot", "docker", "fail2ban-client", "ufw")


def have(tool):
    return shutil.which(tool, path=TOOL_PATH) is not None


def services(errors=None):
    out = measure("services", "systemctl list-units --type=service --state=running --no-legend --plain",
                  errors=errors) or ""
    names = sorted(l.split()[0] for l in out.splitlines() if l.strip())
    enabled = measure("services", "systemctl list-unit-files --state=enabled --no-legend --plain",
                      errors=errors) or ""
    en = sorted(l.split()[0] for l in enabled.splitlines() if l.strip())
    return {"running": names, "enabled": en}


def timers(errors=None):
    out = measure("timers", "systemctl list-timers --all --no-legend --plain", errors=errors) or ""
    return sorted(re.sub(r"\s+", " ", l).split(" ")[-2] for l in out.splitlines() if ".timer" in l)


def listeners(errors=None):
    out = measure("listeners", "sudo ss -tulnpH", errors=errors) or ""
    res = []
    for line in out.splitlines():
        f = line.split()
        if len(f) < 6:
            continue
        proto, local = f[0], f[4]
        m = re.search(r'users:\(\("([^"]+)"', line)
        res.append(f"{proto} {local} {m.group(1) if m else '?'}")
    return sorted(set(res))


def containers(errors=None):
    if not have("docker"):
        return {}
    # through sudo: the alternative (the atlas user in the docker group) is root-equivalent
    out = measure("containers", "sudo docker ps --format '{{.Names}}|{{.Image}}|{{.Ports}}'", errors=errors) or ""
    res = {}
    for line in out.splitlines():
        if "|" in line:
            n, i, p = line.split("|", 2)
            res[n] = {"image": i, "ports": p}
    return res


def key_fingerprints(ak, errors=None):
    """`name comment` of every key in an authorized_keys file (empty file = no keys)."""
    quoted = shlex.quote(ak)
    if not probe("accounts", f"sudo test -s {quoted}", errors):
        return []
    fp = measure("accounts", f"sudo ssh-keygen -lf {quoted}", errors=errors) or ""
    keys = []
    for k in fp.splitlines():
        parts = k.split()
        if len(parts) >= 3:
            keys.append(f"{parts[1]} {' '.join(parts[2:-1])}")
    return sorted(keys)


def accounts(errors=None):
    users = {}
    with open(PASSWD) as f:
        lines = f.read().splitlines()
    for line in lines:
        n, _, uid, gid, _, home, shell = line.strip().split(":")
        if shell.endswith(("nologin", "false", "sync")):
            continue
        keys = key_fingerprints(os.path.join(home, ".ssh/authorized_keys"), errors)
        users[n] = {"uid": int(uid), "shell": shell, "keys": keys}
    return users


def sudoers(errors=None):
    res = {}
    h0 = measure("sudoers", "sudo sha256sum /etc/sudoers", errors=errors)
    if h0:
        res["/etc/sudoers"] = h0.split()[0][:SHA_PREFIX]
    out = measure("sudoers", "sudo ls /etc/sudoers.d", errors=errors) or ""
    for f in out.split():
        path = f"/etc/sudoers.d/{f}"
        h = measure("sudoers", f"sudo sha256sum {shlex.quote(path)}", errors=errors)
        if h:
            res[path] = h.split()[0][:SHA_PREFIX]
    return res


def vhosts(errors=None):
    """Vhosts AND global config fragments (conf-enabled).

    Gap found in practice: a file added to conf-enabled (an ACME alias) went unnoticed while
    only sites-enabled was watched.
    A fragment in conf-enabled applies to ALL vhosts at once - a stronger place to hide
    an alias that exposes files than a single vhost.
    """
    d = "/etc/apache2/sites-enabled"
    res = {}
    d2 = "/etc/apache2/conf-enabled"
    for f in local_listdir(d2, "vhosts", errors):
        path = shlex.quote(f"{d2}/{f}")
        txt = measure("vhosts", f"sudo cat {path}", errors=errors) or ""
        h = measure("vhosts", f"sudo sha256sum {path}", errors=errors)
        if not h:
            continue
        res[f"conf-enabled/{f}"] = {
            "alias": sorted(set(re.findall(r"^\s*Alias(?:Match)?\s+(\S+)", txt, re.M))),
            "sha": h.split()[0][:SHA_PREFIX],
        }
    for f in local_listdir(d, "vhosts", errors):
        path = shlex.quote(f"{d}/{f}")
        txt = measure("vhosts", f"sudo cat {path}", errors=errors) or ""
        names = sorted(set(re.findall(r"^\s*Server(?:Name|Alias)\s+(\S+)", txt, re.M)))
        roots = sorted(set(re.findall(r"^\s*DocumentRoot\s+(\S+)", txt, re.M)))
        proxies = sorted(set(re.findall(r"^\s*ProxyPass\s+\S+\s+(\S+)", txt, re.M)))
        h = sha(f"{d}/{f}", "vhosts", errors)
        if h:
            res[f] = {"names": names, "root": roots, "proxy": proxies, "sha": h}
    return res


def crontab_users(passwd=PASSWD, errors=None):
    """Everyone in /etc/passwd + every file in /var/spool/cron/crontabs (a new account cannot slip by)."""
    u = set()
    try:
        with open(passwd) as f:
            for line in f:
                if ":" in line and not line.startswith("#"):
                    u.add(line.split(":")[0])
    except OSError:
        pass
    if probe("crontabs", "sudo test -d /var/spool/cron/crontabs", errors):
        out = measure("crontabs", "sudo ls /var/spool/cron/crontabs", errors=errors) or ""
        u |= set(out.split())
    return sorted(u)


def crontabs(errors=None):
    res = {}
    for u in crontab_users(errors=errors):
        rc, out, err = run_checked(f"sudo crontab -u {shlex.quote(u)} -l")
        if rc == 1 and "no crontab" in err:
            out = ""     # a user without a crontab is a real, empty result
        elif rc != 0:
            record(errors, "crontabs", f"crontab -u {u} rc={rc} {err or out}")
            continue
        lines = [l for l in out.splitlines() if l.strip() and not l.startswith("#")]
        if lines:
            digest = hashlib.sha256("\n".join(lines).encode()).hexdigest()[:SHA_PREFIX]
            res[u] = {"lines": len(lines), "sha": digest}
    for f in local_listdir("/etc/cron.d", "crontabs", errors):
        h = sha(f"/etc/cron.d/{f}", "crontabs", errors)
        if h:
            res[f"cron.d/{f}"] = {"sha": h}
    return res


def packages(errors=None):
    """Installed packages (status ii) as a sorted list of `name=version`."""
    out = measure("packages", "dpkg-query -W -f='${db:Status-Abbrev} ${Package}=${Version}\\n'",
                  timeout=SLOW_CMD_TIMEOUT, errors=errors) or ""
    res = []
    for l in out.splitlines():
        f = l.split()
        if len(f) == 2 and f[0] == "ii":
            res.append(f[1])
    return sorted(res)


PACKAGE_LIMIT = 25


def shorten_packages(changes, limit=PACKAGE_LIMIT):
    """`apt upgrade` changes hundreds of packages - the output keeps `limit` lines and a counter."""
    pkg = [c for c in changes if re.match(r"[-+] \w+\s+packages:", c)]
    if len(pkg) <= limit:
        return changes
    drop = set(map(id, pkg[limit:]))
    res, inserted = [], False
    for c in changes:
        if id(c) in drop:
            if not inserted:
                # human-facing text (lands in ALERT): from the catalog
                res.append(t("atlas.packages_more", count=len(pkg) - limit))
                inserted = True
            continue
        res.append(c)
    return res


# Thresholds, overridable in sentinel.env. Pick them on data, not on a hunch: replay your own
# snapshots/*.json and count how often a candidate threshold would have fired.
#  ATLAS_DISK_PCT (90): on the reference host 163 hourly snapshots peaked at 76% of /; 90% gives zero
#                       false hits and still leaves time to react to a jump.
#  ATLAS_RAM_MB  (250): the worst measured "available" was ~490 MB; 250 MB is half of that.
#  ATLAS_CERT_DAYS (14): certbot renews at 30 days left, so < 14 days = renewal failing for >= 16 days.
def _env_int(name, default):
    try:
        return int(os.environ.get(name) or default)
    except ValueError:
        return default


THRESHOLD_DISK_PCT = _env_int("ATLAS_DISK_PCT", 90)
THRESHOLD_RAM_MB = _env_int("ATLAS_RAM_MB", 250)
THRESHOLD_CERT_DAYS = _env_int("ATLAS_CERT_DAYS", 14)


def thresholds(snap, ssl_vhost_count):
    """Returns (alarms, unknown). Empty certs while SSL vhosts exist = unknown.

    The message strings are human-facing (they end up in ALERT) and come from the i18n catalog.
    """
    alarms, unknown = [], []
    certs_ = snap.get("certs") or {}
    v = snap.get("vitals") or {}
    if v.get("certs_error"):
        unknown.append(t("atlas.certs_measure_failed", error=v["certs_error"]))
    if ssl_vhost_count is None:
        unknown.append(t("atlas.certs_ssl_count_failed"))
    elif not certs_ and ssl_vhost_count > 0 and not v.get("certs_error"):
        unknown.append(t("atlas.certs_empty", count=ssl_vhost_count))
    for n, c in sorted(certs_.items()):
        days = c.get("days")
        if days is None:
            unknown.append(t("atlas.cert_unreadable", name=n, error=c.get("error", "?")))
        elif days < THRESHOLD_CERT_DAYS:
            what = t("atlas.cert_expired_word") if c.get("expired") else t("atlas.cert_days_left", days=days)
            alarms.append(t("atlas.cert_alarm", name=n, what=what, limit=THRESHOLD_CERT_DAYS))
    try:
        d = int(str(v.get("disk_used_pct")).rstrip("%"))
        if d >= THRESHOLD_DISK_PCT:
            alarms.append(t("atlas.disk_alarm", pct=d, limit=THRESHOLD_DISK_PCT))
    except ValueError:
        unknown.append(t("atlas.disk_unknown", value=repr(v.get("disk_used_pct"))))
    try:
        m = int(v.get("mem_available_mb"))
        if m < THRESHOLD_RAM_MB:
            alarms.append(t("atlas.ram_alarm", mb=m, limit=THRESHOLD_RAM_MB))
    except (ValueError, TypeError):
        unknown.append(t("atlas.ram_unknown", value=repr(v.get("mem_available_mb"))))
    return alarms, unknown


SITES_DIR = os.environ.get("HTTP_SITES_DIR") or "/etc/apache2/sites-enabled"
_SSL_VHOST = re.compile(r"^\s*SSLEngine\s+on|:443", re.M)


def ssl_vhost_count(sites_dir=None):
    """Number of SSL vhost files, or None when it could not be measured.

    No sites directory at all (no Apache) is a real zero. Each file is read through `sudo cat` (the same
    read-only command vhosts() uses); a file that cannot be read makes the whole count unknown.
    """
    sites_dir = sites_dir or SITES_DIR
    if not local_isdir(sites_dir, "vhosts"):
        return 0
    count = 0
    for f in local_listdir(sites_dir, "vhosts"):
        rc, out, err = run_checked(f"sudo cat {shlex.quote(f'{sites_dir}/{f}')}")
        if rc != 0:
            return None
        if _SSL_VHOST.search(out):
            count += 1
    return count


def silent_text(snap):
    d = (snap.get("vitals") or {}).get("silent_failures") or {}
    return "\n".join(f"  {k}: {v}" for k, v in sorted(d.items()))


def silent_unknown_text(snap):
    d = (snap.get("vitals") or {}).get("silent_unknown") or {}
    return "\n".join(f"  {k}: {v}" for k, v in sorted(d.items()))


def certs_measure():
    """Returns (certs, error). error != "" means the measurement itself failed (UNKNOWN).

    Every "Certificate Name" yields an entry. days is None (plus "error") when the expiry
    cannot be read - that is unknown, never a dropped certificate. An expired certificate
    ("INVALID: EXPIRED") gets days 0 and expired True.
    """
    if not have("certbot"):
        return {}, ""   # not installed: no certificates to watch (an SSL vhost without certs still shows)
    rc, out, err = run_checked("sudo certbot certificates", timeout=SLOW_CMD_TIMEOUT)
    if rc is None or rc != 0 or out.startswith("__ERROR__"):
        return {}, f"certbot rc={rc} {err or out}"[:CERT_ERROR_LIMIT]
    res, name = {}, None
    for line in out.splitlines():
        line = line.strip()
        m = re.match(r"Certificate Name: (\S+)", line)
        if m:
            name = m.group(1)
            res[name] = {"expiry": "?", "days": None, "error": "no Expiry Date line"}
            continue
        m = re.match(r"Expiry Date: (.*)", line)
        if m and name:
            rest = m.group(1)
            date = re.match(r"(\S+ \S+)", rest)
            entry = {"expiry": date.group(1) if date else "?"}
            st = re.search(r"\(([^)]*)\)", rest)
            status = st.group(1) if st else ""
            d = re.search(r"(\d+)\s+days?", status)
            if "EXPIRED" in status.upper():
                entry.update(days=0, expired=True)
            elif d and status.upper().startswith("VALID"):
                entry["days"] = int(d.group(1))
            else:
                entry.update(days=None, error=f"unparseable expiry {rest!r}")
            res[name] = entry
    return res, ""


def certs():
    return certs_measure()[0]


def setuid(errors=None):
    out = measure("setuid", "sudo find /usr /bin /sbin /opt -xdev -perm -4000 -type f",
                  timeout=SETUID_TIMEOUT, errors=errors) or ""
    return sorted(out.split())


def firewall(errors=None):
    if not have("ufw"):
        return []
    out = measure("firewall", "sudo ufw status numbered", errors=errors) or ""
    return [re.sub(r"\s+", " ", l.strip()) for l in out.splitlines() if l.strip().startswith("[")]


APT_LIST = "/etc/apt/sources.list"
APT_DIR = "/etc/apt/sources.list.d"


def apt_sources(errors=None):
    res = {}
    for p in [APT_LIST] + [os.path.join(APT_DIR, f) for f in local_listdir(APT_DIR, "apt_sources", errors)]:
        if os.path.exists(p):
            h = sha(p, "apt_sources", errors)
            if h:
                res[p] = h
    return res


# What an attacker uses to persist or alters to hide traces (see sensitive_files).
UNIT_DIRS = ("/etc/systemd/system", "/etc/systemd/user", "/usr/local/lib/systemd/system")
UNIT_SUFFIXES = (".service", ".timer", ".socket", ".path")
SINGLE_FILES = ("/etc/ld.so.preload", "/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf",
                "/etc/pam.d/sshd", "/etc/ssh/sshd_config", "/etc/profile", "/etc/bash.bashrc",
                "/etc/rc.local", "/etc/environment")
WATCHED_DIRS = ("/etc/cron.hourly", "/etc/cron.daily", "/etc/profile.d", "/etc/sudoers.d",
                "/etc/ssh/sshd_config.d", "/etc/apt/apt.conf.d")
HOST_KEY_FILES = ("/etc/ssh/ssh_host_ed25519_key.pub", "/etc/ssh/ssh_host_rsa_key.pub")


def sensitive_hash(path, errors=None):
    h = measure("sensitive_files", f"sudo sha256sum {shlex.quote(path)}", errors=errors)
    return h.split()[0][:SHA_PREFIX] if h else None


def unit_hashes(errors=None):
    """Hashes of systemd units added by hand (not from packages)."""
    res = {}
    for d in UNIT_DIRS:
        if not probe("sensitive_files", f"sudo test -d {shlex.quote(d)}", errors):
            continue
        # the argument list sudoers pins (examples/sudoers.d/atlas); the suffix filter below is a second guard
        out = measure("sensitive_files", f"sudo find {shlex.quote(d)} -maxdepth 2 -type f \\( -name '*.service' "
                      "-o -name '*.timer' -o -name '*.socket' -o -name '*.path' \\)", errors=errors) or ""
        for f in sorted(x for x in out.split() if x.endswith(UNIT_SUFFIXES)):
            h = sensitive_hash(f, errors)
            if h:
                res[f] = h
    return res


def single_file_hashes(errors=None):
    """Single files with a large blast radius; a really absent file is a recorded fact."""
    res = {}
    for f in SINGLE_FILES:
        exists = probe("sensitive_files", f"sudo test -e {shlex.quote(f)}", errors)
        if exists:
            h = sensitive_hash(f, errors)
            if h:
                res[f] = h
        elif exists is False:
            res[f] = "__absent (good)__"
    return res


def dir_listings(errors=None):
    """Directories where a file appearing out of nowhere is a signal in itself."""
    res = {}
    for d in WATCHED_DIRS:
        if probe("sensitive_files", f"sudo test -d {shlex.quote(d)}", errors):
            listing = measure("sensitive_files", f"sudo ls -1 {shlex.quote(d)}", errors=errors) or ""
            res[f"{d}/"] = sorted(listing.split())
        else:
            res[f"{d}/"] = []
    return res


def host_key_fingerprints(errors=None):
    """SSH host keys - a swap = preparation for eavesdropping."""
    keys = []
    for kf in HOST_KEY_FILES:
        if probe("sensitive_files", f"sudo test -e {shlex.quote(kf)}", errors):
            out = measure("sensitive_files", f"sudo ssh-keygen -lf {shlex.quote(kf)}", errors=errors) or ""
            keys += [l.split()[1] for l in out.splitlines() if len(l.split()) > 2]
    return sorted(keys)


def sensitive_files(errors=None):
    """Files an attacker uses to persist - or alters to hide traces.

    The atlas used to look only at what RUNS (services running/enabled). This function looks
    at what WAITS: a systemd unit that is not enabled yet, an ld.so.preload entry, a swapped
    resolver. Classic persistence mechanisms do not show up in `systemctl` until they are
    started - and by then it is too late to detect them as news.
    """
    res = {}
    res.update(unit_hashes(errors))
    res.update(single_file_hashes(errors))
    res.update(dir_listings(errors))
    res["__ssh_host_keys__"] = host_key_fingerprints(errors)
    return res


def silent_failures_checked():
    """Returns (failures, unknown). Timer-launched services that ended with an error in their latest run.

    Found in practice: certbot.service failed on every run for days and did NOT SHOW UP in
    `systemctl --failed`, because oneshot units started from a timer do not stay in the failed
    state - they exit with an error and vanish until the next run.

    NOTE, verified empirically: `systemctl show -p Result` does not show it either -
    for certbot.service it reported "success" despite three documented failures in the journal.
    Systemd does not keep the result of a finished one-shot unit. The only reliable source is
    the journal, and it is the only thing asked here. The first version of this function used
    `Result` and returned "all clean" on a machine with a really broken certbot.
    """
    res, unknown = {}, {}
    rc, out, err = run_checked("systemctl list-timers --all --no-legend --plain")
    if rc != 0:
        return res, {"list-timers": f"rc={rc} {err or out}"[:CERT_ERROR_LIMIT]}
    services_ = set()
    for line in out.splitlines():
        m = re.search(r"(\S+\.service)\s*$", line.strip())
        if m:
            services_.add(m.group(1))
    for u in sorted(services_):
        # We alarm on the CURRENT STATE, not on history: what counts is whether the LAST run
        # ended in an error. The first version counted failures over 7 days and so would have
        # kept glowing for a week after the fix - and an alarm that burns for a week teaches
        # the human to ignore it. History stays as context alongside, not as a reason to alarm.
        # No masking pipe: the journal status is checked, the filtering happens here.
        rc, jout, jerr = run_checked(f"sudo journalctl -u {shlex.quote(u)} --since -14d -o short-iso --no-pager")
        if rc != 0:
            unknown[u] = f"journalctl rc={rc} {jerr or jout}"[:CERT_ERROR_LIMIT]
            continue
        lines = [l for l in jout.splitlines() if re.search("Failed with result|Succeeded|Finished", l)]
        if not lines:
            continue
        last = lines[-1]
        if "Failed with result" not in last:
            continue
        rc7, j7, e7 = run_checked(f"sudo journalctl -u {shlex.quote(u)} --since -7d --no-pager")
        failures = sum(1 for l in j7.splitlines() if "Failed with result" in l) if rc7 == 0 else "?"
        when = last.split()[0] if last.split() else "?"
        # human-facing text (lands in ALERT): from the catalog
        res[u] = t("atlas.silent_failure", when=when, count=failures)
    return res, unknown


def silent_failures():
    return silent_failures_checked()[0]


def os_pretty_name(path=OS_RELEASE):
    """PRETTY_NAME of an os-release file, or None when it cannot be read or has no such line."""
    try:
        with open(path) as f:
            lines = f.read().splitlines()
    except OSError:
        return None
    for line in lines:
        if line.startswith("PRETTY_NAME="):
            try:
                words = shlex.split(line.split("=", 1)[1])
            except ValueError:
                return None
            return " ".join(words) or None
    return None


def host_info(errors=None):
    """Kernel, OS and first address. A value that could not be measured is "?" plus a recorded error."""
    kernel = measure("host", "uname -r", errors=errors)
    ips = measure("host", "hostname -I", errors=errors)
    pretty = os_pretty_name()
    if pretty is None:
        record(errors, "host", f"read {OS_RELEASE}: no PRETTY_NAME")
    return {"kernel": kernel or "?", "os": pretty or "?", "ip": ips.split()[0] if ips and ips.split() else "?"}


def vital_disk(bad):
    """(used_pct, avail) of `/` from the last line of `df -h /`."""
    out = run("df -h /")
    fields = out.splitlines()[-1].split() if out and out.splitlines() else []
    if len(fields) > 4:
        return fields[4], fields[3]
    bad["disk"] = "df -h / failed" if out is None else "df -h / gave no usable line"
    return "?", "?"


def vital_mem(bad):
    """Available MB: the 7th column of the `Mem:` line of `free -m` (the second line)."""
    out = run("free -m")
    lines = out.splitlines() if out else []
    fields = lines[1].split() if len(lines) > 1 else []
    if len(fields) > 6:
        return fields[6]
    bad["mem"] = "free -m failed" if out is None else "free -m gave no usable line"
    return "?"


def vital_load(bad):
    """The three load averages, read from /proc/loadavg."""
    try:
        with open(LOADAVG) as f:
            return " ".join(f.read().split()[:3])
    except OSError as e:
        bad["load"] = f"read {LOADAVG}: {e}"
        return "?"


def vital_banned(bad):
    """Currently banned addresses of the sshd jail; "" when fail2ban is not installed."""
    if not have("fail2ban-client"):
        return ""     # only when installed: sudo logs "command not allowed" for a binary that does not exist
    out = run("sudo fail2ban-client status sshd")
    if out is None:
        bad["banned"] = "fail2ban-client status sshd failed"
        return "?"
    m = re.search(r"Currently banned:\s+(\d+)", out)
    return m.group(1) if m else ""


def vital_failed_units(bad):
    out = run("systemctl --failed --no-legend --plain")
    if out is None:
        bad["failed_units"] = "systemctl --failed failed"
        return "?"
    return str(len([l for l in out.splitlines() if l.strip()]))


def vital_uptime(bad):
    out = run("uptime -p")
    if out is None:
        bad["uptime"] = "uptime -p failed"
        return "?"
    return out


def vitals(errors=None):
    """Volatile numbers (never diffed). A failed command is "?" plus a reason in `vitals_errors`, never a value.

    These failures are not mirrored into `errors`: thresholds() turns "?" disk/RAM into UNKNOWN, and an
    optional tool that flaps must not block bless.
    """
    bad = {}
    used, avail = vital_disk(bad)
    sf, su = silent_failures_checked()
    res = {
        "disk_used_pct": used,
        "disk_avail": avail,
        "mem_available_mb": vital_mem(bad),
        "load": vital_load(bad),
        "uptime": vital_uptime(bad),
        "banned_sshd": vital_banned(bad),
        "failed_units": vital_failed_units(bad),
        "silent_failures": sf,
        "silent_unknown": su,
        # optional tools that are not installed: skipped on purpose, shown by `show` (never diffed)
        "not_present": [tool for tool in OPTIONAL_TOOLS if not have(tool)],
    }
    if bad:
        res["vitals_errors"] = bad
    return res


# The collectors of the snapshot, in snapshot order. Every entry is f(errors=None); snapshot() passes one
# error collector to all of them. (certs and host come first and separately: certs_measure returns a pair.)
SECTIONS = {
    "services": services, "timers": timers, "listeners": listeners, "containers": containers,
    "accounts": accounts, "sudoers": sudoers, "vhosts": vhosts, "crontabs": crontabs,
    "packages": packages, "setuid": setuid, "sensitive_files": sensitive_files, "firewall": firewall,
    "apt_sources": apt_sources, "vitals": vitals,
}


def snapshot():
    errors = {}
    certs_, certs_error = certs_measure()
    snap = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "host": host_info(errors),
        "certs": certs_,
    }
    for name, collect in SECTIONS.items():
        snap[name] = collect(errors)
    MEAS_ERRORS.clear()
    MEAS_ERRORS.update(errors)
    snap["vitals"]["certs_error"] = certs_error
    snap["vitals"]["measure_errors"] = dict(errors)
    return snap


IGNORE = {"generated_at", "vitals", "certs"}  # certs: days count ticks down daily by design


def diff(old, new, path=""):
    out = []
    if isinstance(old, dict) and isinstance(new, dict):
        for k in sorted(set(old) | set(new)):
            if not path and k in IGNORE:
                continue
            p = f"{path}.{k}" if path else k
            if k not in new:
                out.append(f"- REMOVED {p} = {json.dumps(old[k], ensure_ascii=False)[:DIFF_VALUE_LIMIT]}")
            elif k not in old:
                out.append(f"+ ADDED   {p} = {json.dumps(new[k], ensure_ascii=False)[:DIFF_VALUE_LIMIT]}")
            else:
                out += diff(old[k], new[k], p)
    elif isinstance(old, list) and isinstance(new, list):
        for x in sorted(set(map(json.dumps, old)) - set(map(json.dumps, new))):
            out.append(f"- REMOVED {path}: {json.loads(x)}")
        for x in sorted(set(map(json.dumps, new)) - set(map(json.dumps, old))):
            out.append(f"+ ADDED   {path}: {json.loads(x)}")
    elif old != new:
        out.append(f"~ CHANGED {path}: {json.dumps(old, ensure_ascii=False)[:DIFF_CHANGE_LIMIT]} -> {json.dumps(new, ensure_ascii=False)[:DIFF_CHANGE_LIMIT]}")
    return out


def atomic_write_text(path, text):
    """Write `text` to `path` through a temp file in the same directory and os.replace."""
    tmp = "%s.tmp.%d" % (path, os.getpid())
    try:
        with open(tmp, "w") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write(obj, path):
    atomic_write_text(path, json.dumps(obj, indent=1, ensure_ascii=False, sort_keys=True))


WHO_RE = re.compile(r"[A-Za-z0-9_.-]{1,32}")
SECTION_LIMIT = 20       # sections named in an event or notice
SECTION_NAME_LIMIT = 80  # characters of one ALERT section title


def who():
    """The human behind the command: SUDO_USER when well formed, else the effective user."""
    su = os.environ.get("SUDO_USER", "")
    if WHO_RE.fullmatch(su):
        return su
    try:
        return pwd.getpwuid(os.geteuid()).pw_name
    except (KeyError, OSError):
        return "uid%d" % os.geteuid()


def changed_sections(old, new):
    """Sorted top-level keys outside IGNORE whose values differ; [] when there is no old snapshot."""
    if old is None:
        return []
    return sorted(k for k in set(old) | set(new) if k not in IGNORE and old.get(k) != new.get(k))


def alert_sha(raw):
    """sha256 hex of the ALERT bytes after the first newline (the first line is a timestamp)."""
    _, nl, body = raw.partition(b"\n")
    return hashlib.sha256(body if nl else b"").hexdigest()


@contextlib.contextmanager
def state_env():
    """bus and notify locate events.jsonl and the outbox through SENTINEL_ATLAS; make that this state dir."""
    had = "SENTINEL_ATLAS" in os.environ
    prev = os.environ.get("SENTINEL_ATLAS")
    os.environ["SENTINEL_ATLAS"] = BASE
    try:
        yield
    finally:
        if had:
            os.environ["SENTINEL_ATLAS"] = prev
        else:
            os.environ.pop("SENTINEL_ATLAS", None)


def audit_event(sensor, what, evidence):
    """Bus event for a human decision (bless/ack). A bus failure is a stderr line, never an exception."""
    sha = evidence.get("sha256", "")
    fp_sha = "".join(chr(ord("a") + int(c, 16)) for c in sha[:12])
    try:
        with state_env():
            bus.emit({"sensor": sensor, "severity": "warning", "confidence": "measured", "what": what,
                      "fingerprint": "%s:%s" % (sensor, fp_sha), "evidence": evidence})
    except Exception as e:  # noqa: BLE001 - the trail must not break the command
        print("atlas: bus event not written (%s): %s" % (sensor, e), file=sys.stderr)


def tell_human(subject, body, kind):
    try:
        with state_env():
            status = notify.send_or_queue(subject, body, kind)
    except Exception as e:  # noqa: BLE001 - the decision is already recorded; a notice problem is reported, not raised
        print("atlas: notice failed (%s): %s" % (kind, e), file=sys.stderr)
        status = "lost"
    if status != "sent":
        print(t("atlas.notify_not_sent", status=status), file=sys.stderr)
    return status


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def cmd_bless():
    try:
        cur = json.load(open(CURRENT))
    except (OSError, ValueError) as e:
        print(t("atlas.current_unreadable", error=e), file=sys.stderr)
        return 2
    bad = snapshot_unknowns(cur)
    if bad:
        print(t("atlas.bless_refused") + "\n  " + "\n  ".join(bad), file=sys.stderr)
        return 2
    first = not os.path.exists(BASELINE)
    try:
        old = None if first else json.load(open(BASELINE))
    except (OSError, ValueError):
        old = None   # an unreadable old baseline is replaced; every section counts as changed below
    sections = changed_sections(old, cur) if old is not None else sorted(k for k in cur if k not in IGNORE)
    write(cur, BASELINE)
    print("baseline updated")
    sha256 = hashlib.sha256(open(BASELINE, "rb").read()).hexdigest()
    shown = sections[:SECTION_LIMIT]
    audit_event("atlas.bless", "baseline accepted by %s" % who(),
                {"who": who(), "sections": shown, "first": first, "sha256": sha256})
    listing = t("atlas.bless_first") if first else (", ".join(shown) or "-")
    tell_human(t("atlas.bless_subject", who=who()),
               t("atlas.bless_body", who=who(), when=now_iso(), sections=listing, sha256=sha256), "atlas.bless")
    return 0


def cmd_ack():
    alert = os.path.join(BASE, "ALERT")
    acked = os.path.join(BASE, "ALERT.acked")
    try:
        raw = open(alert, "rb").read()
        st = os.stat(alert)
    except OSError:
        print(t("atlas.ack_nothing"), file=sys.stderr)
        return 1
    sha256 = alert_sha(raw)
    atomic_write_text(acked, sha256 + "\n")
    try:
        st2 = os.stat(alert)
        raced = (st2.st_mtime_ns != st.st_mtime_ns) or open(alert, "rb").read() != raw
    except OSError:
        raced = True
    if raced:
        # the patrol rewrote ALERT while we acknowledged: the ack must not cover the new content
        try:
            older = os.stat(alert).st_mtime - 1
        except OSError:
            older = 0
        os.utime(acked, (older, older))
        print(t("atlas.ack_raced"), file=sys.stderr)
        return 3
    body = raw.partition(b"\n")[2].decode("utf-8", "replace")
    sections = [s[:SECTION_NAME_LIMIT] for s in re.findall(r"^== (.+) ==$", body, re.M)][:SECTION_LIMIT]
    audit_event("atlas.ack", "alert acknowledged by %s" % who(),
                {"who": who(), "sections": sections, "sha256": sha256})
    tell_human(t("atlas.ack_subject", who=who()),
               t("atlas.ack_body", who=who(), when=now_iso(), sections=", ".join(sections) or "-", sha256=sha256),
               "atlas.ack")
    print("alert acknowledged")
    return 0


def snapshot_unknowns(snap):
    """EVERY unknown/error field of a snapshot as readable lines; empty list = fully measured."""
    v = (snap.get("vitals") or {})
    out = []
    for k, e in sorted((v.get("measure_errors") or {}).items()):
        out.append(f"measure_errors.{k}: {e}")
    if v.get("certs_error"):
        out.append(f"certs_error: {v['certs_error']}")
    for k, e in sorted((v.get("silent_unknown") or {}).items()):
        out.append(f"silent_unknown.{k}: {e}")
    return out


def measure_errors_text(errors):
    return "\n".join(f"  {k}: {v}" for k, v in sorted(errors.items()))


def load_current():
    """(snapshot, None) from current.json, or (None, exit code 2) after printing why it is unreadable."""
    try:
        with open(CURRENT) as f:
            return json.load(f), None
    except (OSError, ValueError) as e:
        print(t("atlas.current_unreadable", error=e), file=sys.stderr)  # human-facing (ALERT)
        return None, 2


def cmd_silent():
    """Read-only. Exit 0 clean, 1 failures found, 2 could not measure."""
    snap, rc = load_current()
    if snap is None:
        return rc
    txt, u = silent_text(snap), silent_unknown_text(snap)
    if u:
        print(t("atlas.silent_cannot_judge") + "\n" + u + (("\n" + txt) if txt else ""), file=sys.stderr)
        return 2
    if txt:
        print(txt)
        return 1
    return 0


def cmd_thresholds():
    """Read-only: reads current.json written by `check` in the same patrol run."""
    snap, rc = load_current()
    if snap is None:
        return rc
    alarms, unknown = thresholds(snap, ssl_vhost_count())
    for l in alarms:
        print("  " + l)
    for l in unknown:
        print("  " + l, file=sys.stderr)
    return 2 if unknown else (1 if alarms else 0)


def take_snapshot():
    """Measure, then write current.json and the hourly copy under snapshots/."""
    snap = snapshot()
    write(snap, CURRENT)
    os.makedirs(SNAPDIR, exist_ok=True)
    write(snap, os.path.join(SNAPDIR, snap["generated_at"][:13].replace(":", "") + ".json"))
    return snap


def cmd_snap():
    take_snapshot()
    print("snapshot ok")
    return 0


def cmd_show():
    snap = take_snapshot()
    v = snap["vitals"]
    print(f"{snap['host']['os']} / {snap['host']['kernel']} / {snap['host']['ip']}  up {v['uptime']}")
    print(t("atlas.show_disk", used=v["disk_used_pct"], avail=v["disk_avail"], mem=v["mem_available_mb"],
            load=v["load"], bans=v["banned_sshd"]))
    print(t("atlas.show_services", count=len(snap["services"]["running"]),
            containers=", ".join(snap["containers"])))
    print(t("atlas.show_vhosts", vhosts=len(snap["vhosts"]), ports=len(snap["listeners"]),
            accounts=", ".join(snap["accounts"])))
    for d, c in sorted(snap["certs"].items(), key=lambda x: -1 if x[1]["days"] is None else x[1]["days"])[:3]:
        print(t("atlas.show_cert", name=d, days=c["days"] if c["days"] is not None else "?"))
    if v.get("not_present"):
        print(t("atlas.show_not_present", tools=", ".join(v["not_present"])))
    return 0


def cmd_check():
    """Snapshot + diff against the baseline: 0 no changes, 1 changes, 2 UNKNOWN (failed measurement, no baseline)."""
    snap = take_snapshot()
    if snap["vitals"].get("measure_errors"):
        # human-facing (lands in ALERT): a failed measurement is UNKNOWN, never an empty inventory
        print(t("atlas.measure_failed") + "\n" + measure_errors_text(snap["vitals"]["measure_errors"]),
              file=sys.stderr)
        return 2
    if not os.path.exists(BASELINE):
        # never an implicit baseline: whatever state the host is in on the first run would become "normal"
        print(t("atlas.no_baseline"), file=sys.stderr)
        return 2
    with open(BASELINE) as f:
        changes = shorten_packages(diff(json.load(f), snap))
    if not changes:
        print("ATLAS OK - no changes")
        return 0
    print(f"ATLAS: {len(changes)} change(s) against baseline:")
    for c in changes:
        print("  " + c)
    return 1


COMMANDS = {"bless": cmd_bless, "ack": cmd_ack, "thresholds": cmd_thresholds, "silent": cmd_silent,
            "snap": cmd_snap, "show": cmd_show, "check": cmd_check}


def main(argv=None):
    argv = sys.argv if argv is None else argv
    cmd = argv[1] if len(argv) > 1 else "check"
    return COMMANDS.get(cmd, COMMANDS["check"])()


def entry():
    os.chdir(BASE)
    sys.exit(main())


if __name__ == "__main__":
    entry()
