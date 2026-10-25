#!/usr/bin/env python3
"""sentinel-stream: streaming sensors + router in one small daemon (stdlib only, no LLM).

Followers (each restarts its source on EOF/error):
  journal  `journalctl -f -o json` -> auth.ssh.accepted-login, auth.sudo.command,
                                      systemd.unit-failed, kernel.oom-kill
  web      `tail -F sentinel-sensitive.log` -> web.sensitive-hit
Every event goes to the bus (bus.py). A router thread follows the bus and calls router.route()
for each event as it lands (the human is notified only for critical + resident absent).
A source unreadable for > UNREADABLE_SECS emits an `alert` event with confidence `unknown`:
a dead follower must never look like silence.

Configuration: $SENTINEL_ATLAS/sentinel.env (loaded at start; the environment wins), notably
SENTINEL_TRUSTED_SUDO_USERS (default "root"), SENTINEL_WEB_LOG, SENTINEL_LANG and the router's
SENTINEL_EMAIL / SENTINEL_NOTIFY_CMD / SENTINEL_RESIDENT_*.
Env overrides (tests and non-production runs): SENTINEL_ATLAS, SENTINEL_KNOWN_IPS,
SENTINEL_STATE_DIR, SENTINEL_JOURNAL_CMD, SENTINEL_WEB_CMD, SENTINEL_UNREADABLE_SECS,
SENTINEL_RESTART_DELAY, SENTINEL_STABLE_SECS, SENTINEL_HEARTBEAT_SECS, SENTINEL_WATCHDOG_SECS,
plus the bus/router variables.
"""
import ipaddress
import json
import os
import pwd
import re
import shlex
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "atlas"))
import envfile  # noqa: E402

envfile.load(os.environ.get("SENTINEL_ATLAS") or Path(__file__).resolve().parent.parent / "atlas")
import bus  # noqa: E402
import router  # noqa: E402
from i18n import t  # noqa: E402
from untrusted import clean, quote, suspicious  # noqa: E402

# 60 s heartbeat: escalation treats > 5 min of silence as a problem, so 5 beats may be missed.
DEFAULT_HEARTBEAT_SECS = 60
# 30 s ping with WatchdogSec=120: systemd's advice is to ping at half the timeout or faster.
DEFAULT_WATCHDOG_SECS = 30
# 5 min unreadable: long enough to ride out a logrotate or a journald restart, short enough
# to be noticed the same coffee break.
DEFAULT_UNREADABLE_SECS = 300
# 5 s between restarts of a failing source: no busy loop on a 1 vCPU host.
DEFAULT_RESTART_DELAY = 5.0
# A source that stayed up this long counts as healthy again.
DEFAULT_STABLE_SECS = 10.0
TICK = 1.0

# Only these journal fields are requested: smaller JSON, less parsing on 1 vCPU.
JOURNAL_FIELDS = "MESSAGE,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,_PID,UNIT,_TRANSPORT"
# `+` is journalctl's OR between match groups: the kernel ring, PID 1, sudo and ssh.service only.
JOURNAL_CMD = ("journalctl -f -o json -n 0 --output-fields=" + JOURNAL_FIELDS +
               " _SYSTEMD_UNIT=ssh.service + SYSLOG_IDENTIFIER=sudo + _PID=1 + _TRANSPORT=kernel")
WEB_LOG_DEFAULT = "/var/log/apache2/sentinel-sensitive.log"

# Untrusted text (request paths, user names, command lines, process names) enters `what` and
# `message` through untrusted.quote(), evidence and fingerprints through untrusted.clean():
# printable ASCII, bounded, shown as data. Limits per field:
PATH_LIMIT = 80
USER_LIMIT = 32
COMMAND_WHAT_LIMIT = 120
COMMAND_EVIDENCE_LIMIT = 500
PROCESS_LIMIT = 32
IP_LIMIT = 45            # the longest textual IPv6 address
SUSPECT_SAMPLE = 40
SUSPECT_SENSOR = "input.injection-suspect"


def trusted_sudo_users():
    """Users whose sudo is routine (info only, never wakes): SENTINEL_TRUSTED_SUDO_USERS, comma or
    space separated, default "root". Add the account the resident works under: it uses sudo all day."""
    raw = os.environ.get("SENTINEL_TRUSTED_SUDO_USERS")
    raw = "root" if raw is None else raw
    return {u for u in re.split(r"[\s,]+", raw) if u}


def self_user():
    """The account this daemon runs as (the Atlas user). Its successful sudo is Atlas measuring."""
    try:
        return pwd.getpwuid(os.geteuid()).pw_name
    except KeyError:
        return ""


def _env_num(name, default, cast=float):
    v = os.environ.get(name)
    return cast(v) if v else default


def known_ips_default():
    return Path(os.environ.get("SENTINEL_KNOWN_IPS") or bus.atlas_dir() / "known-ips.txt")


def load_known_ips(path):
    ips = set()
    try:
        text = Path(path).read_text()
    except OSError:
        return ips  # unreadable list -> every login is unknown -> critical (fail loud, not quiet)
    for line in text.splitlines():
        tok = line.split("#", 1)[0].split()
        if tok:
            ips.add(_norm_ip(tok[0]))
    return ips


def _norm_ip(s):
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return s


def _ev(sensor, severity, what, fingerprint, evidence, command, message=None, confidence="measured"):
    ev = {"sensor": sensor, "severity": severity, "confidence": confidence, "what": what,
          "evidence": evidence, "command": command, "fingerprint": bus.sanitize_fp(fingerprint)}
    if message:
        ev["message"] = message
    return ev


def _suspects(sensor, field, raw, source, command):
    """At most one `warning` event when `raw` looks like instructions (untrusted.suspicious). It
    never wakes the session (the session sensor passes alert and above) and never blocks the
    original event: a signal for whoever reads the bus, not a verdict."""
    rules = suspicious(raw)
    if not rules:
        return []
    return [_ev(SUSPECT_SENSOR, "warning",
                "instruction-like text in %s from %s: %s" % (field, source, ",".join(rules)),
                "%s:%s:%s:%s" % (SUSPECT_SENSOR, sensor, field, rules[0]),
                {"field": field, "source": source, "rules": rules, "sample": clean(raw, SUSPECT_SAMPLE)},
                command)]


_SSH_RE = re.compile(r"^Accepted (\S+) for (\S+) from (\S+)")
# sudo >= 1.9 pads the user name with leading spaces ("  ops : PWD=..."); a denied command puts the
# reason first ("ops : command not allowed ; PWD=..."), a successful one starts with KEY=value fields.
_SUDO_RE = re.compile(r"^\s*(\S+)\s+:\s*(.*?)COMMAND=(.*)$")
_SUDO_FIELD = re.compile(r"^[A-Z_]+=")
_FAILED_RE = re.compile(r"^(\S+?): Failed with result")
_OOM_RE = re.compile(r"Out of memory: Killed process (\d+) \((.*?)\)")


def journal_events(entry, known_ips_path=None):
    """Map one journald JSON entry to a list of bus events: [] (nothing), [event], or [event plus
    `input.injection-suspect` warnings]. Trusted fields (_SYSTEMD_UNIT, _PID, _TRANSPORT are set by
    journald, not by the sender) are required, so a user cannot forge an alert by logging a
    lookalike line."""
    msg = entry.get("MESSAGE")
    if not isinstance(msg, str):
        return []
    ident = entry.get("SYSLOG_IDENTIFIER")

    if entry.get("_SYSTEMD_UNIT") == "ssh.service" and msg.startswith("Accepted "):
        # "Accepted " with the capital A and the space: the log line "...PubkeyAcceptedAlgorithms..."
        # contains "Accepted" too and is not a login (the trap that fooled the first draft).
        m = _SSH_RE.match(msg)
        if not m:
            return []
        method, user_raw, ip_raw = m.groups()
        user, ip, method = clean(user_raw, USER_LIMIT), clean(ip_raw, IP_LIMIT), clean(method, 32)
        known = _norm_ip(ip_raw) in load_known_ips(known_ips_path or known_ips_default())
        fp = "auth.ssh.accepted-login:%s@%s" % (user, ip.replace(":", "_"))
        cmd = "journalctl -u ssh --since -1h | grep 'Accepted '"
        ev = _ev("auth.ssh.accepted-login", "info" if known else "critical",
                 "SSH login by %s from %s IP %s (%s)" % (quote(user_raw, USER_LIMIT),
                                                         "known" if known else "UNKNOWN", ip, method),
                 fp, {"user": user, "ip": ip, "method": method, "known_ip": known}, cmd)
        if not known:
            ev["message"] = t("stream.ssh_unknown", user=quote(user_raw, USER_LIMIT), ip=ip)
        return [ev] + _suspects(ev["sensor"], "user", user_raw, ip, cmd)

    if ident == "sudo" and "COMMAND=" in msg:
        m = _SUDO_RE.match(msg)
        if not m:
            return []
        user_raw, fields, cmd_raw = m.group(1), m.group(2), m.group(3).strip()
        first = fields.split(";", 1)[0].strip()
        reason = clean(first, 80) if first and not _SUDO_FIELD.match(first) else ""
        exe = clean(os.path.basename(cmd_raw.split()[0]) if cmd_raw.split() else "-", 64)
        user = clean(user_raw, USER_LIMIT)
        me = self_user()
        if not reason and user_raw == me and me != "root":
            # the Atlas user running its allowlisted read-only commands (~300 per patrol): not news
            return []
        trusted = user_raw in trusted_sudo_users() and not reason
        what = "sudo by %s%s: %s" % (quote(user_raw, USER_LIMIT), " (%s)" % reason if reason else "",
                                     quote(cmd_raw, COMMAND_WHAT_LIMIT))
        evidence = {"user": user, "command": clean(cmd_raw, COMMAND_EVIDENCE_LIMIT)}
        if reason:
            evidence["reason"] = reason
        hint = "journalctl -t sudo --since -1h"
        ev = _ev("auth.sudo.command", "info" if trusted else "alert",
                 what, "auth.sudo.command:%s:%s" % (user, exe), evidence, hint)
        if not trusted:
            ev["message"] = t("stream.sudo", user=quote(user_raw, USER_LIMIT),
                              command=quote(cmd_raw, COMMAND_WHAT_LIMIT))
        return [ev] + _suspects(ev["sensor"], "command", cmd_raw, user, hint)

    if entry.get("_PID") == "1" and "Failed with result" in msg:
        # PID 1 and unit names come from the system manager (root-defined units), not from a user
        unit = entry.get("UNIT")
        if not isinstance(unit, str):
            m = _FAILED_RE.match(msg)
            unit = m.group(1) if m else "unknown-unit"
        return [_ev("systemd.unit-failed", "alert", "unit %s failed: %s" % (unit, msg[:200]),
                    "systemd.unit-failed:%s" % unit, {"unit": unit, "message": msg[:300]},
                    "systemctl status %s" % shlex.quote(unit),
                    message=t("stream.unit_failed", unit=unit))]

    if entry.get("_TRANSPORT") == "kernel":
        m = _OOM_RE.search(msg)
        if m:
            # the process name (comm) is chosen by whoever started the process: untrusted
            pid, name_raw = m.groups()
            name = clean(name_raw, PROCESS_LIMIT)
            hint = "journalctl -k --since -1h | grep 'Out of memory'"
            ev = _ev("kernel.oom-kill", "alert",
                     "OOM killer killed %s (pid %s)" % (quote(name_raw, PROCESS_LIMIT), pid),
                     "kernel.oom-kill:%s" % name, {"process": name, "pid": pid}, hint,
                     message=t("stream.oom", name=quote(name_raw, PROCESS_LIMIT)))
            return [ev] + _suspects(ev["sensor"], "process", name_raw, "kernel", hint)
    return []


def classify_journal(entry, known_ips_path=None):
    """The primary event for one journald entry, or None (journal_events without the suspects)."""
    evs = journal_events(entry, known_ips_path)
    return evs[0] if evs else None


# status, bytes, then the request: works with or without the leading "ts vhost ip" fields.
_WEB_RE = re.compile(r'(?:^|\s)(\d{3}) (\d+) "([A-Z]+) (\S+)[^"]*"\s*$')


def web_events(line):
    """One sensitive-path log line -> [] or [web.sensitive-hit, plus suspect warnings]. The request
    path is the attacker's text: quoted in `what`/`message`, cleaned in evidence/fingerprint."""
    m = _WEB_RE.search(line)
    if not m:
        return []
    status, nbytes, method, path = int(m.group(1)), int(m.group(2)), m.group(3), m.group(4)
    prefix = line[:m.start()].split()
    # %v (the configured ServerName) and %a (the peer address) are not client text; cleaned anyway
    vhost = clean(prefix[1], 80) if len(prefix) >= 3 else "-"
    ip = clean(prefix[2], IP_LIMIT) if len(prefix) >= 3 else "-"
    path_raw = path.split("?", 1)[0]
    path_c = clean(path_raw, PATH_LIMIT)
    # grep needs a literal prefix of the logged path, not the "..." of a shortened one
    grep_key = clean(path_raw, len(path_raw) + 1)[:PATH_LIMIT]
    if 200 <= status < 300:
        # %B counts the body only. An empty 2xx is a placeholder page, a non-empty one is a leak.
        sev = "critical" if nbytes > 0 else "warning"
        klass = "2xx"
    else:
        sev, klass = "info", "other"
    hint = "grep -F %s %s" % (shlex.quote(grep_key), WEB_LOG_DEFAULT)
    ev = _ev("web.sensitive-hit", sev,
             "%s %s -> %d (%d body bytes) on %s from %s" % (method, quote(path_raw, PATH_LIMIT), status, nbytes,
                                                            vhost, ip),
             "web.sensitive-hit:%s:%s:%s" % (vhost, path_c, klass),
             {"vhost": vhost, "ip": ip, "status": status, "bytes": nbytes, "path": path_c},
             hint)
    if sev == "critical":
        ev["message"] = t("stream.web_leak", path=quote(path_raw, PATH_LIMIT), status=status, bytes=nbytes,
                          vhost=vhost)
    # the full request target, query included: an injection can live in the query string too
    return [ev] + _suspects(ev["sensor"], "path", path, ip, hint)


def classify_web(line):
    """The primary event for one log line, or None (web_events without the suspects)."""
    evs = web_events(line)
    return evs[0] if evs else None


class Source(threading.Thread):
    """Runs a command, feeds its stdout lines to `handle`, restarts it forever."""

    def __init__(self, name, cmd_fn, handle, stop, readable=lambda: True):
        super().__init__(name=name, daemon=True)
        self.src_name, self.cmd_fn, self.handle, self.stop_evt, self.readable = name, cmd_fn, handle, stop, readable
        self.fail_since = None
        self.alerted = False
        self.up_since = None
        self.proc = None

    def _fail(self):
        self.up_since = None
        if self.fail_since is None:
            self.fail_since = time.monotonic()

    def run(self):
        delay = _env_num("SENTINEL_RESTART_DELAY", DEFAULT_RESTART_DELAY)
        while not self.stop_evt.is_set():
            if not self.readable():
                self._fail()
                self.stop_evt.wait(delay)
                continue
            try:
                self.proc = subprocess.Popen(self.cmd_fn(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                             text=True, errors="replace")
            except OSError as e:
                print("sentinel-stream: %s: cannot start: %s" % (self.src_name, e), file=sys.stderr, flush=True)
                self._fail()
                self.stop_evt.wait(delay)
                continue
            self.up_since = time.monotonic()
            try:
                for line in self.proc.stdout:
                    if self.stop_evt.is_set():
                        break
                    try:
                        self.handle(line.rstrip("\n"))
                    except Exception as e:  # one bad line must not kill the follower
                        print("sentinel-stream: %s: line error: %s" % (self.src_name, e), file=sys.stderr, flush=True)
            except (OSError, ValueError):
                pass
            self.terminate()
            if self.up_since is not None and time.monotonic() - self.up_since >= _env_num(
                    "SENTINEL_STABLE_SECS", DEFAULT_STABLE_SECS):
                self.fail_since = None  # it ran fine for a while, then ended: a fresh outage clock
            self._fail()
            self.stop_evt.wait(delay)

    def terminate(self):
        p = self.proc
        if p and p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        if p:
            try:
                p.stdout.close()
            except Exception:
                pass

    def check_health(self, unreadable_secs):
        """Called from the main tick. Returns an event dict to emit or None."""
        now = time.monotonic()
        readable = self.readable()
        if not readable and self.fail_since is None:
            self.fail_since = now  # live tail on a vanished/unreadable file: the outage starts here
        if readable and self.up_since is not None and self.proc and self.proc.poll() is None and \
                now - self.up_since >= _env_num("SENTINEL_STABLE_SECS", DEFAULT_STABLE_SECS):
            self.fail_since = None
            self.alerted = False
            return None
        if self.fail_since is not None and not self.alerted and now - self.fail_since >= unreadable_secs:
            self.alerted = True
            return _ev("stream.source-unreadable", "alert",
                       "stream source '%s' unreadable for over %d s" % (self.src_name, unreadable_secs),
                       "stream.source-unreadable:%s" % self.src_name,
                       {"source": self.src_name, "seconds": int(now - self.fail_since)},
                       "systemctl status sentinel-stream; journalctl -u sentinel-stream --since -1h",
                       message=t("stream.source_unreadable", source=self.src_name, seconds=int(unreadable_secs)),
                       confidence="unknown")
        return None


def sd_notify(msg):
    path = os.environ.get("NOTIFY_SOCKET")
    if not path:
        return
    if path.startswith("@"):
        path = "\0" + path[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.sendto(msg.encode(), path)
    except OSError:
        pass


def emit_safe(ev):
    try:
        bus.emit(ev)
    except (ValueError, OSError) as e:
        print("sentinel-stream: cannot emit %s: %s" % (ev.get("sensor"), e), file=sys.stderr, flush=True)


def router_loop(stop, ready):
    state = router.default_state_path()
    for ev in bus.follow_events(from_end=True, stop=stop.is_set, on_ready=ready.set):
        try:
            if not bus.validate(ev):
                router.route(ev, state_path=state)
        except Exception as e:
            print("sentinel-stream: router error: %s" % e, file=sys.stderr, flush=True)
    ready.set()


def main():
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    state = router.state_dir()
    state.mkdir(parents=True, exist_ok=True)
    heartbeat = state / "stream.heartbeat"
    hb_secs = _env_num("SENTINEL_HEARTBEAT_SECS", DEFAULT_HEARTBEAT_SECS)
    wd_secs = _env_num("SENTINEL_WATCHDOG_SECS", DEFAULT_WATCHDOG_SECS)
    unreadable = _env_num("SENTINEL_UNREADABLE_SECS", DEFAULT_UNREADABLE_SECS)
    known = known_ips_default()
    web_log = os.environ.get("SENTINEL_WEB_LOG") or WEB_LOG_DEFAULT

    def on_journal(line):
        try:
            entry = json.loads(line)
        except ValueError:
            return
        for ev in journal_events(entry, known) if isinstance(entry, dict) else []:
            emit_safe(ev)

    def on_web(line):
        for ev in web_events(line):
            emit_safe(ev)

    web_cmd_env = os.environ.get("SENTINEL_WEB_CMD")
    sources = [
        Source("journal", lambda: shlex.split(os.environ.get("SENTINEL_JOURNAL_CMD") or JOURNAL_CMD),
               on_journal, stop),
        Source("web", lambda: shlex.split(web_cmd_env or "tail -n 0 -F %s" % shlex.quote(web_log)),
               on_web, stop,
               # tail -F happily waits for a file that never appears: check readability ourselves
               readable=(lambda: True) if web_cmd_env else (lambda: os.access(web_log, os.R_OK))),
    ]
    ready = threading.Event()
    rt = threading.Thread(target=router_loop, args=(stop, ready), name="router", daemon=True)
    rt.start()
    ready.wait(2)  # the router must be positioned at the end of the bus before sources emit
    for s in sources:
        s.start()
    sd_notify("READY=1")

    last_hb = last_wd = 0.0
    while not stop.is_set():
        now = time.monotonic()
        alive = rt.is_alive() and all(s.is_alive() for s in sources)
        for s in sources:
            ev = s.check_health(unreadable)
            if ev:
                emit_safe(ev)
        # Beat only while every thread lives: a crashed thread must stop the beat, so that
        # escalation (heartbeat) and systemd (watchdog restart) see it. Silence is a signal.
        if alive and now - last_hb >= hb_secs:
            try:
                heartbeat.touch()
                os.utime(heartbeat)
            except OSError as e:
                print("sentinel-stream: heartbeat: %s" % e, file=sys.stderr, flush=True)
            last_hb = now
        if alive and now - last_wd >= wd_secs:
            sd_notify("WATCHDOG=1")
            last_wd = now
        stop.wait(TICK)
    sd_notify("STOPPING=1")
    for s in sources:
        s.terminate()
    return 0


if __name__ == "__main__":
    sys.exit(main())
