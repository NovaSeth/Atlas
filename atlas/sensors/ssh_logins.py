#!/usr/bin/env python3
"""Sensor: a successful SSH login from an address not in known-ips.txt.

Output contract: 0 = clean, 1 = event (one JSON line per event on stdout),
2 = unknown (stderr says why: journalctl error, missing permissions, missing known-IP list).
`--text` prints the events as readable lines WITHOUT the timestamp of the current run
(for ALERT: the alert content must not change on every run; the lines are addressed
to the human and come from the i18n catalog).

Source: systemd journal (/var/log/auth.log does not exist on every system), 24 h window.
Pattern: exactly "Accepted " (capital letter + space). Trap seen in practice:
`grep -i accepted` matches "PubkeyAcceptedAlgorithms" in the message about a REJECTED key.

Condition for an event to go out: (a) the IP is added to known-ips.txt or (b) the login
is older than the 24 h window. The fingerprint contains no time: auth.ssh.accepted:<ip>:<user>.

Read-only, zero network, zero LLM. Overridable ONLY for tests:
SSH_JOURNAL_CMD, SSH_KNOWN_IPS, SSH_WINDOW_H.
"""
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(BASE))
import envfile  # noqa: E402
from i18n import t  # noqa: E402

envfile.load(os.environ.get("SENTINEL_ATLAS") or os.path.dirname(BASE))
KNOWN = os.environ.get("SSH_KNOWN_IPS", os.path.join(os.environ.get("SENTINEL_ATLAS") or os.path.dirname(BASE), "known-ips.txt"))
WINDOW_H = float(os.environ.get("SSH_WINDOW_H", "24"))
COMMAND = os.environ.get("SSH_JOURNAL_CMD", "sudo -n journalctl -u ssh --since -24h -o short-iso --no-pager")
PATTERN = re.compile(r"^(\S+) \S+ \S+: Accepted (\S+) for (\S+) from (\S+) port \d+")


def load_known(path):
    res = set()
    with open(path) as f:
        for l in f:
            l = l.split("#", 1)[0].strip()
            if l:
                res.add(l)
    return res


def events(text, known, now):
    latest = {}
    for l in text.splitlines():
        m = PATTERN.match(l)
        if not m:
            continue
        when, method, user, ip = m.groups()
        try:
            t = datetime.fromisoformat(when)
        except ValueError:
            continue
        if t.tzinfo is None:
            t = t.astimezone()
        if t < now - timedelta(hours=WINDOW_H) or ip in known:
            continue
        latest[(ip, user)] = (when, method)
    return latest


def main():
    text_mode = "--text" in sys.argv
    try:
        known = load_known(KNOWN)
    except OSError as e:
        # stderr lands in ALERT ("UNKNOWN: ..."): human-facing, from the catalog
        print(t("ssh.no_known_list", path=KNOWN, error=e), file=sys.stderr)
        return 2
    try:
        p = subprocess.run(COMMAND, shell=True, capture_output=True, text=True, timeout=25)
    except Exception as e:
        print(t("ssh.journal_error", error=e), file=sys.stderr)
        return 2
    if p.returncode != 0:
        print(t("ssh.journal_rc", rc=p.returncode, stderr=p.stderr.strip()[:200]), file=sys.stderr)
        return 2
    now = datetime.now(timezone.utc)
    ev = events(p.stdout, known, now)
    for (ip, user), (when, method) in sorted(ev.items()):
        if text_mode:
            print(t("ssh.login_line", ip=ip, user=user, method=method, when=when))
        else:
            print(json.dumps({
                "ts": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "sensor": "auth.ssh.accepted-login",
                "severity": "critical",
                "confidence": "measured",
                "what": "successful SSH login from an unknown IP",
                "evidence": {"ip": ip, "user": user, "when": when, "method": method},
                "command": "sudo journalctl -u ssh --since -24h | grep 'Accepted '",
                "fingerprint": f"auth.ssh.accepted:{ip}:{user}",
            }, ensure_ascii=False))
    return 1 if ev else 0


if __name__ == "__main__":
    sys.exit(main())
