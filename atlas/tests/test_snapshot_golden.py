#!/usr/bin/env python3
"""Characterization test: snapshot() over fixed collector answers equals a golden file.

It must pass on the code before and after the no-shell refactor (audit 12): the answer table
serves the old shell command strings and the new argv-style ones with the same data.
`python3 atlas/tests/test_snapshot_golden.py --write` regenerates atlas/tests/data/snapshot-golden.json.
"""

import builtins
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ATLAS = Path(__file__).resolve().parent.parent
GOLDEN = Path(__file__).resolve().parent / "data" / "snapshot-golden.json"

PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "ops:x:1000:1000:ops:/home/ops:/bin/bash\n"
)
OS_RELEASE = 'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nNAME="Debian GNU/Linux"\n'
LOADAVG = "0.10 0.20 0.30 1/200 1234\n"
SERVICE_UNIT = "ssh.service loaded active running OpenBSD Secure Shell server"
TIMERS = (
    "Thu 2026-10-29 10:00:00 UTC 1h left Thu 2026-10-29 09:00:00 UTC 1h ago apt-daily.timer apt-daily.service\n"
    "Thu 2026-10-29 11:00:00 UTC 2h left Thu 2026-10-29 03:00:00 UTC 7h ago certbot.timer certbot.service\n"
)
DF = "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        40G   20G   18G  53% /\n"
FREE = (
    "               total        used        free      shared  buff/cache   available\n"
    "Mem:            3900        1200        1500          50        1400        2700\n"
    "Swap:              0           0           0\n"
)
FAIL2BAN = (
    "Status for the jail: sshd\n|- Filter\n|  `- Currently failed:\t0\n"
    "`- Actions\n   |- Currently banned:\t3\n   `- Total banned:\t9\n"
)
CERTS = (
    "Found the following certs:\n  Certificate Name: ok.example\n    Domains: ok.example\n"
    "    Expiry Date: 2027-01-01 00:00:00+00:00 (VALID: 60 days)\n"
)
JOURNAL = (
    "2026-10-27T03:00:00+0000 h systemd[1]: certbot.service: Failed with result 'exit-code'.\n"
    "2026-10-28T03:00:00+0000 h systemd[1]: certbot.service: Failed with result 'exit-code'.\n"
)
UNITS = {"/etc/systemd/system": ["a.service", "b.timer"]}
SINGLE = (
    "/etc/ld.so.preload",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/nsswitch.conf",
    "/etc/pam.d/sshd",
    "/etc/ssh/sshd_config",
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/rc.local",
    "/etc/environment",
)
DIRS = (
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/profile.d",
    "/etc/sudoers.d",
    "/etc/ssh/sshd_config.d",
    "/etc/apt/apt.conf.d",
)
UNIT_DIRS = ("/etc/systemd/system", "/etc/systemd/user", "/usr/local/lib/systemd/system")
ABSENT = {
    "/etc/ld.so.preload",
    "/etc/rc.local",
    "/etc/systemd/user",
    "/usr/local/lib/systemd/system",
    "/etc/ssh/sshd_config.d",
}
H = "0123456789abcdef0123456789abcdef  x\n"


def table():
    t = {}

    def ok(cmd, out=""):
        t[cmd] = (0, out, "")

    ok("systemctl list-units --type=service --state=running --no-legend --plain", SERVICE_UNIT + "\n")
    ok("systemctl list-unit-files --state=enabled --no-legend --plain", "ssh.service enabled enabled\n")
    ok("systemctl list-timers --all --no-legend --plain", TIMERS)
    ok(
        "sudo ss -tulnpH",
        'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n'
        'udp UNCONN 0 0 127.0.0.53:53 0.0.0.0:* users:(("systemd-resolve",pid=2,fd=4))\n',
    )
    ok("sudo docker ps --format '{{.Names}}|{{.Image}}|{{.Ports}}'", "web|nginx:1|0.0.0.0:8080->80/tcp\n")
    ok("sudo test -s /root/.ssh/authorized_keys")
    t["sudo test -s /home/ops/.ssh/authorized_keys"] = (1, "", "")
    ok("sudo ssh-keygen -lf /root/.ssh/authorized_keys", "256 SHA256:abc root@box (ED25519)\n")
    ok("sudo sha256sum /etc/sudoers", H)
    ok("sudo ls /etc/sudoers.d", "README ops\n")
    for f in ("README", "ops"):
        ok("sudo sha256sum /etc/sudoers.d/" + f, H)
    ok("sudo cat /etc/apache2/conf-enabled/alias.conf", "Alias /acme /var/www/acme\n")
    ok("sudo sha256sum /etc/apache2/conf-enabled/alias.conf", H)
    ok(
        "sudo cat /etc/apache2/sites-enabled/a.conf",
        "<VirtualHost *:443>\nServerName a.example\nDocumentRoot /srv/a\nSSLEngine on\n</VirtualHost>\n",
    )
    ok("sudo test -d /var/spool/cron/crontabs")
    ok("sudo ls /var/spool/cron/crontabs", "ops\nroot\n")
    ok("sudo crontab -u root -l", "# comment\n0 * * * * /bin/true\n")
    t["sudo crontab -u ops -l"] = (1, "", "no crontab for ops")
    t["sudo crontab -u daemon -l"] = (1, "", "no crontab for daemon")
    ok("dpkg-query -W -f='${db:Status-Abbrev} ${Package}=${Version}\\n'", "ii  bash=5.2\nrc  old=1.0\nii  zlib1g=1.3\n")
    ok("sudo certbot certificates", CERTS)
    ok("sudo find /usr /bin /sbin /opt -xdev -perm -4000 -type f", "/usr/bin/sudo\n/usr/bin/passwd\n")
    for d in UNIT_DIRS + DIRS:
        t["sudo test -d " + d] = (1, "", "") if d in ABSENT else (0, "", "")
    for f in SINGLE:
        t["sudo test -e " + f] = (1, "", "") if f in ABSENT else (0, "", "")
    for d, names in UNITS.items():
        # old form: the shell filtered by suffix; new form: the whole listing, filtered in Python
        ok(
            "sudo find %s -maxdepth 2 -type f \\( -name '*.service' -o -name '*.timer' -o -name '*.socket' "
            "-o -name '*.path' \\)" % d,
            "\n".join(d + "/" + n for n in names) + "\n",
        )
        ok("sudo find %s -maxdepth 2 -type f" % d, "\n".join(d + "/" + n for n in names + ["notes.txt"]) + "\n")
        for n in names:
            ok("sudo sha256sum %s/%s" % (d, n), H)
    for f in SINGLE:
        if f not in ABSENT:
            ok("sudo sha256sum " + f, H)
    for d in DIRS:
        ok("sudo ls -1 " + d, "one\ntwo\n")
    for kf in ("/etc/ssh/ssh_host_ed25519_key.pub", "/etc/ssh/ssh_host_rsa_key.pub"):
        ok("sudo test -e " + kf)
        ok("sudo ssh-keygen -lf " + kf, "256 SHA256:hostkey%s host (X)\n" % kf[-12:-4])
    ok(
        "sudo journalctl -u apt-daily.service --since -14d -o short-iso --no-pager",
        "2026-10-28T03:00:00+0000 h systemd[1]: Finished apt-daily.service.\n",
    )
    ok("sudo journalctl -u certbot.service --since -14d -o short-iso --no-pager", JOURNAL)
    ok("sudo journalctl -u certbot.service --since -7d --no-pager", JOURNAL)
    ok("uname -r", "6.12.0\n")
    ok("hostname -I", "192.0.2.10 2001:db8::1 \n")
    ok("uptime -p", "up 3 days, 2 hours\n")
    # old shell lines and the new argv-style commands
    ok(". /etc/os-release && echo $PRETTY_NAME", "Debian GNU/Linux 13 (trixie)\n")
    ok("df -h / | tail -1", "/dev/sda1        40G   20G   18G  53% /\n")
    ok("df -h /", DF)
    ok("free -m | awk 'NR==2{print $7}'", "2700\n")
    ok("free -m", FREE)
    ok("cut -d' ' -f1-3 /proc/loadavg", "0.10 0.20 0.30\n")
    ok("sudo fail2ban-client status sshd 2>/dev/null | grep -oP 'Currently banned:\\s+\\K\\d+'", "3\n")
    ok("sudo fail2ban-client status sshd", FAIL2BAN)
    ok("systemctl --failed --no-legend --plain | wc -l", "1\n")
    ok("systemctl --failed --no-legend --plain", "foo.service loaded failed failed Foo\n")
    return t


def stubs():
    t = table()
    unmatched = []

    def run_checked(cmd, timeout=25):
        if cmd in t:
            rc, out, err = t[cmd]
            return rc, out.strip(), err
        unmatched.append(cmd)
        return 127, "", "no stub for: " + cmd

    def run(cmd, timeout=25):
        rc, out, _ = run_checked(cmd, timeout)
        return out if rc == 0 else None

    return run, run_checked, unmatched


def fake_open(path, *a, **kw):
    served = {"/etc/passwd": PASSWD, "/etc/os-release": OS_RELEASE, "/proc/loadavg": LOADAVG}
    if str(path) in served:
        return io.StringIO(served[str(path)])
    return builtins.open(path, *a, **kw)


def snapshot_now():
    state = Path(tempfile.mkdtemp(prefix="atlas-golden-"))
    apt = state / "apt"
    (apt / "sources.list.d").mkdir(parents=True)
    (apt / "sources.list").write_text("deb x\n")
    (apt / "sources.list.d" / "x.list").write_text("deb y\n")
    env = {"SENTINEL_ATLAS": str(state), "SENTINEL_LANG": "en"}
    with mock.patch.dict(os.environ, env):
        spec = importlib.util.spec_from_file_location("atlas_golden", ATLAS / "atlas.py")
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
    run, run_checked, unmatched = stubs()
    listing = {
        "/etc/apache2/conf-enabled": ["alias.conf"],
        "/etc/apache2/sites-enabled": ["a.conf"],
        "/etc/cron.d": ["job"],
        m.APT_DIR: ["x.list"],
    }
    m.APT_LIST = str(apt / "sources.list")
    m.APT_DIR = str(apt / "sources.list.d")
    listing[m.APT_DIR] = ["x.list"]
    m.run, m.run_checked = run, run_checked
    m.have = lambda tool: tool != "ufw"
    m.local_isdir = lambda path, section="local_files", *a, **kw: True
    m.local_listdir = lambda path, section="local_files", *a, **kw: list(listing.get(path, []))
    m.sha = lambda path, section="local_files", *a, **kw: "sha:" + os.path.basename(path)
    m.open = fake_open
    m.MEAS_ERRORS.clear()
    snap = m.snapshot()
    snap.pop("generated_at")
    return json.loads(json.dumps(snap).replace(str(apt), "/APT")), unmatched


def dump(snap):
    return json.dumps(snap, indent=1, ensure_ascii=False, sort_keys=True) + "\n"


class SnapshotGolden(unittest.TestCase):
    def test_every_command_is_answered(self):
        snap, unmatched = snapshot_now()
        self.assertEqual(unmatched, [])
        self.assertEqual(snap["vitals"]["measure_errors"], {})

    def test_snapshot_equals_golden(self):
        snap, _ = snapshot_now()
        self.assertEqual(dump(snap), GOLDEN.read_text())


if __name__ == "__main__":
    if "--write" in sys.argv:
        GOLDEN.write_text(dump(snapshot_now()[0]))
        print("wrote", GOLDEN)
    else:
        unittest.main()
