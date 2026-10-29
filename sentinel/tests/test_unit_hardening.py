"""Unit hardening (audit 10) without breaking mail. Measured on Debian 13 (2026-10-29, systemd-run as a normal
user, `sendmail -odq`): NoNewPrivileges=yes, an empty CapabilityBoundingSet= and ProtectSystem=strict each made a
setuid MTA (exim) fail; ProtectSystem=full + ProtectHome=read-only + PrivateTmp + ProtectControlGroups kept it working."""
import re
import shutil
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

from helpers import SENTINEL

UNITS = SENTINEL / "units"
BASE_KEYS = {"Type", "User", "Environment", "EnvironmentFile", "ExecStart", "TimeoutStartSec", "MemoryMax", "Nice"}
ESC_HARDENING = {"ProtectSystem=full", "ProtectHome=read-only", "ReadWritePaths=@ATLAS_STATE@", "PrivateTmp=yes",
                 "ProtectControlGroups=yes", "UMask=0027"}
STREAM_REQUIRED = ["NoNewPrivileges=yes", "ProtectSystem=strict", "ReadWritePaths=@ATLAS_STATE@", "ProtectHome=read-only",
                   "PrivateTmp=yes", "CapabilityBoundingSet=", "SystemCallFilter=@system-service",
                   "SystemCallArchitectures=native", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
                   "ProtectKernelTunables=yes", "ProtectKernelModules=yes", "ProtectKernelLogs=yes",
                   "ProtectControlGroups=yes", "ProtectClock=yes", "ProtectHostname=yes", "RestrictNamespaces=yes",
                   "RestrictRealtime=yes", "RestrictSUIDSGID=yes", "LockPersonality=yes", "MemoryDenyWriteExecute=yes",
                   "PrivateDevices=yes", "UMask=0027"]


def service_lines(name):
    text = (UNITS / name).read_text()
    body = text.split("[Service]", 1)[1].split("\n[", 1)[0]
    return [l.strip() for l in body.splitlines() if l.strip() and not l.strip().startswith("#")]


def render(name, d):
    t = (UNITS / name).read_text().replace("@ATLAS_CODE@", "/opt/atlas").replace("@ATLAS_STATE@", "/var/lib/atlas")
    p = d / name
    p.write_text(t.replace("@ATLAS_USER@", "atlas"))
    return p


def exposure(path):
    r = subprocess.run(["systemd-analyze", "security", "--offline=true", "--no-pager", str(path)],
                       capture_output=True, text=True, cwd=str(path.parent))
    m = re.search(r"Overall exposure level for \S+: ([0-9.]+)", r.stdout + r.stderr)
    return float(m.group(1)) if m else None


class Hardening(unittest.TestCase):
    def test_stream_has_the_full_set(self):
        lines = service_lines("sentinel-stream.service")
        for want in STREAM_REQUIRED:
            self.assertIn(want, lines)
        self.assertNotIn("ProtectSystem=full", lines)

    def test_escalation_has_no_option_that_breaks_setuid_mail(self):
        lines = service_lines("sentinel-escalation.service")
        extra = {l for l in lines if l.split("=", 1)[0] not in BASE_KEYS}
        self.assertEqual(extra, ESC_HARDENING)

    def test_verify_script_prints_commands_without_root(self):
        r = subprocess.run(["bash", str(UNITS / "verify-hardening.sh"), "--code", "/opt/atlas", "--state",
                            "/var/lib/atlas", "--user", "atlas", "--print"], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        esc = [l for l in r.stdout.splitlines() if "escalation" in l and "systemd-run" in l]
        self.assertTrue(esc)
        self.assertFalse([l for l in esc if "NoNewPrivileges" in l])

    def test_printed_probes_use_the_unit_properties_and_queue_mail(self):
        r = subprocess.run(["bash", str(UNITS / "verify-hardening.sh"), "--code", "/opt/atlas", "--state",
                            "/var/lib/atlas", "--user", "atlas", "--mail-to", "ops", "--print"],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        commands = [shlex.split(line) for line in r.stdout.splitlines() if line.startswith("systemd-run ")]
        self.assertEqual(len(commands), 3)
        for command, expected in zip(commands, (set(STREAM_REQUIRED), ESC_HARDENING, ESC_HARDENING)):
            props = {command[i + 1] for i, arg in enumerate(command) if arg == "-p"}
            self.assertEqual(props, {p.replace("@ATLAS_STATE@", "/var/lib/atlas") for p in expected} | {"User=atlas"})
        self.assertIn("journalctl -n 1 -q --no-pager", commands[0][-3])
        self.assertNotIn("journalctl", commands[1][-3])
        self.assertIn("sendmail -v -odq", commands[2][-3])
        self.assertEqual(commands[2][-1], "ops")

    def test_invalid_arguments_fail_before_printing_actions(self):
        base = ["bash", str(UNITS / "verify-hardening.sh")]
        for args in (["--code"], ["--unknown"],
                     ["--code", "/opt/%n", "--state", "/var/lib/atlas", "--user", "atlas"],
                     ["--code", "/opt/atlas", "--state", "/var/lib/atlas", "--user", "-root"],
                     ["--code", "/opt/atlas", "--state", "/var/lib/atlas", "--user", "atlas", "--mail-to", "-q"]):
            with self.subTest(args=args):
                r = subprocess.run(base + args + ["--print"], capture_output=True, text=True, timeout=60)
                self.assertEqual(r.returncode, 2)
                self.assertEqual(r.stdout, "")

    @unittest.skipUnless(shutil.which("systemd-analyze"), "systemd-analyze not installed")
    def test_exposure_scores(self):
        d = Path(tempfile.mkdtemp(prefix="units-"))
        self.addCleanup(shutil.rmtree, d, True)
        s, e = exposure(render("sentinel-stream.service", d)), exposure(render("sentinel-escalation.service", d))
        if s is None or e is None:
            self.skipTest("systemd-analyze --offline not supported here")
        self.assertLessEqual(s, 2.5)
        self.assertLessEqual(e, 8.6)
