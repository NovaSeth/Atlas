#!/usr/bin/env python3
"""install.sh / uninstall.sh: --dry-run plans every action and changes nothing; templates render
completely; the rendered sudoers drop-in parses. No root, no system change."""
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / "install.sh"
UNINSTALL = ROOT / "uninstall.sh"


def visudo():
    for p in ("/usr/sbin/visudo", "/sbin/visudo", shutil.which("visudo") or ""):
        if p and os.path.exists(p):
            return p
    return None


class InstallDryRun(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="atlas-install-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.state = self.tmp / "state"

    def run_install(self, *args, user="atlas-test-nobody"):
        r = subprocess.run(["bash", str(INSTALL), "--dry-run", "--code", "/opt/atlas", "--state", str(self.state),
                            "--user", user, *args], capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return r.stdout

    def planned(self, out):
        return [l[len("[dry-run] "):] for l in out.splitlines() if l.startswith("[dry-run] ")]

    def test_plans_every_step_and_changes_nothing(self):
        out = self.run_install()
        plan = "\n".join(self.planned(out))
        self.assertFalse(self.state.exists(), "a dry run created the state directory")
        self.assertIn("useradd --system", plan)                                   # user created when missing
        self.assertIn("cp -a %s/atlas" % ROOT, plan)                              # code copied to /opt/atlas
        self.assertIn("install -d -m 0750 -o atlas-test-nobody", plan)
        self.assertIn("%s/examples/sentinel.env %s/sentinel.env" % (ROOT, self.state), plan)
        for u in ("sentinel-stream.service", "sentinel-escalation.service", "sentinel-escalation.timer"):
            self.assertRegex(plan, r"install -m 0644 \S+/%s /etc/systemd/system/%s" % (re.escape(u), re.escape(u)))
        self.assertIn("systemctl daemon-reload", plan)
        self.assertIn("systemctl enable --now sentinel-stream.service sentinel-escalation.timer", plan)
        self.assertRegex(plan, r"install -m 0440 -o root -g root \S+ /etc/sudoers\.d/atlas")
        self.assertIn("atlas.py snap", plan)
        self.assertIn("atlas.py bless", plan)
        self.assertNotIn("a2enconf", plan)                                        # Apache only on request
        self.assertNotIn("crontab -u", plan)                                      # cron only on request
        self.assertIn("SENTINEL_ATLAS=%s /opt/atlas/atlas/patrol.sh" % self.state, out)   # crontab printed
        self.assertNotIn("@ATLAS_", out)

    def test_existing_config_is_never_overwritten(self):
        self.state.mkdir()
        (self.state / "sentinel.env").write_text("SENTINEL_EMAIL=ops@example.com\n")
        out = self.run_install()
        self.assertIn("keeping existing %s/sentinel.env" % self.state, out)
        self.assertNotIn("examples/sentinel.env", "\n".join(self.planned(out)))
        self.assertNotIn("NEXT: set SENTINEL_EMAIL", out)

    def test_optional_apache_and_cron(self):
        plan = "\n".join(self.planned(self.run_install("--with-apache", "--install-cron", "--yes")))
        self.assertIn("/etc/apache2/conf-available/sentinel-sensitive.conf", plan)
        self.assertIn("a2enconf -q sentinel-sensitive", plan)
        self.assertIn("apache2ctl configtest", plan)
        self.assertIn("crontab -u atlas-test-nobody -", plan)

    def test_unknown_option_and_relative_paths_are_refused(self):
        r = subprocess.run(["bash", str(INSTALL), "--dry-run", "--bogus"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        r = subprocess.run(["bash", str(INSTALL), "--dry-run", "--state", "relative/dir"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)

    def test_reinstall_never_blesses_over_an_existing_baseline(self):
        # seen on the test VM: a second `install.sh --yes` silently accepted the current state (with
        # any drift, an intruder's account included) as the new baseline
        self.state.mkdir()
        (self.state / "baseline.json").write_text("{}")
        out = self.run_install("--yes")
        plan = "\n".join(self.planned(out))
        self.assertIn("atlas.py snap", plan)
        self.assertNotIn("atlas.py bless", plan)
        self.assertIn("keeping the existing baseline", out)
        self.assertIn("atlas.py check", out)

    def test_uninstall_dry_run(self):
        r = subprocess.run(["bash", str(UNINSTALL), "--dry-run", "--state", str(self.state), "--user", "atlas-test-nobody"],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        plan = r.stdout
        self.assertIn("systemctl disable --now sentinel-stream.service", plan)
        self.assertIn("rm -f /etc/systemd/system/sentinel-escalation.timer", plan)
        self.assertIn("rm -f /etc/sudoers.d/atlas", plan)
        self.assertIn("a2disconf -q sentinel-sensitive", plan)
        self.assertNotIn("rm -rf", plan)                                          # state kept without --purge
        # seen on the test VM: the removed escalation unit stayed in `systemctl --failed` (not-found failed)
        self.assertIn("systemctl reset-failed sentinel-stream.service sentinel-escalation.service", plan)
        r = subprocess.run(["bash", str(UNINSTALL), "--dry-run", "--purge", "--state", str(self.state)],
                           capture_output=True, text=True, timeout=60)
        self.assertIn("rm -rf --one-file-system %s" % self.state, r.stdout)


class Templates(unittest.TestCase):
    def render(self, path, code="/opt/atlas", state="/var/lib/atlas", user="atlas"):
        return (Path(path).read_text().replace("@ATLAS_CODE@", code).replace("@ATLAS_STATE@", state)
                .replace("@ATLAS_USER@", user))

    def test_every_template_renders_completely(self):
        for p in list((ROOT / "sentinel" / "units").iterdir()) + [ROOT / "examples" / "sudoers.d" / "atlas"]:
            self.assertNotIn("@ATLAS_", self.render(p), p.name)

    @unittest.skipUnless(visudo(), "visudo not installed")
    def test_rendered_sudoers_parses(self):
        tmp = Path(tempfile.mkdtemp(prefix="sudoers-test-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        f = tmp / "atlas"
        f.write_text(self.render(ROOT / "examples" / "sudoers.d" / "atlas"))
        r = subprocess.run([visudo(), "-cf", str(f)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_sudoers_has_no_open_wildcard_and_no_write_command(self):
        text = (ROOT / "examples" / "sudoers.d" / "atlas").read_text()
        rules = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
        self.assertNotRegex(rules, r"/\*")              # no "dir/*": it would match ../ and extra arguments
        self.assertNotIn("ALL=(ALL)", rules)
        for bad in ("/usr/bin/tee", "/usr/bin/rm", "/usr/bin/cp", "/usr/bin/bash", "/usr/bin/sh ", "-exec", "-delete"):
            self.assertNotIn(bad, rules)


if __name__ == "__main__":
    unittest.main()
