"""Static checks of the deploy artifacts (unit template and Apache fragment)."""
import re
import unittest

from helpers import SENTINEL

UNIT = SENTINEL / "units" / "sentinel-stream.service"
CONF = SENTINEL / "apache" / "sentinel-sensitive.conf"


class UnitTests(unittest.TestCase):
    def setUp(self):
        self.text = UNIT.read_text()

    def test_required_directives(self):
        for line in ("User=@ATLAS_USER@", "Restart=always", "WatchdogSec=120", "MemoryMax=80M",
                     "CPUQuota=10%", "Nice=10", "Type=notify", "NotifyAccess=main"):
            self.assertRegex(self.text, r"(?m)^%s\s*$" % re.escape(line))
        self.assertRegex(self.text, r"(?m)^ExecStart=\S*python3 \S*sentinel/stream\.py\s*$")


    def test_every_unit_uses_only_known_placeholders(self):
        for unit in sorted((SENTINEL / "units").iterdir()):
            text = unit.read_text()
            self.assertNotIn("/home/", text, unit.name)
            self.assertEqual(set(re.findall(r"@[A-Z_]+@", text)) - {"@ATLAS_CODE@", "@ATLAS_STATE@", "@ATLAS_USER@"},
                             set(), unit.name)


class TimerTests(unittest.TestCase):
    def test_escalation_timer_runs_on_utc(self):
        # In local time the autumn DST change skips the repeated hour: the escalation was ~70 min blind.
        text = (SENTINEL / "units" / "sentinel-escalation.timer").read_text()
        cal = re.findall(r"(?m)^OnCalendar=(.*)$", text)
        self.assertEqual(len(cal), 1, cal)
        self.assertRegex(cal[0].strip(), r"\sUTC$")
        self.assertIn("/10", cal[0])
        self.assertRegex(text, r"(?m)^Persistent=true\s*$")


class ApacheTests(unittest.TestCase):
    def setUp(self):
        self.text = CONF.read_text()

    def test_customlog_format_and_condition(self):
        self.assertIn('GlobalLog ${APACHE_LOG_DIR}/sentinel-sensitive.log '
                      '"%{%Y-%m-%dT%H:%M:%S}t %v %a %>s %B \\"%r\\"" env=sentinel_sensitive', self.text)

    def test_uses_globallog_not_customlog(self):
        # server-level CustomLog is not inherited by vhosts that define their own CustomLog
        directives = [l for l in self.text.splitlines() if not l.lstrip().startswith("#")]
        self.assertTrue(any(l.startswith("GlobalLog ") for l in directives))
        self.assertFalse(any(l.lstrip().startswith("CustomLog") for l in directives))

    def test_paths_covered(self):
        for frag in ("wp-config", "/\\.env", "/\\.git/", "dump", "\\.sql\\.gz", "phpinfo", "server-status"):
            self.assertRegex(self.text, r"(?im)^SetEnvIfNoCase Request_URI .*" + re.escape(frag) + r".* sentinel_sensitive=1")

    def test_uses_bytes_without_headers(self):
        # %B (body only) not %O: %O includes TLS/headers overhead (an empty 200 once looked like a leak)
        self.assertIn("%B", self.text)
        log = [l for l in self.text.splitlines() if l.startswith("GlobalLog")][0]
        self.assertNotIn("%O", log)


if __name__ == "__main__":
    unittest.main()
