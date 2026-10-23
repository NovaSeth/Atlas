#!/usr/bin/env python3
"""Message catalogs (en default, pl optional) and the one config file sentinel.env:
the catalogs agree on keys and placeholders, bash and Python fill templates the same way, the env
file never executes code and the environment always wins, and a patrol run speaks the configured
language. Temp dirs only."""
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
ATLAS = ROOT / "atlas"
sys.path.insert(0, str(ATLAS))
sys.path.insert(0, str(ATLAS / "tests"))
import envfile  # noqa: E402
import i18n  # noqa: E402
from test_iteration1 import make_patrol, patrol  # noqa: E402

PH = re.compile(r"\{([a-z_]+)\}")


def catalog(lang):
    return {k: v for k, v in json.loads((ROOT / "i18n" / ("%s.json" % lang)).read_text()).items()
            if not k.startswith("_")}


def bash(script, env=None):
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run(["bash", "-c", '. "%s/lib.sh"; %s' % (ATLAS, script)], env=e,
                          capture_output=True, text=True, timeout=30)


class Catalogs(unittest.TestCase):
    def test_same_keys_and_placeholders(self):
        en, pl = catalog("en"), catalog("pl")
        self.assertEqual(set(en), set(pl))
        for k in en:
            self.assertEqual(set(PH.findall(en[k])), set(PH.findall(pl[k])), k)

    def test_python_fallbacks(self):
        with mock.patch.dict(os.environ, {"SENTINEL_LANG": "xx"}):
            self.assertEqual(i18n.t("jobs.no_log", name="a", file="b"), "a: log file missing (b)")
        with mock.patch.dict(os.environ, {"SENTINEL_LANG": "pl"}):
            self.assertEqual(i18n.t("jobs.no_log", name="a", file="b"), "a: brak pliku logu (b)")
            self.assertEqual(i18n.t("no.such.key"), "no.such.key")   # a gap is visible, never silent

    def test_bash_and_python_fill_the_same_way(self):
        value = "a&b \\ /x/ {other}"
        for lang in ("en", "pl"):
            r = bash('t esc.revive unit="$V"; echo; t jobs.no_log name=n file="$V"',
                     {"SENTINEL_LANG": lang, "V": value})
            with mock.patch.dict(os.environ, {"SENTINEL_LANG": lang}):
                want = i18n.t("esc.revive", unit=value) + "\n" + i18n.t("jobs.no_log", name="n", file=value)
            self.assertEqual(r.stdout, want, (lang, r.stderr))

    def test_cli(self):
        r = subprocess.run([sys.executable, str(ATLAS / "i18n.py"), "atlas.disk_alarm", "pct=95", "limit=90"],
                           env=dict(os.environ, SENTINEL_LANG="pl"), capture_output=True, text=True)
        self.assertEqual(r.stdout, "dysk /: 95% zajete (prog 90%)")


class EnvFile(unittest.TestCase):
    TEXT = ('# comment\n\nSENTINEL_EMAIL=ops@example.com\nexport SENTINEL_LANG="pl"\n'
            "QUOTED='a b'\nEVIL=$(touch {canary})\nnot a line\nATLAS_DISK_PCT=50\n")

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="envfile-"))
        self.addCleanup(shutil.rmtree, self.d, True)
        self.canary = self.d / "canary"
        (self.d / "sentinel.env").write_text(self.TEXT.replace("{canary}", str(self.canary)))

    def test_python_parse_and_precedence(self):
        env = {"SENTINEL_LANG": "en"}
        applied = envfile.load(self.d, env)
        self.assertEqual(env["SENTINEL_EMAIL"], "ops@example.com")
        self.assertEqual(env["SENTINEL_LANG"], "en")           # the environment wins
        self.assertNotIn("SENTINEL_LANG", applied)
        self.assertEqual(env["QUOTED"], "a b")
        self.assertEqual(env["EVIL"], "$(touch %s)" % self.canary)   # literal text, never run
        self.assertFalse(self.canary.exists())

    def test_bash_parse_and_precedence(self):
        r = bash('atlas_load_env "%s"; printf "%%s|%%s|%%s|%%s" "$SENTINEL_EMAIL" "$SENTINEL_LANG" "$QUOTED" "$EVIL"' % self.d,
                 {"SENTINEL_LANG": "en"})
        self.assertEqual(r.stdout, "ops@example.com|en|a b|$(touch %s)" % self.canary, r.stderr)
        self.assertFalse(self.canary.exists())

    def test_missing_file_is_fine(self):
        self.assertEqual(envfile.load(self.d / "nowhere", {}), {})
        self.assertEqual(bash('atlas_load_env "%s/nowhere"; echo ok' % self.d).stdout, "ok\n")

    def test_atlas_thresholds_from_env_file(self):
        def load(env):
            with mock.patch.dict(os.environ, env, clear=False):
                for k in ("ATLAS_DISK_PCT", "SENTINEL_LANG"):
                    if k not in env:
                        os.environ.pop(k, None)
                spec = importlib.util.spec_from_file_location("atlas_env_t", str(ATLAS / "atlas.py"))
                m = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(m)
                return m.THRESHOLD_DISK_PCT, m.THRESHOLD_RAM_MB
        self.assertEqual(load({"SENTINEL_ATLAS": str(self.d)}), (50, 250))
        self.assertEqual(load({"SENTINEL_ATLAS": str(self.d), "ATLAS_DISK_PCT": "70"}), (70, 250))


class PatrolLanguage(unittest.TestCase):
    """Gate: a patrol run with SENTINEL_LANG=pl writes Polish ALERT text, with en English."""

    def setUp(self):
        self.d = make_patrol()
        self.addCleanup(shutil.rmtree, self.d, True)

    def alert(self, **env):
        patrol(self.d, STUB_THRESHOLDS_RC=3, STUB_THRESHOLDS_ERR="boom", STUB_SILENT_SLEEP=5,
               PATROL_T_SILENT=1, PATROL_NICE=1, **env)
        return (self.d / "ALERT").read_text()

    def test_polish(self):
        txt = self.alert(SENTINEL_LANG="pl")
        self.assertIn("UNKNOWN: thresholds — kod 3 boom", txt)
        self.assertIn("UNKNOWN: silent-failures — przekroczony limit 1 s", txt)

    def test_english(self):
        txt = self.alert(SENTINEL_LANG="en")
        self.assertIn("UNKNOWN: thresholds — exit code 3 boom", txt)
        self.assertIn("UNKNOWN: silent-failures — time limit of 1 s exceeded", txt)

    def test_language_from_the_state_dirs_env_file(self):
        (self.d / "sentinel.env").write_text("SENTINEL_LANG=pl\n")   # state = code dir when unset
        env = dict(os.environ)
        env.pop("SENTINEL_LANG", None)
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertIn("przekroczony limit", self.alert())


if __name__ == "__main__":
    unittest.main()
