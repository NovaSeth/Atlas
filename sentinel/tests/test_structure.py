"""Structure rules for sentinel/ (audit 17, 20): functions <= 50 lines, limits of untrusted text and timeouts are
named constants."""
import ast
import re
import unittest

from helpers import SENTINEL

FILES = sorted(SENTINEL.glob("*.py"))


class Structure(unittest.TestCase):
    def test_functions_are_short(self):
        long_ = []
        for p in FILES:
            for n in ast.walk(ast.parse(p.read_text())):
                if isinstance(n, ast.FunctionDef) and n.end_lineno - n.lineno + 1 > 50:
                    long_.append("%s:%d %s" % (p.name, n.lineno, n.name))
        self.assertEqual(long_, [])

    def test_text_limits_are_named(self):
        src = (SENTINEL / "stream.py").read_text()
        self.assertIsNone(re.search(r"\b(clean|quote)\([^()]*,\s*\d+\)", src))
        self.assertIsNone(re.search(r"\[:\d+\]", src))

    def test_timeouts_are_named(self):
        for name in ("router.py", "stream.py", "bus.py", "notify.py", "digest.py"):
            path = SENTINEL / name
            if path.exists():
                self.assertIsNone(re.search(r"timeout=\d", path.read_text()), name)
