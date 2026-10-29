#!/usr/bin/env python3
"""current.json / baseline.json that are not a JSON object end in an explicit error, exit 2 (GC5)."""

import contextlib
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ATLAS = Path(__file__).resolve().parent.parent
BAD = {"null": "null", "list": "[1, 2]", "truncated": '{"vitals": {'}


def load(tmp):
    with mock.patch.dict(os.environ, {"SENTINEL_ATLAS": str(tmp), "SENTINEL_LANG": "en"}):
        spec = importlib.util.spec_from_file_location("atlas_validated", ATLAS / "atlas.py")
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
    return m


class StateFilesValidated(unittest.TestCase):
    def run_cmd(self, m, cmd):
        err = io.StringIO()
        with (
            mock.patch.object(sys, "argv", ["atlas.py", cmd]),
            contextlib.redirect_stderr(err),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            rc = m.main()
        return rc, err.getvalue()

    def test_bad_current_json(self):
        for name, text in BAD.items():
            for cmd in ("silent", "thresholds", "bless"):
                tmp = Path(tempfile.mkdtemp(prefix="validated-"))
                (tmp / "current.json").write_text(text)
                rc, err = self.run_cmd(load(tmp), cmd)
                self.assertEqual(rc, 2, (name, cmd))
                self.assertTrue(err.strip(), (name, cmd))

    def test_bad_baseline_in_check(self):
        for name, text in BAD.items():
            tmp = Path(tempfile.mkdtemp(prefix="validated-"))
            (tmp / "baseline.json").write_text(text)
            m = load(tmp)
            snap = {"generated_at": "2026-10-29T10:00:00+00:00", "vitals": {"measure_errors": {}}}
            with mock.patch.object(m, "snapshot", return_value=snap):
                rc, err = self.run_cmd(m, "check")
            self.assertEqual(rc, 2, name)
            self.assertTrue(err.strip(), name)

    def test_every_handler_returns_an_int(self):
        tmp = Path(tempfile.mkdtemp(prefix="validated-"))
        m = load(tmp)
        (tmp / "current.json").write_text("null")
        for cmd in ("silent", "thresholds", "bless", "ack"):
            rc, _ = self.run_cmd(m, cmd)
            self.assertIsInstance(rc, int, cmd)


if __name__ == "__main__":
    unittest.main()
