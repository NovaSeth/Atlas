"""Shared test helpers. Everything runs on temp dirs through env overrides."""
import json
import shutil
import stat
import sys
import tempfile
import time
from pathlib import Path

SENTINEL = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SENTINEL))


def make_event(**over):
    ev = {
        "sensor": "test.sensor",
        "severity": "alert",
        "confidence": "measured",
        "what": "something happened",
        "fingerprint": "test.sensor:one",
    }
    ev.update(over)
    return ev


def tmpdir(testcase):
    d = Path(tempfile.mkdtemp(prefix="sentinel-test-"))
    testcase.addCleanup(shutil.rmtree, str(d), True)
    return d


def stub_notify(d):
    """A notify-command stub (SENTINEL_NOTIFY_CMD) that appends its argv to <d>/notify.calls."""
    p = d / "notify-stub"
    p.write_text('#!/bin/sh\necho "$@" >> "%s/notify.calls"\n' % d)
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return p


def notify_calls(d):
    f = d / "notify.calls"
    return f.read_text().splitlines() if f.exists() else []


def wait_for(pred, timeout=10.0, step=0.1):
    end = time.time() + timeout
    while time.time() < end:
        r = pred()
        if r:
            return r
        time.sleep(step)
    return pred()


def read_bus(path):
    p = Path(path)
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text().splitlines() if line.strip()]
