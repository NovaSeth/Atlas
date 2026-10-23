"""Load the instance configuration file $SENTINEL_ATLAS/sentinel.env (stdlib only).

The file holds KEY=VALUE lines (blank lines and # comments allowed, optional `export ` prefix and one
pair of surrounding quotes; no shell code is ever executed). A variable that is already set in the
environment wins, so cron needs only SENTINEL_ATLAS and systemd's EnvironmentFile= gives the same result.
SENTINEL_ATLAS itself selects where the file is, so setting it inside the file has no effect.
"""
import os
import re
from pathlib import Path

CODE_DIR = Path(__file__).resolve().parent
_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$")


def state_dir():
    """The state directory: SENTINEL_ATLAS, or next to the code (atlas/) when unset."""
    return Path(os.environ.get("SENTINEL_ATLAS") or CODE_DIR)


def parse(text):
    out = {}
    for line in text.splitlines():
        line = line.rstrip("\r")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = _LINE.match(line)
        if not m:
            continue
        k, v = m.group(1), m.group(2)
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        out[k] = v
    return out


def load(directory=None, environ=None):
    """Apply <directory>/sentinel.env to environ (default os.environ) without overriding set keys.
    Returns the dict of keys that were applied."""
    environ = os.environ if environ is None else environ
    path = Path(directory) if directory else state_dir()
    try:
        values = parse((path / "sentinel.env").read_text())
    except OSError:
        return {}
    applied = {}
    for k, v in values.items():
        if k not in environ:
            environ[k] = v
            applied[k] = v
    return applied
