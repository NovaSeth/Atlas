#!/usr/bin/env python3
"""Message catalog for every human-facing string (stdlib only).

Catalogs live in i18n/<lang>.json at the repository root: {"key": "template with {placeholders}"}.
The language comes from SENTINEL_LANG (default en). A key missing from the chosen catalog falls back
to English, and a key missing everywhere prints as the key itself, so a gap is visible, never silent.

    t("thresholds.disk", pct=95, limit=90)          from Python
    i18n.py <key> name=value ...                    from a shell (one message)
    i18n.py --dump                                  key NUL value NUL ... (bash loads the catalog once)
"""

import json
import os
import sys
from pathlib import Path

CATALOG_DIR = Path(os.environ.get("ATLAS_I18N_DIR") or Path(__file__).resolve().parent.parent / "i18n")
DEFAULT_LANG = "en"
_cache = {}


def _load(lang):
    if lang not in _cache:
        try:
            data = json.loads((CATALOG_DIR / ("%s.json" % lang)).read_text(encoding="utf-8"))
            _cache[lang] = {k: v for k, v in data.items() if not k.startswith("_")}
        except (OSError, ValueError):
            _cache[lang] = {}
    return _cache[lang]


def lang():
    return (os.environ.get("SENTINEL_LANG") or DEFAULT_LANG).strip().lower() or DEFAULT_LANG


def catalog(language=None):
    merged = dict(_load(DEFAULT_LANG))
    merged.update(_load(language or lang()))
    return merged


def fill(template, values):
    """Replace {name} for each given name; other braces stay as they are (same rule as lib.sh)."""
    for k, v in values.items():
        template = template.replace("{%s}" % k, str(v))
    return template


def t(key, **values):
    return fill(catalog().get(key, key), values)


def main(argv):
    if argv[:1] == ["--dump"]:
        out = sys.stdout.buffer
        for k, v in sorted(catalog().items()):
            out.write(k.encode() + b"\0" + v.encode("utf-8") + b"\0")
        return 0
    if not argv:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    values = dict(a.split("=", 1) for a in argv[1:] if "=" in a)
    sys.stdout.write(t(argv[0], **values))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
