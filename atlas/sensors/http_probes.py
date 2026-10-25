#!/usr/bin/env python3
"""Sensor: HTTP probes of every enabled vhost, plus optional extra URLs.

Exit contract: 0 = every probe matched, 1 = event (mismatch / host without an expectation,
one line each on stdout), 2 = cannot judge (fetch error, unreadable config, extra-URL lookup
failed; stderr says why). A fetch error is UNKNOWN, never "clean".

For every ServerName found in the sites-enabled configs we GET https://<name>/ and compare
the FIRST status code (redirects are NOT followed: a redirect is the answer) with the allowed
codes in $SENTINEL_ATLAS/http-expected.json (`{"<host>": [codes]}`). A host missing from the file
is an event ("unknown expectation"): a new vhost must be a conscious entry, not a silent blind spot.

Optional key `"_extra_urls_cmd"` in the same file: a shell command printing URLs, one per line,
each of which must answer 200 - for example the newest published post of a CMS (a front page can be
served from cache while posts are broken). Empty or absent = no extra URLs. Keys starting with `_`
are configuration, never hosts. No sites directory at all (no Apache), or only vhosts without a
ServerName (a fresh Apache), = nothing to probe, exit 0.

Read-only, no LLM. Overridable: HTTP_SITES_DIR, HTTP_EXPECTED, HTTP_FETCH_CMD (tests: a command that
takes a URL and prints the status code), HTTP_EXTRA_URLS_CMD (replaces `_extra_urls_cmd`; the older
name HTTP_ARTICLE_CMD is still accepted).
"""
import glob
import json
import os
import re
import shlex
import subprocess
import sys
import urllib.error
import urllib.request

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(BASE))
# untrusted.clean lives with the bus code in <repo>/sentinel
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(BASE)), "sentinel"))
import envfile  # noqa: E402
from i18n import t  # noqa: E402
from untrusted import clean  # noqa: E402

envfile.load(os.environ.get("SENTINEL_ATLAS") or os.path.dirname(BASE))
SITES = os.environ.get("HTTP_SITES_DIR") or "/etc/apache2/sites-enabled"
EXPECTED = os.environ.get("HTTP_EXPECTED", os.path.join(os.environ.get("SENTINEL_ATLAS") or os.path.dirname(BASE), "http-expected.json"))
FETCH_CMD = os.environ.get("HTTP_FETCH_CMD", "")
EXTRA_CMD_ENV = os.environ.get("HTTP_EXTRA_URLS_CMD", os.environ.get("HTTP_ARTICLE_CMD"))
# 10 s: a healthy vhost answers in well under a second; 10 s separates "slow" from "down"
# while staying far below the patrol's per-sensor limit even for ~10 hosts failing in turn.
TIMEOUT = 10
# Reserved TLDs (RFC 2606 / 6761) never resolve on the public internet, e.g. the catch-all default
# vhost `default.invalid`; probing them would report UNKNOWN on every patrol.
RESERVED_TLDS = (".invalid", ".test", ".example", ".localhost")
# Extra URLs come from a CMS (post slugs are written by editors or commenters): untrusted text in
# ALERT, cleaned to printable ASCII. Host names are cleaned to 80 characters, URLs to this:
URL_LIMIT = 120
SERVER_NAME = re.compile(r"^\s*ServerName\s+(\S+)", re.I | re.M)


class FetchError(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def fetch(url):
    """Return the first HTTP status code for url, or raise FetchError."""
    if FETCH_CMD:
        try:
            r = subprocess.run(shlex.split(FETCH_CMD) + [url], capture_output=True, text=True,
                               timeout=TIMEOUT + 5)
        except subprocess.TimeoutExpired:
            raise FetchError("timeout")
        if r.returncode != 0:
            raise FetchError(r.stderr.strip()[:200] or "fetcher exit %d" % r.returncode)
        try:
            return int(r.stdout.strip())
        except ValueError:
            raise FetchError("bad fetcher output %r" % r.stdout[:40])
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(urllib.request.Request(url, headers={"User-Agent": "sentinel-http-probe"}),
                         timeout=TIMEOUT) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code  # 3xx (not followed), 4xx, 5xx are answers, not errors
    except Exception as e:  # DNS, TLS, refused, timeout
        raise FetchError("%s: %s" % (type(e).__name__, e))


def vhosts():
    names = []
    for path in sorted(glob.glob(os.path.join(SITES, "*"))):
        with open(path, errors="replace") as f:
            for n in SERVER_NAME.findall(f.read()):
                if n.lower().rstrip(".").endswith(RESERVED_TLDS):
                    continue
                if n not in names:
                    names.append(n)
    return names


def extra_urls(cmd):
    """URLs printed by the configured command (each must answer 200); [] when no command is set."""
    if not cmd or not cmd.strip():
        return []
    r = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, timeout=60)
    urls = [l.strip() for l in r.stdout.splitlines() if l.strip().startswith("http")]
    if r.returncode != 0 or not urls:
        raise FetchError(t("http.extra_lookup_failed", rc=r.returncode, stderr=r.stderr.strip()[:200]))
    return urls


def main():
    events, unknown = [], []
    if not os.path.isdir(SITES):
        return 0   # no Apache sites directory: nothing to probe (an existing but empty one is UNKNOWN)
    try:
        with open(EXPECTED) as f:
            expected = json.load(f)
        names = vhosts()
    except (OSError, ValueError) as e:
        print(t("http.config_unreadable", error=e), file=sys.stderr)
        return 2
    if not names:
        if glob.glob(os.path.join(SITES, "*")):
            # files were read and none names a host (a fresh Apache: 000-default.conf only): nothing
            # to probe by name is a real, empty result. An empty listing stays UNKNOWN below, because
            # glob cannot tell an empty directory from an unreadable one.
            print(t("http.no_named_vhost", dir=SITES))
            return 0
        print(t("http.no_server_name", dir=SITES), file=sys.stderr)
        return 2
    extra_cmd = EXTRA_CMD_ENV if EXTRA_CMD_ENV is not None else expected.get("_extra_urls_cmd", "")
    for name in names:
        url = "https://%s/" % name
        try:
            code = fetch(url)
        except FetchError as e:
            unknown.append("%s: %s" % (clean(name, 80), clean(e, 200)))
            continue
        if name not in expected:
            events.append(t("http.unknown_expectation", host=clean(name, 80), code=code))
        elif code not in expected[name]:
            events.append(t("http.mismatch", host=clean(name, 80), code=code, expected=expected[name]))
    try:
        for url in extra_urls(extra_cmd):
            try:
                code = fetch(url)
            except FetchError as e:
                unknown.append("%s: %s" % (clean(url, URL_LIMIT), clean(e, 200)))
                continue
            if code != 200:
                events.append(t("http.extra_not_200", url=clean(url, URL_LIMIT), code=code))
    except (FetchError, subprocess.TimeoutExpired) as e:
        unknown.append("extra: %s" % clean(e, 200))
    if unknown:
        print("; ".join(unknown + events), file=sys.stderr)  # keep real mismatches visible too
        return 2
    if events:
        print("\n".join(events))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
