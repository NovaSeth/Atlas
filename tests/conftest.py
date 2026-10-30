"""Test-run guard: no test may hand a message to the host's real MTA.

With SENTINEL_SENDMAIL_CMD pointing at a missing binary, `mailfmt.send_mail` takes its documented fallback to the
plain `mail -s` command, which the tests stub through PATH. Tests that exercise sendmail set their own value.
It is set again before every test: some tests pop every SENTINEL_* variable when they finish.

Host isolation: a resident session inherits SENTINEL_ATLAS, RESIDENT_ENV and similar variables from its service unit.
At import time, before any test module is collected, every SENTINEL_*, ATLAS_* and RESIDENT_* variable is removed
from os.environ; the removed names (never the values) stay in REMOVED_HOST_VARS for tests/test_env_isolation.py.
"""

import os

REMOVED_HOST_VARS = tuple(sorted(k for k in os.environ if k.startswith(("SENTINEL_", "ATLAS_", "RESIDENT_"))))
for _name in REMOVED_HOST_VARS:
    del os.environ[_name]

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _no_real_mta(monkeypatch):
    import os

    if not os.environ.get("SENTINEL_SENDMAIL_CMD"):
        monkeypatch.setenv("SENTINEL_SENDMAIL_CMD", "/nonexistent/atlas-test-sendmail")
