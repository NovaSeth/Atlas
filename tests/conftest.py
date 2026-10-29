"""Test-run guard: no test may hand a message to the host's real MTA.

With SENTINEL_SENDMAIL_CMD pointing at a missing binary, `mailfmt.send_mail` takes its documented fallback to the
plain `mail -s` command, which the tests stub through PATH. Tests that exercise sendmail set their own value.
It is set again before every test: some tests pop every SENTINEL_* variable when they finish.
"""

import pytest


@pytest.fixture(autouse=True)
def _no_real_mta(monkeypatch):
    import os

    if not os.environ.get("SENTINEL_SENDMAIL_CMD"):
        monkeypatch.setenv("SENTINEL_SENDMAIL_CMD", "/nonexistent/atlas-test-sendmail")
