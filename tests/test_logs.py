"""The logging allowlist canary.

The one behavior that matters most: a field not on the allowlist never
reaches the log stream, in any environment, because the call raises
before anything is written.
"""

import logging

import pytest

from manifest_identity.core.logs import ALLOWED_FIELDS, DisallowedLogField, log_event


def test_disallowed_field_raises_and_writes_nothing(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO):
        with pytest.raises(DisallowedLogField):
            log_event("login_attempt", password="hunter2-canary")  # noqa: S106
    assert "hunter2-canary" not in caplog.text


def test_allowed_fields_are_written(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO):
        log_event("request", method="GET", path="/health", status=200)
    assert "request" in caplog.text


def test_the_allowlist_never_contains_secret_shaped_names() -> None:
    # A guard on the guard: these names must never become loggable by a
    # careless allowlist edit. Growing this canary list is fine; growing
    # the allowlist with one of these is a failing test and a conversation.
    forbidden = {"password", "token", "secret", "credential", "authorization", "cookie"}
    assert not (ALLOWED_FIELDS & forbidden)
