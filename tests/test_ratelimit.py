"""The sign-in rate limiter: failures count, success clears, windows slide."""

from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from manifest_identity.core.ratelimit import LoginRateLimiter
from manifest_identity.core.roles import Role
from manifest_identity.models import AuditEvent
from tests.conftest import TEST_PASSWORD, make_user


def test_sixth_failure_is_rate_limited(client: TestClient, db: Session) -> None:
    make_user(db, Role.operator)
    for _ in range(5):
        r = client.post(
            "/auth/login", json={"username": "test.operator", "password": "wrong-here-1"}
        )
        assert r.status_code == 401
    r = client.post(
        "/auth/login", json={"username": "test.operator", "password": "wrong-here-1"}
    )
    assert r.status_code == 429
    # The right password is also refused while the window holds: the
    # limiter answers before credentials are examined.
    r = client.post(
        "/auth/login", json={"username": "test.operator", "password": TEST_PASSWORD}
    )
    assert r.status_code == 429


def test_rejections_do_not_grow_the_audit_table(
    client: TestClient, db: Session
) -> None:
    make_user(db, Role.operator)
    for _ in range(20):
        client.post(
            "/auth/login", json={"username": "test.operator", "password": "wrong-here-1"}
        )
    failures = db.execute(
        select(func.count())
        .select_from(AuditEvent)
        .where(AuditEvent.action == "login_failure")
    ).scalar_one()
    assert failures == 5  # the limiter's bound, not twenty


def test_success_clears_the_username_key_but_not_the_ip_budget(
    client: TestClient, db: Session
) -> None:
    make_user(db, Role.operator)
    for _ in range(4):
        client.post(
            "/auth/login", json={"username": "test.operator", "password": "wrong-here-1"}
        )
    ok = client.post(
        "/auth/login", json={"username": "test.operator", "password": TEST_PASSWORD}
    )
    assert ok.status_code == 200
    # The username slate is clean, but the address budget deliberately
    # is not: one valid login must not refill an attacker's allowance
    # from the same address. One more failure fits, then the address
    # window closes.
    first = client.post(
        "/auth/login", json={"username": "test.operator", "password": "wrong-here-1"}
    )
    assert first.status_code == 401
    second = client.post(
        "/auth/login", json={"username": "test.operator", "password": "wrong-here-1"}
    )
    assert second.status_code == 429


def test_reset_clears_a_key_at_the_unit_level() -> None:
    limiter = LoginRateLimiter(max_failures=2, window_seconds=60)
    limiter.record_failure("k")
    limiter.record_failure("k")
    assert not limiter.allowed("k")
    limiter.reset("k")
    assert limiter.allowed("k")


def test_window_slides(monkeypatch: object) -> None:
    limiter = LoginRateLimiter(max_failures=2, window_seconds=10)
    now = [1000.0]
    import manifest_identity.core.ratelimit as rl

    real_monotonic = rl.time.monotonic
    rl.time.monotonic = lambda: now[0]  # type: ignore[assignment]
    try:
        limiter.record_failure("k")
        limiter.record_failure("k")
        assert not limiter.allowed("k")
        now[0] += 11
        assert limiter.allowed("k")
    finally:
        rl.time.monotonic = real_monotonic  # type: ignore[assignment]


def test_the_write_budget_bounds_heavy_writes(client, db) -> None:
    """Imports and campaign creation carry a per-user budget (D-041):
    thirty writes a minute admits any human pace and refuses a loop."""
    from manifest_identity.core.ratelimit import WRITE_LIMITER
    from manifest_identity.core.roles import Role
    from tests.conftest import ROLE_USERS, auth_header, login, make_user

    make_user(db, Role.operator)
    token = login(client, ROLE_USERS[Role.operator])
    key = f"write:{ROLE_USERS[Role.operator]}"
    for _ in range(WRITE_LIMITER.max_failures):
        WRITE_LIMITER.record_failure(key)
    r = client.post(
        "/campaigns",
        headers=auth_header(token),
        json={"name": "over budget", "scope": "everything",
              "due_at": "2026-09-30T00:00:00+00:00"},
    )
    assert r.status_code == 429
    assert "budget" in r.json()["detail"]
    WRITE_LIMITER.clear()
    r = client.post(
        "/campaigns",
        headers=auth_header(token),
        json={"name": "within budget", "scope": "everything",
              "due_at": "2026-09-30T00:00:00+00:00"},
    )
    # 422 not 429: the budget admits it, and the empty scope refuses it.
    assert r.status_code == 422
