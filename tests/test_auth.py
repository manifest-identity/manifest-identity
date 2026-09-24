"""Sign-in behavior: indistinguishable failures, revocation, expiry."""

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.core import security
from manifest_identity.core.roles import Role
from manifest_identity.models import AuditEvent, AuthSession, utcnow
from tests.conftest import (
    ROLE_USERS,
    TEST_PASSWORD,
    auth_header,
    login,
    make_user,
)


def test_login_returns_token_and_role(client: TestClient, db: Session) -> None:
    make_user(db, Role.operator)
    r = client.post(
        "/auth/login",
        json={"username": "test.operator", "password": TEST_PASSWORD},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["role"] == "operator"
    assert len(body["token"]) > 30


def test_wrong_password_and_unknown_user_answer_identically(
    client: TestClient, db: Session
) -> None:
    make_user(db, Role.operator)
    wrong = client.post(
        "/auth/login", json={"username": "test.operator", "password": "not-it-at-all"}
    )
    unknown = client.post(
        "/auth/login", json={"username": "nobody.here", "password": "not-it-at-all"}
    )
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


def test_unknown_user_still_pays_the_bcrypt_cost(
    client: TestClient, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    real_dummy = security.verify_against_dummy
    monkeypatch.setattr(
        security,
        "verify_against_dummy",
        lambda pw: calls.append("dummy") or real_dummy(pw),
    )
    client.post("/auth/login", json={"username": "nobody.here", "password": "x" * 12})
    assert calls == ["dummy"]


def test_token_is_stored_only_as_a_hash(client: TestClient, db: Session) -> None:
    make_user(db, Role.reviewer)
    token = login(client, "test.reviewer")
    stored = db.execute(select(AuthSession.token_hash)).scalars().all()
    assert token not in stored
    assert security.hash_token(token) in stored


def test_logout_revokes_the_session(client: TestClient, db: Session) -> None:
    make_user(db, Role.reviewer)
    token = login(client, "test.reviewer")
    assert client.get("/auth/me", headers=auth_header(token)).status_code == 200
    assert client.post("/auth/logout", headers=auth_header(token)).status_code == 200
    assert client.get("/auth/me", headers=auth_header(token)).status_code == 401


def test_expired_session_is_rejected(client: TestClient, db: Session) -> None:
    make_user(db, Role.reviewer)
    token = login(client, "test.reviewer")
    row = db.execute(select(AuthSession)).scalar_one()
    row.expires_at = utcnow() - timedelta(seconds=1)
    db.commit()
    assert client.get("/auth/me", headers=auth_header(token)).status_code == 401


def test_login_events_reach_the_audit_table(client: TestClient, db: Session) -> None:
    make_user(db, Role.operator)
    client.post(
        "/auth/login", json={"username": "test.operator", "password": TEST_PASSWORD}
    )
    client.post(
        "/auth/login", json={"username": "test.operator", "password": "wrong-wrong-1"}
    )
    actions = db.execute(select(AuditEvent.action)).scalars().all()
    assert "login_success" in actions
    assert "login_failure" in actions
    success = db.execute(
        select(AuditEvent).where(AuditEvent.action == "login_success")
    ).scalar_one()
    assert success.actor_username == "test.operator"
    assert success.actor_user_id is not None


def test_a_fabricated_token_is_rejected_even_beside_a_live_session(
    client: TestClient, db: Session
) -> None:
    """Found by the mutation check: with token hashing broken to a
    constant, every made-up token matched whatever session existed, and
    nothing here noticed. This holds the actual property: only the
    issued token opens the session it belongs to."""
    make_user(db, Role.operator)
    login(client, ROLE_USERS[Role.operator])
    import secrets

    forged = secrets.token_urlsafe(32)
    r = client.get("/auth/me", headers=auth_header(forged))
    assert r.status_code == 401
