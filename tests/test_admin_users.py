"""User management: create, list, and the edges that matter."""

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.core.roles import Role
from manifest_identity.models import AuditEvent
from tests.conftest import ROLE_USERS, auth_header, login, make_user

NEW_USER_PASSWORD = "pw-" + __import__("secrets").token_urlsafe(16)


def _admin_token(client: TestClient, db: Session) -> str:
    make_user(db, Role.administrator)
    return login(client, "test.admin")


def test_create_then_list(client: TestClient, db: Session) -> None:
    token = _admin_token(client, db)
    r = client.post(
        "/admin/users",
        headers=auth_header(token),
        json={
            "username": "new.reviewer",
            "password": NEW_USER_PASSWORD,
            "role": "reviewer",
        },
    )
    assert r.status_code == 201
    names = [u["username"] for u in client.get(
        "/admin/users", headers=auth_header(token)
    ).json()]
    assert "new.reviewer" in names
    # The creation is attributed in the audit table.
    row = db.execute(
        select(AuditEvent).where(AuditEvent.action == "user_created")
    ).scalar_one()
    assert row.actor_username == "test.admin"
    assert row.target == "new.reviewer"


def test_created_user_can_sign_in(client: TestClient, db: Session) -> None:
    token = _admin_token(client, db)
    client.post(
        "/admin/users",
        headers=auth_header(token),
        json={
            "username": "new.operator",
            "password": NEW_USER_PASSWORD,
            "role": "operator",
        },
    )
    r = client.post(
        "/auth/login",
        json={"username": "new.operator", "password": NEW_USER_PASSWORD},
    )
    assert r.status_code == 200
    assert r.json()["role"] == "operator"


def test_duplicate_username_conflicts(client: TestClient, db: Session) -> None:
    token = _admin_token(client, db)
    body = {
        "username": "twice.made",
        "password": NEW_USER_PASSWORD,
        "role": "reviewer",
    }
    assert client.post(
        "/admin/users", headers=auth_header(token), json=body
    ).status_code == 201
    assert client.post(
        "/admin/users", headers=auth_header(token), json=body
    ).status_code == 409


def test_short_password_states_the_policy(client: TestClient, db: Session) -> None:
    token = _admin_token(client, db)
    r = client.post(
        "/admin/users",
        headers=auth_header(token),
        json={"username": "short.pass", "password": "short", "role": "reviewer"},
    )
    assert r.status_code == 422
    assert "at least 12 characters" in r.json()["detail"]
    assert "short" != r.json()["detail"]  # states the policy, not the input


def test_invalid_role_is_rejected_generically(client: TestClient, db: Session) -> None:
    token = _admin_token(client, db)
    r = client.post(
        "/admin/users",
        headers=auth_header(token),
        json={
            "username": "bad.role",
            "password": NEW_USER_PASSWORD,
            "role": "supreme-leader",
        },
    )
    assert r.status_code == 422
    assert "supreme-leader" not in r.text


def test_revoking_a_users_sessions_ends_them_all(
    client: TestClient, db: Session
) -> None:
    """The stolen-token answer: an administrator ends every session a
    user holds; the user's next request meets 401, other users feel
    nothing, and the act is attributed in the audit table."""
    from sqlalchemy import select

    from manifest_identity.models import AuditEvent

    make_user(db, Role.administrator)
    admin_token = login(client, ROLE_USERS[Role.administrator])
    make_user(db, Role.operator)
    victim_one = login(client, ROLE_USERS[Role.operator])
    victim_two = login(client, ROLE_USERS[Role.operator])

    r = client.post(
        f"/admin/users/{ROLE_USERS[Role.operator]}/sessions/revoke",
        headers=auth_header(admin_token),
    )
    assert r.status_code == 200, r.text
    assert r.json()["sessions_revoked"] == 2

    for token in (victim_one, victim_two):
        assert client.get(
            "/auth/me", headers=auth_header(token)
        ).status_code == 401
    assert client.get(
        "/auth/me", headers=auth_header(admin_token)
    ).status_code == 200

    event = db.execute(
        select(AuditEvent).where(AuditEvent.action == "sessions_revoked")
    ).scalar_one()
    assert event.target == ROLE_USERS[Role.operator]
    assert "2 session(s)" in event.detail

    r = client.post(
        "/admin/users/ghost.user/sessions/revoke",
        headers=auth_header(admin_token),
    )
    assert r.status_code == 404
