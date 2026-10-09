"""Step-up and audited disclosure (D-089): bulk disclosure, bulk change,
and credential creation need the password given within the window; a
fresh sign-in counts; every export leaves an audit record."""

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from manifest_identity.core.deps import require_step_up
from manifest_identity.core.roles import STEP_UP_ROUTES, Role
from manifest_identity.main import app
from manifest_identity.models import AuditEvent, AuthSession, utcnow
from tests.conftest import ROLE_USERS, TEST_PASSWORD, auth_header, login, make_user
from tests.test_matrix import CALL_PLANS, flatten_routes


def _stale(db: Session) -> None:
    """Every session gave its password an hour ago."""
    db.execute(update(AuthSession).values(stepped_up_at=utcnow() - timedelta(hours=1)))
    db.commit()


def _declares_step_up(dependant) -> bool:  # FastAPI's internal type
    return any(d.call is require_step_up or _declares_step_up(d) for d in dependant.dependencies)


def test_the_named_list_and_the_declarations_agree() -> None:
    """One list says which routes need step-up and each route declares
    it; neither can gain a route the other lacks."""
    declared = {
        f"{method} {route.path}"
        for route in flatten_routes(app.routes) if _declares_step_up(route.dependant)
        for method in route.methods - {"HEAD", "OPTIONS"}
    }
    assert declared == set(STEP_UP_ROUTES)


def test_a_fresh_sign_in_counts(client: TestClient, db: Session) -> None:
    make_user(db, Role.reviewer)
    token = login(client, ROLE_USERS[Role.reviewer])
    assert client.get("/export.csv", headers=auth_header(token)).status_code == 200


@pytest.mark.parametrize("route_key", sorted(STEP_UP_ROUTES))
def test_every_listed_route_refuses_a_stale_session(
    client: TestClient, db: Session, route_key: str
) -> None:
    make_user(db, Role.administrator)
    token = login(client, ROLE_USERS[Role.administrator])
    _stale(db)
    method, path, kwargs = CALL_PLANS[route_key]
    path = path.replace("{campaign_id}", "1")
    response = getattr(client, method)(path, headers=auth_header(token), **kwargs)
    assert response.status_code == 403 and response.json()["detail"] == "step_up_required"


def test_the_right_password_steps_up_and_the_wrong_one_does_not(
    client: TestClient, db: Session
) -> None:
    make_user(db, Role.reviewer)
    token = login(client, ROLE_USERS[Role.reviewer])
    _stale(db)
    wrong = client.post("/auth/step-up", json={"password": "not-it"}, headers=auth_header(token))
    assert wrong.status_code == 403 and wrong.json()["detail"] == "password not accepted"
    assert client.get("/export.csv", headers=auth_header(token)).status_code == 403
    right = client.post(
        "/auth/step-up", json={"password": TEST_PASSWORD}, headers=auth_header(token)
    )
    assert right.status_code == 200 and "stepped_up_until" in right.json()
    assert client.get("/export.csv", headers=auth_header(token)).status_code == 200
    actions = db.execute(select(AuditEvent.action).order_by(AuditEvent.id)).scalars().all()
    assert "step_up_failure" in actions and "step_up" in actions


def test_the_wrong_password_never_echoes(client: TestClient, db: Session) -> None:
    make_user(db, Role.reviewer)
    token = login(client, ROLE_USERS[Role.reviewer])
    marker = "step-up-marker-that-must-not-reflect"
    response = client.post("/auth/step-up", json={"password": marker}, headers=auth_header(token))
    assert marker not in response.text
    assert not db.execute(select(AuditEvent).where(AuditEvent.detail.contains(marker))).first()


EXPORTS = ["/export.csv", "/export.json", "/report.html", "/export/observed-grants.csv"]


@pytest.mark.parametrize("path", EXPORTS)
def test_every_export_leaves_a_record(client: TestClient, db: Session, path: str) -> None:
    make_user(db, Role.reviewer)
    token = login(client, ROLE_USERS[Role.reviewer])
    assert client.get(path, headers=auth_header(token)).status_code == 200
    row = db.execute(
        select(AuditEvent).where(AuditEvent.action == "export").order_by(AuditEvent.id.desc())
    ).scalars().first()
    assert row is not None and row.actor_username == ROLE_USERS[Role.reviewer]
    assert row.target == path.lstrip("/")
