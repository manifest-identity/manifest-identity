"""The credential report import: the append-only rules, exercised end to end."""

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.models import AuditEvent, Identity, Observation, Snapshot
from manifest_identity.roles import Role
from tests.conftest import ROLE_USERS, auth_header, login, make_user
from tests.reportlib import ACCOUNT, report, root_row, user_row


def _upload(
    client: TestClient,
    token: str,
    data: bytes,
    captured: str = "2026-08-10T00:00:00+00:00",
) -> object:
    return client.post(
        "/imports/credential-report",
        headers=auth_header(token),
        files={"file": ("report.csv", data, "text/csv")},
        data={"captured_at": captured},
    )


def _operator_token(client: TestClient, db: Session) -> str:
    make_user(db, Role.operator)
    return login(client, ROLE_USERS[Role.operator])


def test_import_creates_identities_and_observations(
    client: TestClient, db: Session
) -> None:
    token = _operator_token(client, db)
    r = _upload(client, token, report(root_row(), user_row("alice"), user_row("bob")))
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["account"] == ACCOUNT
    assert body["identities_new"] == 3
    assert body["observations"] == 3
    listing = client.get("/identities", headers=auth_header(token)).json()["rows"]
    names = {i["display_name"]: i["identity_type"] for i in listing}
    assert names["<root_account>"] == "root"
    assert names["alice"] == "user"
    assert all(i["provisional"] for i in listing)


def test_duplicate_snapshot_is_rejected(client: TestClient, db: Session) -> None:
    token = _operator_token(client, db)
    data = report(user_row("alice"))
    assert _upload(client, token, data).status_code == 201
    r = _upload(client, token, data)
    assert r.status_code == 409
    assert "already imported" in r.json()["detail"]


def test_second_capture_appends_and_never_mutates(
    client: TestClient, db: Session
) -> None:
    token = _operator_token(client, db)
    assert _upload(
        client, token, report(user_row("alice", mfa="FALSE")),
        captured="2026-08-01T00:00:00+00:00",
    ).status_code == 201
    first = db.execute(select(Observation)).scalar_one()
    first_id, first_mfa = first.id, first.mfa_active
    assert _upload(
        client, token, report(user_row("alice", mfa="TRUE")),
        captured="2026-08-08T00:00:00+00:00",
    ).status_code == 201
    db.expire_all()
    rows = db.execute(select(Observation).order_by(Observation.id)).scalars().all()
    assert len(rows) == 2
    # The old observation is untouched; history accumulates (D-006).
    assert rows[0].id == first_id and rows[0].mfa_active == first_mfa
    assert rows[1].mfa_active is True
    # Still one identity: same principal, observed twice.
    assert len(db.execute(select(Identity)).scalars().all()) == 1


def test_out_of_order_import_is_harmless(client: TestClient, db: Session) -> None:
    token = _operator_token(client, db)
    assert _upload(
        client, token, report(user_row("alice")), captured="2026-08-08T00:00:00+00:00"
    ).status_code == 201
    assert _upload(
        client, token, report(user_row("alice")), captured="2026-08-01T00:00:00+00:00"
    ).status_code == 201
    snapshots = db.execute(select(Snapshot)).scalars().all()
    assert len(snapshots) == 2


def test_recreated_principal_is_a_new_identity(
    client: TestClient, db: Session
) -> None:
    token = _operator_token(client, db)
    assert _upload(
        client, token,
        report(user_row("alice", created="2025-01-01T00:00:00+00:00")),
        captured="2026-08-01T00:00:00+00:00",
    ).status_code == 201
    # Same name and ARN, different creation time: the resurrection case.
    assert _upload(
        client, token,
        report(user_row("alice", created="2026-07-15T00:00:00+00:00")),
        captured="2026-08-08T00:00:00+00:00",
    ).status_code == 201
    identities = db.execute(select(Identity)).scalars().all()
    assert len(identities) == 2  # D-016 via the D-029 provisional key


def test_mixed_accounts_reject_the_whole_file(
    client: TestClient, db: Session
) -> None:
    token = _operator_token(client, db)
    r = _upload(
        client, token,
        report(user_row("alice"), user_row("eve", account="999999999999")),
    )
    assert r.status_code == 422
    assert "mixes accounts" in r.json()["detail"]
    # Nothing partial: the transaction never happened.
    assert db.execute(select(Snapshot)).scalars().all() == []
    assert db.execute(select(Identity)).scalars().all() == []


def test_future_capture_time_is_rejected(client: TestClient, db: Session) -> None:
    token = _operator_token(client, db)
    r = _upload(client, token, report(user_row("alice")), captured="2030-01-01T00:00:00+00:00")
    assert r.status_code == 422
    assert "future" in r.json()["detail"]


def test_import_is_audited_with_attribution(
    client: TestClient, db: Session
) -> None:
    token = _operator_token(client, db)
    assert _upload(client, token, report(user_row("alice"))).status_code == 201
    row = db.execute(
        select(AuditEvent).where(AuditEvent.action == "snapshot_imported")
    ).scalar_one()
    assert row.actor_username == ROLE_USERS[Role.operator]
    assert ACCOUNT in (row.target or "")


def test_oversized_file_is_rejected_before_parsing(
    client: TestClient, db: Session
) -> None:
    token = _operator_token(client, db)
    r = _upload(client, token, b"x" * (5 * 1024 * 1024 + 10))
    assert r.status_code == 413
