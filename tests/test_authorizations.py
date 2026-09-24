"""The authorization record: attributed, bounded, append-only.

The properties this file holds are the ones D-073 and D-070 claim. An
authorization cannot exist without an authorizer taken from the
session. A person cannot own one alone. The required fields are the
organization's choice, shipped strict, and changing one is audited.
Nothing is edited: a replacement and a revocation are both new rows,
and the chain reads back in order. Expiry needs no job, because it is
the clock compared to a column.
"""

import json
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.authorize import authorizations
from manifest_identity.core.roles import Role
from manifest_identity.models import AuditEvent, Authorization, Identity
from tests.conftest import ROLE_USERS, auth_header, login, make_user
from tests.test_governance import admin_policy, user_entry

ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
DIRECT = [{"via": "direct", "ref": "", "mode": "active"}]


def seed_identity(client: TestClient, db: Session) -> int:
    """One imported identity to authorize against."""
    make_user(db, Role.administrator)
    token = login(client, ROLE_USERS[Role.administrator])
    payload = {
        "UserDetailList": [user_entry("auth.person", "AIDAAUTH00000000000001")],
        "Policies": [admin_policy()],
    }
    r = client.post(
        "/imports/authorization-details",
        headers=auth_header(token),
        files={"file": ("details.json", json.dumps(payload).encode(),
                        "application/json")},
        data={"captured_at": "2026-08-01T00:00:00+00:00"},
    )
    assert r.status_code == 201, r.text
    identity = db.execute(
        select(Identity).where(Identity.external_id == "AIDAAUTH00000000000001")
    ).scalar_one()
    return int(identity.id)


def body(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "role_definition_external_id": ARN,
        "path": DIRECT,
        "owner_kind": "team",
        "owner_ref": "platform-team",
        "justification": "runs the nightly reconciliation",
    }
    base.update(overrides)
    return base


def admin_token(client: TestClient, db: Session) -> str:
    return login(client, ROLE_USERS[Role.administrator])


def test_an_authorization_names_the_session_as_its_authorizer(
    client: TestClient, db: Session
) -> None:
    identity_id = seed_identity(client, db)
    token = admin_token(client, db)
    r = client.post(
        f"/identities/{identity_id}/authorizations",
        headers=auth_header(token), json=body(),
    )
    assert r.status_code == 201, r.text
    assert r.json()["authorizer"] == ROLE_USERS[Role.administrator]
    assert r.json()["status"] == "authorized"
    # And the body cannot say otherwise: the field is not in the model,
    # so a caller who sends one is ignored rather than believed.
    r2 = client.post(
        f"/identities/{identity_id}/authorizations",
        headers=auth_header(token),
        json=body(authorizer="someone.else", authorizer_username="someone.else"),
    )
    assert r2.status_code == 201, r2.text
    assert r2.json()["authorizer"] == ROLE_USERS[Role.administrator]


def test_every_write_lands_with_its_audit_row(
    client: TestClient, db: Session
) -> None:
    identity_id = seed_identity(client, db)
    token = admin_token(client, db)
    before = len(db.execute(select(AuditEvent)).scalars().all())
    client.post(
        f"/identities/{identity_id}/authorizations",
        headers=auth_header(token), json=body(),
    )
    rows = db.execute(select(AuditEvent)).scalars().all()
    assert len(rows) == before + 1
    assert rows[-1].action == "authorization_written"


def test_a_person_cannot_own_an_authorization_alone(
    client: TestClient, db: Session
) -> None:
    identity_id = seed_identity(client, db)
    token = admin_token(client, db)
    r = client.post(
        f"/identities/{identity_id}/authorizations",
        headers=auth_header(token),
        json=body(owner_kind="individual", owner_ref="one.person"),
    )
    assert r.status_code == 422
    assert "second owner" in r.json()["detail"]
    ok = client.post(
        f"/identities/{identity_id}/authorizations",
        headers=auth_header(token),
        json=body(
            owner_kind="individual", owner_ref="one.person",
            secondary_owner_kind="team", secondary_owner_ref="platform-team",
        ),
    )
    assert ok.status_code == 201, ok.text


def test_justification_is_required_until_an_administrator_says_otherwise(
    client: TestClient, db: Session
) -> None:
    identity_id = seed_identity(client, db)
    token = admin_token(client, db)
    refused = client.post(
        f"/identities/{identity_id}/authorizations",
        headers=auth_header(token), json=body(justification=None),
    )
    assert refused.status_code == 422
    assert "justification is required" in refused.json()["detail"]

    changed = client.put(
        "/admin/settings", headers=auth_header(token),
        json={"values": {"authorization.justification_required": "false"}},
    )
    assert changed.status_code == 200, changed.text
    allowed = client.post(
        f"/identities/{identity_id}/authorizations",
        headers=auth_header(token), json=body(justification=None),
    )
    assert allowed.status_code == 201, allowed.text


def test_changing_a_setting_is_audited_with_the_old_and_new_value(
    client: TestClient, db: Session
) -> None:
    seed_identity(client, db)
    token = admin_token(client, db)
    client.put(
        "/admin/settings", headers=auth_header(token),
        json={"values": {"authorization.expiry_required": "false"}},
    )
    rows = db.execute(
        select(AuditEvent).where(AuditEvent.action == "setting_changed")
    ).scalars().all()
    assert len(rows) == 1
    assert rows[0].target == "authorization.expiry_required"
    assert rows[0].detail == "true to false"


def test_the_shipped_defaults_are_the_strict_ones(
    client: TestClient, db: Session
) -> None:
    seed_identity(client, db)
    token = admin_token(client, db)
    listed = client.get("/admin/settings", headers=auth_header(token)).json()
    shipped = {s["key"]: s["default"] for s in listed}
    assert shipped["authorization.justification_required"] == "true"
    assert shipped["authorization.expiry_required"] == "true"
    # Nobody has chosen, so value equals default and no actor is named.
    for setting in listed:
        assert setting["value"] == setting["default"]
        assert setting["changed_by"] is None


def test_a_setting_outside_the_registry_is_refused(
    client: TestClient, db: Session
) -> None:
    seed_identity(client, db)
    token = admin_token(client, db)
    r = client.put(
        "/admin/settings", headers=auth_header(token),
        json={"values": {"authorization.invented": "true"}},
    )
    assert r.status_code == 422
    assert "no such setting" in r.json()["detail"]


def test_one_bad_value_changes_none_of_the_batch(
    client: TestClient, db: Session
) -> None:
    seed_identity(client, db)
    token = admin_token(client, db)
    r = client.put(
        "/admin/settings", headers=auth_header(token),
        json={"values": {
            "authorization.reference_required": "true",
            "authorization.maximum_lifetime_days": "not a number",
        }},
    )
    assert r.status_code == 422
    after = client.get("/admin/settings", headers=auth_header(token)).json()
    values = {s["key"]: s["value"] for s in after}
    assert values["authorization.reference_required"] == "false"


def test_a_second_authorization_supersedes_the_first_and_both_remain(
    client: TestClient, db: Session
) -> None:
    identity_id = seed_identity(client, db)
    token = admin_token(client, db)
    first = client.post(
        f"/identities/{identity_id}/authorizations",
        headers=auth_header(token), json=body(),
    ).json()
    second = client.post(
        f"/identities/{identity_id}/authorizations",
        headers=auth_header(token),
        json=body(justification="renewed for the next year"),
    ).json()
    assert second["supersedes_id"] == first["id"]
    chain = client.get(
        f"/identities/{identity_id}/authorizations", headers=auth_header(token)
    ).json()
    assert [row["id"] for row in chain] == [second["id"], first["id"]]
    # Only one stands.
    live = authorizations.active(db, identity_id)
    assert [row.id for row in live] == [second["id"]]


def test_a_revocation_is_a_row_and_never_an_edit(
    client: TestClient, db: Session
) -> None:
    identity_id = seed_identity(client, db)
    token = admin_token(client, db)
    written = client.post(
        f"/identities/{identity_id}/authorizations",
        headers=auth_header(token), json=body(),
    ).json()
    r = client.post(
        f"/authorizations/{written['id']}/revoke",
        headers=auth_header(token), json={"reason": "the service was retired"},
    )
    assert r.status_code == 201, r.text
    assert r.json()["status"] == "revoked"
    assert r.json()["supersedes_id"] == written["id"]

    original = db.get(Authorization, written["id"])
    assert original is not None
    assert original.status == "authorized", "the revoked row was edited"
    assert authorizations.active(db, identity_id) == []


def test_a_revocation_says_why(client: TestClient, db: Session) -> None:
    identity_id = seed_identity(client, db)
    token = admin_token(client, db)
    written = client.post(
        f"/identities/{identity_id}/authorizations",
        headers=auth_header(token), json=body(),
    ).json()
    r = client.post(
        f"/authorizations/{written['id']}/revoke",
        headers=auth_header(token), json={"reason": "   "},
    )
    assert r.status_code == 422


def test_a_superseded_authorization_cannot_be_revoked(
    client: TestClient, db: Session
) -> None:
    identity_id = seed_identity(client, db)
    token = admin_token(client, db)
    first = client.post(
        f"/identities/{identity_id}/authorizations",
        headers=auth_header(token), json=body(),
    ).json()
    client.post(
        f"/identities/{identity_id}/authorizations",
        headers=auth_header(token), json=body(justification="renewed"),
    )
    r = client.post(
        f"/authorizations/{first['id']}/revoke",
        headers=auth_header(token), json={"reason": "too late"},
    )
    assert r.status_code == 409
    assert "already replaced" in r.json()["detail"]


def test_expiry_is_the_clock_and_not_a_job(
    client: TestClient, db: Session
) -> None:
    identity_id = seed_identity(client, db)
    token = admin_token(client, db)
    soon = datetime.now(UTC) + timedelta(days=1)
    written = client.post(
        f"/identities/{identity_id}/authorizations",
        headers=auth_header(token),
        json=body(valid_until=soon.isoformat()),
    ).json()
    assert written["status"] == "authorized"
    row = db.get(Authorization, written["id"])
    assert row is not None
    # Nothing runs and nothing is written; the same row reads expired
    # once the moment asked about is past its window.
    later = datetime.now(UTC) + timedelta(days=2)
    assert authorizations.status_of(row, later) == "expired"
    assert authorizations.active(db, identity_id, later) == []
    assert authorizations.active(db, identity_id) != []


def test_the_window_must_make_sense_and_stay_inside_the_bound(
    client: TestClient, db: Session
) -> None:
    identity_id = seed_identity(client, db)
    token = admin_token(client, db)
    backwards = client.post(
        f"/identities/{identity_id}/authorizations",
        headers=auth_header(token),
        json=body(
            valid_from=(datetime.now(UTC) + timedelta(days=10)).isoformat(),
            valid_until=(datetime.now(UTC) + timedelta(days=2)).isoformat(),
        ),
    )
    assert backwards.status_code == 422
    assert "end after it begins" in backwards.json()["detail"]

    too_long = client.post(
        f"/identities/{identity_id}/authorizations",
        headers=auth_header(token),
        json=body(valid_until=(datetime.now(UTC) + timedelta(days=400)).isoformat()),
    )
    assert too_long.status_code == 422
    assert "at most 365 days" in too_long.json()["detail"]


def test_the_quiet_path_is_the_bounded_one(
    client: TestClient, db: Session
) -> None:
    """A caller who says nothing about expiry gets the organization's
    bound, not forever."""
    identity_id = seed_identity(client, db)
    token = admin_token(client, db)
    written = client.post(
        f"/identities/{identity_id}/authorizations",
        headers=auth_header(token), json=body(),
    ).json()
    assert written["valid_until"] is not None


def test_a_path_written_twice_is_one_live_authorization(
    client: TestClient, db: Session
) -> None:
    identity_id = seed_identity(client, db)
    token = admin_token(client, db)
    for _ in range(3):
        client.post(
            f"/identities/{identity_id}/authorizations",
            headers=auth_header(token), json=body(),
        )
    assert len(authorizations.active(db, identity_id)) == 1
    assert len(authorizations.history(db, identity_id)) == 3


def test_two_different_paths_stand_together(
    client: TestClient, db: Session
) -> None:
    identity_id = seed_identity(client, db)
    token = admin_token(client, db)
    client.post(
        f"/identities/{identity_id}/authorizations",
        headers=auth_header(token), json=body(),
    )
    client.post(
        f"/identities/{identity_id}/authorizations",
        headers=auth_header(token),
        json=body(path=[{"via": "membership", "ref": "platform", "mode": "active"}]),
    )
    assert len(authorizations.active(db, identity_id)) == 2


def test_the_reader_may_read_and_may_not_write(
    client: TestClient, db: Session
) -> None:
    identity_id = seed_identity(client, db)
    make_user(db, Role.reviewer)
    reviewer = login(client, ROLE_USERS[Role.reviewer])
    assert client.get(
        f"/identities/{identity_id}/authorizations", headers=auth_header(reviewer)
    ).status_code == 200
    assert client.post(
        f"/identities/{identity_id}/authorizations",
        headers=auth_header(reviewer), json=body(),
    ).status_code == 403


def test_an_unknown_identity_is_404_before_anything_else(
    client: TestClient, db: Session
) -> None:
    seed_identity(client, db)
    token = admin_token(client, db)
    r = client.post(
        "/identities/999999/authorizations", headers=auth_header(token), json=body()
    )
    assert r.status_code == 404


def test_two_roles_held_the_same_way_both_stand(
    client: TestClient, db: Session
) -> None:
    """Supersession keys on the role and the path together. Keying on
    the path alone made every second authorization replace the first,
    because most access arrives directly; the runtime proof found it
    when authorizing one role made the delta report another as
    unauthorized."""
    identity_id = seed_identity(client, db)
    token = admin_token(client, db)
    first = client.post(
        f"/identities/{identity_id}/authorizations",
        headers=auth_header(token), json=body(),
    ).json()
    second = client.post(
        f"/identities/{identity_id}/authorizations",
        headers=auth_header(token),
        json=body(role_definition_external_id="arn:aws:iam::aws:policy/ReadOnlyAccess"),
    ).json()
    assert second["supersedes_id"] is None, "a different role superseded the first"
    live = authorizations.active(db, identity_id)
    assert {row.id for row in live} == {first["id"], second["id"]}


def test_the_same_role_by_the_same_path_still_supersedes(
    client: TestClient, db: Session
) -> None:
    identity_id = seed_identity(client, db)
    token = admin_token(client, db)
    first = client.post(
        f"/identities/{identity_id}/authorizations",
        headers=auth_header(token), json=body(),
    ).json()
    second = client.post(
        f"/identities/{identity_id}/authorizations",
        headers=auth_header(token), json=body(justification="renewed"),
    ).json()
    assert second["supersedes_id"] == first["id"]
    assert len(authorizations.active(db, identity_id)) == 1
