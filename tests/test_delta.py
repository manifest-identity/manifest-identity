"""The delta (1.5): held against authorized, computed at read.

Each class has a fixture that produces it and one that does not, which
is the standing rule for findings here. The last two tests are the
ones that matter most: the delta stores nothing, and every finding
carries when each side was last heard from, because a stale side makes
a delta lie in the reassuring direction (threat 15).
"""

import json
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.compare import delta
from manifest_identity.core.roles import Role
from manifest_identity.models import Authorization, Identity
from tests.conftest import ROLE_USERS, auth_header, login, make_user
from tests.test_governance import admin_policy, user_entry

ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
OTHER_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"
DIRECT = [{"via": "direct", "ref": "", "mode": "active"}]


def seed(client: TestClient, db: Session) -> str:
    make_user(db, Role.administrator)
    token = login(client, ROLE_USERS[Role.administrator])
    payload = {
        "UserDetailList": [
            user_entry("delta.one", "AIDADELTA000000000001", privileged=True),
        ],
        "Policies": [admin_policy()],
    }
    r = client.post(
        "/imports/authorization-details",
        headers=auth_header(token),
        files={"file": ("d.json", json.dumps(payload).encode(), "application/json")},
        data={"captured_at": "2026-08-01T00:00:00+00:00"},
    )
    assert r.status_code == 201, r.text
    return token


def who(db: Session) -> Identity:
    return db.execute(
        select(Identity).where(Identity.external_id == "AIDADELTA000000000001")
    ).scalar_one()


def authorize(
    client: TestClient, token: str, identity_id: int, **overrides: object
) -> dict[str, object]:
    body: dict[str, object] = {
        "role_definition_external_id": ADMIN_ARN,
        "path": DIRECT,
        "owner_kind": "team",
        "owner_ref": "platform-team",
        "justification": "runs the console",
    }
    body.update(overrides)
    r = client.post(
        f"/identities/{identity_id}/authorizations",
        headers=auth_header(token), json=body,
    )
    assert r.status_code == 201, r.text
    return dict(r.json())


def kinds(findings: list[dict[str, object]]) -> list[str]:
    return [str(f["kind"]) for f in findings]


def test_held_but_not_authorized_is_the_starting_state(
    client: TestClient, db: Session
) -> None:
    token = seed(client, db)
    body = client.get("/delta", headers=auth_header(token)).json()
    assert delta.HELD_NOT_AUTHORIZED in kinds(body["findings"])
    assert body["counts"][delta.HELD_NOT_AUTHORIZED] >= 1


def test_authorizing_what_is_held_clears_the_finding(
    client: TestClient, db: Session
) -> None:
    """The fixture that does not produce it."""
    token = seed(client, db)
    identity = who(db)
    authorize(client, token, identity.id)
    body = client.get(
        f"/identities/{identity.id}/delta", headers=auth_header(token)
    ).json()
    assert delta.HELD_NOT_AUTHORIZED not in kinds(body["findings"])
    assert body["findings"] == []


def test_authorized_but_not_held(client: TestClient, db: Session) -> None:
    token = seed(client, db)
    identity = who(db)
    # A role the import never showed this identity holding.
    authorize(client, token, identity.id, role_definition_external_id=OTHER_ARN)
    body = client.get(
        f"/identities/{identity.id}/delta", headers=auth_header(token)
    ).json()
    assert delta.AUTHORIZED_NOT_HELD in kinds(body["findings"])
    found = next(
        f for f in body["findings"] if f["kind"] == delta.AUTHORIZED_NOT_HELD
    )
    assert found["role"] == OTHER_ARN
    assert found["authorization_id"]


def test_expired_and_still_held(client: TestClient, db: Session) -> None:
    token = seed(client, db)
    identity = who(db)
    authorize(client, token, identity.id)
    findings = delta.for_identity(
        db, identity, now=datetime.now(UTC) + timedelta(days=400)
    )
    assert [f.kind for f in findings] == [delta.EXPIRED_STILL_HELD]
    # And not also reported as never authorized: one finding per fact.
    assert delta.HELD_NOT_AUTHORIZED not in [f.kind for f in findings]


def test_an_unexpired_authorization_does_not_produce_it(
    client: TestClient, db: Session
) -> None:
    token = seed(client, db)
    identity = who(db)
    authorize(client, token, identity.id)
    findings = delta.for_identity(db, identity)
    assert delta.EXPIRED_STILL_HELD not in [f.kind for f in findings]


def test_a_revoked_authorization_reads_as_held_but_not_authorized(
    client: TestClient, db: Session
) -> None:
    """Revoking the record does not remove the access, and the delta is
    what says so."""
    token = seed(client, db)
    identity = who(db)
    written = authorize(client, token, identity.id)
    client.post(
        f"/authorizations/{written['id']}/revoke", headers=auth_header(token),
        json={"reason": "the service was retired"},
    )
    findings = delta.for_identity(db, identity)
    assert [f.kind for f in findings] == [delta.HELD_NOT_AUTHORIZED]


def test_owner_disagreement(client: TestClient, db: Session) -> None:
    token = seed(client, db)
    identity = who(db)
    authorize(client, token, identity.id, owner_ref="platform-team")
    client.post(
        f"/identities/{identity.id}/governance", headers=auth_header(token),
        json={"kind": "owner", "value": "data-team", "owner_type": "team"},
    )
    findings = delta.for_identity(db, identity)
    assert delta.OWNER_DISAGREEMENT in [f.kind for f in findings]
    found = next(f for f in findings if f.kind == delta.OWNER_DISAGREEMENT)
    assert "platform-team" in found.detail and "data-team" in found.detail


def test_agreeing_owners_produce_nothing(client: TestClient, db: Session) -> None:
    token = seed(client, db)
    identity = who(db)
    authorize(client, token, identity.id, owner_ref="platform-team")
    client.post(
        f"/identities/{identity.id}/governance", headers=auth_header(token),
        json={"kind": "owner", "value": "platform-team", "owner_type": "team"},
    )
    findings = delta.for_identity(db, identity)
    assert delta.OWNER_DISAGREEMENT not in [f.kind for f in findings]


def test_a_role_that_changed_after_it_was_authorized(
    client: TestClient, db: Session
) -> None:
    token = seed(client, db)
    identity = who(db)
    # Bind the authorization to a hash the observed side does not carry,
    # which is what a changed managed policy looks like afterwards.
    authorize(
        client, token, identity.id,
        role_definition_hash="0" * 64,
    )
    findings = delta.for_identity(db, identity)
    assert delta.DEFINITION_CHANGED in [f.kind for f in findings]


def test_the_same_hash_produces_nothing(client: TestClient, db: Session) -> None:
    token = seed(client, db)
    identity = who(db)
    observed = client.get(
        f"/identities/{identity.id}/observed-grants", headers=auth_header(token)
    ).json()[0]
    authorize(
        client, token, identity.id,
        role_definition_hash=observed["role_definition_hash"],
    )
    findings = delta.for_identity(db, identity)
    assert delta.DEFINITION_CHANGED not in [f.kind for f in findings]


def test_the_delta_stores_nothing(client: TestClient, db: Session) -> None:
    """D-006 applied to the comparison itself: reading it twice leaves
    the database exactly as it was."""
    token = seed(client, db)
    identity = who(db)
    authorize(client, token, identity.id, role_definition_external_id=OTHER_ARN)
    before = len(db.execute(select(Authorization)).scalars().all())
    client.get("/delta", headers=auth_header(token))
    client.get(f"/identities/{identity.id}/delta", headers=auth_header(token))
    after = len(db.execute(select(Authorization)).scalars().all())
    assert before == after
    # And no table named for the delta exists to store one in.
    from manifest_identity.core.db import Base

    assert not [
        name for name in Base.metadata.tables
        if "delta" in name or "finding" in name
    ]


def test_every_finding_says_when_each_side_was_last_heard_from(
    client: TestClient, db: Session
) -> None:
    """A finding from a month-old import is true about a month-old
    world. Saying so is the difference between a delta and a claim."""
    token = seed(client, db)
    identity = who(db)
    authorize(client, token, identity.id, role_definition_external_id=OTHER_ARN)
    body = client.get("/delta", headers=auth_header(token)).json()
    assert body["findings"]
    for finding in body["findings"]:
        assert finding["observed_as_of"], finding
        assert finding["authorized_as_of"], finding
    # The observed side is the import's own capture time, not the wall
    # clock, so a stale import reports as stale.
    assert body["findings"][0]["observed_as_of"].startswith("2026-08-01")


def test_the_worst_class_sorts_first(client: TestClient, db: Session) -> None:
    token = seed(client, db)
    identity = who(db)
    authorize(client, token, identity.id, role_definition_external_id=OTHER_ARN)
    findings = delta.for_estate(db)
    assert [f.kind for f in findings] == sorted(
        [f.kind for f in findings], key=delta.CLASSES.index
    )


def test_a_reviewer_may_read_the_delta(client: TestClient, db: Session) -> None:
    seed(client, db)
    make_user(db, Role.reviewer)
    reviewer = login(client, ROLE_USERS[Role.reviewer])
    assert client.get("/delta", headers=auth_header(reviewer)).status_code == 200


def test_an_unknown_identity_is_404(client: TestClient, db: Session) -> None:
    token = seed(client, db)
    assert client.get(
        "/identities/999999/delta", headers=auth_header(token)
    ).status_code == 404
