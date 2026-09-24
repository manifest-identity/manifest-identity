"""Seeding the authorized record from the observed one (1.4).

The properties: the observed side is offered in the authorized side's
shape and never written by itself; a grant that already carries an
authorization is marked so the page stops asking; the export leaves
empty exactly the two fields a person is being asked for; and the
round trip, export then fill then import, produces the authorizations
the file described and nothing else.
"""

import json

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.authorize import authorizations
from manifest_identity.core.roles import Role
from manifest_identity.models import Authorization, Identity
from tests.conftest import ROLE_USERS, auth_header, login, make_user
from tests.test_governance import admin_policy, group_entry, user_entry

ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def seed(client: TestClient, db: Session) -> str:
    make_user(db, Role.administrator)
    token = login(client, ROLE_USERS[Role.administrator])
    payload = {
        "UserDetailList": [
            user_entry("obs.direct", "AIDAOBS0000000000001", privileged=True),
            {
                **user_entry("obs.member", "AIDAOBS0000000000002"),
                "GroupList": ["platform"],
            },
        ],
        "GroupDetailList": [group_entry("platform", "AGPAOBS0000000000001")],
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


def identity_id(db: Session, external_id: str) -> int:
    return int(db.execute(
        select(Identity).where(Identity.external_id == external_id)
    ).scalar_one().id)


def test_observed_grants_come_back_in_the_authorized_shape(
    client: TestClient, db: Session
) -> None:
    token = seed(client, db)
    who = identity_id(db, "AIDAOBS0000000000001")
    rows = client.get(
        f"/identities/{who}/observed-grants", headers=auth_header(token)
    ).json()
    assert rows, "the imported grant produced no candidate"
    first = rows[0]
    assert first["role_definition_external_id"] == ADMIN_ARN
    assert first["mode"] == "standing"
    assert first["path"] == [{"via": "direct", "ref": "", "mode": "active"}]
    assert first["role_definition_hash"]
    assert first["authorized"] is False


def test_reading_the_observed_side_writes_nothing(
    client: TestClient, db: Session
) -> None:
    """It prefills a decision and never makes one (D-024)."""
    token = seed(client, db)
    who = identity_id(db, "AIDAOBS0000000000001")
    client.get(f"/identities/{who}/observed-grants", headers=auth_header(token))
    client.get("/export/observed-grants.csv", headers=auth_header(token))
    assert db.execute(select(Authorization)).scalars().all() == []


def test_an_authorized_grant_is_marked_so_the_page_stops_asking(
    client: TestClient, db: Session
) -> None:
    token = seed(client, db)
    who = identity_id(db, "AIDAOBS0000000000001")
    before = client.get(
        f"/identities/{who}/observed-grants", headers=auth_header(token)
    ).json()
    assert before[0]["authorized"] is False
    written = client.post(
        f"/identities/{who}/authorizations", headers=auth_header(token),
        json={
            "role_definition_external_id": ADMIN_ARN,
            "path": [{"via": "direct", "ref": "", "mode": "active"}],
            "owner_kind": "team", "owner_ref": "platform-team",
            "justification": "runs the console",
        },
    )
    assert written.status_code == 201, written.text
    after = client.get(
        f"/identities/{who}/observed-grants", headers=auth_header(token)
    ).json()
    assert after[0]["authorized"] is True


def test_a_revoked_authorization_leaves_the_grant_unmarked(
    client: TestClient, db: Session
) -> None:
    token = seed(client, db)
    who = identity_id(db, "AIDAOBS0000000000001")
    written = client.post(
        f"/identities/{who}/authorizations", headers=auth_header(token),
        json={
            "role_definition_external_id": ADMIN_ARN,
            "path": [{"via": "direct", "ref": "", "mode": "active"}],
            "owner_kind": "team", "owner_ref": "platform-team",
            "justification": "runs the console",
        },
    ).json()
    client.post(
        f"/authorizations/{written['id']}/revoke", headers=auth_header(token),
        json={"reason": "no longer needed"},
    )
    rows = client.get(
        f"/identities/{who}/observed-grants", headers=auth_header(token)
    ).json()
    assert rows[0]["authorized"] is False


def test_the_export_leaves_empty_what_a_person_must_answer(
    client: TestClient, db: Session
) -> None:
    token = seed(client, db)
    body = client.get(
        "/export/observed-grants.csv", headers=auth_header(token)
    ).text
    header, *rows = [line for line in body.splitlines() if line.strip()]
    assert header.startswith("identity_id,role,mode,path,owner_kind,owner")
    assert rows
    for line in rows:
        cells = dict(zip(header.split(","), line.split(","), strict=True))
        assert cells["identity_id"]
        assert cells["role"]
        # The two the observed side cannot know.
        assert cells["owner"] == ""
        assert cells["justification"] == ""


def test_the_export_escapes_the_spreadsheet_exit(
    client: TestClient, db: Session
) -> None:
    token = seed(client, db)
    body = client.get(
        "/export/observed-grants.csv", headers=auth_header(token)
    ).text
    for line in body.splitlines():
        for cell in line.split(","):
            assert not cell.startswith(("=", "+", "@", "\t", "\r"))


def test_the_round_trip_produces_what_the_file_says(
    client: TestClient, db: Session
) -> None:
    """Export, fill in the two empty columns, import. The result is the
    authorizations the file described and nothing else."""
    token = seed(client, db)
    body = client.get(
        "/export/observed-grants.csv", headers=auth_header(token)
    ).text
    header, *rows = [line for line in body.splitlines() if line.strip()]
    columns = header.split(",")
    filled = [header]
    for line in rows:
        cells = dict(zip(columns, line.split(","), strict=True))
        cells["owner_kind"] = "team"
        cells["owner"] = "platform-team"
        cells["justification"] = "carried over from what was observed"
        filled.append(",".join(cells[name] for name in columns))
    r = client.post(
        "/authorizations/import",
        headers=auth_header(token),
        files={"file": ("filled.csv", ("\n".join(filled) + "\n").encode(), "text/csv")},
    )
    assert r.status_code == 201, r.text
    assert r.json()["refused"] == 0, r.json()["refusals"]
    assert r.json()["would_write"] == len(rows)

    who = identity_id(db, "AIDAOBS0000000000001")
    live = authorizations.active(db, who)
    assert [row.role_definition_external_id for row in live] == [ADMIN_ARN]
    assert live[0].owner_ref == "platform-team"

    # And the grants now read as authorized, which is the round trip
    # closing: what was observed is what was authorized.
    marked = client.get(
        f"/identities/{who}/observed-grants", headers=auth_header(token)
    ).json()
    assert all(grant["authorized"] for grant in marked)


def test_group_derived_access_is_offered_and_keeps_its_hop(
    client: TestClient, db: Session
) -> None:
    """Access through a group is access the identity holds. Leaving it
    out would let a person fill in an export, import it, and believe an
    estate authorized while a whole class went unmentioned."""
    token = seed(client, db)
    member = identity_id(db, "AIDAOBS0000000000002")
    rows = client.get(
        f"/identities/{member}/observed-grants", headers=auth_header(token)
    ).json()
    assert rows, "the group member produced no candidate grant"
    assert rows[0]["path"] == [
        {"via": "membership", "ref": "platform", "mode": "active"}
    ]
    body = client.get(
        "/export/observed-grants.csv", headers=auth_header(token)
    ).text
    assert "membership:platform" in body


def test_the_group_hop_survives_the_round_trip(
    client: TestClient, db: Session
) -> None:
    token = seed(client, db)
    member = identity_id(db, "AIDAOBS0000000000002")
    body = client.get(
        "/export/observed-grants.csv", headers=auth_header(token)
    ).text
    header, *rows = [line for line in body.splitlines() if line.strip()]
    columns = header.split(",")
    filled = [header]
    for line in rows:
        cells = dict(zip(columns, line.split(","), strict=True))
        cells["owner_kind"] = "team"
        cells["owner"] = "platform-team"
        cells["justification"] = "carried over from what was observed"
        filled.append(",".join(cells[name] for name in columns))
    r = client.post(
        "/authorizations/import", headers=auth_header(token),
        files={"file": ("f.csv", ("\n".join(filled) + "\n").encode(), "text/csv")},
    )
    assert r.status_code == 201, r.text
    live = authorizations.active(db, member)
    assert [row.path for row in live] == [
        [{"via": "membership", "ref": "platform", "mode": "active"}]
    ]


def test_an_unknown_identity_is_404(client: TestClient, db: Session) -> None:
    token = seed(client, db)
    r = client.get("/identities/999999/observed-grants", headers=auth_header(token))
    assert r.status_code == 404
