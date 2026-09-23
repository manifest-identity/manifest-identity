"""The governance lifecycle, and the findings that change when a human answers.

Set, supersede, clear, and attest, each attributed on the record and
audited in the same transaction. The owner is typed, an assigned owner
outranks the tag, a disagreement between them is surfaced, and an
individual owner on a privileged identity is named as the offboarding
exposure it is (D-038).
"""

import json
from urllib.parse import quote

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.models import AuditEvent, GovernanceRecord, Group, Identity
from manifest_identity.roles import Role
from tests.conftest import ROLE_USERS, auth_header, login, make_user

ACCOUNT = "123456789012"
ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
ADMIN_DOCUMENT = quote(json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}))


def admin_policy() -> dict[str, object]:
    return {
        "PolicyName": "AdministratorAccess",
        "Arn": ADMIN_ARN,
        "PolicyVersionList": [
            {"IsDefaultVersion": True, "Document": ADMIN_DOCUMENT}
        ],
    }


def user_entry(
    name: str,
    user_id: str,
    *,
    tag_owner: str | None = None,
    privileged: bool = False,
) -> dict[str, object]:
    entry: dict[str, object] = {
        "UserName": name,
        "UserId": user_id,
        "Arn": f"arn:aws:iam::{ACCOUNT}:user/{name}",
        "CreateDate": "2025-01-01T00:00:00Z",
        "Tags": (
            [{"Key": "owner", "Value": tag_owner}] if tag_owner else []
        ),
    }
    if privileged:
        entry["AttachedManagedPolicies"] = [
            {"PolicyName": "AdministratorAccess", "PolicyArn": ADMIN_ARN}
        ]
    return entry


def group_entry(name: str, group_id: str) -> dict[str, object]:
    return {
        "GroupName": name,
        "GroupId": group_id,
        "Arn": f"arn:aws:iam::{ACCOUNT}:group/{name}",
        "AttachedManagedPolicies": [
            {"PolicyName": "AdministratorAccess", "PolicyArn": ADMIN_ARN}
        ],
    }


def import_details(
    client: TestClient, token: str, payload: dict[str, object]
) -> None:
    r = client.post(
        "/imports/authorization-details",
        headers=auth_header(token),
        files={"file": ("details.json", json.dumps(payload).encode(),
                        "application/json")},
        data={"captured_at": "2026-08-01T00:00:00+00:00"},
    )
    assert r.status_code == 201, r.text


def operator_token(client: TestClient, db: Session) -> str:
    make_user(db, Role.operator)
    return login(client, ROLE_USERS[Role.operator])


def identity_id(db: Session, name: str) -> int:
    return db.execute(
        select(Identity.id).where(Identity.first_display_name == name)
    ).scalar_one()


def detail(client: TestClient, token: str, ident: int) -> dict[str, object]:
    r = client.get(f"/identities/{ident}", headers=auth_header(token))
    assert r.status_code == 200, r.text
    return dict(r.json())


def finding_codes(view: dict[str, object]) -> set[str]:
    return {f["code"] for f in view["findings"]}  # type: ignore[index,union-attr]


def set_record(
    client: TestClient,
    token: str,
    ident: int,
    body: dict[str, object],
    expect: int = 201,
) -> dict[str, object]:
    r = client.post(
        f"/identities/{ident}/governance",
        headers=auth_header(token),
        json=body,
    )
    assert r.status_code == expect, r.text
    return dict(r.json()) if expect == 201 else {}


def test_owner_lifecycle_supersedes_and_clears(
    client: TestClient, db: Session
) -> None:
    token = operator_token(client, db)
    import_details(client, token, {
        "UserDetailList": [user_entry("caretaker", "AIDAGOV0000000000001",
                                      tag_owner="platform-team")],
    })
    ident = identity_id(db, "caretaker")

    set_record(client, token, ident,
               {"kind": "owner", "value": "identity-platform",
                "owner_type": "team"})
    view = detail(client, token, ident)
    assert view["owner"] == "identity-platform"
    assert view["owner_type"] == "team"
    assert view["owner_source"] == "assigned"

    # A second owner supersedes the first; the first stays in history,
    # closed and attributed, never edited.
    set_record(client, token, ident,
               {"kind": "owner", "value": "payments-bu",
                "owner_type": "business_unit"})
    view = detail(client, token, ident)
    assert view["owner"] == "payments-bu"
    owners = [r for r in view["governance"] if r["kind"] == "owner"]
    assert len(owners) == 2
    closed = [r for r in owners if r["cleared_at"] is not None]
    assert len(closed) == 1
    assert closed[0]["cleared_by"] == ROLE_USERS[Role.operator]

    # Clearing the active owner falls back to the observed tag.
    active = next(r for r in owners if r["cleared_at"] is None)
    r = client.delete(f"/governance/{active['id']}", headers=auth_header(token))
    assert r.status_code == 200, r.text
    view = detail(client, token, ident)
    assert view["owner"] == "platform-team"
    assert view["owner_source"] == "tag"
    assert view["owner_type"] == "unknown"


def test_owner_type_is_required_there_and_refused_elsewhere(
    client: TestClient, db: Session
) -> None:
    token = operator_token(client, db)
    import_details(client, token, {
        "UserDetailList": [user_entry("typed", "AIDAGOV0000000000002")],
    })
    ident = identity_id(db, "typed")
    set_record(client, token, ident,
               {"kind": "owner", "value": "someone"}, expect=422)
    set_record(client, token, ident,
               {"kind": "purpose", "value": "runs the nightly batch",
                "owner_type": "team"}, expect=422)
    set_record(client, token, ident,
               {"kind": "owner", "value": "x", "owner_type": "committee"},
               expect=422)


def test_assigning_an_owner_answers_the_unowned_finding(
    client: TestClient, db: Session
) -> None:
    token = operator_token(client, db)
    import_details(client, token, {
        "UserDetailList": [user_entry("orphan", "AIDAGOV0000000000003",
                                      privileged=True)],
        "Policies": [admin_policy()],
    })
    ident = identity_id(db, "orphan")
    assert "unowned_privileged" in finding_codes(detail(client, token, ident))

    set_record(client, token, ident,
               {"kind": "owner", "value": "identity-platform",
                "owner_type": "team"})
    codes = finding_codes(detail(client, token, ident))
    assert "unowned_privileged" not in codes

    # The list view applies the same adjustment, so its counts agree.
    rows = client.get("/identities", headers=auth_header(token)).json()["rows"]
    mine = next(r for r in rows if r["id"] == ident)
    assert mine["owner"] == "identity-platform"


def test_owner_tag_disagreement_is_surfaced_not_resolved(
    client: TestClient, db: Session
) -> None:
    token = operator_token(client, db)
    import_details(client, token, {
        "UserDetailList": [user_entry("contested", "AIDAGOV0000000000004",
                                      tag_owner="platform-team")],
    })
    ident = identity_id(db, "contested")
    set_record(client, token, ident,
               {"kind": "owner", "value": "identity-platform",
                "owner_type": "team"})
    view = detail(client, token, ident)
    codes = finding_codes(view)
    assert "owner_tag_disagreement" in codes
    disagreement = next(
        f for f in view["findings"] if f["code"] == "owner_tag_disagreement"
    )
    assert "identity-platform" in disagreement["explanation"]
    assert "platform-team" in disagreement["explanation"]

    # Agreement, in any case, is quiet.
    set_record(client, token, ident,
               {"kind": "owner", "value": "Platform-Team",
                "owner_type": "team"})
    assert "owner_tag_disagreement" not in finding_codes(
        detail(client, token, ident)
    )


def test_individual_owner_on_privilege_is_named_as_exposure(
    client: TestClient, db: Session
) -> None:
    token = operator_token(client, db)
    import_details(client, token, {
        "UserDetailList": [
            user_entry("heirloom", "AIDAGOV0000000000005", privileged=True),
            user_entry("sandbox", "AIDAGOV0000000000006"),
        ],
        "Policies": [admin_policy()],
    })
    privileged = identity_id(db, "heirloom")
    quiet = identity_id(db, "sandbox")
    for ident in (privileged, quiet):
        set_record(client, token, ident,
                   {"kind": "owner", "value": "terry",
                    "owner_type": "individual"})
    assert "individually_owned_privileged" in finding_codes(
        detail(client, token, privileged)
    )
    # An individual owning an unprivileged identity is legitimate and
    # stays quiet.
    assert "individually_owned_privileged" not in finding_codes(
        detail(client, token, quiet)
    )


def test_flags_accumulate_and_clear_one_by_one(
    client: TestClient, db: Session
) -> None:
    token = operator_token(client, db)
    import_details(client, token, {
        "UserDetailList": [user_entry("flagged", "AIDAGOV0000000000007")],
    })
    ident = identity_id(db, "flagged")
    first = set_record(client, token, ident,
                       {"kind": "flag", "value": "key purpose unclear"})
    set_record(client, token, ident,
               {"kind": "flag", "value": "candidate for federation"})
    view = detail(client, token, ident)
    active = [r for r in view["governance"]
              if r["kind"] == "flag" and r["cleared_at"] is None]
    assert len(active) == 2

    r = client.delete(f"/governance/{first['id']}", headers=auth_header(token))
    assert r.status_code == 200
    view = detail(client, token, ident)
    active = [r for r in view["governance"]
              if r["kind"] == "flag" and r["cleared_at"] is None]
    assert [r["value"] for r in active] == ["candidate for federation"]

    rows = client.get("/identities", headers=auth_header(token)).json()["rows"]
    assert next(r for r in rows if r["id"] == ident)["flagged"] is True


def test_attestation_is_the_reviewers_act_and_is_attributed(
    client: TestClient, db: Session
) -> None:
    token = operator_token(client, db)
    import_details(client, token, {
        "UserDetailList": [user_entry("attested", "AIDAGOV0000000000008")],
    })
    ident = identity_id(db, "attested")
    make_user(db, Role.reviewer)
    reviewer = login(client, ROLE_USERS[Role.reviewer])
    r = client.post(
        f"/identities/{ident}/attest",
        headers=auth_header(reviewer),
        json={"value": "still needed for the nightly batch"},
    )
    assert r.status_code == 201, r.text
    record = r.json()
    assert record["actor"] == ROLE_USERS[Role.reviewer]
    assert record["kind"] == "attestation"

    # The reviewer may attest and may not reassign ownership.
    r = client.post(
        f"/identities/{ident}/governance",
        headers=auth_header(reviewer),
        json={"kind": "owner", "value": "x", "owner_type": "team"},
    )
    assert r.status_code == 403


def test_every_write_carries_its_audit_row(
    client: TestClient, db: Session
) -> None:
    token = operator_token(client, db)
    import_details(client, token, {
        "UserDetailList": [user_entry("audited", "AIDAGOV0000000000009")],
    })
    ident = identity_id(db, "audited")
    record = set_record(client, token, ident,
                        {"kind": "purpose", "value": "runs the nightly batch"})
    events = db.execute(
        select(AuditEvent).where(AuditEvent.action == "governance_set")
    ).scalars().all()
    assert any(e.target == f"identity:{ident}" for e in events)

    client.delete(f"/governance/{record['id']}", headers=auth_header(token))
    cleared = db.execute(
        select(AuditEvent).where(AuditEvent.action == "governance_cleared")
    ).scalars().all()
    assert any(
        e.target == f"identity:{ident}"
        and e.actor_username == ROLE_USERS[Role.operator]
        for e in cleared
    )


def test_targets_must_exist_and_clears_need_an_active_record(
    client: TestClient, db: Session
) -> None:
    token = operator_token(client, db)
    r = client.post(
        "/identities/999999/governance",
        headers=auth_header(token),
        json={"kind": "flag", "value": "nobody home"},
    )
    assert r.status_code == 404
    r = client.post(
        "/groups/999999/attest", headers=auth_header(token),
        json={"value": "nothing to attest"},
    )
    assert r.status_code == 404
    assert client.delete(
        "/governance/999999", headers=auth_header(token)
    ).status_code == 404
    # A cleared record cannot be cleared twice.
    import_details(client, token, {
        "UserDetailList": [user_entry("twice", "AIDAGOV0000000000010")],
    })
    ident = identity_id(db, "twice")
    record = set_record(client, token, ident,
                        {"kind": "flag", "value": "clear me"})
    assert client.delete(
        f"/governance/{record['id']}", headers=auth_header(token)
    ).status_code == 200
    assert client.delete(
        f"/governance/{record['id']}", headers=auth_header(token)
    ).status_code == 404


def test_group_governance_owner_and_flag(
    client: TestClient, db: Session
) -> None:
    token = operator_token(client, db)
    import_details(client, token, {
        "GroupDetailList": [group_entry("admins", "AGPAGOV0000000000001")],
        "Policies": [admin_policy()],
    })
    group_id = db.execute(
        select(Group.id).where(Group.display_name == "admins")
    ).scalar_one()

    groups = client.get("/groups", headers=auth_header(token)).json()
    mine = next(g for g in groups if g["name"] == "admins")
    assert mine["id"] == group_id
    assert mine["owner"] is None
    assert "unowned_privileged_group" in {f["code"] for f in mine["findings"]}

    r = client.post(
        f"/groups/{group_id}/governance",
        headers=auth_header(token),
        json={"kind": "owner", "value": "identity-platform",
              "owner_type": "team"},
    )
    assert r.status_code == 201, r.text
    r = client.post(
        f"/groups/{group_id}/governance",
        headers=auth_header(token),
        json={"kind": "flag", "value": "membership under review"},
    )
    assert r.status_code == 201

    groups = client.get("/groups", headers=auth_header(token)).json()
    mine = next(g for g in groups if g["name"] == "admins")
    assert mine["owner"] == "identity-platform"
    assert mine["flagged"] is True
    assert "unowned_privileged_group" not in {
        f["code"] for f in mine["findings"]
    }
    kinds = {r["kind"] for r in mine["governance"]}
    assert kinds == {"owner", "flag"}


def test_governance_values_return_as_data_never_as_markup(
    client: TestClient, db: Session
) -> None:
    """The stored value round-trips exactly; rendering it as text is
    the page's one rule, and the API's job is to not mangle or
    interpret it on the way through."""
    token = operator_token(client, db)
    import_details(client, token, {
        "UserDetailList": [user_entry("hostile", "AIDAGOV0000000000011")],
    })
    ident = identity_id(db, "hostile")
    payload = '<img src=x onerror="alert(1)">'
    set_record(client, token, ident,
               {"kind": "flag", "value": payload})
    view = detail(client, token, ident)
    values = [r["value"] for r in view["governance"]]
    assert payload in values
    stored = db.execute(select(GovernanceRecord.value)).scalars().all()
    assert payload in stored
