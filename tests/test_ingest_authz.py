"""Authorization details import: reconciliation, groups, resurrection."""

import json
from urllib.parse import quote

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.core.roles import Role
from manifest_identity.models import Grant, Identity, IdentityKind, Membership, RoleDefinition
from tests.conftest import ROLE_USERS, auth_header, login, make_user
from tests.reportlib import ACCOUNT, report, user_row


def details(account: str = ACCOUNT, **lists: object) -> bytes:
    return json.dumps(lists).encode()


def user_entry(
    name: str,
    user_id: str,
    account: str = ACCOUNT,
    created: str = "2025-01-01T00:00:00Z",
    groups: list[str] | None = None,
) -> dict[str, object]:
    return {
        "UserName": name,
        "UserId": user_id,
        "Arn": f"arn:aws:iam::{account}:user/{name}",
        "CreateDate": created,
        "GroupList": groups or [],
        "Tags": [{"Key": "owner", "Value": "platform-team"}],
    }


def role_entry(name: str, role_id: str, account: str = ACCOUNT) -> dict[str, object]:
    trust = quote(json.dumps({"Version": "2012-10-17", "Statement": []}))
    return {
        "RoleName": name,
        "RoleId": role_id,
        "Arn": f"arn:aws:iam::{account}:role/{name}",
        "CreateDate": "2024-06-01T00:00:00Z",
        "AssumeRolePolicyDocument": trust,
        "RoleLastUsed": {"LastUsedDate": "2026-08-01T00:00:00Z", "Region": "us-west-2"},
    }


def group_entry(name: str, group_id: str, account: str = ACCOUNT) -> dict[str, object]:
    return {
        "GroupName": name,
        "GroupId": group_id,
        "Arn": f"arn:aws:iam::{account}:group/{name}",
        "AttachedManagedPolicies": [
            {"PolicyName": "AdministratorAccess",
             "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}
        ],
    }


def _upload(client: TestClient, token: str, data: bytes, captured: str) -> object:
    return client.post(
        "/imports/authorization-details",
        headers=auth_header(token),
        files={"file": ("details.json", data, "application/json")},
        data={"captured_at": captured},
    )


def _token(client: TestClient, db: Session) -> str:
    make_user(db, Role.operator)
    return login(client, ROLE_USERS[Role.operator])


def test_provisional_identity_upgrades_to_real_identifier(
    client: TestClient, db: Session
) -> None:
    token = _token(client, db)
    # First the credential report knows alice only by her immutable pair.
    r = client.post(
        "/imports/credential-report",
        headers=auth_header(token),
        files={"file": ("r.csv", report(user_row("alice")), "text/csv")},
        data={"captured_at": "2026-08-01T00:00:00+00:00"},
    )
    assert r.status_code == 201
    before = db.execute(select(Identity)).scalar_one()
    assert before.provisional and before.external_id.startswith("cr:")
    # Then the authorization details supply the real identifier.
    r = _upload(
        client,
        token,
        details(UserDetailList=[
            user_entry("alice", "AIDAALICE0000000000001",
                       created="2025-01-01T00:00:00+00:00")
        ]),
        "2026-08-02T00:00:00+00:00",
    )
    assert r.status_code == 201
    assert r.json()["identities_known"] == 1  # upgraded, not created
    db.expire_all()
    after = db.execute(select(Identity)).scalar_one()
    assert after.id == before.id  # same identity, same history
    assert after.external_id == "AIDAALICE0000000000001"
    assert after.provisional is False


def test_roles_groups_membership_and_policy_documents(
    client: TestClient, db: Session
) -> None:
    token = _token(client, db)
    payload = details(
        UserDetailList=[
            user_entry("bob", "AIDABOB00000000000001", groups=["admins"])
        ],
        RoleDetailList=[role_entry("deploy-role", "AROADEPLOY0000000001")],
        GroupDetailList=[group_entry("admins", "AGPAADMINS0000000001")],
        Policies=[{
            "PolicyName": "local-policy",
            "PolicyId": "ANPALOCAL00000000001",
            "Arn": f"arn:aws:iam::{ACCOUNT}:policy/local-policy",
            "PolicyVersionList": [{
                "IsDefaultVersion": True,
                "Document": quote(json.dumps(
                    {"Version": "2012-10-17",
                     "Statement": [{"Effect": "Allow", "Action": "*",
                                    "Resource": "*"}]}
                )),
            }],
        }],
    )
    r = _upload(client, token, payload, "2026-08-02T00:00:00+00:00")
    assert r.status_code == 201, r.text
    types = {
        i.first_display_name: i.provider_type
        for i in db.execute(select(Identity)).scalars()
        if i.kind != IdentityKind.group
    }
    assert types == {"bob": "user", "deploy-role": "role"}
    group = db.execute(select(Identity).where(Identity.kind == IdentityKind.group)).scalar_one()
    assert group.first_display_name == "admins"
    membership = db.execute(select(Membership)).scalar_one()
    member = db.get(Identity, membership.member_id)
    assert member is not None and member.external_id == "AIDABOB00000000000001"
    definitions = db.execute(select(RoleDefinition)).scalars().all()
    customer = [d for d in definitions if d.managed_by == "customer" and d.contents]
    assert customer, "the customer policy document is a versioned role definition"
    assert customer[0].contents["Statement"][0]["Action"] == "*"
    assert db.execute(select(Grant)).scalars().all(), "attachments became grants"


def test_resurrection_is_a_new_identity_and_visible(
    client: TestClient, db: Session
) -> None:
    token = _token(client, db)
    assert _upload(
        client, token,
        details(UserDetailList=[user_entry("phoenix", "AIDAOLD00000000000001")]),
        "2026-08-01T00:00:00+00:00",
    ).status_code == 201
    # Same name, same ARN shape, new identifier: deleted and recreated.
    assert _upload(
        client, token,
        details(UserDetailList=[
            user_entry("phoenix", "AIDANEW00000000000001",
                       created="2026-07-01T00:00:00Z")
        ]),
        "2026-08-08T00:00:00+00:00",
    ).status_code == 201
    identities = db.execute(select(Identity)).scalars().all()
    assert len(identities) == 2  # D-016: a new principal, not an heir
    listing = client.get("/identities", headers=auth_header(token)).json()["rows"]
    assert all(i["name_reused"] for i in listing if i["display_name"] == "phoenix")


def test_truncated_export_is_rejected_whole(client: TestClient, db: Session) -> None:
    token = _token(client, db)
    payload = json.dumps({
        "IsTruncated": True,
        "UserDetailList": [user_entry("alice", "AIDAALICE0000000000001")],
    }).encode()
    r = _upload(client, token, payload, "2026-08-01T00:00:00+00:00")
    assert r.status_code == 422
    assert "truncated" in r.json()["detail"]
    assert db.execute(select(Identity)).scalars().all() == []


def test_mixed_accounts_reject_but_aws_managed_policies_do_not(
    client: TestClient, db: Session
) -> None:
    token = _token(client, db)
    # An AWS-managed policy ARN (account "aws") must not trip the check.
    ok = details(
        UserDetailList=[user_entry("alice", "AIDAALICE0000000000001")],
        Policies=[{
            "PolicyName": "AdministratorAccess",
            "Arn": "arn:aws:iam::aws:policy/AdministratorAccess",
            "PolicyVersionList": [],
        }],
    )
    assert _upload(client, token, ok, "2026-08-01T00:00:00+00:00").status_code == 201
    # A second real account must.
    mixed = details(
        UserDetailList=[
            user_entry("alice", "AIDAALICE0000000000002"),
            user_entry("eve", "AIDAEVE000000000000001", account="999999999999"),
        ],
    )
    r = _upload(client, token, mixed, "2026-08-02T00:00:00+00:00")
    assert r.status_code == 422
    assert "mixes accounts" in r.json()["detail"]
