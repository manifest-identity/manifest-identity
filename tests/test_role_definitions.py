"""Role definitions as versioned, authorizable objects (1.7).

Three halves. Comparing two versions of a definition is a reading
problem, tested against the shapes documents take, including the two
sides a comparison can be missing. Authorizing a definition is a record
problem, tested through the routes with the same discipline as the
other two records: appended, superseded, refused when it names a
version no import observed. And the delta's two role-level classes are
tested in both directions, one fixture that produces each and one that
does not, which is the standing rule for findings here.

The sentence that matters most is the one a reviewer reads when a role
changed after it was authorized. Before this it said "the role changed";
now it says what arrived.
"""

import json

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.compare import delta
from manifest_identity.core.roles import Role
from manifest_identity.models import Identity, RoleDefinition
from manifest_identity.observe import policy_analysis
from tests.conftest import ROLE_USERS, auth_header, login, make_user

ACCOUNT = "123456789012"
ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def allow(*actions: str, resource: str = "*") -> dict[str, object]:
    return {"Effect": "Allow", "Action": list(actions), "Resource": resource}


def document(*statements: dict[str, object]) -> dict[str, object]:
    return {"Version": "2012-10-17", "Statement": list(statements)}


# Comparing two versions.


def test_added_and_removed_actions_are_named() -> None:
    before = document(allow("s3:GetObject", "s3:ListBucket"))
    after = document(allow("s3:GetObject", "s3:PutObject", "s3:DeleteObject"))
    change = policy_analysis.describe_change(before, after)
    assert change.added == ["s3:deleteobject", "s3:putobject"]
    assert change.removed == ["s3:listbucket"]
    assert change.material
    assert "added s3:deleteobject, s3:putobject" in change.as_text()
    assert "removed s3:listbucket" in change.as_text()


def test_a_line_crossed_is_named_in_the_findings_own_words() -> None:
    """The reviewer's question is not which strings changed but whether
    the new version can do something the old one could not."""
    before = document(allow("ec2:DescribeInstances"))
    after = document(allow("iam:PassRole", "ec2:RunInstances"))
    change = policy_analysis.describe_change(before, after)
    assert any("passed role" in line for line in change.crossed)
    assert change.material


def test_a_version_that_only_removes_is_not_material() -> None:
    before = document(allow("s3:GetObject", "s3:PutObject"))
    after = document(allow("s3:GetObject"))
    change = policy_analysis.describe_change(before, after)
    assert change.removed == ["s3:putobject"]
    assert not change.material


def test_a_missing_side_is_said_and_not_read_as_empty() -> None:
    """Reading a missing document as an empty policy would make every
    action in the other version look newly added."""
    after = document(allow("s3:GetObject"))
    change = policy_analysis.describe_change(None, after)
    assert change.added == []
    assert change.undescribable
    assert "never observed" in change.as_text()
    both = policy_analysis.describe_change(None, None)
    assert both.undescribable
    assert not both.material


def test_everything_except_is_one_named_token() -> None:
    after = document({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"})
    actions = policy_analysis.allowed_actions(after)
    assert actions == frozenset({policy_analysis.EVERYTHING_EXCEPT + "iam:*"})
    change = policy_analysis.describe_change(document(allow("s3:GetObject")), after)
    assert "an allow written as everything except" in change.crossed


def test_a_long_list_is_bounded_with_a_count() -> None:
    many = [f"svc:Action{n:02d}" for n in range(20)]
    change = policy_analysis.describe_change(document(), document(allow(*many)))
    assert len(change.added) == 20
    text = change.as_text()
    assert "and 8 more" in text
    assert "svc:action19" not in text


# The record and its routes.


CUSTOM_ARN = f"arn:aws:iam::{ACCOUNT}:policy/team-tools"


def payload(actions: list[str]) -> dict[str, object]:
    return {
        "AccountId": ACCOUNT,
        "UserDetailList": [
            {
                "UserName": "holder",
                "UserId": "AIDAHOLDER00000000017",
                "Arn": f"arn:aws:iam::{ACCOUNT}:user/holder",
                "CreateDate": "2025-01-01T00:00:00Z",
                "AttachedManagedPolicies": [
                    {"PolicyName": "team-tools", "PolicyArn": CUSTOM_ARN},
                    {"PolicyName": "AdministratorAccess", "PolicyArn": ADMIN_ARN},
                ],
            }
        ],
        "Policies": [
            {
                "PolicyName": "team-tools",
                "Arn": CUSTOM_ARN,
                "PolicyVersionList": [
                    {"IsDefaultVersion": True, "Document": document(allow(*actions))}
                ],
            },
            {
                "PolicyName": "AdministratorAccess",
                "Arn": ADMIN_ARN,
                "PolicyVersionList": [
                    {"IsDefaultVersion": True, "Document": document(allow("*"))}
                ],
            },
        ],
    }


def import_at(
    client: TestClient, token: str, body: dict[str, object], captured: str
) -> None:
    response = client.post(
        "/imports/authorization-details",
        headers=auth_header(token),
        files={"file": ("d.json", json.dumps(body).encode(), "application/json")},
        data={"captured_at": captured},
    )
    assert response.status_code == 201, response.text


def seed(client: TestClient, db: Session) -> str:
    make_user(db, Role.administrator)
    token = login(client, ROLE_USERS[Role.administrator])
    import_at(client, token, payload(["s3:GetObject"]), "2026-07-01T00:00:00+00:00")
    return token


def custom_hash(db: Session) -> str:
    return db.execute(
        select(RoleDefinition.contents_hash)
        .where(RoleDefinition.external_id == CUSTOM_ARN)
        .order_by(RoleDefinition.id.desc())
    ).scalars().first()


def authorize_custom(client: TestClient, token: str, db: Session) -> dict[str, object]:
    response = client.post(
        "/role-definitions/authorize",
        headers=auth_header(token),
        json={
            "role_definition_external_id": CUSTOM_ARN,
            "role_definition_hash": custom_hash(db),
            "owner_kind": "team",
            "owner_ref": "platform-team",
            "justification": "the team's own tooling policy",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_the_list_shows_custom_definitions_and_never_the_providers_own(
    client: TestClient, db: Session
) -> None:
    token = seed(client, db)
    rows = client.get("/role-definitions", headers=auth_header(token)).json()
    names = {row["display_name"] for row in rows}
    assert "team-tools" in names
    assert "AdministratorAccess" not in names
    assert all(row["authorized"] is False for row in rows)


def test_authorizing_a_custom_definition_marks_it_and_supersedes_on_a_new_version(
    client: TestClient, db: Session
) -> None:
    token = seed(client, db)
    first = authorize_custom(client, token, db)
    assert first["authorized"] is True
    assert first["owner_ref"] == "platform-team"
    # The definition changes. Authorizing the new version supersedes the
    # old record for the same definition rather than sitting beside it.
    import_at(
        client, token, payload(["s3:GetObject", "s3:PutObject"]),
        "2026-08-01T00:00:00+00:00",
    )
    second = authorize_custom(client, token, db)
    assert second["authorization_id"] != first["authorization_id"]
    rows = client.get("/role-definitions", headers=auth_header(token)).json()
    mine = next(row for row in rows if row["display_name"] == "team-tools")
    assert mine["authorization_id"] == second["authorization_id"]


def test_a_version_no_import_observed_is_refused(
    client: TestClient, db: Session
) -> None:
    token = seed(client, db)
    response = client.post(
        "/role-definitions/authorize",
        headers=auth_header(token),
        json={
            "role_definition_external_id": CUSTOM_ARN,
            "role_definition_hash": "0" * 64,
            "owner_kind": "team",
            "owner_ref": "platform-team",
        },
    )
    assert response.status_code == 422
    assert "no import has observed" in response.json()["detail"]


def test_a_providers_definition_cannot_be_authorized_here(
    client: TestClient, db: Session
) -> None:
    token = seed(client, db)
    provider_hash = db.execute(
        select(RoleDefinition.contents_hash).where(RoleDefinition.external_id == ADMIN_ARN)
    ).scalars().first()
    response = client.post(
        "/role-definitions/authorize",
        headers=auth_header(token),
        json={
            "role_definition_external_id": ADMIN_ARN,
            "role_definition_hash": provider_hash,
            "owner_kind": "team",
            "owner_ref": "platform-team",
        },
    )
    assert response.status_code == 422
    assert "provider" in response.json()["detail"]


def test_revoking_writes_a_row_and_the_definition_reads_unauthorized(
    client: TestClient, db: Session
) -> None:
    token = seed(client, db)
    first = authorize_custom(client, token, db)
    response = client.post(
        f"/role-definitions/{first['authorization_id']}/revoke",
        headers=auth_header(token),
        json={"reason": "the team was dissolved"},
    )
    assert response.status_code == 201, response.text
    rows = client.get("/role-definitions", headers=auth_header(token)).json()
    mine = next(row for row in rows if row["display_name"] == "team-tools")
    assert mine["authorized"] is False


# The two role-level delta classes.


def holder(db: Session) -> Identity:
    return db.execute(
        select(Identity).where(Identity.external_id == "AIDAHOLDER00000000017")
    ).scalar_one()


def test_a_custom_definition_nobody_authorized_is_a_finding(
    client: TestClient, db: Session
) -> None:
    seed(client, db)
    kinds = [f.kind for f in delta.for_definitions(db)]
    assert delta.CUSTOM_DEFINITION_NOT_AUTHORIZED in kinds
    # The provider's own policy is never asked to justify itself here.
    assert all(
        f.role != "AdministratorAccess" for f in delta.for_definitions(db)
    )


def test_authorizing_it_clears_that_finding(client: TestClient, db: Session) -> None:
    token = seed(client, db)
    authorize_custom(client, token, db)
    kinds = [f.kind for f in delta.for_definitions(db)]
    assert delta.CUSTOM_DEFINITION_NOT_AUTHORIZED not in kinds
    assert delta.CUSTOM_DEFINITION_CHANGED not in kinds


def test_a_definition_that_moved_after_authorization_names_what_arrived(
    client: TestClient, db: Session
) -> None:
    """The role-level twin of the per-holder finding, for the person who
    owns the policy rather than the people who hold it."""
    token = seed(client, db)
    authorize_custom(client, token, db)
    import_at(
        client, token, payload(["s3:GetObject", "iam:PassRole", "ec2:RunInstances"]),
        "2026-08-01T00:00:00+00:00",
    )
    found = [
        f for f in delta.for_definitions(db)
        if f.kind == delta.CUSTOM_DEFINITION_CHANGED
    ]
    assert len(found) == 1
    assert found[0].actions_added == ["ec2:runinstances", "iam:passrole"]
    assert any("passed role" in line for line in found[0].capabilities_gained)
    assert "added ec2:runinstances, iam:passrole" in found[0].detail


def test_the_per_holder_finding_now_names_the_change_too(
    client: TestClient, db: Session
) -> None:
    """What 1.7 owed the existing finding: it said the role changed and
    now says what arrived."""
    token = seed(client, db)
    identity = holder(db)
    response = client.post(
        f"/identities/{identity.id}/authorizations",
        headers=auth_header(token),
        json={
            "role_definition_external_id": CUSTOM_ARN,
            "role_definition_hash": custom_hash(db),
            "path": [{"via": "direct", "ref": "", "mode": "active"}],
            "owner_kind": "team",
            "owner_ref": "platform-team",
            "justification": "holds the team tooling",
        },
    )
    assert response.status_code == 201, response.text
    import_at(
        client, token, payload(["s3:GetObject", "s3:DeleteBucket"]),
        "2026-08-01T00:00:00+00:00",
    )
    changed = [
        f for f in delta.for_identity(db, holder(db))
        if f.kind == delta.DEFINITION_CHANGED
    ]
    assert len(changed) == 1
    assert changed[0].actions_added == ["s3:deletebucket"]
    assert "added s3:deletebucket" in changed[0].detail


def test_the_estate_delta_carries_definition_findings(
    client: TestClient, db: Session
) -> None:
    token = seed(client, db)
    body = client.get("/delta", headers=auth_header(token)).json()
    assert delta.CUSTOM_DEFINITION_NOT_AUTHORIZED in body["counts"]
    assert any(
        row["kind"] == delta.CUSTOM_DEFINITION_NOT_AUTHORIZED
        for row in body["definition_findings"]
    )
