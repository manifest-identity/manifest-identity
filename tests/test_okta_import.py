"""The sixth provider (1.14e): an Okta organization on the neutral tables.

The document is the management API's objects under a key each, so the
parser is held to the same contract as the others and the assertions
read the result through the same routes: a user whose credentials Okta
holds has a password and a federated one does not, a group carries a
role to its members with the group's name kept, an administrator role
reads from a table of what its type may do, a custom role from its
permissions, and every application assignment is a grant somebody can
be asked to authorize.
"""

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.compare import delta
from manifest_identity.core.roles import Role
from manifest_identity.models import Credential, Grant, Identity, RoleDefinition
from manifest_identity.observe import policy_analysis
from manifest_identity.observe.okta_importer import custom_role_capabilities, role_capabilities
from manifest_identity.observe.providers.okta import org_export as export
from manifest_identity.sample_data import GENERATIONS, file_set
from tests.conftest import ROLE_USERS, auth_header, login, make_user


def operator(client: TestClient, db: Session) -> str:
    make_user(db, Role.operator)
    return login(client, ROLE_USERS[Role.operator])


def import_generation(client: TestClient, token: str, generation: int) -> tuple[int, dict]:
    captured = GENERATIONS[generation]
    name = f"{captured.strftime('%Y-%m-%d')}-okta-org.json"
    response = client.post(
        "/imports/okta-org",
        headers=auth_header(token),
        files={"file": (name, file_set()[name].encode(), "application/json")},
        data={"captured_at": captured.isoformat()},
    )
    return response.status_code, response.json()


def import_all(client: TestClient, token: str) -> None:
    for generation in range(len(GENERATIONS)):
        status, body = import_generation(client, token, generation)
        assert status == 201, body


def inventory(client: TestClient, token: str) -> dict[str, dict]:
    rows = client.get("/identities?limit=500", headers=auth_header(token)).json()["rows"]
    return {row["display_name"]: row for row in rows}


def detail(client: TestClient, token: str, identity_id: int) -> dict:
    return client.get(f"/identities/{identity_id}", headers=auth_header(token)).json()


def named(db: Session, name: str) -> Identity:
    return db.execute(select(Identity).where(Identity.first_display_name == name)).scalar_one()


# The parser.

USER = "00utest0000000000001"
GROUP = "00gtest0000000000001"


def minimal(**overrides: object) -> bytes:
    document: dict[str, object] = {
        "org": {"id": "00otest0000000000001", "subdomain": "acme"},
        "users": [{"id": USER, "profile": {"login": "alice@acme.test"}, "status": "ACTIVE"}],
        "groups": [{"id": GROUP, "profile": {"name": "g"}, "members": [USER]}],
    }
    document.update(overrides)
    return json.dumps(document).encode()


def test_the_parser_reads_the_apis_own_shapes() -> None:
    parsed = export.parse_org_export(minimal(
        role_assignments=[{"id": "ra0test0000000000001", "type": "ORG_ADMIN",
                           "assignmentType": "GROUP", "principal_id": GROUP}],
        apps=[{"id": "0oatest0000000000001", "label": "Payroll",
               "assignments": [{"principal_id": USER, "scope": "USER"}]}],
    ))
    assert parsed.users[0].provider_type == "OKTA"
    assert parsed.users[0].factors is None, "factors not joined in is unknown, not none"
    assert parsed.role_assignments[0].assignment_type == "GROUP"
    assert parsed.apps[0].assignments[0].principal_id == USER


@pytest.mark.parametrize(
    ("overrides", "rule"),
    [
        ({"org": {"id": "short", "subdomain": "acme"}}, "not an Okta identifier"),
        ({"users": [{"id": USER, "profile": {"login": "a@b"}, "status": "ASLEEP"}]},
         "status is not one"),
        ({"groups": [{"id": GROUP, "profile": {"name": "g"},
                      "members": ["00unobody00000000001"]}]}, "does not list as a user"),
        ({"role_assignments": [{"id": "ra0test0000000000001", "type": "ORG_ADMIN",
                                "assignmentType": "USER", "principal_id": GROUP}]},
         "disagrees with its principal"),
        ({"role_assignments": [{"id": "ra0test0000000000001", "type": "CUSTOM",
                                "assignmentType": "USER", "principal_id": USER}]},
         "must name its role"),
    ],
)
def test_a_file_that_breaks_the_apis_rules_is_refused_without_echo(
    overrides: dict[str, object], rule: str
) -> None:
    with pytest.raises(export.ParseError) as caught:
        export.parse_org_export(minimal(**overrides))
    message = str(caught.value)
    assert rule in message
    for value in ("short", "ASLEEP", "00unobody"):
        assert value not in message


# The capabilities.


def test_administrator_roles_read_from_the_table_of_types() -> None:
    assert role_capabilities("SUPER_ADMIN", "x")["administers"] is True
    org = role_capabilities("ORG_ADMIN", "x")
    assert org["changes_access"] is True and org["administers"] is False
    assert policy_analysis.read_policy(role_capabilities("HELP_DESK_ADMIN", "x")).iam_mutating
    reader = role_capabilities("READ_ONLY_ADMIN", "x")
    assert reader["reads"] is True and reader["writes"] is False
    app = role_capabilities("APP_ADMIN", "x")
    assert app["writes"] is True and app["changes_access"] is False


def test_a_custom_role_reads_from_its_permissions_and_names_them() -> None:
    reader = custom_role_capabilities(export.ParsedCustomRole(
        id="cr0test0000000000001", label="Auditor",
        permissions=["okta.users.read", "okta.groups.read"],
    ))
    assert reader["reads"] is True and reader["changes_access"] is False
    grown = custom_role_capabilities(export.ParsedCustomRole(
        id="cr0test0000000000001", label="Auditor",
        permissions=["okta.users.read", "okta.groups.read", "okta.users.manage"],
    ))
    assert grown["changes_access"] is True
    assert policy_analysis.describe_change(reader, grown).added == ["okta.users.manage"]


# The importer.


def test_the_organization_becomes_the_neutral_rows(client: TestClient, db: Session) -> None:
    token = operator(client, db)
    status, body = import_generation(client, token, 0)
    assert status == 201, body
    assert body["account"] == "sample-org"
    rows = inventory(client, token)
    assert rows["sam@example.test"]["identity_type"] == "user"
    assert "okta-admins" not in rows, "a group stays out of the inventory"
    groups = {g["name"]: g for g in client.get("/groups", headers=auth_header(token)).json()}
    assert groups["Everyone"]["members"] == 5
    assert groups["okta-admins"]["privileged"] is True


def test_only_a_user_okta_holds_the_password_of_has_one_here(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    import_generation(client, token, 0)
    dev = named(db, "dev@example.test")
    assert db.execute(
        select(Credential).where(Credential.identity_id == dev.id)
    ).scalars().all() == [], "a federated user signs in elsewhere"
    former = named(db, "former@example.test")
    password = db.execute(
        select(Credential).where(Credential.identity_id == former.id)
    ).scalar_one()
    assert password.kind == "password" and password.active is False
    mike = named(db, "mike@example.test")
    d = detail(client, token, mike.id)
    assert d["kind"] == "person"


def test_a_group_carries_its_role_and_its_app_to_the_members_with_the_hop_kept(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    import_generation(client, token, 0)
    rita = named(db, "rita@example.test")
    d = detail(client, token, rita.id)
    held = {(h["role"], tuple(x["ref"] for x in h["path"])) for h in d["holds_now"]}
    assert ("Organization Administrator", ("okta-admins",)) in held
    assert ("Payroll", ("okta-admins",)) in held
    grants = db.execute(
        select(Grant).where(Grant.source_kind == "app_assignment")
    ).scalars().all()
    assert len(grants) == 3, "two group assignments and one direct"


def test_an_inactive_assignment_is_not_held(client: TestClient, db: Session) -> None:
    token = operator(client, db)
    import_generation(client, token, 0)
    former = named(db, "former@example.test")
    assert detail(client, token, former.id)["holds_now"] == []
    assert db.execute(
        select(RoleDefinition).where(RoleDefinition.external_id == "okta:role:READ_ONLY_ADMIN")
    ).scalar_one_or_none() is None, "a role nobody holds is not a definition yet"


def test_the_same_snapshot_twice_is_a_conflict_and_the_wrong_door_says_so(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    assert import_generation(client, token, 0)[0] == 201
    status, body = import_generation(client, token, 0)
    assert status == 409 and "already imported" in body["detail"]
    name = f"{GENERATIONS[0].strftime('%Y-%m-%d')}-okta-org.json"
    response = client.post(
        "/imports/azure-tenant",
        headers=auth_header(token),
        files={"file": (name, file_set()[name].encode(), "application/json")},
        data={"captured_at": GENERATIONS[0].isoformat()},
    )
    assert response.status_code == 422
    assert "shaped like an Okta organization export" in response.json()["detail"]


# The findings and the delta.


def test_the_sample_organization_produces_the_findings_it_was_built_for(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    import_all(client, token)
    rows = inventory(client, token)

    def codes(name: str) -> set[str]:
        return {f["code"] for f in detail(client, token, rows[name]["id"])["findings"]}

    assert "admin_equivalent" in codes("sam@example.test")
    # Rita administers the organization through her group; Mike has no
    # second factor, no sign-in, and a custom role that grew to manage
    # users; the help desk became a user administrator in the third month.
    assert "iam_mutating" in codes("rita@example.test")
    assert {"password_without_mfa", "unused_identity", "iam_mutating"} <= codes("mike@example.test")
    assert "iam_mutating" in codes("helpdesk@example.test")
    dev = rows["dev@example.test"]
    assert dev["critical"] == 0 and dev["warning"] == 0, "a federated developer is quiet"
    former = rows["former@example.test"]
    assert former["critical"] == 0 and former["warning"] == 0, "deprovisioned is quiet"


def test_the_grown_custom_role_and_every_app_assignment_are_differences(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    import_all(client, token)
    findings = delta.for_definitions(db)
    auditor = [f for f in findings if f.role_ref == "okta:role:custom:cr0sample00000000001"]
    assert auditor and auditor[0].kind == delta.CUSTOM_DEFINITION_NOT_AUTHORIZED
    mike = named(db, "mike@example.test")
    held = {f.role for f in delta.for_identity(db, mike) if f.kind == delta.HELD_NOT_AUTHORIZED}
    assert "okta:app:0oasample00000000001" in held, "the payroll application, directly"
    assert "okta:app:0oasample00000000002" in held, "source control, through engineering"
