"""The fifth provider (1.14d): an Azure and Entra tenant on the neutral tables.

The document is Graph's objects and the command line's output under a
key each, so the parser is held to the same contract as the others and
the assertions read the result through the same routes: a member signs
in and a guest is from another tenant, a service principal's secrets
and certificates are credentials with windows, a group inside a group
passes its members up, a directory role is held standing by a member
and eligibly by a PIM instance, and an assignment sits at the
subscription or the resource group it names.
"""

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.compare import delta
from manifest_identity.core.models import ScopeNode
from manifest_identity.core.roles import Role
from manifest_identity.models import Credential, Grant, Identity, Membership, RoleDefinition
from manifest_identity.observe import policy_analysis
from manifest_identity.observe.azure_importer import (
    azure_role_capabilities,
    directory_role_capabilities,
)
from manifest_identity.observe.providers.azure import tenant_export as export
from manifest_identity.sample_data import GENERATIONS, SUBSCRIPTION, TENANT, file_set
from tests.conftest import ROLE_USERS, auth_header, login, make_user


def operator(client: TestClient, db: Session) -> str:
    make_user(db, Role.operator)
    return login(client, ROLE_USERS[Role.operator])


def import_generation(client: TestClient, token: str, generation: int) -> tuple[int, dict]:
    captured = GENERATIONS[generation]
    name = f"{captured.strftime('%Y-%m-%d')}-azure-tenant.json"
    response = client.post(
        "/imports/azure-tenant",
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

GUID = "00000000-0000-4000-8000-0000000000{:02d}"


def minimal(**overrides: object) -> bytes:
    document: dict[str, object] = {
        "tenant": {"id": GUID.format(1), "displayName": "acme"},
        "users": [{"id": GUID.format(2), "userPrincipalName": "alice@acme.test"}],
        "groups": [{"id": GUID.format(3), "displayName": "g",
                    "members": [{"@odata.type": "#microsoft.graph.user", "id": GUID.format(2)}]}],
    }
    document.update(overrides)
    return json.dumps(document).encode()


def test_the_parser_reads_graphs_own_shapes() -> None:
    parsed = export.parse_tenant_export(minimal(
        subscriptions=[{"id": GUID.format(9), "displayName": "s", "role_assignments": [
            {"principalId": GUID.format(2), "principalType": "User",
             "roleDefinitionId": "/subscriptions/x/providers/Microsoft.Authorization/"
                                 "roleDefinitions/" + GUID.format(7),
             "roleDefinitionName": "Reader",
             "scope": f"/subscriptions/{GUID.format(9)}/resourceGroups/app/providers/x/y"},
        ]}],
    ))
    assert parsed.users[0].guest is False
    assert parsed.groups[0].members[0].kind == "user"
    assignment = parsed.subscriptions[0].assignments[0]
    assert assignment.role_definition_id == GUID.format(7)
    assert assignment.resource_group == "app"


@pytest.mark.parametrize(
    ("overrides", "rule"),
    [
        ({"tenant": {"id": "not-a-guid", "displayName": "x"}}, "not a GUID"),
        ({"users": [{"id": GUID.format(2), "userPrincipalName": "a@b", "userType": "Robot"}]},
         "Member or Guest"),
        ({"groups": [{"id": GUID.format(3), "displayName": "g", "members": [
            {"@odata.type": "#microsoft.graph.user", "id": GUID.format(8)}]}]},
         "does not list"),
        ({"subscriptions": [{"id": GUID.format(9), "role_assignments": [
            {"principalId": GUID.format(2), "principalType": "User",
             "roleDefinitionId": "r", "roleDefinitionName": "Reader",
             "scope": "/subscriptions/" + GUID.format(4)}]}]}, "not inside this subscription"),
        ({"tenant": {"id": GUID.format(1), "displayName": "x", "cloud": "AzureMars"}},
         "AzureCloud or AzureUSGovernment"),
    ],
)
def test_a_file_that_breaks_the_directorys_rules_is_refused_without_echo(
    overrides: dict[str, object], rule: str
) -> None:
    with pytest.raises(export.ParseError) as caught:
        export.parse_tenant_export(minimal(**overrides))
    message = str(caught.value)
    assert rule in message
    for value in ("not-a-guid", "Robot", "AzureMars"):
        assert value not in message


# The capabilities.


def test_directory_roles_read_from_their_published_names() -> None:
    assert directory_role_capabilities("Global Administrator", "t")["administers"] is True
    user_admin = directory_role_capabilities("User Administrator", "t")
    assert user_admin["changes_access"] is True and user_admin["administers"] is False
    assert policy_analysis.read_policy(user_admin).iam_mutating
    reader = directory_role_capabilities("Global Reader", "t")
    assert reader["reads"] is True and reader["writes"] is False
    other = directory_role_capabilities("Exchange Administrator", "t")
    assert other["writes"] is True and other["changes_access"] is False


def test_azure_roles_read_from_their_actions_when_listed_and_their_names_otherwise() -> None:
    owner = azure_role_capabilities("Owner", None)
    assert owner["administers"] is True
    assert azure_role_capabilities("User Access Administrator", None)["changes_access"] is True
    assert azure_role_capabilities("Storage Blob Data Reader", None)["writes"] is False
    custom = azure_role_capabilities("Deployer", export.ParsedRoleDefinition(
        id="x", name="Deployer", custom=True,
        actions=["Microsoft.Compute/*/write", "Microsoft.Authorization/roleAssignments/write"],
        not_actions=["Microsoft.Compute/virtualMachines/delete"],
    ))
    assert custom["changes_access"] is True and custom["administers"] is False
    assert policy_analysis.allowed_actions(custom) == {
        "microsoft.compute/*/write", "microsoft.authorization/roleassignments/write",
        "not microsoft.compute/virtualmachines/delete",
    }


# The importer.


def test_the_tenant_becomes_the_neutral_rows(client: TestClient, db: Session) -> None:
    token = operator(client, db)
    status, body = import_generation(client, token, 0)
    assert status == 201, body
    assert body["account"] == TENANT
    rows = inventory(client, token)
    assert rows["Sam Owner"]["identity_type"] == "user"
    assert rows["deploy-pipeline"]["identity_type"] == "application"
    assert rows["webapp-identity"]["identity_type"] == "managedidentity"
    assert "cloud-admins" not in rows, "a group stays out of the inventory"
    guest = named(db, "Contractor Lee")
    assert guest.home == "other_tenant" and guest.origin == "guest"
    assert db.execute(
        select(Credential).where(Credential.identity_id == guest.id)
    ).scalars().all() == [], "a guest holds no password here"
    nodes = {n.kind: n for n in db.execute(
        select(ScopeNode).where(ScopeNode.provider == "azure")
    ).scalars()}
    assert nodes["tenant"].external_id == TENANT
    assert nodes["subscription"].parent_id == nodes["tenant"].id
    assert nodes["resource_group"].parent_id == nodes["subscription"].id


def test_secrets_and_certificates_are_credentials_with_windows(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    import_generation(client, token, 0)
    legacy = named(db, "legacy-integration")
    credentials = {
        c.external_id[-2:]: c for c in db.execute(
            select(Credential).where(Credential.identity_id == legacy.id)
        ).scalars()
    }
    assert credentials["02"].kind == "client_secret" and credentials["02"].active is False
    assert credentials["03"].kind == "client_secret" and credentials["03"].active is True
    assert credentials["04"].kind == "certificate" and credentials["04"].active is True
    d = detail(client, token, legacy.id)
    codes = {f["code"] for f in d["findings"]}
    # An application's certificate is not an AWS signing certificate.
    assert "legacy_certificate" not in codes
    assert d["kind"] == "service"


def test_a_group_inside_a_group_passes_its_members_up(client: TestClient, db: Session) -> None:
    token = operator(client, db)
    import_generation(client, token, 0)
    rita = named(db, "Rita Ops")
    memberships = {
        m.group_id for m in db.execute(
            select(Membership).where(Membership.member_id == rita.id)
        ).scalars()
    }
    groups = {g.first_display_name: g.id for g in db.execute(
        select(Identity).where(Identity.kind == "group")
    ).scalars()}
    assert memberships == {groups["cloud-admins"], groups["engineering"], groups["developers"]}
    d = detail(client, token, rita.id)
    held = {(h["role"], tuple(x["ref"] for x in h["path"])) for h in d["holds_now"]}
    assert ("Owner", ("cloud-admins",)) in held
    assert ("Contributor", ("developers",)) in held


def test_an_eligibility_is_what_an_identity_can_obtain_and_not_what_it_holds(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    import_generation(client, token, 0)
    rita = named(db, "Rita Ops")
    d = detail(client, token, rita.id)
    obtainable = [h["role"] for h in d["can_obtain"]]
    assert obtainable == ["Global Administrator"]
    assert "Global Administrator" not in [h["role"] for h in d["holds_now"]]
    # Rita administers the subscription through the cloud-admins group,
    # which is standing; the eligible directory role must not be what
    # the finding names.
    findings = {f["code"]: f["explanation"] for f in d["findings"]}
    assert "Global Administrator" not in findings["admin_equivalent"], "eligible is not held"
    assert "cloud-admins" in findings["admin_equivalent"]
    assert "iam_mutating" not in findings, (
        "the standing User Administrator role is subsumed by administering"
    )
    grant = db.execute(
        select(Grant).where(Grant.identity_id == rita.id, Grant.mode == "eligible")
    ).scalar_one()
    assert grant.source_kind == "role_eligibility"


def test_an_assignment_sits_at_the_node_its_scope_names(client: TestClient, db: Session) -> None:
    token = operator(client, db)
    import_generation(client, token, 0)
    rows = {
        (i.first_display_name, d.display_name_last): n
        for g, d, i, n in db.execute(
            select(Grant, RoleDefinition, Identity, ScopeNode)
            .join(RoleDefinition, Grant.role_definition_id == RoleDefinition.id)
            .join(Identity, Grant.identity_id == Identity.id)
            .join(ScopeNode, Grant.scope_node_id == ScopeNode.id)
            .where(Grant.source_kind == "role_assignment")
        ).all()
    }
    assert rows[("cloud-admins", "Owner")].kind == "subscription"
    assert rows[("Contractor Lee", "Contributor")].display_name == "app"
    assert rows[("legacy-integration", "Owner")].display_name == "legacy"
    # An assignment to a principal the directory no longer lists is a
    # guest with origin unresolved, so it shows rather than vanishing.
    unresolved = db.execute(
        select(Identity).where(Identity.origin == "unresolved")
    ).scalar_one()
    assert unresolved.home == "other_tenant"


def test_the_same_snapshot_twice_is_a_conflict_and_the_wrong_door_says_so(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    assert import_generation(client, token, 0)[0] == 201
    status, body = import_generation(client, token, 0)
    assert status == 409 and "already imported" in body["detail"]
    name = f"{GENERATIONS[0].strftime('%Y-%m-%d')}-azure-tenant.json"
    response = client.post(
        "/imports/google-cloud",
        headers=auth_header(token),
        files={"file": (name, file_set()[name].encode(), "application/json")},
        data={"captured_at": GENERATIONS[0].isoformat()},
    )
    assert response.status_code == 422
    assert "shaped like an Azure and Entra tenant export" in response.json()["detail"]


# The findings and the delta.


def test_the_sample_tenant_produces_the_findings_it_was_built_for(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    import_all(client, token)
    rows = inventory(client, token)

    def codes(name: str) -> set[str]:
        return {f["code"] for f in detail(client, token, rows[name]["id"])["findings"]}

    assert "admin_equivalent" in codes("Sam Owner")
    assert {"password_without_mfa", "unused_identity"} <= codes("Legacy Mike")
    assert "iam_mutating" in codes("Legacy Mike"), "User Access Administrator in the third month"
    assert "admin_equivalent" in codes("legacy-integration"), "Owner of a resource group"
    assert "admin_equivalent" in codes("Contractor Lee"), "a guest made Owner in the second month"
    former = rows["Former Employee"]
    assert former["critical"] == 0 and former["warning"] == 0, "a disabled account is quiet"
    assert rows["webapp-identity"]["critical"] == 0


def test_the_guests_grown_grant_and_the_orphaned_assignment_are_differences(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    import_all(client, token)
    guest = named(db, "Contractor Lee")
    mine = delta.for_identity(db, guest)
    held = [f.role for f in mine if f.kind == delta.HELD_NOT_AUTHORIZED]
    assert held == [f"azure:role:{'8e3af657-a8ff-443c-a75c-2fe8c4bcb635'}"]
    unresolved = db.execute(select(Identity).where(Identity.origin == "unresolved")).scalar_one()
    assert any(f.kind == delta.HELD_NOT_AUTHORIZED for f in delta.for_identity(db, unresolved))
    rita = named(db, "Rita Ops")
    kinds = {f.kind for f in delta.for_identity(db, rita)}
    assert delta.ELIGIBLE_NOT_AUTHORIZED in kinds
    assert SUBSCRIPTION  # the subscription the assignments name
