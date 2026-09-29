"""The fourth provider (1.14c): a Google Cloud project on the neutral tables.

The document is gcloud's own answers under a key each, so the parser
is held to the same contract as the others and the assertions read
the result through the same routes: a service account is a service
whose user-managed keys are credentials with ages, a user is seen only
through its bindings, a group and a domain and the public forms and a
deleted principal are guests named for what they are, and a role's
permissions become capabilities the privilege reading speaks.
"""

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.compare import delta
from manifest_identity.core.roles import Role
from manifest_identity.models import Credential, Identity, RoleDefinition
from manifest_identity.observe import policy_analysis
from manifest_identity.observe.google_cloud_importer import (
    capabilities_from_name,
    capabilities_from_permissions,
)
from manifest_identity.observe.providers.google_cloud import project_export as export
from manifest_identity.sample_data import GENERATIONS, PROJECT, file_set
from tests.conftest import ROLE_USERS, auth_header, login, make_user


def operator(client: TestClient, db: Session) -> str:
    make_user(db, Role.operator)
    return login(client, ROLE_USERS[Role.operator])


def import_generation(client: TestClient, token: str, generation: int) -> tuple[int, dict]:
    captured = GENERATIONS[generation]
    name = f"{captured.strftime('%Y-%m-%d')}-google-cloud.json"
    response = client.post(
        "/imports/google-cloud",
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


def minimal(**overrides: object) -> bytes:
    document: dict[str, object] = {
        "project": {"projectId": "acme-prod", "projectNumber": "42"},
        "policy": {"bindings": [
            {"role": "roles/owner", "members": ["user:alice@example.test"]},
        ]},
        "service_accounts": [
            {"email": "ci@acme-prod.iam.gserviceaccount.com", "uniqueId": "7"},
        ],
    }
    document.update(overrides)
    return json.dumps(document).encode()


def test_the_parser_reads_gclouds_own_shapes() -> None:
    parsed = export.parse_project_export(minimal(
        keys={"ci@acme-prod.iam.gserviceaccount.com": [
            {"name": "projects/p/serviceAccounts/x/keys/k1", "keyType": "USER_MANAGED",
             "validAfterTime": "2026-01-01T00:00:00Z", "validBeforeTime": "9999-12-31T23:59:59Z"},
        ]},
    ))
    assert parsed.project_id == "acme-prod"
    assert parsed.bindings[0].members[0].kind == "user"
    assert parsed.service_accounts[0].keys[0].id == "k1"


@pytest.mark.parametrize(
    ("member", "kind", "name"),
    [
        ("user:a@example.test", "user", "a@example.test"),
        ("serviceAccount:s@p.iam.gserviceaccount.com", "serviceAccount",
         "s@p.iam.gserviceaccount.com"),
        ("group:g@example.test", "group", "g@example.test"),
        ("domain:example.test", "domain", "example.test"),
        ("allUsers", "public", "allUsers"),
        ("allAuthenticatedUsers", "public", "allAuthenticatedUsers"),
        ("deleted:user:gone@example.test?uid=1", "deleted", "user:gone@example.test?uid=1"),
        ("principalSet://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/*",
         "federated", "iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/*"),
    ],
)
def test_every_member_form_a_policy_writes_is_read(member: str, kind: str, name: str) -> None:
    parsed = export.parse_member(member, "here")
    assert (parsed.kind, parsed.name) == (kind, name)


@pytest.mark.parametrize(
    ("overrides", "rule"),
    [
        ({"project": {"projectId": "Not Valid", "projectNumber": "1"}}, "project identifier"),
        ({"policy": {"bindings": [{"role": "owner", "members": []}]}}, "not a role name"),
        ({"policy": {"bindings": [{"role": "roles/owner", "members": ["robot:x"]}]}},
         "not written the way a policy writes one"),
        ({"service_accounts": [{"email": "a@b", "uniqueId": "1"},
                               {"email": "a@b", "uniqueId": "2"}]}, "appears twice"),
        ({"keys": {"ci@acme-prod.iam.gserviceaccount.com": [
            {"name": "k", "keyType": "MAGIC"}]}}, "USER_MANAGED or SYSTEM_MANAGED"),
    ],
)
def test_a_file_that_breaks_the_providers_rules_is_refused_without_echo(
    overrides: dict[str, object], rule: str
) -> None:
    with pytest.raises(export.ParseError) as caught:
        export.parse_project_export(minimal(**overrides))
    message = str(caught.value)
    assert rule in message
    for value in ("Not Valid", "robot", "MAGIC"):
        assert value not in message


# The capabilities.


def test_the_fixed_roles_read_as_the_provider_defines_them() -> None:
    owner = capabilities_from_name("roles/owner")
    assert owner["administers"] is True
    assert policy_analysis.read_policy(owner).admin_equivalent
    editor = capabilities_from_name("roles/editor")
    assert editor["administers"] is False and editor["changes_access"] is False
    assert editor["writes"] is True
    key_admin = capabilities_from_name("roles/iam.serviceAccountKeyAdmin")
    assert key_admin["changes_access"] is True
    assert policy_analysis.read_policy(key_admin).iam_mutating


def test_an_unlisted_role_is_read_from_its_name() -> None:
    viewer = capabilities_from_name("roles/bigquery.dataViewer")
    assert viewer["reads"] is True and viewer["writes"] is False
    admin = capabilities_from_name("roles/storage.admin")
    assert admin["writes"] is True and admin["changes_access"] is False
    assert admin["administers"] is False, "a service administrator does not administer the project"


def test_a_permission_list_names_what_a_role_can_do() -> None:
    plain = capabilities_from_permissions("projects/p/roles/x", [
        "compute.instances.get", "compute.instances.create",
    ])
    assert plain["writes"] is True and plain["changes_access"] is False
    assert policy_analysis.allowed_actions(plain) == {
        "compute.instances.get", "compute.instances.create",
    }
    grown = capabilities_from_permissions("projects/p/roles/x", [
        "compute.instances.get", "compute.instances.create",
        "resourcemanager.projects.setIamPolicy",
    ])
    assert grown["changes_access"] is True
    change = policy_analysis.describe_change(plain, grown)
    assert change.added == ["resourcemanager.projects.setiampolicy"]
    acts_as = capabilities_from_permissions("projects/p/roles/y", ["iam.serviceAccounts.actAs"])
    assert acts_as["changes_access"] is True, "acting as an account is holding its access"


# The importer.


def test_the_project_becomes_the_neutral_rows(client: TestClient, db: Session) -> None:
    token = operator(client, db)
    status, body = import_generation(client, token, 0)
    assert status == 201, body
    assert body["account"] == PROJECT
    rows = inventory(client, token)
    assert rows[f"ci@{PROJECT}.iam.gserviceaccount.com"]["identity_type"] == "serviceaccount"
    assert rows["sam@example.test"]["identity_type"] == "user"
    assert rows["allUsers"]["identity_type"] == "public"
    assert rows["developers@example.test"]["identity_type"] == "group"
    ci = named(db, f"ci@{PROJECT}.iam.gserviceaccount.com")
    # Keyed by the identifier, not the address.
    assert ci.external_id == "serviceaccount:100000000000000000010"
    public = named(db, "allUsers")
    assert public.home == "consumer" and public.origin == "public"
    group = named(db, "developers@example.test")
    assert group.home == "identity_provider" and group.kind == "external"


def test_only_user_managed_keys_are_credentials_and_they_carry_their_ages(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    import_generation(client, token, 0)
    deploy = named(db, f"deploy@{PROJECT}.iam.gserviceaccount.com")
    assert db.execute(
        select(Credential).where(Credential.identity_id == deploy.id)
    ).scalars().all() == [], "a provider-managed key is nobody's credential"
    legacy = named(db, f"legacy@{PROJECT}.iam.gserviceaccount.com")
    keys = db.execute(select(Credential).where(Credential.identity_id == legacy.id)).scalars().all()
    assert {k.external_id for k in keys} == {"b1", "b2"}
    assert all(k.kind == "access_key" and k.active for k in keys)
    d = detail(client, token, legacy.id)
    codes = {f["code"] for f in d["findings"]}
    assert {"key_age", "multiple_active_keys"} <= codes


def test_a_definitions_permissions_and_a_binding_condition_are_kept(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    import_generation(client, token, 0)
    deployer = db.execute(
        select(RoleDefinition).where(
            RoleDefinition.external_id == f"projects/{PROJECT}/roles/deployer"
        )
    ).scalar_one()
    assert deployer.managed_by == "customer"
    assert deployer.contents is not None
    assert "iam.serviceAccounts.actAs" in deployer.contents["actions"]
    owner = db.execute(
        select(RoleDefinition).where(RoleDefinition.external_id == "roles/owner")
    ).scalar_one()
    assert owner.managed_by == "provider"
    deploy = named(db, f"deploy@{PROJECT}.iam.gserviceaccount.com")
    d = detail(client, token, deploy.id)
    assert [h["role"] for h in d["holds_now"]] == ["Deployer"]


def test_the_same_snapshot_twice_is_a_conflict_and_the_wrong_door_says_so(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    assert import_generation(client, token, 0)[0] == 201
    status, body = import_generation(client, token, 0)
    assert status == 409 and "already imported" in body["detail"]
    name = f"{GENERATIONS[0].strftime('%Y-%m-%d')}-google-cloud.json"
    response = client.post(
        "/imports/github-organization",
        headers=auth_header(token),
        files={"file": (name, file_set()[name].encode(), "application/json")},
        data={"captured_at": GENERATIONS[0].isoformat()},
    )
    assert response.status_code == 422
    assert "shaped like a Google Cloud project export" in response.json()["detail"]


# The findings and the delta.


def test_the_sample_project_produces_the_findings_it_was_built_for(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    import_all(client, token)
    rows = inventory(client, token)

    def codes(name: str) -> set[str]:
        return {f["code"] for f in detail(client, token, rows[name]["id"])["findings"]}

    assert "admin_equivalent" in codes("sam@example.test")
    legacy = codes(f"legacy@{PROJECT}.iam.gserviceaccount.com")
    assert {"iam_mutating", "key_age", "multiple_active_keys", "unused_identity"} <= legacy
    assert "iam_mutating" in codes(f"deploy@{PROJECT}.iam.gserviceaccount.com"), "acts as"
    ci = rows[f"ci@{PROJECT}.iam.gserviceaccount.com"]
    assert ci["critical"] == 0 and ci["warning"] == 0, "a used, recent key is quiet"
    assert rows["allUsers"]["critical"] == 0, "a public reader is a difference, not a finding"


def test_a_deleted_principal_still_bound_and_a_grown_role_are_differences(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    import_all(client, token)
    gone = named(db, "user:former@example.test?uid=100000000000000000001")
    assert gone.origin == "deleted"
    mine = delta.for_identity(db, gone)
    assert [f.role for f in mine if f.kind == delta.HELD_NOT_AUTHORIZED] == ["roles/editor"]
    findings = delta.for_definitions(db)
    deployer = [f for f in findings if f.role_ref == f"projects/{PROJECT}/roles/deployer"]
    assert deployer and deployer[0].kind == delta.CUSTOM_DEFINITION_NOT_AUTHORIZED
