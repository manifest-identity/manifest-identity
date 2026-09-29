"""The second provider (1.12): GitHub on the neutral tables.

The claim under test is the product plan's: the same neutral tables, a
different vocabulary ending at the parser. So the assertions read the
inventory, the paths, the findings, and the delta through the same
routes the AWS estate uses, and never a GitHub word. The parser is held
to the contract the AWS parsers set: bounded, verified against its own
claims, and no error repeats file content.
"""

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.compare import delta
from manifest_identity.core.roles import Role
from manifest_identity.models import Grant, Identity, Membership, RoleDefinition
from manifest_identity.observe import paths
from manifest_identity.observe.providers.github import organization_export as export
from manifest_identity.sample_data import GENERATIONS, ORGANIZATION, file_set
from tests.conftest import ROLE_USERS, auth_header, login, make_user


def operator(client: TestClient, db: Session) -> str:
    make_user(db, Role.operator)
    return login(client, ROLE_USERS[Role.operator])


def import_generation(client: TestClient, token: str, generation: int) -> tuple[int, dict]:
    captured = GENERATIONS[generation]
    name = f"{captured.strftime('%Y-%m-%d')}-github-organization.json"
    response = client.post(
        "/imports/github-organization",
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
        "organization": {"login": "acme", "id": 1},
        "members": [{"login": "alice", "id": 10, "role": "owner", "two_factor_enabled": True}],
        "teams": [{"slug": "core", "id": 20, "name": "core", "members": ["alice"],
                   "repositories": [{"name": "app", "permission": "admin"}]}],
        "repositories": [{"name": "app", "id": 30, "visibility": "private"}],
    }
    document.update(overrides)
    return json.dumps(document).encode()


def test_the_parser_reads_the_documented_shape() -> None:
    parsed = export.parse_organization_export(minimal())
    assert parsed.login == "acme"
    assert parsed.members[0].role == "owner"
    assert parsed.teams[0].repositories == [("app", "admin")]


@pytest.mark.parametrize(
    ("overrides", "rule"),
    [
        ({"teams": [{"slug": "core", "id": 20, "members": ["nobody-here"]}]},
         "does not list as a member"),
        ({"repositories": [{"name": "app", "id": 30,
                            "collaborators": [{"login": "alice", "permission": "god"}]}]},
         "five repository levels"),
        ({"members": [{"login": "alice", "id": 10}, {"login": "alice", "id": 11}]},
         "more than once"),
        ({"members": [{"login": "alice", "id": 10, "role": "emperor"}]},
         "owner, member, or billing_manager"),
        ({"members": [{"login": "alice", "id": 10, "created_at": "yesterday-ish"}]},
         "not ISO 8601"),
        ({"tokens": [{"id": 1, "owner": "ghost"}]}, "does not list as a member"),
    ],
)
def test_a_file_that_contradicts_itself_is_refused_without_echo(
    overrides: dict[str, object], rule: str
) -> None:
    with pytest.raises(export.ParseError) as caught:
        export.parse_organization_export(minimal(**overrides))
    message = str(caught.value)
    assert rule in message
    for value in ("nobody-here", "god", "emperor", "yesterday-ish", "ghost"):
        assert value not in message


def test_a_login_that_is_not_a_login_is_refused() -> None:
    with pytest.raises(export.ParseError):
        export.parse_organization_export(
            minimal(members=[{"login": "<script>", "id": 10}])
        )


# The importer: the neutral rows it writes.


def test_the_organization_becomes_the_neutral_rows(client: TestClient, db: Session) -> None:
    token = operator(client, db)
    status, body = import_generation(client, token, 0)
    assert status == 201, body
    assert body["account"] == ORGANIZATION
    rows = inventory(client, token)
    # Members, the guest, the deploy keys, and the installations are
    # identities; teams are groups and stay out of the inventory.
    assert rows["sam-owner"]["identity_type"] == "user"
    assert rows["contractor-lee"]["identity_type"] == "user"
    assert rows["terraform-runner"]["identity_type"] == "deploy_key"
    assert rows["org-admin-tool"]["identity_type"] == "installation"
    assert "platform" not in rows
    assert {g["name"] for g in client.get("/groups", headers=auth_header(token)).json()} >= {
        "platform", "developers", "incident-commanders",
    }
    # Every identity is keyed by the numeric id, never the login.
    guest = named(db, "contractor-lee")
    assert guest.external_id == "user:2001"
    assert guest.home == "other_tenant"
    assert guest.origin == "outside_collaborator"


def test_the_definitions_are_provider_managed_capability_documents(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    import_generation(client, token, 0)
    owner = db.execute(
        select(RoleDefinition).where(
            RoleDefinition.external_id == f"github:organization:{ORGANIZATION}:owner"
        )
    ).scalar_one()
    assert owner.managed_by == "provider"
    assert owner.contents is not None
    assert owner.contents["kind"] == "capabilities"
    assert owner.contents["administers"] is True
    reader = db.execute(
        select(RoleDefinition).where(
            RoleDefinition.external_id == f"github:repository:{ORGANIZATION}/api:read"
        )
    ).scalar_one()
    assert reader.contents is not None
    assert reader.contents["administers"] is False
    # An installation's permissions are its own definition, versioned
    # like any customer-managed one.
    app = db.execute(
        select(RoleDefinition).where(
            RoleDefinition.external_id == "github:installation:org-admin-tool:permissions"
        )
    ).scalar_one()
    assert app.managed_by == "customer"
    assert app.contents is not None
    assert app.contents["permissions"]["administration"] == "write"


def test_a_repository_grant_sits_at_the_repository_node(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    import_generation(client, token, 0)
    bot = named(db, "release-bot")
    grants = {
        definition.external_id: grant
        for grant, definition in db.execute(
            select(Grant, RoleDefinition)
            .join(RoleDefinition, Grant.role_definition_id == RoleDefinition.id)
            .where(Grant.identity_id == bot.id)
        ).all()
    }
    api_write = grants[f"github:repository:{ORGANIZATION}/api:write"]
    assert api_write.scope_node_id != bot.scope_node_id, "the repository, not the organization"
    assert api_write.source_kind == "repository_permission"


def test_team_access_arrives_through_the_membership_hop(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    import_generation(client, token, 0)
    rows = inventory(client, token)
    d = detail(client, token, rows["rita-ops"]["id"])
    held = {entry["role"]: entry for entry in d["holds_now"]}
    infra_admin = held[f"admin on {ORGANIZATION}/infra"]
    assert infra_admin["path"] == [{"via": "membership", "ref": "platform", "mode": "active"}]
    assert held[f"owner of {ORGANIZATION}"]["path"] == [
        {"via": "direct", "ref": "", "mode": "active"}
    ]


def test_a_child_teams_members_are_the_parents_members_too(
    client: TestClient, db: Session
) -> None:
    """GitHub's own rule, written as rows so the hop is readable: the
    frontend team sits under developers, so new-dev holds what
    developers holds, through developers."""
    token = operator(client, db)
    import_generation(client, token, 1)
    rows = inventory(client, token)
    d = detail(client, token, rows["new-dev"]["id"])
    held = {(entry["role"], tuple(h["ref"] for h in entry["path"])) for entry in d["holds_now"]}
    assert (f"write on {ORGANIZATION}/api", ("developers",)) in held
    assert (f"write on {ORGANIZATION}/website", ("frontend",)) in held
    new_dev = named(db, "new-dev")
    memberships = db.execute(
        select(Membership).where(Membership.member_id == new_dev.id)
    ).scalars().all()
    assert len(memberships) == 2


def test_the_same_snapshot_twice_is_a_conflict(client: TestClient, db: Session) -> None:
    token = operator(client, db)
    assert import_generation(client, token, 0)[0] == 201
    status, body = import_generation(client, token, 0)
    assert status == 409
    assert "already imported" in body["detail"]


def test_a_github_export_sent_as_an_aws_file_is_refused_by_shape(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    name = f"{GENERATIONS[0].strftime('%Y-%m-%d')}-github-organization.json"
    response = client.post(
        "/imports/authorization-details",
        headers=auth_header(token),
        files={"file": (name, file_set()[name].encode(), "application/json")},
        data={"captured_at": GENERATIONS[0].isoformat()},
    )
    assert response.status_code == 422
    assert "shaped like a GitHub organization export" in response.json()["detail"]


# The findings and the delta, through the engine the AWS estate uses.


def test_the_sample_organization_produces_the_findings_it_was_built_for(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    import_all(client, token)
    rows = inventory(client, token)

    def codes(name: str) -> set[str]:
        return {f["code"] for f in detail(client, token, rows[name]["id"])["findings"]}

    assert "admin_equivalent" in codes("sam-owner"), "an owner administers the organization"
    assert "admin_equivalent" in codes("org-admin-tool"), "an app that writes members"
    assert {"password_without_mfa", "unused_identity"} <= codes("legacy-mike")
    # The owner who turned a second factor on in the third month no
    # longer carries the finding at the newest import.
    assert "password_without_mfa" not in codes("rita-ops")
    assert rows["dev-amir"]["critical"] == 0 and rows["dev-amir"]["warning"] == 0
    assert rows["ci-runner"]["critical"] == 0, "writing contents is not administering"
    groups = {g["name"]: g for g in client.get("/groups", headers=auth_header(token)).json()}

    def group_codes(name: str) -> set[str]:
        return {f["code"] for f in groups[name]["findings"]}

    assert "empty_privileged_group" in group_codes("incident-commanders")
    assert "membership_drift" in group_codes("platform")
    assert groups["developers"]["privileged"] is False


def test_the_guest_with_admin_is_a_difference_nobody_authorized(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    import_all(client, token)
    guest = named(db, "contractor-lee")
    findings = delta.for_identity(db, guest)
    assert any(
        f.kind == delta.HELD_NOT_AUTHORIZED
        and f.role == f"github:repository:{ORGANIZATION}/website:admin"
        for f in findings
    )
    # And the path expansion reads the newest organization import as
    # the current one, the same way it reads an AWS one.
    newest = paths.newest_import(db, guest.scope_node_id)
    assert newest is not None
    held, obtainable = paths.split(paths.for_identity(db, import_id=newest, identity=guest))
    assert [p.role_ref for p in held] == [
        f"github:repository:{ORGANIZATION}/website:admin"
    ]
    assert obtainable == []


def test_a_deploy_key_is_a_service_identity_holding_an_ssh_key(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    import_all(client, token)
    rows = inventory(client, token)
    d = detail(client, token, rows["terraform-runner"]["id"])
    assert d["kind"] == "service"
    assert [entry["role"] for entry in d["holds_now"]] == [f"write on {ORGANIZATION}/infra"]
    # The key's last use is the identity's activity, so an unused key
    # would read as an unused identity.
    assert d["last_activity"] is not None
    assert d["last_activity"].startswith("2026-07-27")
