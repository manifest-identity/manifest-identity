"""Authority is a binding at a place, and it stops at that place.

The role matrix says which roles a route admits; this file proves the
other half (D-070, D-072): a user holding the right role at the wrong
node is refused, and the refusal says so. Two passes. The unit pass
walks the tree function directly: a binding at a parent covers a
child, a binding at a sibling does not, a revoked binding covers
nothing, and a binding at the global node covers everything. The route
pass calls every scoped write route three times, bound inside the
target's scope, bound outside it, and bound globally, so a route that
forgot its scope check fails here rather than in someone's estate.
"""

import json

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.core.roles import Role
from manifest_identity.core.scope import (
    active_bindings,
    find_or_create_node,
    global_node,
    holds,
    revoke,
    roles_held,
)
from manifest_identity.models import (
    Campaign,
    CampaignItem,
    GovernanceRecord,
    Identity,
    Partition,
    Provider,
    ScopeNode,
    User,
    utcnow,
)
from tests.conftest import TEST_PASSWORD, auth_header, login, make_user
from tests.test_governance import admin_policy, group_entry, user_entry

# The estate the route pass runs against: one organization, two
# accounts under it. Identities are imported into the first.
HOME_ACCOUNT = "123456789012"
OTHER_ACCOUNT = "210987654321"


def make_tree(db: Session) -> tuple[ScopeNode, ScopeNode, ScopeNode]:
    """An organization with two accounts under it."""
    org = find_or_create_node(
        db, Provider.aws, Partition.aws_commercial, "organization",
        "o-testorg", "test organization", None,
    )
    home = find_or_create_node(
        db, Provider.aws, Partition.aws_commercial, "account",
        HOME_ACCOUNT, HOME_ACCOUNT, org,
    )
    other = find_or_create_node(
        db, Provider.aws, Partition.aws_commercial, "account",
        OTHER_ACCOUNT, OTHER_ACCOUNT, org,
    )
    db.commit()
    return org, home, other


def user_at(db: Session, username: str, role: Role, node: ScopeNode) -> str:
    return make_user(db, role, username=username, scope_node_id=node.id)


def test_a_binding_at_a_parent_covers_the_child(client: TestClient, db: Session) -> None:
    org, home, other = make_tree(db)
    name = user_at(db, "scope.org", Role.administrator, org)
    user = db.execute(select(User).where(User.username == name)).scalar_one()
    assert holds(db, user, [Role.administrator], home.id)
    assert holds(db, user, [Role.administrator], other.id)


def test_a_binding_at_a_sibling_covers_neither_the_parent_nor_the_sibling(
    client: TestClient, db: Session
) -> None:
    org, home, other = make_tree(db)
    name = user_at(db, "scope.home", Role.administrator, home)
    user = db.execute(select(User).where(User.username == name)).scalar_one()
    assert holds(db, user, [Role.administrator], home.id)
    assert not holds(db, user, [Role.administrator], other.id)
    assert not holds(db, user, [Role.administrator], org.id)
    # A route whose target has no scope is answered by a global binding
    # alone, so an account administrator cannot reach it.
    assert not holds(db, user, [Role.administrator], None)


def test_a_global_binding_covers_every_node(client: TestClient, db: Session) -> None:
    _, home, other = make_tree(db)
    name = make_user(db, Role.administrator, username="scope.global")
    user = db.execute(select(User).where(User.username == name)).scalar_one()
    for node_id in (home.id, other.id, global_node(db).id, None):
        assert holds(db, user, [Role.administrator], node_id)


def test_a_revoked_binding_covers_nothing(client: TestClient, db: Session) -> None:
    _, home, _ = make_tree(db)
    name = user_at(db, "scope.revoked", Role.administrator, home)
    user = db.execute(select(User).where(User.username == name)).scalar_one()
    assert holds(db, user, [Role.administrator], home.id)
    revoke(db, active_bindings(db, user.id)[0], user)
    db.commit()
    assert not holds(db, user, [Role.administrator], home.id)
    assert roles_held(db, user) == set()


def test_the_role_still_has_to_match(client: TestClient, db: Session) -> None:
    _, home, _ = make_tree(db)
    name = user_at(db, "scope.reviewer", Role.reviewer, home)
    user = db.execute(select(User).where(User.username == name)).scalar_one()
    assert holds(db, user, [Role.reviewer], home.id)
    assert not holds(db, user, [Role.administrator], home.id)


def test_a_cycle_in_the_tree_does_not_hang_the_walk(client: TestClient, db: Session) -> None:
    """Parents are set by administrators, so the walk refuses to trust
    the tree's shape: a node that is its own ancestor terminates."""
    _, home, other = make_tree(db)
    home.parent_id = other.id
    other.parent_id = home.id
    db.commit()
    name = make_user(db, Role.administrator, username="scope.cycle")
    user = db.execute(select(User).where(User.username == name)).scalar_one()
    assert holds(db, user, [Role.administrator], home.id)


def seed_estate(client: TestClient, db: Session) -> dict[str, int]:
    """Import one account's identities, then place a campaign item and
    a governance record on one of them, so every scoped write route has
    a real target inside HOME_ACCOUNT."""
    make_user(db, Role.administrator, username="scope.seed")
    token = login(client, "scope.seed")
    payload = {
        "UserDetailList": [user_entry("scope.person", "AIDASCOPE0000000000001",
                                      privileged=True)],
        "GroupDetailList": [group_entry("scope-group", "AGPASCOPE0000000000001")],
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
        select(Identity).where(Identity.external_id == "AIDASCOPE0000000000001")
    ).scalar_one()
    group = db.execute(
        select(Identity).where(Identity.external_id == "AGPASCOPE0000000000001")
    ).scalar_one()
    record = GovernanceRecord(
        target_type="identity", target_id=identity.id, kind="purpose",
        value="scope fixture", actor_username="scope.seed",
    )
    campaign = Campaign(
        name="scope cycle", scope="everything", created_by="scope.seed",
        due_at=utcnow(), scope_node_id=identity.scope_node_id,
    )
    db.add_all([record, campaign])
    db.flush()
    item = CampaignItem(
        campaign_id=campaign.id, target_type="identity", target_id=identity.id,
        display_name="scope.person", recommendation="review",
    )
    db.add(item)
    db.commit()
    return {
        "identity": identity.id,
        "group": group.id,
        "record": record.id,
        "campaign": campaign.id,
        "item": item.id,
    }


SAMPLE_REPORT = (
    b"user,arn,user_creation_time,password_enabled,password_last_used,"
    b"password_last_changed,password_next_rotation,mfa_active,"
    b"access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,"
    b"access_key_1_last_used_region,access_key_1_last_used_service,"
    b"access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,"
    b"access_key_2_last_used_region,access_key_2_last_used_service,"
    b"cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated\n"
    b"scope.person,arn:aws:iam::" + HOME_ACCOUNT.encode() + b":user/scope.person,"
    b"2025-01-01T00:00:00+00:00,TRUE,N/A,2025-01-01T00:00:00+00:00,N/A,TRUE,"
    b"FALSE,N/A,N/A,N/A,N/A,FALSE,N/A,N/A,N/A,N/A,FALSE,N/A,FALSE,N/A\n"
)


def scoped_calls(ids: dict[str, int]) -> dict[str, tuple[str, str, dict[str, object]]]:
    """Every route that checks a scope, called with a target inside
    HOME_ACCOUNT. Each is a write; the reads are scoped by what the
    query returns, not by a refusal, and are not in this pass."""
    return {
        "POST /imports/credential-report": (
            "post", "/imports/credential-report",
            {"files": {"file": ("report.csv", SAMPLE_REPORT, "text/csv")},
             "data": {"captured_at": "2026-09-01T00:00:00+00:00"}},
        ),
        "POST /imports/authorization-details": (
            "post", "/imports/authorization-details",
            {"files": {"file": ("details.json", json.dumps({
                "UserDetailList": [user_entry("scope.second",
                                              "AIDASCOPE0000000000002")],
            }).encode(), "application/json")},
             "data": {"captured_at": "2026-09-02T00:00:00+00:00"}},
        ),
        "POST /identities/{identity_id}/governance": (
            "post", f"/identities/{ids['identity']}/governance",
            {"json": {"kind": "flag", "value": "scope exercise"}},
        ),
        "POST /groups/{group_id}/governance": (
            "post", f"/groups/{ids['group']}/governance",
            {"json": {"kind": "flag", "value": "scope exercise"}},
        ),
        "POST /identities/{identity_id}/attest": (
            "post", f"/identities/{ids['identity']}/attest",
            {"json": {"value": "scope attestation"}},
        ),
        "POST /groups/{group_id}/attest": (
            "post", f"/groups/{ids['group']}/attest",
            {"json": {"value": "scope attestation"}},
        ),
        "DELETE /governance/{record_id}": (
            "delete", f"/governance/{ids['record']}", {},
        ),
        "POST /campaigns/{campaign_id}/items/{item_id}/disposition": (
            "post",
            f"/campaigns/{ids['campaign']}/items/{ids['item']}/disposition",
            {"json": {"disposition": "certify"}},
        ),
    }


def test_every_scoped_write_refuses_a_binding_outside_the_target(
    client: TestClient, db: Session
) -> None:
    ids = seed_estate(client, db)
    _, _, other = make_tree(db)
    user_at(db, "scope.outsider", Role.administrator, other)
    token = login(client, "scope.outsider")
    for key, (method, path, kwargs) in scoped_calls(ids).items():
        response = client.request(
            method.upper(), path, headers=auth_header(token), **kwargs  # type: ignore[arg-type]
        )
        assert response.status_code == 403, f"{key}: {response.status_code}"
        assert "requires role at this scope" in response.json()["detail"], key


def test_every_scoped_write_admits_a_binding_inside_the_target(
    client: TestClient, db: Session
) -> None:
    ids = seed_estate(client, db)
    _, home, _ = make_tree(db)
    # The import created the account node; bind at the one the
    # identities actually hang from.
    node = db.get(ScopeNode, db.get(Identity, ids["identity"]).scope_node_id)
    assert node is not None and node.external_id == HOME_ACCOUNT
    user_at(db, "scope.insider", Role.administrator, node)
    token = login(client, "scope.insider")
    for key, (method, path, kwargs) in scoped_calls(ids).items():
        response = client.request(
            method.upper(), path, headers=auth_header(token), **kwargs  # type: ignore[arg-type]
        )
        assert response.status_code < 400, f"{key}: {response.status_code}"
    assert home is not None


def test_every_scoped_write_admits_a_global_binding(
    client: TestClient, db: Session
) -> None:
    ids = seed_estate(client, db)
    make_user(db, Role.administrator, username="scope.everywhere")
    token = login(client, "scope.everywhere")
    for key, (method, path, kwargs) in scoped_calls(ids).items():
        response = client.request(
            method.upper(), path, headers=auth_header(token), **kwargs  # type: ignore[arg-type]
        )
        assert response.status_code < 400, f"{key}: {response.status_code}"


def test_administration_is_global_in_this_version(
    client: TestClient, db: Session
) -> None:
    """An administrator bound at an account holds the role the matrix
    admits, and is still refused every administrative route, because
    those routes name no node and only a global binding answers (D-070).
    Per-node administration arrives with per-team views."""
    _, home, _ = make_tree(db)
    user_at(db, "scope.account.admin", Role.administrator, home)
    token = login(client, "scope.account.admin")
    calls: list[tuple[str, str, dict[str, object]]] = [
        ("post", "/admin/users", {"json": {
            "username": "scope.made", "password": TEST_PASSWORD, "role": "reviewer",
        }}),
        ("post", "/admin/users/scope.account.admin/bindings",
         {"json": {"role": "reviewer"}}),
        ("post", "/admin/scopes", {"json": {
            "provider": "aws", "partition": "aws_commercial", "kind": "account",
            "external_id": "000000000001", "display_name": "refused",
        }}),
    ]
    for method, path, kwargs in calls:
        response = client.request(
            method.upper(), path, headers=auth_header(token), **kwargs  # type: ignore[arg-type]
        )
        assert response.status_code == 403, f"{path}: {response.status_code}"
        assert "requires role at this scope" in response.json()["detail"]
