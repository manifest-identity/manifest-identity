"""The third provider (1.14b): a Kubernetes cluster on the neutral tables.

The dump is the cluster's own answer to one kubectl command, so the
parser is held to the same contract as the others and the assertions
read the result through the same routes: a service account is a
service, a user is a name the authenticator asserts, a group is either
one of the cluster's own two or an outsider whose members are unknown,
a role's rules become capabilities the privilege reading speaks, and a
binding is a grant at the namespace or the cluster.
"""

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.compare import delta
from manifest_identity.core.models import ScopeNode
from manifest_identity.core.roles import Role
from manifest_identity.models import Grant, Identity, Membership, RoleDefinition
from manifest_identity.observe import policy_analysis
from manifest_identity.observe.kubernetes_importer import role_capabilities
from manifest_identity.observe.providers.kubernetes import rbac_dump
from manifest_identity.sample_data import CLUSTER, GENERATIONS, file_set
from tests.conftest import ROLE_USERS, auth_header, login, make_user


def operator(client: TestClient, db: Session) -> str:
    make_user(db, Role.operator)
    return login(client, ROLE_USERS[Role.operator])


def import_generation(
    client: TestClient, token: str, generation: int, cluster: str = CLUSTER,
) -> tuple[int, dict]:
    captured = GENERATIONS[generation]
    name = f"{captured.strftime('%Y-%m-%d')}-kubernetes-rbac.json"
    response = client.post(
        "/imports/kubernetes-rbac",
        headers=auth_header(token),
        files={"file": (name, file_set()[name].encode(), "application/json")},
        data={"captured_at": captured.isoformat(), "cluster": cluster},
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


def dump(*items: dict[str, object]) -> bytes:
    return json.dumps({"kind": "List", "items": list(items)}).encode()


def binding(name: str, role: str, *subjects: dict[str, object], namespace: str | None = None,
            role_kind: str = "ClusterRole") -> dict[str, object]:
    metadata: dict[str, object] = {"name": name}
    if namespace:
        metadata["namespace"] = namespace
    return {
        "kind": "RoleBinding" if namespace else "ClusterRoleBinding",
        "metadata": metadata,
        "roleRef": {"kind": role_kind, "name": role},
        "subjects": list(subjects),
    }


def test_the_parser_reads_a_kubectl_list() -> None:
    parsed = rbac_dump.parse_rbac_dump(dump(
        {"kind": "ClusterRole", "metadata": {"name": "r"},
         "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}]},
        binding("b", "r", {"kind": "User", "name": "alice"}),
        {"kind": "ServiceAccount", "metadata": {"name": "sa", "namespace": "ns", "uid": "u1"}},
        {"kind": "ConfigMap", "metadata": {"name": "not-access", "namespace": "ns"}},
    ))
    assert [r.name for r in parsed.roles] == ["r"]
    assert parsed.bindings[0].subjects[0].kind == "User"
    assert parsed.service_accounts[0].uid == "u1"
    assert parsed.skipped == 1, "an object that is not access is counted, not read"


@pytest.mark.parametrize(
    ("items", "rule"),
    [
        ([{"kind": "Role", "metadata": {"name": "r"}, "rules": []}], "must carry a namespace"),
        ([{"kind": "ClusterRole", "metadata": {"name": "r"},
           "rules": [{"resources": ["pods"], "verbs": ["fly"]}]}], "not one the API defines"),
        ([binding("b", "r", {"kind": "Robot", "name": "x"})], "not User, Group, or ServiceAccount"),
        ([binding("b", "r", {"kind": "ServiceAccount", "name": "x"})], "needs a namespace"),
        ([binding("b", "r", role_kind="Role")], "cannot bind a Role"),
        ([{"kind": "ClusterRole", "metadata": {"name": "twice"}, "rules": []},
          {"kind": "ClusterRole", "metadata": {"name": "twice"}, "rules": []}], "appears twice"),
    ],
)
def test_a_dump_that_breaks_the_apis_rules_is_refused_without_echo(
    items: list[dict[str, object]], rule: str
) -> None:
    with pytest.raises(rbac_dump.ParseError) as caught:
        rbac_dump.parse_rbac_dump(dump(*items))
    assert rule in str(caught.value)
    assert "fly" not in str(caught.value) and "Robot" not in str(caught.value)


def test_a_file_that_is_not_a_list_is_refused() -> None:
    with pytest.raises(rbac_dump.ParseError):
        rbac_dump.parse_rbac_dump(b'{"kind": "Pod"}')


# The rules become capabilities.


def parsed_role(*rules: dict[str, object], kind: str = "ClusterRole") -> rbac_dump.ParsedRole:
    return rbac_dump.parse_rbac_dump(dump(
        {"kind": kind, "metadata": {"name": "r", "namespace": "ns"}, "rules": list(rules)},
    )).roles[0]


def test_every_verb_on_every_resource_administers() -> None:
    document = role_capabilities(parsed_role(
        {"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}
    ))
    assert document["administers"] is True
    assert policy_analysis.read_policy(document).admin_equivalent


def test_bind_and_escalate_change_access_without_administering() -> None:
    document = role_capabilities(parsed_role(
        {"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["clusterroles"],
         "verbs": ["bind", "escalate"]}
    ))
    assert document["administers"] is False
    assert document["changes_access"] is True
    reading = policy_analysis.read_policy(document)
    assert reading.iam_mutating and not reading.admin_equivalent


def test_writing_bindings_changes_access_and_reading_pods_does_not() -> None:
    writer = role_capabilities(parsed_role(
        {"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["rolebindings"],
         "verbs": ["create"]}
    ))
    reader = role_capabilities(parsed_role(
        {"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list", "watch"]}
    ))
    assert writer["changes_access"] is True
    assert reader["changes_access"] is False and reader["writes"] is False
    assert reader["reads"] is True


def test_the_rules_ride_as_actions_so_a_changed_role_names_what_it_gained() -> None:
    before = role_capabilities(parsed_role(
        {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]}
    ))
    after = role_capabilities(parsed_role(
        {"apiGroups": [""], "resources": ["secrets"], "verbs": ["*"]}
    ))
    assert policy_analysis.allowed_actions(before) == {"get secrets", "list secrets"}
    change = policy_analysis.describe_change(before, after)
    assert change.added == ["* secrets"]
    assert change.removed == ["get secrets", "list secrets"]


# The importer.


def test_the_cluster_becomes_the_neutral_rows(client: TestClient, db: Session) -> None:
    token = operator(client, db)
    status, body = import_generation(client, token, 0)
    assert status == 201, body
    assert body["account"] == CLUSTER
    rows = inventory(client, token)
    assert rows["kube-system/deployer"]["identity_type"] == "serviceaccount"
    assert rows["ops-lead"]["identity_type"] == "user"
    assert rows["system:masters"]["identity_type"] == "group"
    # The cluster's own group is a group with members and stays out of
    # the inventory; an outside group is a guest in it.
    assert "system:serviceaccounts:monitoring" not in rows
    groups = {g["name"]: g for g in client.get("/groups", headers=auth_header(token)).json()}
    assert groups["system:serviceaccounts:monitoring"]["members"] == 1
    masters = named(db, "system:masters")
    assert masters.home == "identity_provider" and masters.kind == "external"
    nodes = {n.kind: n for n in db.execute(
        select(ScopeNode).where(ScopeNode.provider == "kubernetes")
    ).scalars()}
    assert nodes["cluster"].external_id == CLUSTER
    assert nodes["namespace"].parent_id == nodes["cluster"].id


def test_a_role_binding_grants_at_the_namespace_and_a_cluster_binding_at_the_cluster(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    import_generation(client, token, 0)
    nadia = named(db, "dev-nadia")
    ops = named(db, "ops-lead")
    grants = {
        (g.identity_id, d.external_id): (g, n)
        for g, d, n in db.execute(
            select(Grant, RoleDefinition, ScopeNode)
            .join(RoleDefinition, Grant.role_definition_id == RoleDefinition.id)
            .join(ScopeNode, Grant.scope_node_id == ScopeNode.id)
        ).all()
    }
    edit_grant, edit_node = grants[(nadia.id, "clusterrole:edit")]
    assert edit_node.kind == "namespace" and edit_node.display_name == "payments"
    assert edit_grant.source_kind == "rolebinding"
    admin_grant, admin_node = grants[(ops.id, "clusterrole:cluster-admin")]
    assert admin_node.kind == "cluster"
    assert admin_grant.source_kind == "clusterrolebinding"


def test_the_shipped_roles_are_the_providers_and_the_rest_are_the_customers(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    import_generation(client, token, 0)
    managed = {
        d.external_id: d.managed_by for d in db.execute(select(RoleDefinition)).scalars()
    }
    assert managed["clusterrole:cluster-admin"] == "provider"
    assert managed["clusterrole:secrets-reader"] == "customer"
    assert managed["role:payments/config-reader"] == "customer"


def test_the_clusters_own_group_lists_its_service_accounts(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    import_generation(client, token, 0)
    prometheus = named(db, "monitoring/prometheus")
    memberships = db.execute(
        select(Membership).where(Membership.member_id == prometheus.id)
    ).scalars().all()
    assert len(memberships) == 1
    d = detail(client, token, prometheus.id)
    assert [(h["role"], h["path"][0]["ref"]) for h in d["holds_now"]] == [
        ("view", "system:serviceaccounts:monitoring")
    ]


def test_a_binding_to_a_role_the_file_does_not_hold_is_a_definition_with_no_contents(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    response = client.post(
        "/imports/kubernetes-rbac",
        headers=auth_header(token),
        files={"file": ("d.json", dump(binding("b", "ghost", {"kind": "User", "name": "x"})),
                        "application/json")},
        data={"captured_at": "2026-08-01T00:00:00+00:00", "cluster": "c"},
    )
    assert response.status_code == 201, response.text
    ghost = db.execute(
        select(RoleDefinition).where(RoleDefinition.external_id == "clusterrole:ghost")
    ).scalar_one()
    assert ghost.contents is None
    x = named(db, "x")
    assert detail(client, token, x.id)["findings"] == [], "nothing is guessed about it"


def test_the_cluster_name_is_required_and_checked(client: TestClient, db: Session) -> None:
    token = operator(client, db)
    response = client.post(
        "/imports/kubernetes-rbac",
        headers=auth_header(token),
        files={"file": ("d.json", dump(), "application/json")},
        data={"captured_at": "2026-08-01T00:00:00+00:00", "cluster": "Not A Cluster"},
    )
    assert response.status_code == 422


def test_the_same_snapshot_twice_is_a_conflict_and_the_wrong_door_says_so(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    assert import_generation(client, token, 0)[0] == 201
    status, body = import_generation(client, token, 0)
    assert status == 409 and "already imported" in body["detail"]
    name = f"{GENERATIONS[0].strftime('%Y-%m-%d')}-kubernetes-rbac.json"
    response = client.post(
        "/imports/github-organization",
        headers=auth_header(token),
        files={"file": (name, file_set()[name].encode(), "application/json")},
        data={"captured_at": GENERATIONS[0].isoformat()},
    )
    assert response.status_code == 422
    assert "shaped like a Kubernetes role-based access control dump" in response.json()["detail"]


# The findings and the delta.


def test_the_sample_cluster_produces_the_findings_it_was_built_for(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    import_all(client, token)
    rows = inventory(client, token)

    def codes(name: str) -> set[str]:
        return {f["code"] for f in detail(client, token, rows[name]["id"])["findings"]}

    assert "admin_equivalent" in codes("ops-lead")
    assert "admin_equivalent" in codes("kube-system/deployer")
    assert "admin_equivalent" in codes("system:masters"), "a guest group holding admin"
    assert "iam_mutating" in codes("ci/rbac-bot"), "bind and escalate change access"
    assert rows["payments/api"]["critical"] == 0 and rows["payments/api"]["warning"] == 0
    assert rows["monitoring/prometheus"]["critical"] == 0


def test_a_changed_custom_role_and_a_new_door_are_differences(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    import_all(client, token)
    findings = delta.for_definitions(db)
    changed = [f for f in findings if f.role_ref == "clusterrole:secrets-reader"]
    assert changed and changed[0].kind == delta.CUSTOM_DEFINITION_NOT_AUTHORIZED
    contractor = named(db, "new-contractor")
    mine = delta.for_identity(db, contractor)
    assert [f.role for f in mine if f.kind == delta.HELD_NOT_AUTHORIZED] == ["clusterrole:admin"]
