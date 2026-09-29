"""Every provider's file through the table door (1.14a).

Two claims are tested. The recipes under recipes/ turn a provider's own
export into the door's table, so each jq recipe is run here against an
input in that provider's documented shape and its output must import
clean through the shipped mapping. And the sample table shipped for
each provider imports and produces the delta, so a person can try any
provider on the list the day they meet the product.

jq is a distribution package rather than a Python one, so the recipe
tests skip where it is absent (the floor job) and run where the
pipeline installs it (the application job).
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.compare import delta
from manifest_identity.core.roles import Role
from manifest_identity.models import Identity
from manifest_identity.sample_data import PROVIDER_TABLES, file_set
from tests.conftest import ROLE_USERS, auth_header, login, make_user

ROOT = Path(__file__).resolve().parent.parent
RECIPES = ROOT / "recipes"
JQ = shutil.which("jq")

# Inputs in each provider's documented shape, small and invented.
KUBECTL_BINDINGS = {
    "kind": "List",
    "items": [
        {
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "cluster-admin"},
            "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
            "subjects": [
                {"kind": "Group", "name": "system:masters"},
                {"kind": "User", "name": "ops-lead"},
                {"kind": "ServiceAccount", "name": "deployer", "namespace": "kube-system"},
            ],
        },
        {
            "kind": "RoleBinding",
            "metadata": {"name": "config", "namespace": "payments"},
            "roleRef": {"kind": "Role", "name": "config-reader"},
            "subjects": [{"kind": "ServiceAccount", "name": "api", "namespace": "payments"}],
        },
        {
            "kind": "RoleBinding",
            "metadata": {"name": "editors", "namespace": "payments"},
            "roleRef": {"kind": "ClusterRole", "name": "edit"},
            "subjects": [{"kind": "User", "name": "dev-nadia"}],
        },
    ],
}

GCLOUD_POLICY = {
    "bindings": [
        {"role": "roles/owner", "members": ["user:sam@example.test"]},
        {"role": "roles/editor",
         "members": ["serviceAccount:ci@sample-project.iam.gserviceaccount.com",
                     "group:data-readers@example.test"],
         "condition": {"expression": "request.time < timestamp('2027-01-01T00:00:00Z')"}},
        {"role": "roles/storage.objectViewer", "members": ["allUsers"]},
    ],
    "etag": "BwX0000000=",
    "version": 3,
}

AZ_ASSIGNMENTS = [
    {
        "principalId": "a1b2c3d4-0000-0000-0000-000000000001",
        "principalName": "sam@example.test",
        "principalType": "User",
        "roleDefinitionId": "/subscriptions/11111111-2222-3333-4444-555555555555/providers/"
                            "Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
        "roleDefinitionName": "Owner",
        "scope": "/subscriptions/11111111-2222-3333-4444-555555555555",
    },
    {
        "principalId": "a1b2c3d4-0000-0000-0000-000000000002",
        "principalName": None,
        "principalType": "ServicePrincipal",
        "roleDefinitionId": "/subscriptions/11111111-2222-3333-4444-555555555555/providers/"
                            "Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c",
        "roleDefinitionName": "Contributor",
        "scope": "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/app",
    },
]

OKTA_ADMINS = [
    {
        "user": {"id": "00u0000000000000sam", "status": "ACTIVE",
                 "profile": {"login": "sam@example.test"}},
        "roles": [{"type": "SUPER_ADMIN", "label": "Super Organization Administrator",
                   "assignmentType": "USER"}],
    },
    {
        "user": {"id": "00u0000000000000rita", "status": "ACTIVE",
                 "profile": {"login": "rita@example.test"}},
        "roles": [{"type": "ORG_ADMIN", "label": "Organization Administrator",
                   "assignmentType": "GROUP"}],
    },
]

RECIPE_RUNS = [
    ("kubernetes.jq", ["--arg", "cluster", "sample-cluster"], KUBECTL_BINDINGS, 5),
    ("google-cloud.jq", ["--arg", "project", "sample-project"], GCLOUD_POLICY, 4),
    ("azure.jq", [], AZ_ASSIGNMENTS, 2),
    ("okta.jq", ["--arg", "org", "sample-org"], OKTA_ADMINS, 2),
]


def operator(client: TestClient, db: Session) -> str:
    make_user(db, Role.operator)
    return login(client, ROLE_USERS[Role.operator])


def post_table(client: TestClient, token: str, data: bytes, path: str) -> tuple[int, dict]:
    response = client.post(
        path,
        headers=auth_header(token),
        files={"file": ("observed.csv", data, "text/csv")},
        data={"captured_at": "2026-08-01T00:00:00+00:00"},
    )
    return response.status_code, response.json()


def run_recipe(name: str, arguments: list[str], document: object) -> bytes:
    completed = subprocess.run(  # noqa: S603
        [str(JQ), "-r", *arguments, "-f", str(RECIPES / name)],
        input=json.dumps(document).encode(), capture_output=True, check=True, timeout=30,
    )
    return completed.stdout


@pytest.mark.skipif(JQ is None, reason="jq is not installed here")
@pytest.mark.parametrize(("name", "arguments", "document", "rows"), RECIPE_RUNS)
def test_a_recipe_turns_the_providers_export_into_a_table_the_door_reads(
    client: TestClient, db: Session, name: str, arguments: list[str],
    document: object, rows: int,
) -> None:
    token = operator(client, db)
    table = run_recipe(name, arguments, document)
    assert table.splitlines()[0].decode() == (
        '"provider","account","identity_id","identity_name","identity_type",'
        '"identity_kind","role","role_name","mode","path"'
    )
    status, body = post_table(client, token, table, "/imports/observed/dry-run")
    assert status == 200, body
    assert body["refusals"] == [], body["refusals"]
    assert len(body["written"]) == rows


@pytest.mark.skipif(JQ is None, reason="jq is not installed here")
def test_the_kubernetes_recipe_keeps_the_namespace_on_a_role_and_not_on_a_cluster_role(
) -> None:
    table = run_recipe("kubernetes.jq", ["--arg", "cluster", "c"], KUBECTL_BINDINGS).decode()
    assert '"role:payments/config-reader"' in table
    assert '"clusterrole:edit"' in table, "a RoleBinding to a ClusterRole names the cluster role"
    assert '"group:system:masters"' in table


@pytest.mark.skipif(JQ is None, reason="jq is not installed here")
def test_the_google_recipe_records_a_public_grant_as_a_guest() -> None:
    table = run_recipe("google-cloud.jq", ["--arg", "project", "p"], GCLOUD_POLICY).decode()
    assert '"allUsers","allUsers","allUsers","external"' in table
    assert '"serviceAccount","service"' in table


@pytest.mark.skipif(JQ is None, reason="jq is not installed here")
def test_the_azure_recipe_files_every_assignment_under_its_subscription() -> None:
    table = run_recipe("azure.jq", [], AZ_ASSIGNMENTS).decode()
    lines = table.splitlines()[1:]
    assert all('"11111111-2222-3333-4444-555555555555"' in line for line in lines)
    # A service principal with no resolved name keeps its id as its name.
    assert '"a1b2c3d4-0000-0000-0000-000000000002","a1b2c3d4-0000-0000-0000-000000000002"' in table


@pytest.mark.parametrize("provider", sorted(PROVIDER_TABLES))
def test_each_providers_sample_table_imports_and_the_delta_reads_it(
    client: TestClient, db: Session, provider: str
) -> None:
    token = operator(client, db)
    name = f"observed-{provider.replace('_', '-')}.csv"
    status, body = post_table(client, token, file_set()[name].encode(), "/imports/observed")
    assert status == 201, body
    assert body["refusals"] == []
    assert len(body["written"]) == len(PROVIDER_TABLES[provider])
    identities = db.execute(select(Identity)).scalars().all()
    assert identities
    findings = [f for i in identities for f in delta.for_identity(db, i)]
    assert any(f.kind == delta.HELD_NOT_AUTHORIZED for f in findings)


def test_every_recipe_names_its_command_and_its_limit() -> None:
    """A recipe is documentation with a runnable half: each says how to
    produce its input and what the native parser will add."""
    for path in sorted(RECIPES.iterdir()):
        text = path.read_text()
        assert "1.14a" in text, path.name
        assert "recipes/" + path.name in text, f"{path.name} does not show how to run itself"
    assert {p.name for p in RECIPES.iterdir()} == {
        "kubernetes.jq", "google-cloud.jq", "azure.jq", "okta.jq",
        "active-directory.ps1", "database.sql",
    }
