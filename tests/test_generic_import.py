"""Any provider's table through a mapping, and the source check (1.11).

The observed side's file door writes the same neutral rows the AWS
parsers write, so the proof is the delta: a spreadsheet of on-premises
accounts imported here produces a held-but-not-authorized finding the
same as an AWS export does. The rest is the file door's discipline,
applied to this door: a dry run writes nothing, a bad row is refused by
its line and does not stop the file, a file naming two accounts is
refused whole.

The source check is the other half of 1.11. Every import route reads
the shape of the file before parsing it, and a file named as one source
and shaped as another is refused with both named.
"""

import json

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.compare import delta
from manifest_identity.core.roles import Role
from manifest_identity.models import Grant, Identity, Import, RoleDefinition
from manifest_identity.observe import generic_import
from tests.conftest import ROLE_USERS, auth_header, login, make_user
from tests.test_governance import admin_policy, user_entry

TEMPLATE_HEADER = (
    "provider,account,identity_id,identity_name,identity_type,identity_kind,"
    "role,role_name,mode,path"
)

ROWS = [
    "active_directory,corp,S-1-5-21-1,alice,user,person,Domain Admins,Domain Admins,standing,",
    "active_directory,corp,S-1-5-21-2,svc-backup,user,service,Backup Operators,"
    "Backup Operators,standing,membership:backup-team",
    "active_directory,corp,S-1-5-21-3,bob,user,person,Domain Admins,Domain Admins,eligible,",
]


def table(*rows: str) -> bytes:
    return ("\n".join([TEMPLATE_HEADER, *rows]) + "\n").encode()


def operator(client: TestClient, db: Session) -> str:
    make_user(db, Role.administrator)
    return login(client, ROLE_USERS[Role.administrator])


def post_table(
    client: TestClient, token: str, data: bytes, *, path: str = "/imports/observed",
    captured: str = "2026-08-01T00:00:00+00:00", mapping_id: int | None = None,
) -> tuple[int, dict[str, object]]:
    form: dict[str, str] = {"captured_at": captured}
    if mapping_id is not None:
        form["mapping_id"] = str(mapping_id)
    response = client.post(
        path,
        headers=auth_header(token),
        files={"file": ("accounts.csv", data, "text/csv")},
        data=form,
    )
    return response.status_code, response.json()


def test_a_dry_run_reads_everything_and_writes_nothing(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    status, body = post_table(client, token, table(*ROWS), path="/imports/observed/dry-run")
    assert status == 200, body
    assert body["mapping_name"] == generic_import.DEFAULT_MAPPING_NAME
    assert len(body["written"]) == 3
    assert body["refusals"] == []
    assert db.execute(select(Identity)).first() is None
    assert db.execute(select(Import)).first() is None


def test_a_table_becomes_the_same_rows_a_parser_writes_and_the_delta_reads_them(
    client: TestClient, db: Session
) -> None:
    """The point of the door: a spreadsheet of directory accounts gets
    the delta the same day, and the group hop survives the round trip."""
    token = operator(client, db)
    status, body = post_table(client, token, table(*ROWS))
    assert status == 201, body
    assert len(body["written"]) == 3
    assert body["import_id"] is not None

    identities = {i.external_id: i for i in db.execute(select(Identity)).scalars()}
    assert set(identities) == {"S-1-5-21-1", "S-1-5-21-2", "S-1-5-21-3"}
    assert identities["S-1-5-21-2"].kind == "service"
    definitions = {d.external_id for d in db.execute(select(RoleDefinition)).scalars()}
    assert definitions == {"Domain Admins", "Backup Operators"}
    grants = list(db.execute(select(Grant)).scalars())
    assert len(grants) == 3
    by_identity = {g.identity_id: g for g in grants}
    assert by_identity[identities["S-1-5-21-2"].id].path == [
        {"via": "membership", "ref": "backup-team", "mode": "active"}
    ]
    assert by_identity[identities["S-1-5-21-3"].id].mode == "eligible"

    findings = delta.for_identity(db, identities["S-1-5-21-1"])
    assert delta.HELD_NOT_AUTHORIZED in [f.kind for f in findings]


def test_a_bad_row_is_refused_by_its_line_and_the_rest_are_written(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    bad_provider = "mainframe,corp,S-9,mallory,user,person,Domain Admins,Domain Admins,standing,"
    bad_path = "active_directory,corp,S-8,eve,user,person,Domain Admins,Domain Admins,standing,>>"
    status, body = post_table(client, token, table(ROWS[0], bad_provider, bad_path))
    assert status == 201, body
    assert len(body["written"]) == 1
    assert [r["row"] for r in body["refusals"]] == [3, 4]
    assert "provider" in body["refusals"][0]["reason"]
    assert "empty hop" in body["refusals"][1]["reason"]


def test_a_file_naming_two_accounts_is_refused_whole(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    other = "active_directory,lab,S-7,carol,user,person,Domain Admins,Domain Admins,standing,"
    status, body = post_table(client, token, table(ROWS[0], other))
    assert status == 422
    assert "more than one" in body["detail"]
    assert db.execute(select(Identity)).first() is None


def test_the_same_snapshot_twice_is_a_conflict(client: TestClient, db: Session) -> None:
    token = operator(client, db)
    assert post_table(client, token, table(*ROWS))[0] == 201
    status, body = post_table(client, token, table(*ROWS))
    assert status == 409
    assert "already imported" in body["detail"]


def test_a_mapping_with_the_organizations_own_columns(
    client: TestClient, db: Session
) -> None:
    """Their spreadsheet, their column names, with the provider and the
    account as constants the file does not carry."""
    token = operator(client, db)
    response = client.post(
        "/mappings",
        headers=auth_header(token),
        json={
            "name": "HR export",
            "source_kind": "observed_grants",
            "fields": {
                "provider": {"constant": "active_directory"},
                "account": {"constant": "corp"},
                "identity_external_id": {"column": "SID"},
                "identity_display_name": {"column": "Display Name"},
                "role_definition_external_id": {"column": "Group"},
            },
        },
    )
    assert response.status_code == 201, response.text
    mapping_id = response.json()["id"]
    data = b"SID,Display Name,Group,Department\nS-1,dave,Domain Admins,Finance\n"
    status, body = post_table(client, token, data, mapping_id=mapping_id)
    assert status == 201, body
    assert body["written"][0]["identity_external_id"] == "S-1"
    assert body["ignored_columns"] == ["Department"]
    listed = client.get("/mappings", headers=auth_header(token)).json()
    assert {row["source_kind"] for row in listed} == {"authorizations", "observed_grants"}


def test_an_observed_mapping_cannot_feed_the_authorized_door(
    client: TestClient, db: Session
) -> None:
    """The two doors have different field sets, and a mapping for one
    is refused by the other rather than half-applied."""
    token = operator(client, db)
    observed = generic_import.default_mapping(db)
    db.commit()
    response = client.post(
        "/authorizations/import/dry-run",
        headers=auth_header(token),
        files={"file": ("a.csv", table(*ROWS), "text/csv")},
        data={"mapping_id": str(observed.id)},
    )
    assert response.status_code == 404


# The source check.


def test_a_credential_report_sent_as_authorization_details_is_refused_by_shape(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    report = (
        b"user,arn,user_creation_time,password_enabled\n"
        b"alice,arn:aws:iam::1:user/alice,2025-01-01T00:00:00+00:00,true\n"
    )
    response = client.post(
        "/imports/authorization-details",
        headers=auth_header(token),
        files={"file": ("report.csv", report, "text/csv")},
        data={"captured_at": "2026-08-01T00:00:00+00:00"},
    )
    assert response.status_code == 422
    assert "shaped like an AWS credential report" in response.json()["detail"]
    assert "import it as that source" in response.json()["detail"]


def test_authorization_details_sent_as_a_credential_report_is_refused_by_shape(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    details = json.dumps({
        "UserDetailList": [user_entry("alice", "AIDASHAPE00000000001")],
        "Policies": [admin_policy()],
    }).encode()
    response = client.post(
        "/imports/credential-report",
        headers=auth_header(token),
        files={"file": ("details.json", details, "application/json")},
        data={"captured_at": "2026-08-01T00:00:00+00:00"},
    )
    assert response.status_code == 422
    assert "shaped like an AWS authorization details export" in response.json()["detail"]


def test_an_aws_export_sent_to_the_table_door_is_refused_by_shape(
    client: TestClient, db: Session
) -> None:
    token = operator(client, db)
    details = json.dumps({"UserDetailList": []}).encode()
    status, body = post_table(client, token, details)
    assert status == 422
    assert "not a table for a mapping" in body["detail"]


def test_the_shipped_template_imports_clean(client: TestClient, db: Session) -> None:
    """The documented template is a file like any other and goes through
    the shipped mapping without a refusal."""
    from pathlib import Path

    token = operator(client, db)
    data = Path(__file__).parent.parent.joinpath("sample-data/observed-template.csv").read_bytes()
    status, body = post_table(client, token, data, path="/imports/observed/dry-run")
    assert status == 200, body
    assert body["refusals"] == []
    assert body["written"]
