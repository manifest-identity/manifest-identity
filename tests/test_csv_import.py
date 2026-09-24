"""The file door: the customer's shape, our rules (D-074).

What these hold: a mapping missing a required field refuses the file
before a row is read; a missing optional column is named rather than
either refused or hidden; a date without a declared format is refused
rather than guessed; unmapped columns are counted; the dry run writes
nothing and promises exactly what the write does; every row goes
through the same checks the form applies; and a mapping is superseded
rather than edited, with every import naming the one that read it.
"""

import json
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.authorize import authorizations, csv_import
from manifest_identity.core.roles import Role
from manifest_identity.models import (
    AuditEvent,
    Authorization,
    Identity,
    ImportBatch,
    ImportMapping,
)
from tests.conftest import ROLE_USERS, auth_header, login, make_user
from tests.test_governance import admin_policy, user_entry

ROLE_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"
TEMPLATE = Path(__file__).parent.parent / "sample-data" / "authorizations-template.csv"


def seed(client: TestClient, db: Session, *names: str) -> dict[str, str]:
    """Import identities so a file has something to authorize."""
    make_user(db, Role.administrator)
    token = login(client, ROLE_USERS[Role.administrator])
    wanted = names or ("csv.one", "csv.two")
    payload = {
        "UserDetailList": [
            user_entry(name, f"AIDACSV{index:015d}")
            for index, name in enumerate(wanted, start=1)
        ],
        "Policies": [admin_policy()],
    }
    r = client.post(
        "/imports/authorization-details",
        headers=auth_header(token),
        files={"file": ("d.json", json.dumps(payload).encode(), "application/json")},
        data={"captured_at": "2026-08-01T00:00:00+00:00"},
    )
    assert r.status_code == 201, r.text
    return {
        identity.first_display_name: identity.external_id
        for identity in db.execute(select(Identity)).scalars()
    }


def upload(
    client: TestClient, token: str, text: str, *, path: str = "import",
    mapping_id: int | None = None,
) -> object:
    data = {"mapping_id": str(mapping_id)} if mapping_id else {}
    return client.post(
        f"/authorizations/{path}",
        headers=auth_header(token),
        files={"file": ("rows.csv", text.encode(), "text/csv")},
        data=data,
    )


def file_for(ids: dict[str, str]) -> str:
    return (
        "identity_id,role,mode,path,owner_kind,owner,justification\n"
        f"{ids['csv.one']},{ROLE_ARN},standing,,team,platform-team,reads the bucket\n"
        f"{ids['csv.two']},{ROLE_ARN},standing,,team,platform-team,runs the job\n"
    )


def test_the_shipped_template_imports_clean(
    client: TestClient, db: Session
) -> None:
    """The documented template and the shipped mapping cannot drift
    apart, because this reads the file the repository ships."""
    # The template names demonstration identifiers; point them at
    # identities that exist here, leaving every other column as shipped.
    ids = seed(client, db, "csv.one", "csv.two")
    token = login(client, ROLE_USERS[Role.administrator])
    text = TEMPLATE.read_text()
    header, *rows = text.splitlines()
    external = [ids["csv.one"], ids["csv.two"]]
    rewritten = "\n".join(
        [header] + [
            ",".join([external[i]] + row.split(",")[1:])
            for i, row in enumerate(rows)
        ]
    ) + "\n"
    r = upload(client, token, rewritten)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["would_write"] == 2, body
    assert body["refused"] == 0, body["refusals"]
    assert body["ignored_columns"] == []
    assert body["absent_fields"] == []


def test_a_mapping_missing_a_required_field_refuses_before_any_row(
    client: TestClient, db: Session
) -> None:
    ids = seed(client, db)
    token = login(client, ROLE_USERS[Role.administrator])
    made = client.post(
        "/mappings", headers=auth_header(token),
        json={"name": "no owner", "fields": {
            "identity_external_id": {"column": "identity_id"},
            "role_definition_external_id": {"column": "role"},
        }},
    )
    assert made.status_code == 422
    assert "does not cover every required field" in made.json()["detail"]
    assert "owner_ref" in made.json()["detail"]
    assert db.execute(select(Authorization)).scalars().all() == []
    assert ids


def test_a_file_without_a_required_column_refuses_whole(
    client: TestClient, db: Session
) -> None:
    ids = seed(client, db)
    token = login(client, ROLE_USERS[Role.administrator])
    text = (
        "identity_id,mode,owner_kind,owner,justification\n"
        f"{ids['csv.one']},standing,team,platform-team,no role column here\n"
    )
    r = upload(client, token, text)
    assert r.status_code == 422
    assert "does not have the columns the mapping needs" in r.json()["detail"]
    assert "role" in r.json()["detail"]


def test_a_missing_optional_column_is_named_not_refused(
    client: TestClient, db: Session
) -> None:
    """The shipped mapping covers more columns than a small file
    carries. That is reported so a misspelled column in a mapping is
    visible, and it does not refuse the file."""
    ids = seed(client, db)
    token = login(client, ROLE_USERS[Role.administrator])
    r = upload(client, token, file_for(ids), path="import/dry-run")
    assert r.status_code == 200, r.text
    absent = r.json()["absent_fields"]
    assert "reference" in absent and "valid_until" in absent
    assert r.json()["would_write"] == 2


def test_unmapped_columns_are_counted_rather_than_silent(
    client: TestClient, db: Session
) -> None:
    ids = seed(client, db)
    token = login(client, ROLE_USERS[Role.administrator])
    text = (
        "identity_id,role,mode,path,owner_kind,owner,justification,Cost Centre\n"
        f"{ids['csv.one']},{ROLE_ARN},standing,,team,platform-team,reads,CC-42\n"
    )
    r = upload(client, token, text, path="import/dry-run")
    assert r.status_code == 200, r.text
    assert r.json()["ignored_columns"] == ["Cost Centre"]


def test_a_date_without_a_declared_format_is_refused(
    client: TestClient, db: Session
) -> None:
    """03/04/2026 is two different days in two countries, so a mapping
    that does not say which is a refusal rather than a guess."""
    ids = seed(client, db)
    token = login(client, ROLE_USERS[Role.administrator])
    made = client.post(
        "/mappings", headers=auth_header(token),
        json={"name": "dates without a format", "fields": {
            "identity_external_id": {"column": "identity_id"},
            "role_definition_external_id": {"column": "role"},
            "owner_kind": {"constant": "team"},
            "owner_ref": {"column": "owner"},
            "justification": {"column": "justification"},
            "valid_until": {"column": "ends"},
        }},
    ).json()
    text = (
        "identity_id,role,owner,justification,ends\n"
        f"{ids['csv.one']},{ROLE_ARN},platform-team,reads the bucket,03/04/2026\n"
    )
    r = upload(client, token, text, path="import/dry-run", mapping_id=made["id"])
    assert r.status_code == 200, r.text
    assert r.json()["refused"] == 1
    assert "no format" in r.json()["refusals"][0]["reason"]


def test_a_declared_format_is_honoured(client: TestClient, db: Session) -> None:
    ids = seed(client, db)
    token = login(client, ROLE_USERS[Role.administrator])
    made = client.post(
        "/mappings", headers=auth_header(token),
        json={"name": "british dates", "fields": {
            "identity_external_id": {"column": "identity_id"},
            "role_definition_external_id": {"column": "role"},
            "owner_kind": {"constant": "team"},
            "owner_ref": {"column": "owner"},
            "justification": {"column": "justification"},
            "valid_until": {"column": "ends", "format": "%d/%m/%Y"},
        }},
    ).json()
    text = (
        "identity_id,role,owner,justification,ends\n"
        f"{ids['csv.one']},{ROLE_ARN},platform-team,reads the bucket,03/04/2027\n"
    )
    r = upload(client, token, text, mapping_id=made["id"])
    assert r.status_code == 201, r.text
    assert r.json()["would_write"] == 1
    row = db.execute(select(Authorization)).scalars().one()
    assert row.valid_until is not None
    assert (row.valid_until.month, row.valid_until.day) == (4, 3)


def test_a_constant_fills_a_column_the_file_does_not_have(
    client: TestClient, db: Session
) -> None:
    ids = seed(client, db)
    token = login(client, ROLE_USERS[Role.administrator])
    made = client.post(
        "/mappings", headers=auth_header(token),
        json={"name": "owner kind by constant", "fields": {
            "identity_external_id": {"column": "identity_id"},
            "role_definition_external_id": {"column": "role"},
            "owner_kind": {"constant": "team"},
            "owner_ref": {"column": "owner"},
            "justification": {"column": "why"},
        }},
    ).json()
    text = (
        "identity_id,role,owner,why\n"
        f"{ids['csv.one']},{ROLE_ARN},platform-team,reads the bucket\n"
    )
    r = upload(client, token, text, mapping_id=made["id"])
    assert r.status_code == 201, r.text
    row = db.execute(select(Authorization)).scalars().one()
    assert row.owner_kind == "team"


def test_a_field_naming_both_a_column_and_a_constant_is_refused(
    client: TestClient, db: Session
) -> None:
    seed(client, db)
    token = login(client, ROLE_USERS[Role.administrator])
    r = client.post(
        "/mappings", headers=auth_header(token),
        json={"name": "both", "fields": {
            "identity_external_id": {"column": "identity_id"},
            "role_definition_external_id": {"column": "role"},
            "owner_kind": {"column": "kind", "constant": "team"},
            "owner_ref": {"column": "owner"},
        }},
    )
    assert r.status_code == 422
    assert "takes one" in r.json()["detail"]


def test_a_mapping_naming_an_unknown_field_is_refused(
    client: TestClient, db: Session
) -> None:
    seed(client, db)
    token = login(client, ROLE_USERS[Role.administrator])
    r = client.post(
        "/mappings", headers=auth_header(token),
        json={"name": "invented", "fields": {
            "identity_external_id": {"column": "identity_id"},
            "role_definition_external_id": {"column": "role"},
            "owner_kind": {"constant": "team"},
            "owner_ref": {"column": "owner"},
            "cost_centre": {"column": "cc"},
        }},
    )
    assert r.status_code == 422
    assert "does not have: cost_centre" in r.json()["detail"]


def test_the_dry_run_writes_nothing(client: TestClient, db: Session) -> None:
    ids = seed(client, db)
    token = login(client, ROLE_USERS[Role.administrator])
    r = upload(client, token, file_for(ids), path="import/dry-run")
    assert r.status_code == 200, r.text
    assert r.json()["would_write"] == 2
    assert r.json()["batch_id"] is None
    assert db.execute(select(Authorization)).scalars().all() == []
    assert db.execute(select(ImportBatch)).scalars().all() == []


def test_the_dry_run_promises_what_the_write_does(
    client: TestClient, db: Session
) -> None:
    """One set of rules, called twice. A preview that could pass where
    the write fails would be worse than no preview."""
    ids = seed(client, db)
    token = login(client, ROLE_USERS[Role.administrator])
    text = (
        "identity_id,role,mode,path,owner_kind,owner,justification\n"
        f"{ids['csv.one']},{ROLE_ARN},standing,,team,platform-team,reads the bucket\n"
        f"{ids['csv.two']},{ROLE_ARN},standing,,individual,one.person,owns it\n"
        f"AIDAMISSING000000001,{ROLE_ARN},standing,,team,platform-team,unknown\n"
    )
    preview = upload(client, token, text, path="import/dry-run").json()
    written = upload(client, token, text).json()
    assert preview["would_write"] == written["would_write"] == 1
    assert [r["row"] for r in preview["refusals"]] == [
        r["row"] for r in written["refusals"]
    ]
    assert [r["reason"] for r in preview["refusals"]] == [
        r["reason"] for r in written["refusals"]
    ]


def test_the_form_rules_apply_to_every_row(
    client: TestClient, db: Session
) -> None:
    ids = seed(client, db)
    token = login(client, ROLE_USERS[Role.administrator])
    text = (
        "identity_id,role,mode,path,owner_kind,owner,justification\n"
        f"{ids['csv.one']},{ROLE_ARN},standing,,individual,one.person,owns it\n"
        f"{ids['csv.two']},{ROLE_ARN},standing,,team,platform-team,\n"
    )
    r = upload(client, token, text)
    assert r.status_code == 201, r.text
    reasons = " ".join(x["reason"] for x in r.json()["refusals"])
    # The person-owner rule and the required-field setting, both from
    # the same code the form calls.
    assert "second owner" in reasons
    assert "justification is required" in reasons
    assert r.json()["would_write"] == 0


def test_a_refused_row_does_not_stop_the_ones_after_it(
    client: TestClient, db: Session
) -> None:
    ids = seed(client, db)
    token = login(client, ROLE_USERS[Role.administrator])
    text = (
        "identity_id,role,mode,path,owner_kind,owner,justification\n"
        f"AIDAMISSING000000001,{ROLE_ARN},standing,,team,platform-team,unknown one\n"
        f"{ids['csv.one']},{ROLE_ARN},standing,,team,platform-team,reads the bucket\n"
    )
    r = upload(client, token, text)
    assert r.json()["would_write"] == 1
    assert [x["row"] for x in r.json()["refusals"]] == [2]


def test_every_written_row_names_the_batch_and_the_mapping(
    client: TestClient, db: Session
) -> None:
    """The property the whole design is for: a mapping later found
    wrong leaves every row it read findable."""
    ids = seed(client, db)
    token = login(client, ROLE_USERS[Role.administrator])
    r = upload(client, token, file_for(ids))
    batch_id = r.json()["batch_id"]
    assert batch_id is not None
    batch = db.get(ImportBatch, batch_id)
    assert batch is not None
    rows = db.execute(
        select(Authorization).where(Authorization.batch_id == batch_id)
    ).scalars().all()
    assert len(rows) == 2
    assert all(row.entry_path == "csv" for row in rows)
    mapping = db.get(ImportMapping, batch.mapping_id)
    assert mapping is not None
    assert mapping.name == csv_import.DEFAULT_MAPPING_NAME


def test_an_import_writes_one_audit_row_naming_the_mapping(
    client: TestClient, db: Session
) -> None:
    ids = seed(client, db)
    token = login(client, ROLE_USERS[Role.administrator])
    upload(client, token, file_for(ids))
    rows = db.execute(
        select(AuditEvent).where(AuditEvent.action == "authorizations_imported")
    ).scalars().all()
    assert len(rows) == 1
    assert "2 written, 0 refused" in (rows[0].detail or "")


def test_a_mapping_is_superseded_rather_than_edited(
    client: TestClient, db: Session
) -> None:
    seed(client, db)
    token = login(client, ROLE_USERS[Role.administrator])
    fields = {
        "identity_external_id": {"column": "identity_id"},
        "role_definition_external_id": {"column": "role"},
        "owner_kind": {"constant": "team"},
        "owner_ref": {"column": "owner"},
    }
    first = client.post(
        "/mappings", headers=auth_header(token),
        json={"name": "their export", "fields": fields},
    ).json()
    assert first["version"] == 1
    second = client.post(
        "/mappings", headers=auth_header(token),
        json={
            "name": "their export",
            "fields": {**fields, "owner_ref": {"column": "Owner Team"}},
            "supersedes_id": first["id"],
        },
    ).json()
    assert second["version"] == 2
    assert second["supersedes_id"] == first["id"]
    listed = client.get("/mappings", headers=auth_header(token)).json()
    names = [m["id"] for m in listed]
    assert first["id"] in names and second["id"] in names


def test_the_importer_is_the_authorizer_of_every_row(
    client: TestClient, db: Session
) -> None:
    ids = seed(client, db)
    make_user(db, Role.operator)
    operator = login(client, ROLE_USERS[Role.operator])
    r = upload(client, operator, file_for(ids))
    assert r.status_code == 201, r.text
    rows = db.execute(select(Authorization)).scalars().all()
    assert {row.authorizer_username for row in rows} == {ROLE_USERS[Role.operator]}


def test_a_file_that_is_not_a_file_is_refused_by_name(
    client: TestClient, db: Session
) -> None:
    seed(client, db)
    token = login(client, ROLE_USERS[Role.administrator])
    for payload, expected in (
        (b"\xff\xfe\x00not utf 8", "not valid UTF-8"),
        (b"", "empty"),
    ):
        r = client.post(
            "/authorizations/import",
            headers=auth_header(token),
            files={"file": ("rows.csv", payload, "text/csv")},
        )
        assert r.status_code == 422, r.text
        assert expected in r.json()["detail"]


def test_two_columns_with_one_name_are_refused(
    client: TestClient, db: Session
) -> None:
    seed(client, db)
    token = login(client, ROLE_USERS[Role.administrator])
    r = upload(client, token, "identity_id,role,role\na,b,c\n")
    assert r.status_code == 422
    assert "two columns with the same name" in r.json()["detail"]


def test_a_path_in_a_cell_becomes_hops(client: TestClient, db: Session) -> None:
    ids = seed(client, db)
    token = login(client, ROLE_USERS[Role.administrator])
    text = (
        "identity_id,role,mode,path,owner_kind,owner,justification\n"
        f"{ids['csv.one']},{ROLE_ARN},standing,membership:platform-admins,"
        "team,platform-team,arrives through the group\n"
    )
    r = upload(client, token, text)
    assert r.status_code == 201, r.text
    row = db.execute(select(Authorization)).scalars().one()
    assert row.path == [
        {"via": "membership", "ref": "platform-admins", "mode": "active"}
    ]


def test_an_empty_path_cell_is_a_direct_hop(client: TestClient, db: Session) -> None:
    ids = seed(client, db)
    token = login(client, ROLE_USERS[Role.administrator])
    upload(client, token, file_for(ids))
    rows = db.execute(select(Authorization)).scalars().all()
    assert all(row.path == [{"via": "direct", "ref": "", "mode": "active"}]
               for row in rows)


def test_importing_the_same_file_twice_supersedes_rather_than_duplicates(
    client: TestClient, db: Session
) -> None:
    ids = seed(client, db)
    token = login(client, ROLE_USERS[Role.administrator])
    upload(client, token, file_for(ids))
    upload(client, token, file_for(ids))
    identity = db.execute(
        select(Identity).where(Identity.external_id == ids["csv.one"])
    ).scalar_one()
    assert len(authorizations.active(db, identity.id)) == 1
    assert len(authorizations.history(db, identity.id)) == 2
