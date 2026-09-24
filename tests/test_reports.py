"""Escaping canaries, figure fidelity, and evidence completeness.

The three artifacts answer to the same rules as the page: hostile
values stay data at every exit, and every figure a report states is
the engine's figure, not a second computation.
"""

import csv
import io

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from manifest_identity.core.roles import Role
from manifest_identity.decide.reports import EVIDENCE_CSV_COLUMNS, csv_safe
from tests.conftest import ROLE_USERS, auth_header, login, make_user
from tests.test_campaigns import create_campaign, detail, dispose
from tests.test_governance import (
    admin_policy,
    import_details,
    operator_token,
    user_entry,
)

FORMULA = "=HYPERLINK(\"https://example.invalid\",\"click\")"
MARKUP = '<img src=x onerror="alert(1)">'


def test_formula_leaders_are_neutralized() -> None:
    assert csv_safe("=SUM(A1:A9)") == "'=SUM(A1:A9)"
    assert csv_safe("+1") == "'+1"
    assert csv_safe("-1") == "'-1"
    assert csv_safe("@cmd") == "'@cmd"
    assert csv_safe("\t=x") == "'\t=x"
    assert csv_safe("plain-name") == "plain-name"
    assert csv_safe(None) == ""


def test_hostile_names_stay_data_in_every_artifact(
    client: TestClient, db: Session
) -> None:
    token = operator_token(client, db)
    import_details(client, token, {
        "UserDetailList": [
            user_entry(FORMULA, "AIDAREP0000000000001"),
            user_entry(MARKUP, "AIDAREP0000000000002"),
        ],
    })

    # CSV: the formula arrives prefixed, never bare at cell start.
    text = client.get("/export.csv", headers=auth_header(token)).text
    rows = list(csv.reader(io.StringIO(text)))
    names = [row[1] for row in rows[1:]]
    assert "'" + FORMULA in names
    assert FORMULA not in names

    # JSON: raw data, exactly as stored, because JSON is parsed.
    body = client.get("/export.json", headers=auth_header(token)).json()
    exported = {row["name"] for row in body["identities"]}
    assert FORMULA in exported
    assert MARKUP in exported

    # HTML: the engine escapes by default; the payload never appears
    # as markup, and its escaped form does appear as text.
    html = client.get("/report.html", headers=auth_header(token)).text
    assert MARKUP not in html
    assert "&lt;img src=x" in html
    assert "<script" not in html.lower()


def test_report_figures_are_the_engines_figures(
    client: TestClient, db: Session
) -> None:
    token = operator_token(client, db)
    import_details(client, token, {
        "UserDetailList": [
            user_entry("quiet-one", "AIDAREP0000000000003",
                       tag_owner="platform-team"),
            user_entry("loud-one", "AIDAREP0000000000004", privileged=True),
        ],
        "Policies": [admin_policy()],
    })
    inventory = client.get("/identities", headers=auth_header(token)).json()["rows"]
    export = client.get("/export.json", headers=auth_header(token)).json()
    by_name = {row["name"]: row for row in export["identities"]}
    for identity in inventory:
        row = by_name[identity["display_name"]]
        for tier in ("critical", "warning", "notice"):
            assert row[tier] == identity[tier], identity["display_name"]
    # Ranked: the loud one outranks the quiet one.
    names = [row["name"] for row in export["identities"]]
    assert names.index("loud-one") < names.index("quiet-one")


def test_evidence_export_carries_population_and_every_decision(
    client: TestClient, db: Session
) -> None:
    token = operator_token(client, db)
    import_details(client, token, {
        "UserDetailList": [
            user_entry("first", "AIDAREP0000000000005"),
            user_entry("second", "AIDAREP0000000000006"),
        ],
    })
    cid = int(create_campaign(client, token)["id"])  # type: ignore[arg-type]
    items = list(detail(client, token, cid)["items"])  # type: ignore[arg-type]
    make_user(db, Role.reviewer)
    reviewer = login(client, ROLE_USERS[Role.reviewer])
    dispose(client, reviewer, cid, items[0]["id"], "certify")
    dispose(client, token, cid, items[1]["id"], "insufficient_evidence",
            note="no usage record")

    evidence = client.get(
        f"/campaigns/{cid}/evidence", headers=auth_header(token)
    ).json()
    assert evidence["total"] == 2
    assert evidence["coverage"] == "2 of 2"
    assert "frozen at creation" in evidence["population_statement"]
    by_name = {d["display_name"]: d for d in evidence["decisions"]}
    assert by_name["first"]["disposed_by"] == ROLE_USERS[Role.reviewer]
    assert by_name["first"]["disposed_at"] is not None
    assert by_name["second"]["disposition_note"] == "no usage record"
    for decision in evidence["decisions"]:
        assert decision["recommendation_reasons"]
        assert decision["evidence"]


def test_evidence_csv_matches_the_json_and_stays_escaped(
    client: TestClient, db: Session
) -> None:
    token = operator_token(client, db)
    import_details(client, token, {
        "UserDetailList": [
            user_entry(FORMULA, "AIDAREP0000000000007"),
            user_entry("plain", "AIDAREP0000000000008"),
        ],
    })
    cid = int(create_campaign(client, token)["id"])  # type: ignore[arg-type]
    items = list(detail(client, token, cid)["items"])  # type: ignore[arg-type]
    for item in items:
        dispose(client, token, cid, item["id"], "certify")

    json_export = client.get(
        f"/campaigns/{cid}/evidence", headers=auth_header(token)
    ).json()
    r = client.get(
        f"/campaigns/{cid}/evidence.csv", headers=auth_header(token)
    )
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    rows = list(csv.reader(io.StringIO(r.text)))

    # The summary rows carry the same population statement and coverage
    # the JSON export states, because the CSV is built from it.
    summary = {row[0]: row[1] for row in rows if len(row) == 2}
    assert (
        summary["population_statement"]
        == json_export["population_statement"]
    )
    assert summary["coverage"] == json_export["coverage"] == "2 of 2"

    # One decision row per item, and the hostile name arrives prefixed,
    # never bare at cell start, exactly as in the inventory CSV.
    header_at = rows.index(list(EVIDENCE_CSV_COLUMNS))
    decisions = [row for row in rows[header_at + 1:] if row]
    assert len(decisions) == len(json_export["decisions"]) == 2
    names = [row[0] for row in decisions]
    assert "'" + FORMULA in names
    assert FORMULA not in names
