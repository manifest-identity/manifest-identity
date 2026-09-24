"""Campaign lifecycle, disposition rules, the delta, and the rollup.

The invariants under test: the population freezes at creation, every
disposition is one item with a note where the meaning needs one, a
decision is final for that campaign, close refuses while items are
open, and the recommendation always names its reasons and never
decides.
"""

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.core.roles import Role
from manifest_identity.decide.campaigns import Recommendation, evidence_delta, recommend
from manifest_identity.models import AuditEvent
from manifest_identity.observe.derive import MIN_OBSERVATION_DAYS
from manifest_identity.observe.findings import Finding
from tests.conftest import ROLE_USERS, auth_header, login, make_user
from tests.test_governance import (
    admin_policy,
    group_entry,
    identity_id,
    import_details,
    operator_token,
    user_entry,
)


def make_population(client: TestClient, db: Session, token: str) -> None:
    import_details(client, token, {
        "UserDetailList": [
            user_entry("keeper", "AIDACAMP000000000001",
                       tag_owner="platform-team"),
            user_entry("mighty", "AIDACAMP000000000002", privileged=True),
        ],
        "GroupDetailList": [group_entry("admins", "AGPACAMP000000000001")],
        "Policies": [admin_policy()],
    })


def create_campaign(
    client: TestClient,
    token: str,
    *,
    name: str = "quarterly review",
    scope: str = "everything",
    recurrence: str = "none",
    expect: int = 201,
) -> dict[str, object]:
    r = client.post(
        "/campaigns",
        headers=auth_header(token),
        json={
            "name": name,
            "scope": scope,
            "due_at": "2026-09-30T00:00:00+00:00",
            "recurrence": recurrence,
        },
    )
    assert r.status_code == expect, r.text
    return dict(r.json()) if expect == 201 else {}


def detail(client: TestClient, token: str, cid: int) -> dict[str, object]:
    r = client.get(f"/campaigns/{cid}", headers=auth_header(token))
    assert r.status_code == 200, r.text
    return dict(r.json())


def dispose(
    client: TestClient,
    token: str,
    cid: int,
    item_id: int,
    disposition: str,
    note: str | None = None,
    expect: int = 200,
) -> None:
    body: dict[str, object] = {"disposition": disposition}
    if note is not None:
        body["note"] = note
    r = client.post(
        f"/campaigns/{cid}/items/{item_id}/disposition",
        headers=auth_header(token),
        json=body,
    )
    assert r.status_code == expect, r.text


def test_the_lifecycle_end_to_end(client: TestClient, db: Session) -> None:
    token = operator_token(client, db)
    make_population(client, db, token)
    created = create_campaign(client, token, recurrence="quarterly")
    cid = int(created["id"])  # type: ignore[arg-type]
    assert created["total"] == 3  # two identities and one group
    assert created["disposed"] == 0

    view = detail(client, token, cid)
    assert view["next_due"] is not None
    items = list(view["items"])  # type: ignore[arg-type]
    for item in items:
        assert item["recommendation_reasons"], item["display_name"]
        assert item["evidence"]["finding_codes"] is not None

    # The reviewer decides; deciding is the review.
    make_user(db, Role.reviewer)
    reviewer = login(client, ROLE_USERS[Role.reviewer])
    dispose(client, reviewer, cid, items[0]["id"], "certify")
    dispose(client, reviewer, cid, items[1]["id"], "insufficient_evidence",
            note="no usage history for the key")
    # Close refuses while the third is open, and names the count.
    r = client.post(f"/campaigns/{cid}/close", headers=auth_header(token))
    assert r.status_code == 409
    assert "1 item(s) undecided" in r.json()["detail"]

    dispose(client, token, cid, items[2]["id"], "revoke_recommended")
    r = client.post(f"/campaigns/{cid}/close", headers=auth_header(token))
    assert r.status_code == 200, r.text
    closed = r.json()
    assert closed["closed_by"] == ROLE_USERS[Role.operator]
    assert closed["disposed"] == 3

    # A closed campaign accepts no more decisions.
    dispose(client, token, cid, items[0]["id"], "certify", expect=409)

    actions = {
        e.action
        for e in db.execute(select(AuditEvent)).scalars()
    }
    assert {"campaign_created", "item_disposed", "campaign_closed"} <= actions


def test_a_decision_is_final_within_its_campaign(
    client: TestClient, db: Session
) -> None:
    token = operator_token(client, db)
    make_population(client, db, token)
    cid = int(create_campaign(client, token)["id"])  # type: ignore[arg-type]
    items = list(detail(client, token, cid)["items"])  # type: ignore[arg-type]
    dispose(client, token, cid, items[0]["id"], "certify")
    dispose(client, token, cid, items[0]["id"], "revoke_recommended",
            expect=409)


def test_notes_are_required_where_meaning_needs_them(
    client: TestClient, db: Session
) -> None:
    token = operator_token(client, db)
    make_population(client, db, token)
    cid = int(create_campaign(client, token)["id"])  # type: ignore[arg-type]
    items = list(detail(client, token, cid)["items"])  # type: ignore[arg-type]
    dispose(client, token, cid, items[0]["id"], "insufficient_evidence",
            expect=422)
    dispose(client, token, cid, items[0]["id"], "delegated", expect=422)
    dispose(client, token, cid, items[0]["id"], "delegated",
            note="handed to the platform lead")


def test_scope_privileged_freezes_only_the_privileged(
    client: TestClient, db: Session
) -> None:
    token = operator_token(client, db)
    make_population(client, db, token)
    created = create_campaign(client, token, scope="privileged")
    cid = int(created["id"])  # type: ignore[arg-type]
    names = {
        i["display_name"]
        for i in detail(client, token, cid)["items"]  # type: ignore[union-attr]
    }
    assert names == {"mighty", "admins"}


def test_an_empty_scope_refuses_to_become_a_campaign(
    client: TestClient, db: Session
) -> None:
    token = operator_token(client, db)
    make_population(client, db, token)
    create_campaign(client, token, scope="flagged", expect=422)


def test_the_rollup_collects_what_was_missing(
    client: TestClient, db: Session
) -> None:
    token = operator_token(client, db)
    make_population(client, db, token)
    cid = int(create_campaign(client, token)["id"])  # type: ignore[arg-type]
    items = list(detail(client, token, cid)["items"])  # type: ignore[arg-type]
    dispose(client, token, cid, items[0]["id"], "insufficient_evidence",
            note="no owner and no usage history")
    rollup = client.get(
        "/campaigns/rollup", headers=auth_header(token)
    ).json()
    assert len(rollup) == 1
    assert rollup[0]["note"] == "no owner and no usage history"
    assert rollup[0]["display_name"] == items[0]["display_name"]


def test_the_delta_shows_what_changed_since_certification(
    client: TestClient, db: Session
) -> None:
    token = operator_token(client, db)
    make_population(client, db, token)
    first = int(create_campaign(client, token, name="cycle one")["id"])  # type: ignore[arg-type]
    items = list(detail(client, token, first)["items"])  # type: ignore[arg-type]
    for item in items:
        dispose(client, token, first, item["id"], "certify")
    client.post(f"/campaigns/{first}/close", headers=auth_header(token))

    # Between cycles, the world changes: mighty gains an assigned owner.
    ident = identity_id(db, "mighty")
    r = client.post(
        f"/identities/{ident}/governance",
        headers=auth_header(token),
        json={"kind": "owner", "value": "identity-platform",
              "owner_type": "team"},
    )
    assert r.status_code == 201

    second = int(create_campaign(client, token, name="cycle two")["id"])  # type: ignore[arg-type]
    mighty = next(
        i
        for i in detail(client, token, second)["items"]  # type: ignore[union-attr]
        if i["display_name"] == "mighty"
    )
    assert any("owner changed" in line for line in mighty["delta"])
    assert any(
        "unowned_privileged" in line and "resolved" in line
        for line in mighty["delta"]
    )


def test_recommendations_name_their_reasons() -> None:
    finding = Finding(
        code="admin_equivalent", tier="critical", anchor="NHI5",
        explanation="holds administrator-equivalent privilege",
    )
    unused = Finding(
        code="unused_identity", tier="warning", anchor="NHI1",
        explanation="not used for 100 days",
    )
    warning = Finding(
        code="key_age", tier="warning", anchor="NHI7",
        explanation="the key is 200 days old",
    )

    thin: Recommendation = recommend([finding], MIN_OBSERVATION_DAYS - 1)
    assert thin.verdict == "insufficient_evidence"
    assert any("minimum" in reason for reason in thin.reasons)

    assert recommend([unused], 60).verdict == "revoke_recommended"
    assert recommend([finding], 60).verdict == "revoke_recommended"

    weighed = recommend([warning], 60)
    assert weighed.verdict == "certify"
    assert any("warnings to weigh" in reason for reason in weighed.reasons)

    quiet = recommend([], 60)
    assert quiet.verdict == "certify"
    assert quiet.reasons


def test_the_delta_reads_evidence_differences() -> None:
    previous = {
        "finding_codes": ["key_age"],
        "owner": None,
        "privilege_sources": ["ReadOnly, held directly"],
    }
    current = {
        "finding_codes": ["admin_equivalent"],
        "owner": "identity-platform",
        "privilege_sources": ["AdministratorAccess, held directly"],
    }
    lines = evidence_delta(previous, current)
    assert any("appeared" in line and "admin_equivalent" in line
               for line in lines)
    assert any("resolved" in line and "key_age" in line for line in lines)
    assert any("owner changed from nobody to identity-platform" in line
               for line in lines)
    assert any("gained" in line and "AdministratorAccess" in line
               for line in lines)
    assert any("lost" in line and "ReadOnly" in line for line in lines)
    assert evidence_delta(None, current) == []
