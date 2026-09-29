"""Integration tokens and the read-only surface (1.10).

A token is a second kind of credential, so the tests are about the
boundary as much as the reads: a token opens the read surface and
nothing else, a session opens everything else and not the read surface,
a revoked token opens nothing, and every request under a token counts
against that token's own budget.

The reads themselves are paged from cursors, and the change feed is the
audit record, so the tests check that a cursor advances, that the last
page says so, and that a consumer that has caught up gets an empty page
rather than an error.
"""

import json

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from manifest_identity.api import deps as token_deps
from manifest_identity.core.roles import Role
from tests.conftest import ROLE_USERS, auth_header, login, make_user
from tests.test_governance import admin_policy, user_entry


def administrator(client: TestClient, db: Session) -> str:
    make_user(db, Role.administrator)
    return login(client, ROLE_USERS[Role.administrator])


def mint(client: TestClient, session: str, name: str = "siem") -> dict[str, object]:
    response = client.post(
        "/admin/tokens", headers=auth_header(session), json={"name": name}
    )
    assert response.status_code == 201, response.text
    return response.json()


def populate(client: TestClient, session: str, count: int = 3) -> None:
    payload = {
        "UserDetailList": [
            user_entry(f"reader-{n}", f"AIDAREADAPI0000000{n:03d}", privileged=(n == 0))
            for n in range(count)
        ],
        "Policies": [admin_policy()],
    }
    response = client.post(
        "/imports/authorization-details",
        headers=auth_header(session),
        files={"file": ("d.json", json.dumps(payload).encode(), "application/json")},
        data={"captured_at": "2026-08-01T00:00:00+00:00"},
    )
    assert response.status_code == 201, response.text


def test_a_token_is_shown_once_and_the_list_never_carries_it(
    client: TestClient, db: Session
) -> None:
    session = administrator(client, db)
    minted = mint(client, session)
    assert minted["token"]
    listed = client.get("/admin/tokens", headers=auth_header(session)).json()
    assert [row["name"] for row in listed] == ["siem"]
    assert "token" not in listed[0]
    assert listed[0]["revoked_at"] is None


def test_a_token_opens_the_read_surface_and_a_session_does_not(
    client: TestClient, db: Session
) -> None:
    session = administrator(client, db)
    populate(client, session)
    token = str(mint(client, session)["token"])
    with_token = client.get("/api/v1/identities", headers=auth_header(token))
    assert with_token.status_code == 200, with_token.text
    assert len(with_token.json()["items"]) == 3
    with_session = client.get("/api/v1/identities", headers=auth_header(session))
    assert with_session.status_code == 401
    # And the other way: a token holds no role, so a session route
    # refuses it before any role check.
    assert client.get("/identities", headers=auth_header(token)).status_code == 401


def test_a_revoked_token_opens_nothing(client: TestClient, db: Session) -> None:
    session = administrator(client, db)
    minted = mint(client, session)
    token = str(minted["token"])
    assert client.get("/api/v1/changes", headers=auth_header(token)).status_code == 200
    response = client.post(
        f"/admin/tokens/{minted['id']}/revoke",
        headers=auth_header(session),
        json={"reason": "the integration was retired"},
    )
    assert response.status_code == 201, response.text
    assert response.json()["revoked_at"] is not None
    assert client.get("/api/v1/changes", headers=auth_header(token)).status_code == 401


def test_identities_page_from_a_cursor_and_the_last_page_says_so(
    client: TestClient, db: Session
) -> None:
    session = administrator(client, db)
    populate(client, session, count=5)
    token = str(mint(client, session)["token"])
    first = client.get(
        "/api/v1/identities?limit=2", headers=auth_header(token)
    ).json()
    assert len(first["items"]) == 2
    assert first["next_cursor"] == first["items"][-1]["id"]
    seen = [row["id"] for row in first["items"]]
    cursor = first["next_cursor"]
    while cursor is not None:
        page = client.get(
            f"/api/v1/identities?limit=2&cursor={cursor}", headers=auth_header(token)
        ).json()
        seen += [row["id"] for row in page["items"]]
        cursor = page["next_cursor"]
    assert len(seen) == 5
    assert seen == sorted(seen)


def test_the_change_feed_advances_its_cursor_and_catches_up(
    client: TestClient, db: Session
) -> None:
    session = administrator(client, db)
    token = str(mint(client, session)["token"])
    first = client.get("/api/v1/changes", headers=auth_header(token)).json()
    assert first["items"], "the mint itself is in the audit record"
    assert any(row["action"] == "integration_token_created" for row in first["items"])
    cursor = first["next_cursor"]
    caught_up = client.get(
        f"/api/v1/changes?cursor={cursor}", headers=auth_header(token)
    ).json()
    assert caught_up["items"] == []
    assert caught_up["next_cursor"] == cursor
    populate(client, session)
    later = client.get(
        f"/api/v1/changes?cursor={cursor}", headers=auth_header(token)
    ).json()
    assert any(row["action"] == "snapshot_imported" for row in later["items"])
    assert later["next_cursor"] > cursor


def test_the_delta_is_readable_under_a_token(client: TestClient, db: Session) -> None:
    session = administrator(client, db)
    populate(client, session)
    token = str(mint(client, session)["token"])
    body = client.get("/api/v1/delta", headers=auth_header(token)).json()
    assert body["total"] >= 1
    assert any(row["kind"] == "held_not_authorized" for row in body["items"])


def test_each_token_has_its_own_read_budget(client: TestClient, db: Session) -> None:
    session = administrator(client, db)
    token = str(mint(client, session)["token"])
    other = str(mint(client, session, name="ticketing")["token"])
    token_deps.READ_LIMITER.clear()
    for _ in range(token_deps.READ_LIMITER.max_failures):
        assert client.get("/api/v1/changes", headers=auth_header(token)).status_code == 200
    throttled = client.get("/api/v1/changes", headers=auth_header(token))
    assert throttled.status_code == 429
    # The other token is unaffected, because the budget is per token.
    assert client.get("/api/v1/changes", headers=auth_header(other)).status_code == 200
    token_deps.READ_LIMITER.clear()


def test_minting_needs_an_administrator_and_a_name_is_unique(
    client: TestClient, db: Session
) -> None:
    session = administrator(client, db)
    make_user(db, Role.operator)
    operator = login(client, ROLE_USERS[Role.operator])
    assert client.post(
        "/admin/tokens", headers=auth_header(operator), json={"name": "x"}
    ).status_code == 403
    mint(client, session, name="siem")
    duplicate = client.post(
        "/admin/tokens", headers=auth_header(session), json={"name": "siem"}
    )
    assert duplicate.status_code == 409
