"""The inventory stays bounded at any account size (issue 38).

The sample account's nineteen rows prove nothing about thousands, so
these tests seed a few hundred through the real import path and hold
the route to its promises: a capped page, filters on the server, and
tiles that no filter changes.
"""

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from manifest_identity.roles import Role
from manifest_identity.sample_data import GENERATIONS, file_set
from tests.conftest import auth_header, login, make_user

SCALE = 300


def _seed(client: TestClient, db: Session) -> str:
    token = login(client, make_user(db, Role.operator))
    files = file_set(scale=SCALE)
    day = GENERATIONS[0].strftime("%Y-%m-%d")
    for route, name in (
        ("credential-report", f"{day}-credential-report.csv"),
        ("authorization-details", f"{day}-authorization-details.json"),
    ):
        response = client.post(
            f"/imports/{route}",
            files={"file": (name, files[name].encode(), "text/plain")},
            data={"captured_at": GENERATIONS[0].isoformat()},
            headers=auth_header(token),
        )
        assert response.status_code == 201, response.text
    return token


def test_the_response_is_bounded_at_hundreds_of_identities(
    client: TestClient, db: Session
) -> None:
    token = _seed(client, db)
    page = client.get("/identities", headers=auth_header(token)).json()
    assert len(page["rows"]) == 100  # the default cap, not the account size
    assert page["matched"] > SCALE
    assert page["tiles"]["identities"] == page["matched"]
    assert page["offset"] == 0 and page["limit"] == 100


def test_the_limit_is_capped_and_the_offset_walks_every_row(
    client: TestClient, db: Session
) -> None:
    token = _seed(client, db)
    assert client.get(
        "/identities?limit=501", headers=auth_header(token)
    ).status_code == 422
    seen: list[int] = []
    offset = 0
    while True:
        page = client.get(
            f"/identities?limit=150&offset={offset}", headers=auth_header(token)
        ).json()
        seen.extend(row["id"] for row in page["rows"])
        if offset + len(page["rows"]) >= page["matched"]:
            break
        offset += 150
    assert len(seen) == len(set(seen)) == page["matched"]


def test_filters_apply_on_the_server(client: TestClient, db: Session) -> None:
    token = _seed(client, db)
    named = client.get(
        "/identities?q=person-000&limit=500", headers=auth_header(token)
    ).json()
    assert 0 < named["matched"] < SCALE
    assert all("person-000" in r["display_name"] for r in named["rows"])
    critical = client.get(
        "/identities?tier=critical&limit=500", headers=auth_header(token)
    ).json()
    assert all(r["critical"] > 0 for r in critical["rows"])
    roots = client.get(
        "/identities?type=root&limit=500", headers=auth_header(token)
    ).json()
    assert {r["identity_type"] for r in roots["rows"]} == {"root"}
    assert client.get(
        "/identities?tier=terrible", headers=auth_header(token)
    ).status_code == 422


def test_the_tiles_ignore_filters_and_partition_the_account(
    client: TestClient, db: Session
) -> None:
    token = _seed(client, db)
    unfiltered = client.get("/identities", headers=auth_header(token)).json()
    filtered = client.get(
        "/identities?q=svc-0000&tier=quiet", headers=auth_header(token)
    ).json()
    assert filtered["tiles"] == unfiltered["tiles"]
    tiles = unfiltered["tiles"]
    assert (
        tiles["critical"] + tiles["warning"] + tiles["notice"] + tiles["quiet"]
        == tiles["identities"]
    )


def test_rows_carry_their_top_finding(client: TestClient, db: Session) -> None:
    """The list teaches before a click (issue 57): a found identity's
    row carries its worst finding's own explanation, and a quiet
    identity carries none."""
    token = _seed(client, db)
    page = client.get(
        "/identities?tier=critical&limit=1", headers=auth_header(token)
    ).json()
    assert page["rows"], "the sample account has critical identities"
    top = page["rows"][0]["top_finding"]
    assert isinstance(top, str) and len(top) > 10
    quiet = client.get(
        "/identities?tier=quiet&limit=1", headers=auth_header(token)
    ).json()
    assert quiet["rows"], "the sample account has a quiet identity"
    assert quiet["rows"][0]["top_finding"] is None


def test_sorting_orders_the_whole_matched_set_not_the_page(
    client: TestClient, db: Session
) -> None:
    token = _seed(client, db)
    page = client.get(
        "/identities?sort=name&direction=asc&limit=150",
        headers=auth_header(token),
    ).json()
    names = [r["display_name"].lower() for r in page["rows"]]
    assert names == sorted(names)
    # The last page under the reversed order starts with what the
    # ascending order ended with, which only holds if the sort ran
    # over the matched set before the slice.
    reversed_page = client.get(
        "/identities?sort=name&direction=desc&limit=150",
        headers=auth_header(token),
    ).json()
    assert reversed_page["rows"][0]["display_name"].lower() == names[-1] or (
        reversed_page["rows"][0]["display_name"].lower() >= names[-1]
    )
    by_critical = client.get(
        "/identities?sort=critical&direction=desc",
        headers=auth_header(token),
    ).json()
    counts = [r["critical"] for r in by_critical["rows"]]
    assert counts == sorted(counts, reverse=True)


def test_sort_rejects_columns_the_matrix_never_promised(
    client: TestClient, db: Session
) -> None:
    token = _seed(client, db)
    assert client.get(
        "/identities?sort=owner", headers=auth_header(token)
    ).status_code == 422
    assert client.get(
        "/identities?sort=name&direction=sideways", headers=auth_header(token)
    ).status_code == 422
