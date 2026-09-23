"""Person or service is derived from the credential shape, never
stored, and the inventory filters and sorts by it (issue 37).

The three heuristic cases each have a sample identity, so the
classification is exercised on the committed account and not only on
hand-built states.
"""

from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from manifest_identity.derive import DerivedState, classify
from manifest_identity.roles import Role
from manifest_identity.sample_data import GENERATIONS, file_set
from tests.conftest import auth_header, login, make_user


def _seed(client: TestClient, db: Session) -> dict[str, str]:
    token = login(client, make_user(db, Role.operator))
    files = file_set()
    day = GENERATIONS[-1].strftime("%Y-%m-%d")
    for route, name in (
        ("credential-report", f"{day}-credential-report.csv"),
        ("authorization-details", f"{day}-authorization-details.json"),
    ):
        response = client.post(
            f"/imports/{route}",
            files={"file": (name, files[name].encode(), "text/plain")},
            data={"captured_at": GENERATIONS[-1].isoformat()},
            headers=auth_header(token),
        )
        assert response.status_code == 201, response.text
    return auth_header(token)


def _state(**overrides: object) -> DerivedState:
    base = dict(
        as_of=datetime(2026, 8, 1, tzinfo=UTC), observed_days=30, display_name="x",
        identity_type="user", identity_created_at=None, password_enabled=None,
        mfa_active=None, key1_active=None, key1_age_days=None, key2_active=None,
        key2_age_days=None, cert1_active=None, cert2_active=None,
        last_activity=None, last_activity_days=None, attached_policies=0,
        inline_policies=0, group_names=[],
    )
    base.update(overrides)
    return DerivedState(**base)  # type: ignore[arg-type]


def test_the_three_heuristic_cases_and_the_fixed_types() -> None:
    assert classify(_state(password_enabled=True, mfa_active=True)).kind == "person"
    assert classify(_state(key1_active=True)).kind == "service"
    assert classify(_state(password_enabled=True, key1_active=True)).kind == "mixed"
    assert classify(_state()).kind == "unknown"
    assert classify(_state(identity_type="root")).kind == "person"
    assert classify(_state(identity_type="role")).kind == "service"
    assert "MFA" in classify(_state(password_enabled=True, mfa_active=False)).reason


def test_the_sample_account_exercises_every_case(client: TestClient, db: Session) -> None:
    headers = _seed(client, db)
    rows = {r["display_name"]: r
            for r in client.get("/identities?limit=500", headers=headers).json()["rows"]}
    assert rows["ops-console"]["kind"] == "person"
    assert rows["ci-deployer"]["kind"] == "service"
    assert rows["dev-lisa"]["kind"] == "mixed"
    detail = client.get(f"/identities/{rows['dev-lisa']['id']}", headers=headers).json()
    assert detail["kind"] == "mixed" and "access keys" in detail["kind_reason"]


def test_the_filter_and_the_sort_use_the_classification(client: TestClient, db: Session) -> None:
    headers = _seed(client, db)
    people = client.get("/identities?kind=person", headers=headers).json()["rows"]
    assert people and all(r["kind"] == "person" for r in people)
    ordered = client.get("/identities?sort=kind&direction=asc", headers=headers).json()["rows"]
    kinds = [r["kind"] for r in ordered]
    assert kinds == sorted(kinds)
    assert client.get("/identities?kind=robot", headers=headers).status_code == 422
