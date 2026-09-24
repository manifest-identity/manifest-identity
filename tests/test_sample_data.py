"""The sample account: deterministic, harmless, and complete.

The last of those is the one that matters. A demo that exercises half
the rules teaches a reader that the other half are decorative, so this
suite asserts that importing the shipped files produces every finding
the engine can produce.
"""

import re
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from manifest_identity.core.roles import Role
from manifest_identity.sample_data import GENERATIONS, file_set
from tests.conftest import ROLE_USERS, auth_header, login, make_user

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample-data"

# Shapes that would mean a credential reached a tracked file. The
# scanner at commit time is the mechanism; this is the belt.
CREDENTIAL_SHAPES = (
    re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),          # access key identifiers
    re.compile(r"BEGIN [A-Z ]*PRIVATE KEY"),             # key material
    re.compile(r"(?i)\b(password|secret|token)\s*[:=]\s*\S+"),
    re.compile(r"\b[A-Za-z0-9+/]{40}\b"),                # secret-key shaped
)

EVERY_FINDING = {
    # credential hygiene
    "root_used", "password_without_mfa", "key_age", "multiple_active_keys",
    "legacy_certificate", "unused_identity",
    # privilege
    "admin_equivalent", "privilege_escalation_capable", "iam_mutating",
    "wildcard_privilege", "broad_read", "everything_except_grant",
    "trust_public", "trust_cross_account", "unowned_privileged",
    # groups
    "empty_privileged_group", "unowned_privileged_group", "membership_drift",
}


def test_generation_is_deterministic() -> None:
    first = file_set()
    again = file_set()
    assert first == again


def test_committed_files_match_the_generator() -> None:
    """The shipped files and the code that makes them cannot drift:
    one source, checked, the same rule the role matrix follows."""
    generated = file_set()
    on_disk = {path.name: path.read_text() for path in SAMPLE_DIR.glob("*")}
    assert on_disk == generated, (
        "sample-data/ is stale; regenerate with "
        "python -m manifest_identity.sample_data sample-data"
    )


def test_no_credential_shaped_strings_anywhere() -> None:
    for name, content in file_set().items():
        for shape in CREDENTIAL_SHAPES:
            assert not shape.search(content), f"{name} matched {shape.pattern}"


def _import_everything(client: TestClient, token: str) -> None:
    files = file_set()
    for captured in GENERATIONS:
        day = captured.strftime("%Y-%m-%d")
        for name, route in (
            (f"{day}-credential-report.csv", "credential-report"),
            (f"{day}-authorization-details.json", "authorization-details"),
        ):
            response = client.post(
                f"/imports/{route}",
                headers=auth_header(token),
                files={"file": (name, files[name].encode(), "text/plain")},
                data={"captured_at": captured.isoformat()},
            )
            assert response.status_code == 201, (name, response.text)


def test_the_sample_account_produces_every_finding(
    client: TestClient, db: Session
) -> None:
    make_user(db, Role.operator)
    token = login(client, ROLE_USERS[Role.operator])
    _import_everything(client, token)

    seen: set[str] = set()
    identities = client.get("/identities", headers=auth_header(token)).json()["rows"]
    for row in identities:
        detail = client.get(
            f"/identities/{row['id']}", headers=auth_header(token)
        ).json()
        seen.update(finding["code"] for finding in detail["findings"])
    for group in client.get("/groups", headers=auth_header(token)).json():
        seen.update(finding["code"] for finding in group["findings"])

    missing = EVERY_FINDING - seen
    assert not missing, f"the sample data never triggers: {sorted(missing)}"


def test_the_sample_account_shows_a_resurrection(
    client: TestClient, db: Session
) -> None:
    make_user(db, Role.operator)
    token = login(client, ROLE_USERS[Role.operator])
    _import_everything(client, token)
    identities = client.get("/identities", headers=auth_header(token)).json()["rows"]
    phoenix = [row for row in identities if row["display_name"] == "phoenix"]
    assert len(phoenix) == 2, "the recreated name should be two identities"
    assert all(row["name_reused"] for row in phoenix)


def test_ordinary_things_stay_quiet(client: TestClient, db: Session) -> None:
    """A finding on everything is the same as a finding on nothing."""
    make_user(db, Role.operator)
    token = login(client, ROLE_USERS[Role.operator])
    _import_everything(client, token)
    identities = client.get("/identities", headers=auth_header(token)).json()["rows"]
    quiet = {
        row["display_name"]
        for row in identities
        if row["critical"] == 0 and row["warning"] == 0
    }
    # The service role holding a read-only policy is furniture.
    assert "app-runtime" in quiet
    groups = client.get("/groups", headers=auth_header(token)).json()
    readers = [g for g in groups if g["name"] == "readers"][0]
    assert readers["findings"] == []
    assert readers["privileged"] is False


def test_the_scaled_set_holds_every_small_set_invariant() -> None:
    """Issue 36's contract: scale changes the size, nothing else.
    Deterministic, free of credential shapes, and a strict superset of
    the curated set, so every archetype the small account teaches is
    still present in the large one."""
    scaled = file_set(scale=300)
    assert scaled == file_set(scale=300)
    curated = file_set()
    for name, content in scaled.items():
        for shape in CREDENTIAL_SHAPES:
            assert not shape.search(content), f"{name} matched {shape.pattern}"
        # Scale adds identities, so it grows the credential reports.
        # The authorization template is a shipped example of the file
        # door's shape, not a population, and does not scale with one.
        if name.endswith("-credential-report.csv"):
            small_rows = set(curated[name].splitlines())
            large_rows = content.splitlines()
            assert small_rows <= set(large_rows)
            # header + curated rows + one row per scaled identity
            assert len(large_rows) == len(small_rows) + 300


def test_scale_zero_is_the_committed_set() -> None:
    assert file_set(scale=0) == file_set()


def test_the_scaled_population_mixes_people_and_services() -> None:
    """The bulk must be distinguishable in the application the same way
    the curated set is: people carry passwords, services carry keys,
    and the names say which is which."""
    report = file_set(scale=90)[
        f"{GENERATIONS[2].strftime('%Y-%m-%d')}-credential-report.csv"
    ]
    people_rows = [r for r in report.splitlines() if r.startswith("person-")]
    service_rows = [r for r in report.splitlines() if r.startswith("svc-")]
    assert len(people_rows) == 30
    assert len(service_rows) == 60
    for row in people_rows:
        fields = row.split(",")
        assert fields[3] == "TRUE"   # password_enabled
        assert fields[8] == "FALSE"  # no access key
    for row in service_rows:
        fields = row.split(",")
        assert fields[3] == "FALSE"
        assert fields[8] == "TRUE"


def test_a_scaled_import_works_end_to_end(
    client: TestClient, db: Session
) -> None:
    """A few hundred identities import and list; the invariant is that
    scale is a data property, not a new code path."""
    operator = make_user(db, Role.operator)
    token = login(client, operator)
    files = file_set(scale=120)
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
    listing = client.get("/identities?limit=500", headers=auth_header(token))
    assert listing.status_code == 200
    names = {row["display_name"] for row in listing.json()["rows"]}
    assert "person-00000" in names and "svc-00001" in names
    assert len(names) > 120
