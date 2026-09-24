"""The role matrix, enforced and complete.

Two properties. Drift: every registered route is either in the matrix
or explicitly public, so a new route cannot ship unguarded. Enforcement:
for every matrix row and every role, the live endpoint answers allow or
403 exactly as the matrix says, using real sessions, so a route that
forgot its dependency fails here.
"""

import json
import secrets

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from manifest_identity.core.roles import PUBLIC_ROUTES, ROUTE_ROLES, Role
from manifest_identity.main import app
from tests.conftest import ROLE_USERS, auth_header, login, make_user

SAMPLE_REPORT = (
    b"user,arn,user_creation_time,password_enabled,password_last_used,"
    b"password_last_changed,password_next_rotation,mfa_active,"
    b"access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,"
    b"access_key_1_last_used_region,access_key_1_last_used_service,"
    b"access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,"
    b"access_key_2_last_used_region,access_key_2_last_used_service,"
    b"cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated\n"
    b"matrix.user,arn:aws:iam::123456789012:user/matrix.user,"
    b"2025-01-01T00:00:00+00:00,TRUE,N/A,2025-01-01T00:00:00+00:00,N/A,TRUE,"
    b"FALSE,N/A,N/A,N/A,N/A,FALSE,N/A,N/A,N/A,N/A,FALSE,N/A,FALSE,N/A\n"
)

# A file the mapping can read whose rows name no identity: the call is
# a valid one, so a denial is provably authorization.
SAMPLE_AUTHORIZATIONS = (
    b"identity_id,role,mode,path,owner_kind,owner,justification\n"
    b"AIDANOBODY000000000001,arn:aws:iam::aws:policy/ReadOnlyAccess,"
    b"standing,,team,matrix-team,matrix exercise\n"
)

# How to call each governed route with a valid request, so a denial is
# provably authorization and not validation. Values are request kwargs.
CALL_PLANS: dict[str, tuple[str, str, dict[str, object]]] = {
    "GET /auth/me": ("get", "/auth/me", {}),
    "POST /auth/logout": ("post", "/auth/logout", {}),
    "GET /admin/users": ("get", "/admin/users", {}),
    "POST /admin/users": (
        "post",
        "/admin/users",
        {
            "json": {
                "username": "matrix.made",
                "password": "pw-" + secrets.token_urlsafe(16),
                "role": "reviewer",
            }
        },
    ),
    "POST /imports/credential-report": (
        "post",
        "/imports/credential-report",
        {
            "files": {"file": ("report.csv", SAMPLE_REPORT, "text/csv")},
            "data": {"captured_at": "2026-08-01T00:00:00+00:00"},
        },
    ),
    "POST /imports/authorization-details": (
        "post",
        "/imports/authorization-details",
        {
            "files": {
                "file": (
                    "details.json",
                    json.dumps({"UserDetailList": [{
                        "UserName": "matrix.auth",
                        "UserId": "AIDAMATRIX000000000001",
                        "Arn": "arn:aws:iam::123456789012:user/matrix.auth",
                        "CreateDate": "2025-01-01T00:00:00Z",
                    }]}).encode(),
                    "application/json",
                )
            },
            "data": {"captured_at": "2026-08-01T00:00:00+00:00"},
        },
    ),
    "POST /admin/users/{username}/sessions/revoke": (
        "post",
        "/admin/users/nobody.here/sessions/revoke",
        {},
    ),
    "POST /admin/users/{username}/bindings": (
        "post",
        "/admin/users/nobody.here/bindings",
        {"json": {"role": "reviewer"}},
    ),
    "POST /admin/users/{username}/bindings/{binding_id}/revoke": (
        "post",
        "/admin/users/nobody.here/bindings/1/revoke",
        {},
    ),
    "GET /admin/scopes": ("get", "/admin/scopes", {}),
    "GET /admin/settings": ("get", "/admin/settings", {}),
    "GET /delta": ("get", "/delta", {}),
    "GET /identities/{identity_id}/delta": ("get", "/identities/1/delta", {}),
    "GET /identities/{identity_id}/observed-grants": (
        "get", "/identities/1/observed-grants", {},
    ),
    "GET /export/observed-grants.csv": (
        "get", "/export/observed-grants.csv", {},
    ),
    "GET /mappings": ("get", "/mappings", {}),
    "POST /mappings": (
        "post",
        "/mappings",
        {"json": {"name": "matrix mapping", "fields": {
            "identity_external_id": {"column": "identity_id"},
            "role_definition_external_id": {"column": "role"},
            "owner_kind": {"constant": "team"},
            "owner_ref": {"column": "owner"},
        }}},
    ),
    "POST /authorizations/import/dry-run": (
        "post",
        "/authorizations/import/dry-run",
        {"files": {"file": ("a.csv", SAMPLE_AUTHORIZATIONS, "text/csv")}},
    ),
    "POST /authorizations/import": (
        "post",
        "/authorizations/import",
        {"files": {"file": ("a.csv", SAMPLE_AUTHORIZATIONS, "text/csv")}},
    ),
    "PUT /admin/settings": (
        "put",
        "/admin/settings",
        {"json": {"values": {"authorization.reference_required": "false"}}},
    ),
    "POST /admin/scopes": (
        "post",
        "/admin/scopes",
        {"json": {"provider": "aws", "partition": "aws_commercial", "kind": "account",
                  "external_id": "000000000000", "display_name": "test"}},
    ),
    "GET /imports": ("get", "/imports", {}),
    "GET /identities": ("get", "/identities", {}),
    "GET /identities/{identity_id}": ("get", "/identities/999999", {}),
    "GET /groups": ("get", "/groups", {}),
    # Identity 1 exists by the time these rows run: the import rows
    # above land first and create it. The group and record rows point
    # at nothing on purpose; a 404 there is still an authorization
    # allow, which the escape below accepts for parameterized routes.
    "POST /identities/{identity_id}/governance": (
        "post",
        "/identities/1/governance",
        {"json": {"kind": "flag", "value": "matrix exercise"}},
    ),
    "POST /groups/{group_id}/governance": (
        "post",
        "/groups/999999/governance",
        {"json": {"kind": "flag", "value": "matrix exercise"}},
    ),
    "POST /identities/{identity_id}/attest": (
        "post",
        "/identities/1/attest",
        {"json": {"value": "matrix attestation"}},
    ),
    "POST /groups/{group_id}/attest": (
        "post",
        "/groups/999999/attest",
        {"json": {"value": "matrix attestation"}},
    ),
    "DELETE /governance/{record_id}": ("delete", "/governance/999999", {}),
    "GET /identities/{identity_id}/authorizations": (
        "get", "/identities/1/authorizations", {},
    ),
    "POST /identities/{identity_id}/authorizations": (
        "post",
        "/identities/1/authorizations",
        {"json": {
            "role_definition_external_id": "arn:aws:iam::aws:policy/ReadOnlyAccess",
            "path": [{"via": "direct", "ref": "", "mode": "active"}],
            "owner_kind": "team",
            "owner_ref": "matrix-team",
            "justification": "matrix exercise",
        }},
    ),
    "POST /authorizations/{authorization_id}/revoke": (
        "post",
        "/authorizations/999999/revoke",
        {"json": {"reason": "matrix exercise"}},
    ),
    "POST /campaigns": (
        "post",
        "/campaigns",
        {
            "json": {
                "name": "matrix cycle",
                "scope": "everything",
                "due_at": "2026-09-30T00:00:00+00:00",
            }
        },
    ),
    "GET /campaigns": ("get", "/campaigns", {}),
    "GET /campaigns/rollup": ("get", "/campaigns/rollup", {}),
    "GET /campaigns/{campaign_id}": ("get", "/campaigns/999999", {}),
    "POST /campaigns/{campaign_id}/items/{item_id}/disposition": (
        "post",
        "/campaigns/999999/items/999999/disposition",
        {"json": {"disposition": "certify"}},
    ),
    "POST /campaigns/{campaign_id}/close": (
        "post",
        "/campaigns/999999/close",
        {},
    ),
    "GET /export.csv": ("get", "/export.csv", {}),
    "GET /export.json": ("get", "/export.json", {}),
    "GET /report.html": ("get", "/report.html", {}),
    "GET /campaigns/{campaign_id}/evidence": (
        "get",
        "/campaigns/999999/evidence",
        {},
    ),
    "GET /campaigns/{campaign_id}/evidence.csv": (
        "get",
        "/campaigns/999999/evidence.csv",
        {},
    ),
}


def flatten_routes(routes: object) -> list[APIRoute]:
    """The framework wraps included routers lazily, and iterating
    app.routes alone silently sees none of their routes; this drift
    test was vacuous for every governed route until the flattening
    below was added. The count canary in the drift test keeps the next
    framework change from making it vacuous again."""
    out: list[APIRoute] = []
    for route in routes:  # type: ignore[attr-defined]
        if type(route).__name__ == "_IncludedRouter":
            out.extend(flatten_routes(route.original_router.routes))
        elif isinstance(route, APIRoute):
            out.append(route)
    return out


def route_keys() -> set[str]:
    return {
        f"{method} {route.path}"
        for route in flatten_routes(app.routes)
        for method in route.methods - {"HEAD", "OPTIONS"}
    }


def test_every_route_is_governed_or_named_public() -> None:
    keys = route_keys()
    # The canary: if enumeration ever collapses again, this fails
    # before the per-route loop silently passes on nothing.
    assert len(keys) >= len(ROUTE_ROLES), (
        "route enumeration sees fewer routes than the matrix governs; "
        "the flattening no longer matches the framework"
    )
    for key in keys:
        assert key in ROUTE_ROLES or key in PUBLIC_ROUTES, (
            f"route {key} is neither in ROUTE_ROLES nor PUBLIC_ROUTES"
        )
    # Both directions: a matrix row whose route is gone is stale.
    for key in set(ROUTE_ROLES) | set(PUBLIC_ROUTES):
        assert key in keys, f"matrix or public row without a route: {key}"


def test_routes_match_the_documented_enumeration() -> None:
    """The README states the route surface in a fenced block, and this
    test holds the application to it, the figures-verified doctrine
    applied to routes."""
    import re
    from pathlib import Path

    text = Path(__file__).parent.parent.joinpath("README.md").read_text()
    match = re.search(r"```routes\n(.*?)```", text, re.DOTALL)
    assert match, "README.md no longer carries the ```routes block"
    documented = {
        line.strip() for line in match.group(1).splitlines() if line.strip()
    }
    assert documented == route_keys(), (
        "the documented route enumeration disagrees with the "
        f"application: only-documented={sorted(documented - route_keys())} "
        f"only-live={sorted(route_keys() - documented)}"
    )


def test_the_stated_figures_are_the_counted_figures() -> None:
    """The README's bold figures drifted twice in one day, once past a
    new route and once past a new test file, because the enumeration
    was gated and the prose numbers were not. Now a stated figure is a
    counted figure: each lives in exactly one sentence, and this test
    recounts it from the thing itself."""
    import re
    from pathlib import Path

    root = Path(__file__).parent.parent
    text = root.joinpath("README.md").read_text()

    stated = re.search(r"\*\*(\d+) tests in (\d+) files\*\*", text)
    assert stated, "README.md no longer states the test figure"
    test_files = sorted(root.glob("tests/test_*.py"))
    functions = sum(
        len(re.findall(r"^def test_", f.read_text(), re.MULTILINE))
        for f in test_files
    )
    assert (int(stated.group(1)), int(stated.group(2))) == (
        functions, len(test_files)
    ), (
        f"README states {stated.group(0)}; counted {functions} tests "
        f"in {len(test_files)} files"
    )

    routes_stated = re.findall(r"\*\*(\d+) routes\*\*", text)
    assert len(routes_stated) == 1, "the route figure must live once"
    assert int(routes_stated[0]) == len(route_keys()), (
        f"README states {routes_stated[0]} routes; "
        f"the application serves {len(route_keys())}"
    )


def test_the_stated_decision_count_is_the_counted_count() -> None:
    """The decision figure drifted ten entries behind before this
    existed; a stated figure is a counted figure, decisions included."""
    import re
    from pathlib import Path

    root = Path(__file__).parent.parent
    text = root.joinpath("README.md").read_text()
    stated = re.search(r"\*\*(\d+) recorded decisions", text)
    assert stated, "README.md no longer states the decision figure"
    counted = len(re.findall(
        r"^## D-", root.joinpath("DECISIONS.md").read_text(), re.MULTILINE
    ))
    assert int(stated.group(1)) == counted, (
        f"README states {stated.group(1)} recorded decisions; "
        f"DECISIONS.md holds {counted}"
    )


def test_every_matrix_row_has_a_call_plan() -> None:
    assert set(CALL_PLANS) == set(ROUTE_ROLES)


def test_matrix_rows_are_enforced_for_every_role(
    client: TestClient, db: Session
) -> None:
    for role in Role:
        make_user(db, role)
    tokens = {role: login(client, ROLE_USERS[role]) for role in Role}

    for key, (method, path, kwargs) in CALL_PLANS.items():
        allowed = ROUTE_ROLES[key]
        for role in Role:
            # Logout revokes the session it uses; give that row its own
            # disposable session so later rows keep valid tokens. The
            # import row gets a distinct capture time per call so the
            # allow case is never a duplicate rejection.
            token = (
                login(client, ROLE_USERS[role])
                if key == "POST /auth/logout"
                else tokens[role]
            )
            call_kwargs = dict(kwargs)
            if key.startswith("POST /imports/"):
                call_kwargs["data"] = {
                    "captured_at": f"2026-08-0{1 + list(Role).index(role)}T00:00:00+00:00"
                }
            response = client.request(
                method.upper(), path, headers=auth_header(token), **call_kwargs  # type: ignore[arg-type]
            )
            if role in allowed:
                # A 404 on a parameterized route is an allow:
                # authorization passed and the lookup ran.
                if response.status_code == 404 and "{" in key:
                    continue
                assert response.status_code < 400, (
                    f"{key} should admit {role}: {response.status_code}"
                )
            else:
                assert response.status_code == 403, (
                    f"{key} should refuse {role}: {response.status_code}"
                )
                assert "requires role" in response.json()["detail"]


def test_unauthenticated_calls_get_401_not_403(client: TestClient) -> None:
    for key, (method, path, kwargs) in CALL_PLANS.items():
        response = client.request(method.upper(), path, **kwargs)  # type: ignore[arg-type]
        assert response.status_code == 401, f"{key}: {response.status_code}"
