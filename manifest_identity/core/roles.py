"""The role vocabulary and the route matrix, single source.

ROUTE_ROLES is the one data structure that answers "who may call what."
The route dependencies read it to enforce, and the tests read it to
verify, so the enforced matrix and the tested matrix cannot drift
apart. A route is either in this matrix, or named public here, or the
drift test fails the build.
"""

from enum import StrEnum


class Role(StrEnum):
    reviewer = "reviewer"
    operator = "operator"
    administrator = "administrator"


ALL_ROLES: frozenset[Role] = frozenset(Role)

# Key form: "METHOD /path", matching FastAPI's registered routes.
ROUTE_ROLES: dict[str, frozenset[Role]] = {
    "GET /auth/me": ALL_ROLES,
    "POST /auth/logout": ALL_ROLES,
    "POST /auth/step-up": ALL_ROLES,
    "GET /admin/users": frozenset({Role.administrator}),
    "POST /admin/users": frozenset({Role.administrator}),
    # Ending a compromised user's sessions is the administrator's act,
    # and the threat model's stolen-token answer.
    "POST /admin/users/{username}/sessions/revoke": frozenset(
        {Role.administrator}
    ),
    # Bindings and the scope tree are the administrator's acts, global
    # in v0.3 (D-070): an administrator at a node cannot yet bind
    # below it.
    "POST /admin/users/{username}/bindings": frozenset({Role.administrator}),
    "POST /admin/users/{username}/bindings/{binding_id}/revoke": frozenset(
        {Role.administrator}
    ),
    # An integration token is a second kind of credential, and minting
    # or revoking one is the administrator's act (1.10).
    "GET /admin/tokens": frozenset({Role.administrator}),
    "POST /admin/tokens": frozenset({Role.administrator}),
    "POST /admin/tokens/{token_id}/revoke": frozenset({Role.administrator}),
    "GET /admin/scopes": frozenset({Role.administrator}),
    "POST /admin/scopes": frozenset({Role.administrator}),
    # Which fields an authorization must carry is the organization's
    # choice, and choosing is the administrator's act (D-070).
    "GET /admin/settings": frozenset({Role.administrator}),
    "PUT /admin/settings": frozenset({Role.administrator}),
    # Reviewers read; importing changes the record, so it is the
    # operator's and administrator's act.
    "POST /imports/credential-report": frozenset({Role.operator, Role.administrator}),
    "POST /imports/authorization-details": frozenset({Role.operator, Role.administrator}),
    "POST /imports/github-organization": frozenset({Role.operator, Role.administrator}),
    "POST /imports/kubernetes-rbac": frozenset({Role.operator, Role.administrator}),
    "POST /imports/google-cloud": frozenset({Role.operator, Role.administrator}),
    "POST /imports/azure-tenant": frozenset({Role.operator, Role.administrator}),
    "POST /imports/okta-org": frozenset({Role.operator, Role.administrator}),
    "POST /imports/active-directory": frozenset({Role.operator, Role.administrator}),
    "POST /imports/sharphound": frozenset({Role.operator, Role.administrator}),
    # Any provider's table through a mapping (1.11): the observed side's
    # file door, the same actors as the parsers' routes.
    "POST /imports/observed/dry-run": frozenset({Role.operator, Role.administrator}),
    "POST /imports/observed": frozenset({Role.operator, Role.administrator}),
    "GET /imports": ALL_ROLES,
    # A door into the estate is read by everyone who reviews and
    # written by the same actors who write an authorization, because
    # authorizing a trust is the same act one level up.
    "GET /relationships": ALL_ROLES,
    "POST /relationships/authorize": frozenset({Role.operator, Role.administrator}),
    "POST /relationships/{authorization_id}/revoke": frozenset(
        {Role.operator, Role.administrator}
    ),
    # A custom definition is read by everyone who reviews and authorized
    # by the same actors who authorize a holder, because saying a policy
    # is supposed to exist is the same act as saying who may hold it,
    # asked of a different owner.
    "GET /role-definitions": ALL_ROLES,
    "POST /role-definitions/authorize": frozenset({Role.operator, Role.administrator}),
    "POST /role-definitions/{authorization_id}/revoke": frozenset(
        {Role.operator, Role.administrator}
    ),
    # Who was told is part of the record every reviewer reads.
    "GET /alerts": ALL_ROLES,
    "GET /identities": ALL_ROLES,
    "GET /identities/{identity_id}": ALL_ROLES,
    "GET /groups": ALL_ROLES,
    # Governance writes change the record, so owner, purpose, and flag
    # are the operator's and administrator's acts. Attestation is every
    # role's act, because "I looked and it is still needed" is exactly
    # what a reviewer is for.
    "POST /identities/{identity_id}/governance": frozenset(
        {Role.operator, Role.administrator}
    ),
    "POST /groups/{group_id}/governance": frozenset(
        {Role.operator, Role.administrator}
    ),
    "POST /identities/{identity_id}/attest": ALL_ROLES,
    "POST /groups/{group_id}/attest": ALL_ROLES,
    "DELETE /governance/{record_id}": frozenset(
        {Role.operator, Role.administrator}
    ),
    # Authorizing access is the operator's and administrator's act;
    # reading the record is every role's, because a reviewer who
    # cannot see what was authorized cannot review anything (D-073).
    "GET /identities/{identity_id}/authorizations": ALL_ROLES,
    "POST /identities/{identity_id}/authorizations": frozenset(
        {Role.operator, Role.administrator}
    ),
    "POST /authorizations/{authorization_id}/revoke": frozenset(
        {Role.operator, Role.administrator}
    ),
    # The delta is the product, and it is a read for every role: a
    # reviewer who cannot see the difference cannot review anything.
    "GET /delta": ALL_ROLES,
    "GET /identities/{identity_id}/delta": ALL_ROLES,
    # Reading the observed side in the authorized side's shape is a
    # read: it prefills a decision and never makes one (D-024).
    "GET /identities/{identity_id}/observed-grants": ALL_ROLES,
    "GET /export/observed-grants.csv": ALL_ROLES,
    # A mapping says how someone else's file is read, which is a
    # governance act: everyone may see the mappings, and writing one
    # is the operator's and administrator's (D-074).
    "GET /mappings": ALL_ROLES,
    "POST /mappings": frozenset({Role.operator, Role.administrator}),
    # A dry run writes nothing, and is still not a reader's act: it is
    # the step before importing, and it names identities.
    "POST /authorizations/import/dry-run": frozenset(
        {Role.operator, Role.administrator}
    ),
    "POST /authorizations/import": frozenset({Role.operator, Role.administrator}),
    # Creating and closing a campaign shape the review; deciding an
    # item is the review, so disposition is open to every role, one
    # item at a time, with no bulk operation anywhere (D-039).
    "POST /campaigns": frozenset({Role.operator, Role.administrator}),
    "GET /campaigns": ALL_ROLES,
    "GET /campaigns/rollup": ALL_ROLES,
    "GET /campaigns/{campaign_id}": ALL_ROLES,
    "POST /campaigns/{campaign_id}/items/{item_id}/disposition": ALL_ROLES,
    "POST /campaigns/{campaign_id}/close": frozenset(
        {Role.operator, Role.administrator}
    ),
    # Reads over the same assessment the inventory shows; a reviewer
    # who may see the page may carry it away.
    "GET /export.csv": ALL_ROLES,
    "GET /export.json": ALL_ROLES,
    "GET /report.html": ALL_ROLES,
    "GET /campaigns/{campaign_id}/evidence": ALL_ROLES,
    "GET /campaigns/{campaign_id}/evidence.csv": ALL_ROLES,
}

# Routes that are reachable without a session, each with its reason.
PUBLIC_ROUTES: frozenset[str] = frozenset(
    {
        "POST /auth/login",  # the way in
        "GET /health",  # liveness for the platform
        "GET /health/database",  # readiness for the platform
        "GET /",  # the page shell, which carries no data
    }
)

# Routes an integration token opens and a session does not (1.10). They
# are not in the matrix because a token holds no role; they are named
# here so the surface enumeration can hold that every route is either
# governed by a role, public, or under a token, and nothing else.
TOKEN_ROUTES: frozenset[str] = frozenset(
    {
        "GET /api/v1/identities",
        "GET /api/v1/delta",
        "GET /api/v1/changes",
    }
)

# Routes that need the password given within the step-up window
# (D-089): bulk disclosure, bulk change of the authorized record, and
# credential creation. Each declares the step-up dependency itself; a
# test holds this list and the declarations to each other.
STEP_UP_ROUTES: frozenset[str] = frozenset(
    {
        "GET /export.csv",
        "GET /export.json",
        "GET /report.html",
        "GET /campaigns/{campaign_id}/evidence",
        "GET /campaigns/{campaign_id}/evidence.csv",
        "GET /export/observed-grants.csv",
        "POST /authorizations/import",
        "POST /admin/users",
        "POST /admin/tokens",
    }
)
