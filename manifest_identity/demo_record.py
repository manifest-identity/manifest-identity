"""The populated record: what the demo estate looks like after an
administrator has done the work (1.16, D-085).

The observed files show an estate on day one, where every held grant
is unauthorized and every difference is the same difference. This
module writes the second record the way a customer would: most of
what is held is authorized by a named operator through the file door,
with an owner, a justification, a reference, and a control; a few
cases are planted so every class of difference shows at least once;
and owners, purposes, a flag, and an attestation go on the identities
and groups. The rows are derived from the observed export at run time
rather than shipped as a file, because an authorization is keyed to
the exact path the observed side derived, and a file written by hand
against a generated estate drifts the first time the estate does.

Every write goes through the same functions the routes call, so it is
attributed and audited as it would be in use, and every step converges:
a second run finds each record present and writes nothing.
"""

from __future__ import annotations

import csv
import hashlib
import io
import secrets
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.authorize import (
    authorizations,
    csv_import,
    from_observed,
    governance,
    relationships,
    role_definitions,
)
from manifest_identity.core import audit, security
from manifest_identity.core.models import ScopeNode, User
from manifest_identity.core.roles import Role
from manifest_identity.core.scope import bind, global_node
from manifest_identity.observe.models import (
    Identity,
    IdentityKind,
    Import,
    ObservedRelationship,
    RoleDefinition,
)

OPERATOR = "demo.operator"
REVIEW = "REV-2026Q3"
CONTROL = "AC-6"
VALID_FROM = datetime(2026, 6, 15, tzinfo=UTC)
VALID_UNTIL = datetime(2027, 6, 1, tzinfo=UTC)
# The planted expiry: ended in July, while the newest import still
# shows the access held.
EXPIRED_UNTIL = datetime(2026, 7, 31, tzinfo=UTC)

# The team that owns each estate's access, by the provider of its node.
TEAM_BY_PROVIDER = {
    "aws": "platform-team",
    "github": "engineering",
    "kubernetes": "platform-team",
    "gcp": "data-platform",
    "azure": "cloud-ops",
    "okta": "it-service-desk",
    "active_directory": "directory-ops",
}
JUSTIFICATION_BY_SOURCE = {
    "attachment": "standing access confirmed at the quarterly review",
    "inline_policy": "standing access confirmed at the quarterly review",
    "organization_role": "membership in the organization at the level the team agreed",
    "team_permission": "the team's access to its own repositories",
    "repository_permission": "direct access to the repository, reviewed with its owner",
    "deploy_key": "the key the deployment needs, held by the pipeline",
    "installation": "the installation's permissions as documented by its vendor",
    "clusterrolebinding": "cluster access the platform team runs on",
    "rolebinding": "namespace access for the team that owns the workload",
    "binding": "project access confirmed with the project owner",
    "directory_role": "directory role held by the person named for it",
    "role_assignment": "assignment reviewed with the subscription owner",
    "app_assignment": "the application the person's role requires",
    "privileged_group": "membership in the group the domain is run from",
}
# Access that stays unauthorized on purpose: the contractor, the
# public grant, the deleted principal, the foreign account, the
# everything-except grant, the wildcard trust, and the tool with
# organization-wide permissions. They are the demo's open questions.
NEVER = frozenset({
    "contractor-lee", "new-contractor", "contractor lee", "legacy-integration",
    "allusers", "except-all", "partner-legacy", "org-admin-tool",
    "44444444-0000-4000-8000-000000000001",
    "user:former@example.test?uid=100000000000000000001",
})
# The custom definition authorized at an older version, so the delta
# names what it gained (1.7); left out of the file and written by hand.
VERSIONED = "okta:role:custom:cr0sample00000000001"
UNOWNED_GROUPS = frozenset({"backup operators", "break-glass"})
PURPOSE_TYPES = frozenset({
    "serviceaccount", "sp", "deploy_key", "installation", "computer", "role",
})


def _team(providers: dict[int, str], node_id: int) -> str:
    return TEAM_BY_PROVIDER.get(providers.get(node_id, ""), "platform-team")


def _providers(db: Session) -> dict[int, str]:
    return {node.id: node.provider for node in db.execute(select(ScopeNode)).scalars()}


def ensure_operator(db: Session, admin: User) -> User:
    """The named person who authorizes: an operator the demo creates
    with a password nobody is given, because the account exists to be
    the author of record and not to be signed into."""
    found = db.execute(select(User).where(User.username == OPERATOR)).scalar_one_or_none()
    if found is not None:
        return found
    user = User(
        username=OPERATOR,
        password_hash=security.hash_password(secrets.token_urlsafe(24) + "Aa1"),
    )
    db.add(user)
    db.flush()
    bind(db, user, Role.operator, global_node(db), admin)
    audit.record(
        db, actor_user_id=admin.id, actor_username=admin.username,
        action="user_created", target=f"user:{OPERATOR}",
        detail="the demo's operator, the named person the authorized record is attributed to",
    )
    db.commit()
    return user


def _skip(grant: from_observed.ObservedGrant) -> bool:
    """One held grant in five stays unauthorized, chosen by a hash of
    the identity and the role so the choice is stable across runs."""
    digest = hashlib.sha256(
        f"{grant.identity_external_id}|{grant.role_definition_external_id}".encode()
    ).digest()
    return digest[0] % 5 == 0


def authorize_holds(db: Session, operator: User) -> dict[str, int]:
    """Most of what is held, through the file door, plus the planted
    rows: the expired ones for the legacy accounts, and two for access
    nobody holds any more."""
    providers = _providers(db)
    grants = from_observed.for_estate(db)
    existing: dict[int, set[str]] = {}
    rows: list[dict[str, str]] = []
    for grant in sorted(
        grants,
        key=lambda g: (g.account, g.identity_external_id, g.role_definition_external_id,
                       g.path_text()),
    ):
        name = grant.display_name.lower()
        if grant.authorized or name in NEVER or grant.role_definition_external_id == VERSIONED:
            continue
        if grant.identity_id not in existing:
            existing[grant.identity_id] = {
                authorizations.grant_key(row.path, row.role_definition_external_id)
                for row in authorizations.latest_rows(db, grant.identity_id)
            }
        key = authorizations.grant_key(grant.path, grant.role_definition_external_id)
        if key in existing[grant.identity_id]:
            continue
        expired = "legacy" in name
        if not expired and _skip(grant):
            continue
        identity = db.get(Identity, grant.identity_id)
        node_id = identity.scope_node_id if identity else 0
        rows.append({
            "identity_id": grant.identity_external_id,
            "role": grant.role_definition_external_id,
            "mode": grant.mode,
            "path": grant.path_text(),
            "owner_kind": "team",
            "owner": _team(providers, node_id),
            "secondary_owner_kind": "",
            "secondary_owner": "",
            "justification": JUSTIFICATION_BY_SOURCE.get(
                grant.source_kind, "standing access confirmed at the quarterly review",
            ),
            "reference": REVIEW,
            "control": CONTROL,
            "valid_from": VALID_FROM.strftime("%Y-%m-%d"),
            "valid_until": (EXPIRED_UNTIL if expired else VALID_UNTIL).strftime("%Y-%m-%d"),
        })
    rows += _not_held_rows(db, existing)
    if not rows:
        return {"authorizations": 0, "refusals": 0}
    columns = [
        column
        for spec in csv_import.DEFAULT_FIELDS.values()
        if (column := spec.get("column")) is not None
    ]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    data = buffer.getvalue().encode()
    mapping = csv_import.default_mapping(db, operator.username)
    preview = csv_import.dry_run(db, mapping, data)
    if preview.refusals:
        for refusal in preview.refusals:
            print(f"demo record: row {refusal.row} refused: {refusal.reason}")
    result = csv_import.write(db, mapping, data, operator, "demo-authorizations.csv")
    db.commit()
    return {"authorizations": len(result.written), "refusals": len(result.refusals)}


def _not_held_rows(db: Session, existing: dict[int, set[str]]) -> list[dict[str, str]]:
    """Two authorizations for access the newest import no longer
    shows: the leaver who was a domain administrator in June, and the
    deprovisioned Okta user whose read-only role went inactive."""
    wanted = [
        ("S-1-5-21-1000-2000-3000-1104", "ad:group:S-1-5-21-1000-2000-3000-512",
         "membership:Domain Admins", "directory-ops",
         "the leaver's access, authorized before the departure and never revoked"),
        ("user:00usample00000000005", "okta:role:READ_ONLY_ADMIN", "", "it-service-desk",
         "read-only administration for the former analyst"),
    ]
    rows = []
    for external_id, role, path, team, why in wanted:
        identity = db.execute(
            select(Identity).where(Identity.external_id == external_id)
        ).scalars().first()
        if identity is None:
            continue
        keys = existing.setdefault(identity.id, {
            authorizations.grant_key(row.path, row.role_definition_external_id)
            for row in authorizations.latest_rows(db, identity.id)
        })
        from manifest_identity.observe.mapping import parse_path
        if authorizations.grant_key(parse_path(path), role) in keys:
            continue
        rows.append({
            "identity_id": external_id, "role": role, "mode": "standing", "path": path,
            "owner_kind": "team", "owner": team, "secondary_owner_kind": "",
            "secondary_owner": "", "justification": why, "reference": REVIEW,
            "control": CONTROL, "valid_from": VALID_FROM.strftime("%Y-%m-%d"),
            "valid_until": VALID_UNTIL.strftime("%Y-%m-%d"),
        })
    return rows


def _versions(db: Session, external_id: str) -> list[RoleDefinition]:
    return list(db.execute(
        select(RoleDefinition)
        .where(RoleDefinition.external_id == external_id)
        .order_by(RoleDefinition.first_seen_import_id)
    ).scalars())


def authorize_versioned(db: Session, operator: User) -> int:
    """One authorization bound to the June version of a definition the
    July file changed, so the delta names what the role gained."""
    versions = _versions(db, VERSIONED)
    if len(versions) < 2:
        return 0
    oldest = versions[0]
    holder = db.execute(
        select(Identity).where(Identity.external_id == "user:00usample00000000003")
    ).scalars().first()
    if holder is None:
        return 0
    path = [{"via": "direct", "ref": "", "mode": "active"}]
    key = authorizations.grant_key(path, VERSIONED)
    if any(
        authorizations.grant_key(row.path, row.role_definition_external_id) == key
        for row in authorizations.latest_rows(db, holder.id)
    ):
        return 0
    authorizations.authorize(db, authorizations.Request(
        identity_id=holder.id, scope_node_id=holder.scope_node_id,
        role_definition_external_id=VERSIONED, mode="standing", path=path,
        owner_kind="team", owner_ref="it-service-desk",
        role_definition_hash=oldest.contents_hash,
        justification="the auditor role as it stood when the audit began",
        reference=REVIEW, control_reference=CONTROL,
        valid_from=VALID_FROM, valid_until=VALID_UNTIL,
    ), operator, now=datetime.now(UTC))
    db.commit()
    return 1


def authorize_relationships(db: Session, operator: User) -> int:
    """Three doors authorized and two left open: the service trust and
    the vendor's audit role are documented, the partner forest trust is
    documented, and the wildcard trust and the partner's open role are
    the findings."""
    # Each door with the kind of principal it is from, stated here
    # rather than read off the string: a name is not evidence of what
    # it names.
    wanted = [
        ("trust", "app-runtime", "ec2.amazonaws.com", "service", "platform-team",
         "the compute service assumes the runtime role"),
        ("trust", "vendor-audit", "arn:aws:iam::999999999999:root", "aws", "security",
         "the auditor's account, under contract until the audit closes"),
        ("trust", None, "partner.example.test", "domain", "directory-ops",
         "the partner forest, one way, for the shared application"),
    ]
    written = 0
    now = datetime.now(UTC)
    for kind, to_name, from_ref, from_kind, team, why in wanted:
        to_identity = None
        to_node = None
        if to_name is not None:
            to_identity = db.execute(
                select(Identity).where(Identity.first_display_name == to_name)
            ).scalars().first()
            if to_identity is None:
                continue
        else:
            observed = db.execute(
                select(ObservedRelationship).where(
                    ObservedRelationship.kind == kind, ObservedRelationship.from_ref == from_ref,
                ).order_by(ObservedRelationship.id.desc())
            ).scalars().first()
            if observed is None:
                continue
            import_row = db.get(Import, observed.import_id)
            to_node = import_row.scope_node_id if import_row else None
        key = relationships.door_key(kind, to_identity.id if to_identity else None, from_ref)
        if relationships.active_for_door(db, key, now) is not None:
            continue
        relationships.authorize(db, relationships.Request(
            kind=kind, to_identity_id=to_identity.id if to_identity else None,
            to_scope_node_id=to_node, from_ref=from_ref, from_kind=from_kind,
            owner_kind="team", owner_ref=team, justification=why,
            valid_from=VALID_FROM, valid_until=None,
        ), operator, now=now)
        written += 1
    db.commit()
    return written


def authorize_definitions(db: Session, operator: User) -> int:
    """Custom definitions with an owner: three at the version now held,
    and the cluster's secrets reader at its June version, which the
    July file widened, so the delta says so."""
    wanted = [
        ("inline:AIDASAMPLEDATAPIPELI#pipeline-runner", "data-team", "newest",
         "the pipeline's own policy, reviewed with its owner"),
        ("okta:app:0oasample00000000001", "finance", "newest",
         "the payroll application, assigned by the finance owner"),
        ("projects/sample-project/roles/deployer", "data-platform", "newest",
         "the deployer role the pipeline uses"),
        ("clusterrole:secrets-reader", "platform-team", "oldest",
         "the audit tool's reader, as scoped when it was approved"),
    ]
    written = 0
    now = datetime.now(UTC)
    for external_id, team, which, why in wanted:
        versions = _versions(db, external_id)
        if not versions:
            continue
        chosen = versions[0] if which == "oldest" else versions[-1]
        if role_definitions.active_for(db, external_id, now) is not None:
            continue
        role_definitions.authorize(db, role_definitions.Request(
            role_definition_external_id=external_id, role_definition_hash=chosen.contents_hash,
            owner_kind="team", owner_ref=team, justification=why,
            valid_from=VALID_FROM, valid_until=None,
        ), operator, now=now)
        written += 1
    db.commit()
    return written


def govern(db: Session, operator: User) -> int:
    """Owners on most identities and groups, purposes on the services,
    one flag, one attestation, and one owner who disagrees with the
    provider's tag."""
    providers = _providers(db)
    written = 0

    def has(target_type: str, target_id: int, kind: str) -> bool:
        return any(r.kind == kind for r in governance.active_records(db, target_type, target_id))

    def put(target_type: str, target_id: int, kind: str, value: str,
            owner_type: str | None = None) -> None:
        nonlocal written
        if has(target_type, target_id, kind):
            return
        governance.set_record(
            db, target_type=target_type, target_id=target_id, kind=kind, value=value,
            owner_type=owner_type, actor=operator,
        )
        written += 1

    for identity in db.execute(select(Identity).order_by(Identity.id)).scalars():
        name = identity.first_display_name.lower()
        target = "group" if identity.kind == IdentityKind.group else "identity"
        if name in NEVER or "legacy" in name:
            continue
        if target == "group":
            if name in UNOWNED_GROUPS:
                continue
            put("group", identity.id, "owner", _team(providers, identity.scope_node_id), "team")
            continue
        if identity.kind == IdentityKind.external:
            continue
        owner = (
            "data-platform" if name == "wide-writer"
            else _team(providers, identity.scope_node_id)
        )
        put("identity", identity.id, "owner", owner, "team")
        if identity.provider_type in PURPOSE_TYPES:
            put(
                "identity", identity.id, "purpose",
                f"runs the {identity.first_display_name} workload",
            )
        if name == "except-all":
            put("identity", identity.id, "flag", "the everything-except grant is under review")
        if name == "report-reader":
            put(
                "identity", identity.id, "attestation",
                "reviewed at the quarterly review, still needed",
            )
    db.commit()
    return written


def populate(db: Session, admin: User) -> dict[str, int]:
    operator = ensure_operator(db, admin)
    stats = authorize_holds(db, operator)
    stats["versioned"] = authorize_versioned(db, operator)
    stats["relationships"] = authorize_relationships(db, operator)
    stats["definitions"] = authorize_definitions(db, operator)
    stats["governance"] = govern(db, operator)
    return stats
