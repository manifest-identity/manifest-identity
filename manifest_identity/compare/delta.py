"""The delta: held against authorized, computed at read.

Nothing here is stored (D-006 applied to the comparison itself). The
two records are the evidence; the difference between them is derived
every time somebody asks, so it cannot go stale, cannot be edited, and
cannot disagree with the records it came from.

Five classes, and each says what a person should do about it:

- **held but not authorized**: the identity holds access nobody wrote
  down. Either authorize it or take it away.
- **authorized but not held**: the record claims access the provider
  does not show. Either the record is stale or the access was removed
  outside the process; the authorization should be revoked or the
  grant restored.
- **expired and still held**: an authorization ran out and the access
  did not. This is the class that exists because expiry is real rather
  than decorative.
- **owner disagreement**: the authorization names one owner and the
  observed tag names another, so nobody can say who answers for it.
- **role definition changed**: the access still matches an
  authorization by name, but the role's contents were rehashed since,
  so what was authorized is not what is now held.

Every finding carries `observed_as_of` and `authorized_as_of`. A
finding computed from a month-old import is still true about a
month-old world, and saying so is the difference between a delta and
a claim.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from manifest_identity.authorize import (
    authorizations,
    from_observed,
    lifecycle,
    relationships,
    role_definitions,
)
from manifest_identity.authorize.models import (
    Authorization,
    AuthorizationStatus,
    GovernanceRecord,
)
from manifest_identity.core.models import ScopeNode
from manifest_identity.observe import paths, policy_analysis
from manifest_identity.observe.models import (
    Grant,
    Identity,
    IdentityKind,
    Import,
    RoleDefinition,
)

HELD_NOT_AUTHORIZED = "held_not_authorized"
# Access that arrives through a door nobody authorized, and privilege an
# identity can take at will that nobody wrote down. Both are things the
# old comparison could not see, because it read what an identity holds
# and access does not only arrive by being held (1.6).
ACCESS_VIA_UNAUTHORIZED_RELATIONSHIP = "access_via_unauthorized_relationship"
ELIGIBLE_NOT_AUTHORIZED = "eligible_not_authorized"
# Two classes about a definition rather than about who holds it (1.7).
# A custom policy somebody wrote is a thing somebody should own, and a
# custom policy whose contents moved after it was agreed is the change
# the owner has to see, whether or not any holder's reviewer does.
CUSTOM_DEFINITION_NOT_AUTHORIZED = "custom_definition_not_authorized"
CUSTOM_DEFINITION_CHANGED = "custom_definition_changed"
AUTHORIZED_NOT_HELD = "authorized_not_held"
EXPIRED_STILL_HELD = "expired_still_held"
OWNER_DISAGREEMENT = "owner_disagreement"
DEFINITION_CHANGED = "definition_changed"

# Ordered worst first, which is the order a page should show them and
# a campaign should queue them.
CLASSES = (
    HELD_NOT_AUTHORIZED,
    ACCESS_VIA_UNAUTHORIZED_RELATIONSHIP,
    EXPIRED_STILL_HELD,
    ELIGIBLE_NOT_AUTHORIZED,
    DEFINITION_CHANGED,
    CUSTOM_DEFINITION_CHANGED,
    CUSTOM_DEFINITION_NOT_AUTHORIZED,
    AUTHORIZED_NOT_HELD,
    OWNER_DISAGREEMENT,
)

TITLES = {
    HELD_NOT_AUTHORIZED: "held but not authorized",
    ACCESS_VIA_UNAUTHORIZED_RELATIONSHIP: "reached through an unauthorized relationship",
    ELIGIBLE_NOT_AUTHORIZED: "can be obtained and is not authorized",
    AUTHORIZED_NOT_HELD: "authorized but not held",
    EXPIRED_STILL_HELD: "expired and still held",
    OWNER_DISAGREEMENT: "owner disagreement",
    DEFINITION_CHANGED: "the role changed after it was authorized",
    CUSTOM_DEFINITION_CHANGED: "a custom definition changed after it was authorized",
    CUSTOM_DEFINITION_NOT_AUTHORIZED: "a custom definition nobody authorized",
}


@dataclass
class DeltaFinding:
    kind: str
    identity_id: int
    identity_external_id: str
    display_name: str
    account: str
    role: str
    path: list[dict[str, str]]
    detail: str
    authorization_id: int | None
    observed_as_of: datetime | None
    authorized_as_of: datetime | None
    # For a definition that changed: what arrived, what left, and which
    # lines the new version crosses, so a page can show them as a list
    # rather than making a reviewer parse a sentence.
    actions_added: list[str] = field(default_factory=list)
    actions_removed: list[str] = field(default_factory=list)
    capabilities_gained: list[str] = field(default_factory=list)

    @property
    def title(self) -> str:
        return TITLES[self.kind]


@dataclass
class RoleDefinitionFinding:
    """A finding whose subject is a definition rather than an identity.
    It carries the same two timestamps as an identity finding, for the
    same reason: a month-old import is true about a month-old world."""

    kind: str
    role_definition_id: int
    role: str
    role_ref: str
    account: str
    detail: str
    authorization_id: int | None
    observed_as_of: datetime | None
    authorized_as_of: datetime | None
    actions_added: list[str] = field(default_factory=list)
    actions_removed: list[str] = field(default_factory=list)
    capabilities_gained: list[str] = field(default_factory=list)

    @property
    def title(self) -> str:
        return TITLES[self.kind]


def for_definitions(
    db: Session, now: datetime | None = None
) -> list[RoleDefinitionFinding]:
    """Every custom definition at each scope's newest import, against
    the record of which ones somebody authorized and at what version.

    Only customer-managed definitions are asked to justify themselves.
    A provider's built-in policy was written by the provider and changes
    when the provider says so; its changes reach every holder through
    the per-holder finding, and nobody in the organization owns it.
    """
    out: list[RoleDefinitionFinding] = []
    nodes = db.execute(select(ScopeNode)).scalars().all()
    for node in nodes:
        newest = paths.newest_import(db, node.id)
        if newest is None:
            continue
        observed_at = _observed_as_of(db, node.id)
        definition_ids = {
            definition_id
            for (definition_id,) in db.execute(
                select(Grant.role_definition_id).where(Grant.import_id == newest)
            )
        }
        if not definition_ids:
            continue
        definitions = db.execute(
            select(RoleDefinition).where(
                RoleDefinition.id.in_(definition_ids),
                RoleDefinition.managed_by == role_definitions.CUSTOMER,
            ).order_by(RoleDefinition.display_name_last)
        ).scalars().all()
        for definition in definitions:
            standing = role_definitions.active_for(db, definition.external_id, now)
            if standing is None:
                out.append(RoleDefinitionFinding(
                    kind=CUSTOM_DEFINITION_NOT_AUTHORIZED,
                    role_definition_id=definition.id,
                    role=definition.display_name_last,
                    role_ref=definition.external_id,
                    account=node.external_id,
                    detail="this custom definition exists and nobody has said it "
                    "should, so nobody owns what it grants",
                    authorization_id=None,
                    observed_as_of=observed_at,
                    authorized_as_of=None,
                ))
                continue
            if standing.role_definition_hash == definition.contents_hash:
                continue
            change = policy_analysis.describe_change(
                _definition_contents(db, definition.external_id, standing.role_definition_hash),
                definition.contents,
            )
            out.append(RoleDefinitionFinding(
                kind=CUSTOM_DEFINITION_CHANGED,
                role_definition_id=definition.id,
                role=definition.display_name_last,
                role_ref=definition.external_id,
                account=node.external_id,
                detail="the definition's contents changed after it was authorized: "
                + change.as_text(),
                authorization_id=standing.id,
                observed_as_of=observed_at,
                authorized_as_of=standing.authorized_at,
                actions_added=change.added,
                actions_removed=change.removed,
                capabilities_gained=change.crossed,
            ))
    out.sort(key=lambda f: (CLASSES.index(f.kind), f.role))
    return out


def _key(path: list[dict[str, str]], role: str) -> str:
    return authorizations.grant_key(path, role)


def _definition_contents(
    db: Session, external_id: str, contents_hash: str
) -> dict[str, object] | None:
    """One version's document, or nothing when that version was never
    observed, which the comparison says out loud rather than treating
    as an empty policy."""
    return db.execute(
        select(RoleDefinition.contents).where(
            RoleDefinition.external_id == external_id[:2048],
            RoleDefinition.contents_hash == contents_hash,
        ).limit(1)
    ).scalar()


def _observed_as_of(db: Session, node_id: int) -> datetime | None:
    return db.execute(
        select(func.max(Import.captured_at)).where(Import.scope_node_id == node_id)
    ).scalar_one_or_none()


def _owner_tag(db: Session, identity_id: int) -> str | None:
    """The owner a person recorded on the identity itself, which the
    governance layer already resolves; the authorization names an owner
    per grant, and the two disagreeing means nobody can say who
    answers for it."""
    return db.execute(
        select(GovernanceRecord.value)
        .where(
            GovernanceRecord.target_type == "identity",
            GovernanceRecord.target_id == identity_id,
            GovernanceRecord.kind == "owner",
            GovernanceRecord.cleared_at.is_(None),
        )
        .order_by(GovernanceRecord.created_at.desc(), GovernanceRecord.id.desc())
    ).scalars().first()


def for_identity(  # noqa: C901
    db: Session, identity: Identity, now: datetime | None = None
) -> list[DeltaFinding]:
    node = db.get(ScopeNode, identity.scope_node_id)
    account = node.external_id if node else ""
    observed_at = _observed_as_of(db, identity.scope_node_id)
    held = from_observed.for_identity(db, identity)
    held_by_key = {_key(g.path, g.role_definition_external_id): g for g in held}

    rows = authorizations.latest_rows(db, identity.id)
    authorized_at = max((row.authorized_at for row in rows), default=None)
    owner_tag = _owner_tag(db, identity.id)

    def finding(
        kind: str, role: str, path: list[dict[str, str]], detail: str,
        authorization: Authorization | None = None,
    ) -> DeltaFinding:
        return DeltaFinding(
            kind=kind,
            identity_id=identity.id,
            identity_external_id=identity.external_id,
            display_name=identity.first_display_name,
            account=account,
            role=role,
            path=path,
            detail=detail,
            authorization_id=authorization.id if authorization else None,
            observed_as_of=observed_at,
            authorized_as_of=authorized_at,
        )

    out: list[DeltaFinding] = []
    live_keys: set[str] = set()
    for row in rows:
        key = _key(row.path, row.role_definition_external_id)
        status = lifecycle.status_of(row, now)
        if status == AuthorizationStatus.revoked:
            continue
        if status == AuthorizationStatus.expired:
            if key in held_by_key:
                out.append(finding(
                    EXPIRED_STILL_HELD, row.role_definition_external_id, row.path,
                    (
                        "the authorization ended "
                        f"{row.valid_until.date() if row.valid_until else 'unknown'}"
                        " and the access is still held"
                    ),
                    row,
                ))
            continue
        live_keys.add(key)
        if key not in held_by_key:
            out.append(finding(
                AUTHORIZED_NOT_HELD, row.role_definition_external_id, row.path,
                "the record authorizes access the newest import does not show",
                row,
            ))
            continue
        observed = held_by_key[key]
        if (
            row.role_definition_hash
            and observed.role_definition_hash
            and row.role_definition_hash != observed.role_definition_hash
        ):
            # Naming what changed is the part that tells a reviewer
            # whether it matters (1.7). Both versions are rows this
            # product already holds, looked up by the hash each side
            # recorded.
            change = policy_analysis.describe_change(
                _definition_contents(
                    db, row.role_definition_external_id, row.role_definition_hash
                ),
                _definition_contents(
                    db, row.role_definition_external_id,
                    observed.role_definition_hash,
                ),
            )
            changed = finding(
                DEFINITION_CHANGED, row.role_definition_external_id, row.path,
                "the role's contents changed after it was authorized: "
                + change.as_text(),
                row,
            )
            changed.actions_added = change.added
            changed.actions_removed = change.removed
            changed.capabilities_gained = change.crossed
            out.append(changed)
        if owner_tag and row.owner_ref and owner_tag != row.owner_ref:
            out.append(finding(
                OWNER_DISAGREEMENT, row.role_definition_external_id, row.path,
                f"the authorization names {row.owner_ref} and the identity's "
                f"owner record names {owner_tag}",
                row,
            ))

    for key, grant in held_by_key.items():
        if key not in live_keys:
            # An expired authorization already produced its own, sharper
            # finding; this one is for access nobody ever wrote down.
            if any(
                f.kind == EXPIRED_STILL_HELD
                and _key(f.path, f.role) == key
                for f in out
            ):
                continue
            out.append(finding(
                HELD_NOT_AUTHORIZED, grant.role_definition_external_id, grant.path,
                "the identity holds this and no authorization covers it",
            ))
    out.extend(_reachable_findings(db, identity, finding, live_keys, now))
    out.sort(key=lambda f: (CLASSES.index(f.kind), f.role))
    return out


def _reachable_findings(
    db: Session,
    identity: Identity,
    finding: Callable[..., DeltaFinding],
    live_keys: set[str],
    now: datetime | None,
) -> list[DeltaFinding]:
    """The two classes that read the route rather than the hold.

    Comparing what an identity holds against what was authorized misses
    everything that arrives another way. A role an identity may assume
    is privilege it can take whenever it likes, and the door it takes it
    through is a thing somebody should have agreed to. Both are computed
    from the same expansion the page and the export use.
    """
    newest = paths.newest_import(db, identity.scope_node_id)
    if newest is None:
        return []
    reachable = paths.for_identity(db, import_id=newest, identity=identity)
    standing_doors = {
        relationships.door_key(row.kind, row.to_identity_id, row.from_ref)
        for row in relationships.latest_rows(db)
        if lifecycle.status_of(row, now) == AuthorizationStatus.authorized
    }

    out: list[DeltaFinding] = []
    for kind, into, from_ref in paths.doors_for(
        db, import_id=newest, identity=identity
    ):
        if relationships.door_key(kind, into, from_ref) in standing_doors:
            continue
        reached = db.get(Identity, into) if into else None
        out.append(finding(
            ACCESS_VIA_UNAUTHORIZED_RELATIONSHIP,
            reached.first_display_name if reached else "",
            [{"via": "trust", "ref": reached.first_display_name if reached else "",
              "mode": "assumable"}],
            f"this identity may cross a {kind} into "
            f"{reached.first_display_name if reached else 'an unnamed target'} "
            f"from {from_ref}, and no authorization covers that "
            f"{kind}",
        ))

    for path in reachable:
        hops = [hop.as_dict() for hop in path.hops]
        if path.holds_now:
            continue
        if _key(hops, path.role_ref) in live_keys:
            continue
        out.append(finding(
            ELIGIBLE_NOT_AUTHORIZED, path.role_ref, hops,
            "the identity can obtain this whenever it chooses and no "
            "authorization covers it",
        ))
    return out


def for_estate(db: Session, now: datetime | None = None) -> list[DeltaFinding]:
    out: list[DeltaFinding] = []
    identities = db.execute(
        select(Identity)
        .where(Identity.kind != IdentityKind.group)
        .order_by(Identity.scope_node_id, Identity.first_display_name)
    ).scalars().all()
    for identity in identities:
        out.extend(for_identity(db, identity, now))
    out.sort(key=lambda f: (CLASSES.index(f.kind), f.account, f.display_name))
    return out


def definition_counts(findings: list[RoleDefinitionFinding]) -> dict[str, int]:
    out: dict[str, int] = {}
    for finding in findings:
        out[finding.kind] = out.get(finding.kind, 0) + 1
    return out


def counts(findings: list[DeltaFinding]) -> dict[str, int]:
    tally = dict.fromkeys(CLASSES, 0)
    for finding in findings:
        tally[finding.kind] += 1
    return tally
