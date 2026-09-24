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

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from manifest_identity.authorize import authorizations, from_observed
from manifest_identity.authorize.models import (
    Authorization,
    AuthorizationStatus,
    GovernanceRecord,
)
from manifest_identity.core.models import ScopeNode
from manifest_identity.observe.models import Identity, IdentityKind, Import

HELD_NOT_AUTHORIZED = "held_not_authorized"
AUTHORIZED_NOT_HELD = "authorized_not_held"
EXPIRED_STILL_HELD = "expired_still_held"
OWNER_DISAGREEMENT = "owner_disagreement"
DEFINITION_CHANGED = "definition_changed"

# Ordered worst first, which is the order a page should show them and
# a campaign should queue them.
CLASSES = (
    HELD_NOT_AUTHORIZED,
    EXPIRED_STILL_HELD,
    DEFINITION_CHANGED,
    AUTHORIZED_NOT_HELD,
    OWNER_DISAGREEMENT,
)

TITLES = {
    HELD_NOT_AUTHORIZED: "held but not authorized",
    AUTHORIZED_NOT_HELD: "authorized but not held",
    EXPIRED_STILL_HELD: "expired and still held",
    OWNER_DISAGREEMENT: "owner disagreement",
    DEFINITION_CHANGED: "the role changed after it was authorized",
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

    @property
    def title(self) -> str:
        return TITLES[self.kind]


def _key(path: list[dict[str, str]], role: str) -> str:
    return authorizations.grant_key(path, role)


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


def for_identity(
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
        status = authorizations.status_of(row, now)
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
            out.append(finding(
                DEFINITION_CHANGED, row.role_definition_external_id, row.path,
                "the role's contents changed after it was authorized, "
                "so what is held is not what was agreed",
                row,
            ))
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
    out.sort(key=lambda f: (CLASSES.index(f.kind), f.role))
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


def counts(findings: list[DeltaFinding]) -> dict[str, int]:
    tally = dict.fromkeys(CLASSES, 0)
    for finding in findings:
        tally[finding.kind] += 1
    return tally
