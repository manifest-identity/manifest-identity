"""Authorizing a relationship: the door, rather than what is behind it.

An authorization says a person may hold a definition. A relationship
authorization says a door may exist at all: this role may be assumed by
that account, this identity provider may federate into this estate. The
two are different questions, and answering only the first leaves the way
in ungoverned while every grant behind it is neatly owned.

The record follows the same rules as an authorization, for the same
reasons. Nothing is edited: a change writes a new row that supersedes
the one it replaces, so the history of a trust is readable rather than
overwritten. The authorizer comes from the session and never from the
request. Every write carries its audit row in the same transaction, so
a failed write leaves no record claiming it happened.

The supersession key is the door itself, which is the kind, the identity
trusted into, and the principal trusted from. Keying on anything less
was the defect found in the delta at 1.5, where a second authorization
silently replaced a first that governed something else.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.authorize import lifecycle
from manifest_identity.authorize.lifecycle import is_expired
from manifest_identity.authorize.models import (
    AuthorizationStatus,
    AuthorizedRelationship,
)
from manifest_identity.core import audit
from manifest_identity.core.models import User, aware, utcnow

OWNER_KINDS = ("person", "team", "service")


class RelationshipError(ValueError):
    """A relationship that cannot be written, with the reason a person
    reads rather than a field name."""


@dataclass
class Request:
    kind: str
    to_identity_id: int | None
    to_scope_node_id: int | None
    from_ref: str
    from_kind: str
    owner_kind: str
    owner_ref: str
    justification: str | None
    valid_from: datetime | None
    valid_until: datetime | None


def door_key(kind: str, to_identity_id: int | None, from_ref: str) -> str:
    """What makes two records the same door. Two trusts into the same
    role from different principals are two doors, and a record for one
    must never supersede the record for the other."""
    return f"{kind}|{to_identity_id or 0}|{from_ref}"



def latest_rows(db: Session) -> list[AuthorizedRelationship]:
    """The newest row of every chain: what nothing supersedes."""
    superseded = lifecycle.superseded_ids(db, AuthorizedRelationship.supersedes_id)
    rows = list(db.execute(select(AuthorizedRelationship)).scalars())
    return [row for row in rows if row.id not in superseded]


def active_for_door(
    db: Session, key: str, now: datetime | None = None
) -> AuthorizedRelationship | None:
    moment = now or utcnow()
    for row in latest_rows(db):
        if door_key(row.kind, row.to_identity_id, row.from_ref) != key:
            continue
        if row.status != AuthorizationStatus.authorized:
            continue
        if is_expired(row, moment):
            continue
        return row
    return None


def check(request: Request, now: datetime) -> tuple[datetime, datetime | None]:
    if request.owner_kind not in OWNER_KINDS:
        raise RelationshipError(
            "owner kind is one of: " + ", ".join(OWNER_KINDS)
        )
    if not request.owner_ref.strip():
        raise RelationshipError("a relationship needs an owner")
    if not request.from_ref.strip():
        raise RelationshipError("a relationship needs the principal it is from")
    if request.to_identity_id is None and request.to_scope_node_id is None:
        raise RelationshipError(
            "a relationship needs what it reaches: an identity or a scope"
        )
    valid_from = aware(request.valid_from) if request.valid_from else now
    valid_until = aware(request.valid_until) if request.valid_until else None
    if valid_until is not None and valid_until <= valid_from:
        raise RelationshipError("the validity window ends before it starts")
    return valid_from, valid_until


def authorize(
    db: Session, request: Request, actor: User, now: datetime | None = None
) -> AuthorizedRelationship:
    """Write one relationship authorization, superseding whatever door
    it replaces, with its audit row in the same transaction. The caller
    commits."""
    moment = now or utcnow()
    valid_from, valid_until = check(request, moment)
    key = door_key(request.kind, request.to_identity_id, request.from_ref)
    previous = active_for_door(db, key, moment)
    row = AuthorizedRelationship(
        kind=request.kind,
        to_identity_id=request.to_identity_id,
        to_scope_node_id=request.to_scope_node_id,
        from_ref=request.from_ref,
        from_kind=request.from_kind,
        owner_kind=request.owner_kind,
        owner_ref=request.owner_ref,
        **lifecycle.authorizer(actor, moment),
        justification=request.justification,
        valid_from=valid_from,
        valid_until=valid_until,
        status=AuthorizationStatus.authorized,
        supersedes_id=previous.id if previous else None,
    )
    db.add(row)
    db.flush()
    audit.record(
        db,
        actor_user_id=actor.id,
        actor_username=actor.username,
        action="relationship_authorized",
        target=f"relationship:{request.kind}:{request.to_identity_id or 0}",
        detail=(
            f"from {request.from_ref}"
            + (f", superseding {previous.id}" if previous else "")
            + (f", until {valid_until.date()}" if valid_until else ", no expiry")
        ),
    )
    return row


def revoke(
    db: Session,
    row: AuthorizedRelationship,
    actor: User,
    reason: str,
    now: datetime | None = None,
) -> AuthorizedRelationship:
    """Revoking writes a row rather than changing one, so the record
    says the door was open and then closed, by whom, and why."""
    moment = now or utcnow()
    if not reason.strip():
        raise RelationshipError("a revocation needs a reason")
    closed = AuthorizedRelationship(
        kind=row.kind,
        to_identity_id=row.to_identity_id,
        to_scope_node_id=row.to_scope_node_id,
        from_ref=row.from_ref,
        from_kind=row.from_kind,
        owner_kind=row.owner_kind,
        owner_ref=row.owner_ref,
        **lifecycle.closing(row, actor, reason, moment),
    )
    db.add(closed)
    db.flush()
    audit.record(
        db,
        actor_user_id=actor.id,
        actor_username=actor.username,
        action="relationship_revoked",
        target=f"relationship:{row.kind}:{row.to_identity_id or 0}",
        detail=f"from {row.from_ref}, superseding {row.id}, reason recorded",
    )
    return closed
