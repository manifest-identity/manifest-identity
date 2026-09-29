"""Authorizing a custom definition: the policy itself, as written.

An authorization says who may hold a definition. A relationship
authorization says a door may exist. This says a definition somebody in
the organization wrote is supposed to exist and look like this, bound
to the hash of the contents that were agreed. Its owner is the person
who wrote the policy, which is usually not the person it is attached
to, and that is why it is its own record rather than a field on the
holder's authorization.

Only customer-managed definitions are recorded here. A provider's
built-in policy is the provider's to change, nobody in the organization
authored it, and its changes are already reported to every holder.

Same rules as the other two records: nothing is edited, a new hash is a
new row that supersedes the old, the authorizer comes from the session,
and every write carries its audit row in the same transaction. The
supersession key is the definition's stable identifier, because there
is one answer to whether a given policy is supposed to exist, and a new
version of it replaces that answer rather than sitting beside it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.authorize.models import (
    AuthorizationStatus,
    AuthorizedRoleDefinition,
)
from manifest_identity.core import audit
from manifest_identity.core.models import User, aware, utcnow
from manifest_identity.observe.models import RoleDefinition

OWNER_KINDS = ("person", "team", "service")
CUSTOMER = "customer"


class RoleDefinitionError(ValueError):
    """A definition that cannot be authorized, with the reason a person
    reads rather than a field name."""


@dataclass
class Request:
    role_definition_external_id: str
    role_definition_hash: str
    owner_kind: str
    owner_ref: str
    justification: str | None
    valid_from: datetime | None
    valid_until: datetime | None



def is_expired(row: AuthorizedRoleDefinition, now: datetime | None = None) -> bool:
    moment = now or utcnow()
    return row.valid_until is not None and aware(row.valid_until) <= moment


def status_of(row: AuthorizedRoleDefinition, now: datetime | None = None) -> str:
    if row.status != AuthorizationStatus.authorized:
        return str(row.status)
    return "expired" if is_expired(row, now) else str(row.status)


def superseded_ids(db: Session) -> set[int]:
    return {
        superseded
        for (superseded,) in db.execute(
            select(AuthorizedRoleDefinition.supersedes_id).where(
                AuthorizedRoleDefinition.supersedes_id.is_not(None)
            )
        )
        if superseded is not None
    }


def latest_rows(db: Session) -> list[AuthorizedRoleDefinition]:
    """The newest row of every chain: what nothing supersedes."""
    superseded = superseded_ids(db)
    rows = list(db.execute(select(AuthorizedRoleDefinition)).scalars())
    return [row for row in rows if row.id not in superseded]


def active_for(
    db: Session, external_id: str, now: datetime | None = None
) -> AuthorizedRoleDefinition | None:
    """The standing authorization for one definition, if any."""
    moment = now or utcnow()
    for row in latest_rows(db):
        if row.role_definition_external_id != external_id[:2048]:
            continue
        if row.status != AuthorizationStatus.authorized:
            continue
        if is_expired(row, moment):
            continue
        return row
    return None


def observed_version(
    db: Session, external_id: str, contents_hash: str
) -> RoleDefinition | None:
    """The definition row the request names. A hash nobody observed is
    refused: authorizing contents this product has never seen would
    make the delta compare the record against nothing."""
    return db.execute(
        select(RoleDefinition).where(
            RoleDefinition.external_id == external_id[:2048],
            RoleDefinition.contents_hash == contents_hash,
        )
    ).scalars().first()


def check(db: Session, request: Request, now: datetime) -> tuple[
    RoleDefinition, datetime, datetime | None
]:
    if request.owner_kind not in OWNER_KINDS:
        raise RoleDefinitionError("owner kind is one of: " + ", ".join(OWNER_KINDS))
    if not request.owner_ref.strip():
        raise RoleDefinitionError("a definition needs an owner")
    definition = observed_version(
        db, request.role_definition_external_id, request.role_definition_hash
    )
    if definition is None:
        raise RoleDefinitionError(
            "no import has observed that definition at that version"
        )
    if definition.managed_by != CUSTOMER:
        raise RoleDefinitionError(
            "a provider's built-in definition is the provider's to change; "
            "only a custom one is authorized here"
        )
    valid_from = aware(request.valid_from) if request.valid_from else now
    valid_until = aware(request.valid_until) if request.valid_until else None
    if valid_until is not None and valid_until <= valid_from:
        raise RoleDefinitionError("the validity window ends before it starts")
    return definition, valid_from, valid_until


def authorize(
    db: Session, request: Request, actor: User, now: datetime | None = None
) -> AuthorizedRoleDefinition:
    """Write one authorization for a custom definition, superseding the
    standing one for the same definition, with its audit row in the
    same transaction. The caller commits."""
    moment = now or utcnow()
    definition, valid_from, valid_until = check(db, request, moment)
    previous = active_for(db, request.role_definition_external_id, moment)
    row = AuthorizedRoleDefinition(
        provider_id=definition.provider_id,
        role_definition_external_id=request.role_definition_external_id[:2048],
        role_definition_hash=request.role_definition_hash,
        display_name=definition.display_name_last,
        owner_kind=request.owner_kind,
        owner_ref=request.owner_ref,
        # From the session, never from the request (threat 14).
        authorizer_user_id=actor.id,
        authorizer_username=actor.username,
        authorized_at=moment,
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
        action="role_definition_authorized",
        target=f"role_definition:{definition.id}",
        detail=(
            f"{definition.display_name_last} at {request.role_definition_hash[:12]}"
            + (f", superseding {previous.id}" if previous else "")
            + (f", until {valid_until.date()}" if valid_until else ", no expiry")
        ),
    )
    return row


def revoke(
    db: Session,
    row: AuthorizedRoleDefinition,
    actor: User,
    reason: str,
    now: datetime | None = None,
) -> AuthorizedRoleDefinition:
    """Revoking writes a row rather than changing one, so the record
    says the definition was authorized and then was not, by whom, and
    why."""
    moment = now or utcnow()
    if not reason.strip():
        raise RoleDefinitionError("a revocation needs a reason")
    closed = AuthorizedRoleDefinition(
        provider_id=row.provider_id,
        role_definition_external_id=row.role_definition_external_id,
        role_definition_hash=row.role_definition_hash,
        display_name=row.display_name,
        owner_kind=row.owner_kind,
        owner_ref=row.owner_ref,
        authorizer_user_id=actor.id,
        authorizer_username=actor.username,
        authorized_at=moment,
        justification=reason,
        valid_from=row.valid_from,
        valid_until=moment,
        status=AuthorizationStatus.revoked,
        supersedes_id=row.id,
    )
    db.add(closed)
    db.flush()
    audit.record(
        db,
        actor_user_id=actor.id,
        actor_username=actor.username,
        action="role_definition_revoked",
        target=f"role_definition_authorization:{row.id}",
        detail=f"{row.display_name}, superseding {row.id}, reason recorded",
    )
    return closed
