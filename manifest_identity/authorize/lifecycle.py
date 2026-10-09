"""The lifecycle every authorized record shares.

Three records answer three questions: an authorization says who may
hold a definition, a relationship authorization says a door may exist,
and a role definition authorization says a custom policy is supposed to
exist. They live by one set of rules. Nothing is edited: a change
writes a row that supersedes the one it replaces. The authorizer comes
from the session and never from the request. A revocation is a row that
closes the window, not an edit to the row it ends. Expiry is the clock
compared with a column.

Those rules were once written out in each of the three modules, and the
copies had begun to differ. They live here so that a change to one of
them reaches every record at once. What differs between the records,
the request each accepts, the checks it runs, and the key that decides
what supersedes what, stays in each record's own module.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import ColumnElement, select
from sqlalchemy.orm import InstrumentedAttribute, Session

from manifest_identity.authorize.models import (
    Authorization,
    AuthorizationStatus,
    AuthorizedRelationship,
    AuthorizedRoleDefinition,
)
from manifest_identity.core.models import User, aware, utcnow

Record = Authorization | AuthorizedRelationship | AuthorizedRoleDefinition


def is_expired(row: Record, now: datetime | None = None) -> bool:
    return row.valid_until is not None and aware(row.valid_until) <= (now or utcnow())


def status_of(row: Record, now: datetime | None = None) -> str:
    """The status as the record stands: what was written, unless the
    clock has overtaken it."""
    if row.status == AuthorizationStatus.authorized and is_expired(row, now):
        return AuthorizationStatus.expired
    return row.status


def superseded_ids(
    db: Session, column: InstrumentedAttribute[int | None], *where: ColumnElement[bool]
) -> set[int]:
    """The rows something newer has replaced, read from one record's
    supersedes column, narrowed by any conditions given."""
    return {
        superseded
        for (superseded,) in db.execute(select(column).where(column.is_not(None), *where))
        if superseded is not None
    }


def authorizer(actor: User, moment: datetime) -> dict[str, object]:
    """Who wrote a row and when, from the session, never from the
    request (threat 14)."""
    return {
        "authorizer_user_id": actor.id,
        "authorizer_username": actor.username,
        "authorized_at": moment,
    }


def closing(row: Record, actor: User, reason: str, moment: datetime) -> dict[str, object]:
    """The columns of the row that revokes `row`: its window ends now,
    the reason is the justification, and it supersedes what it ends, so
    the ended row stays readable beneath it."""
    return {
        **authorizer(actor, moment),
        "justification": reason,
        "valid_from": row.valid_from,
        "valid_until": moment,
        "status": AuthorizationStatus.revoked,
        "supersedes_id": row.id,
    }
