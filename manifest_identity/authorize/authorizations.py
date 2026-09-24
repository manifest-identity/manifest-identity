"""The authorization write path: what an identity may hold, by whom,
until when.

Four properties give this module its shape, and each is a test.

The authorizer comes from the session and never from the request
(threat 14). There is no field on any model here that a caller can
send to name someone else, so a forged approval is not a validation
failure to catch; it is a request shape that does not exist.

Nothing is edited. A change writes a new row that supersedes the old
one, and a revocation writes a row too, so the chain from first
authorization to last is the history and no past state is erasable
(D-006). The active row for a path is the newest one nothing
supersedes, whose status is authorized and whose window covers now.

Expiry is computed, never stored. A row whose valid_until has passed
is expired the moment the clock says so, with nothing to run and
nothing to forget; this is the same rule the observed half follows,
and it means the delta cannot be wrong because a job did not fire.

Which fields are required is an administrator's choice with a secure
default (D-070), read through core.options at write time, so an
organization that relaxes justification does it deliberately and the
relaxation is audited.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.authorize.models import (
    Authorization,
    AuthorizationStatus,
    EntryPath,
)
from manifest_identity.core import audit, options
from manifest_identity.core.models import User, utcnow

# An owner who is a person is the orphan in waiting (D-038): the
# person leaves and the access stays. A person may own an
# authorization, but never alone.
PERSON_OWNER_KINDS = frozenset({"individual", "person"})


class AuthorizationError(ValueError):
    """A refusal the caller can act on: a missing required field, an
    impossible window, a person owning alone."""


@dataclass(frozen=True)
class Request:
    """What a caller may say. The authorizer, the time, and the status
    are not here on purpose: they come from the session and the clock."""

    identity_id: int
    scope_node_id: int
    role_definition_external_id: str
    mode: str
    path: list[dict[str, str]]
    owner_kind: str
    owner_ref: str
    entry_path: str = EntryPath.form
    role_definition_hash: str | None = None
    secondary_owner_kind: str | None = None
    secondary_owner_ref: str | None = None
    justification: str | None = None
    reference: str | None = None
    control_reference: str | None = None
    valid_from: datetime | None = None
    valid_until: datetime | None = None


def path_key(path: list[dict[str, str]]) -> str:
    """The hops, in order, as one string. Derived rather than stored so
    a path written two ways cannot become two live authorizations."""
    return "|".join(
        f"{hop.get('via', '')}:{hop.get('ref', '')}:{hop.get('mode', '')}"
        for hop in path
    )


def grant_key(path: list[dict[str, str]], role: str) -> str:
    """What makes two authorizations about the same access: the same
    role, arriving by the same hops.

    The role has to be in here. An earlier version keyed supersession
    on the path alone, and because most access arrives directly, every
    identity's second authorization silently replaced its first. The
    runtime proof found it: authorizing one role made the delta report
    another as unauthorized. One key, used by the write path and the
    delta both, so they cannot disagree about what "the same access"
    means."""
    return path_key(path) + "|" + role


def _aware(moment: datetime) -> datetime:
    # The unit-test database stores naive datetimes; comparisons here
    # must not depend on which database answered.
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)


def is_expired(row: Authorization, now: datetime | None = None) -> bool:
    if row.valid_until is None:
        return False
    return _aware(row.valid_until) <= (now or utcnow())


def status_of(row: Authorization, now: datetime | None = None) -> str:
    """The status as the record stands: what was written, unless the
    clock has overtaken it."""
    if row.status == AuthorizationStatus.authorized and is_expired(row, now):
        return AuthorizationStatus.expired
    return row.status


def superseded_ids(db: Session, identity_id: int) -> set[int]:
    return {
        superseded
        for (superseded,) in db.execute(
            select(Authorization.supersedes_id).where(
                Authorization.identity_id == identity_id,
                Authorization.supersedes_id.is_not(None),
            )
        ).all()
        if superseded is not None
    }


def history(db: Session, identity_id: int) -> list[Authorization]:
    return list(
        db.execute(
            select(Authorization)
            .where(Authorization.identity_id == identity_id)
            .order_by(Authorization.authorized_at.desc(), Authorization.id.desc())
        ).scalars()
    )


def latest_rows(db: Session, identity_id: int) -> list[Authorization]:
    """The newest row of every chain: what nothing supersedes."""
    superseded = superseded_ids(db, identity_id)
    return [row for row in history(db, identity_id) if row.id not in superseded]


def active(
    db: Session, identity_id: int, now: datetime | None = None
) -> list[Authorization]:
    """What this identity is authorized to hold right now."""
    moment = now or utcnow()
    return [
        row
        for row in latest_rows(db, identity_id)
        if status_of(row, moment) == AuthorizationStatus.authorized
        and _aware(row.valid_from) <= moment
    ]


def active_for_grant(
    db: Session, identity_id: int, key: str, now: datetime | None = None
) -> Authorization | None:
    for row in active(db, identity_id, now):
        if grant_key(row.path, row.role_definition_external_id) == key:
            return row
    return None


def _check(db: Session, request: Request, valid_until: datetime | None) -> None:
    """Every refusal states the rule and repeats nothing the caller
    sent, which is the same contract the parsers hold to."""
    if not request.path:
        raise AuthorizationError("an authorization needs a path of at least one hop")
    for hop in request.path:
        if not hop.get("via"):
            raise AuthorizationError("every hop in the path names how access arrives")
    if request.owner_kind in PERSON_OWNER_KINDS and not (
        request.secondary_owner_kind and request.secondary_owner_ref
    ):
        raise AuthorizationError(
            "a person may own an authorization only with a second owner named, "
            "because one owner who leaves is one orphaned access"
        )
    if options.get_bool(db, "authorization.justification_required") and not (
        request.justification and request.justification.strip()
    ):
        raise AuthorizationError("a justification is required by this organization")
    if options.get_bool(db, "authorization.reference_required") and not (
        request.reference and request.reference.strip()
    ):
        raise AuthorizationError("a reference is required by this organization")
    if options.get_bool(db, "authorization.control_reference_required") and not (
        request.control_reference and request.control_reference.strip()
    ):
        raise AuthorizationError(
            "a control reference is required by this organization"
        )
    if options.get_bool(db, "authorization.expiry_required") and valid_until is None:
        raise AuthorizationError("an expiry is required by this organization")


def check_only(
    db: Session, request: Request, now: datetime | None = None
) -> tuple[datetime, datetime | None]:
    """Every rule `authorize` applies, applied without writing, and the
    window it resolved. The dry run of a file import calls this, so a
    preview cannot promise a row the write would refuse: there is one
    set of rules and this is it."""
    moment = now or utcnow()
    valid_from = _aware(request.valid_from) if request.valid_from else moment
    maximum = options.get_int(db, "authorization.maximum_lifetime_days")
    if request.valid_until is None:
        # Nothing said: the organization's bound is the answer, so the
        # quiet path is the bounded one.
        valid_until: datetime | None = (
            moment + timedelta(days=maximum)
            if options.get_bool(db, "authorization.expiry_required")
            else None
        )
    else:
        valid_until = _aware(request.valid_until)
    _check(db, request, valid_until)
    if valid_until is not None:
        if valid_until <= valid_from:
            raise AuthorizationError("an authorization must end after it begins")
        if valid_until > valid_from + timedelta(days=maximum):
            raise AuthorizationError(
                f"this organization allows at most {maximum} days, "
                "and a longer window needs the setting changed first"
            )
    return valid_from, valid_until


def authorize(
    db: Session, request: Request, actor: User, now: datetime | None = None
) -> Authorization:
    """Write one authorization, superseding whatever it replaces, with
    its audit row in the same transaction. The caller commits."""
    moment = now or utcnow()
    valid_from, valid_until = check_only(db, request, moment)
    key = grant_key(request.path, request.role_definition_external_id)
    previous = active_for_grant(db, request.identity_id, key, moment)
    row = Authorization(
        identity_id=request.identity_id,
        role_definition_external_id=request.role_definition_external_id,
        role_definition_hash=request.role_definition_hash,
        scope_node_id=request.scope_node_id,
        mode=request.mode,
        path=request.path,
        owner_kind=request.owner_kind,
        owner_ref=request.owner_ref,
        secondary_owner_kind=request.secondary_owner_kind,
        secondary_owner_ref=request.secondary_owner_ref,
        # From the session, never from the request (threat 14).
        authorizer_user_id=actor.id,
        authorizer_username=actor.username,
        authorized_at=moment,
        justification=request.justification,
        reference=request.reference,
        control_reference=request.control_reference,
        valid_from=valid_from,
        valid_until=valid_until,
        status=AuthorizationStatus.authorized,
        supersedes_id=previous.id if previous else None,
        entry_path=request.entry_path,
    )
    db.add(row)
    db.flush()
    audit.record(
        db,
        actor_user_id=actor.id,
        actor_username=actor.username,
        action="authorization_written",
        target=f"identity:{request.identity_id}",
        detail=(
            f"{request.role_definition_external_id} as {request.mode}"
            + (f", superseding {previous.id}" if previous else "")
            + (f", until {valid_until.date()}" if valid_until else ", no expiry")
        ),
    )
    return row


def revoke(
    db: Session,
    target: Authorization,
    actor: User,
    reason: str,
    now: datetime | None = None,
) -> Authorization:
    """Revocation is a row, not an edit: it says who ended this and
    why, and the authorization it ended stays readable beneath it."""
    moment = now or utcnow()
    if not reason.strip():
        raise AuthorizationError("a revocation says why, so the record explains itself")
    row = Authorization(
        identity_id=target.identity_id,
        role_definition_external_id=target.role_definition_external_id,
        role_definition_hash=target.role_definition_hash,
        scope_node_id=target.scope_node_id,
        mode=target.mode,
        path=target.path,
        owner_kind=target.owner_kind,
        owner_ref=target.owner_ref,
        secondary_owner_kind=target.secondary_owner_kind,
        secondary_owner_ref=target.secondary_owner_ref,
        authorizer_user_id=actor.id,
        authorizer_username=actor.username,
        authorized_at=moment,
        justification=reason,
        reference=target.reference,
        control_reference=target.control_reference,
        valid_from=target.valid_from,
        valid_until=moment,
        status=AuthorizationStatus.revoked,
        supersedes_id=target.id,
        entry_path=target.entry_path,
    )
    db.add(row)
    db.flush()
    audit.record(
        db,
        actor_user_id=actor.id,
        actor_username=actor.username,
        action="authorization_revoked",
        target=f"identity:{target.identity_id}",
        detail=f"authorization {target.id}: {reason}",
    )
    return row
