"""Authorization routes: write one, read the chain, revoke one.

Every write is scoped by the identity's own node before anything is
read from the body (D-072), and 404 comes before 403, so a caller
cannot map an estate by asking which identities exist. The authorizer
is taken from the session in the module beneath this one, and no
request model here carries a field that names a person, a time, or a
status; those are not validated away, they are absent.
"""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from manifest_identity.authorize import authorizations
from manifest_identity.authorize.models import Authorization, EntryPath
from manifest_identity.core.db import get_session
from manifest_identity.core.deps import (
    AuthContext,
    ThrottledWrite,
    require_roles,
    require_scope,
)
from manifest_identity.observe.models import GrantMode, Identity

router = APIRouter(tags=["authorize"])

OWNER_KINDS = ("team", "business_unit", "individual", "vendor", "unknown")


class Hop(BaseModel):
    """One step by which access arrives. Bounded on every axis,
    because a path is caller-supplied JSON that the delta will read
    back for the life of the record."""

    via: str = Field(min_length=1, max_length=24, pattern=r"^[a-z_]+$")
    ref: str = Field(default="", max_length=255)
    mode: str = Field(default="active", max_length=16, pattern=r"^[a-z_]*$")


class AuthorizeRequest(BaseModel):
    role_definition_external_id: str = Field(min_length=1, max_length=2048)
    path: list[Hop] = Field(min_length=1, max_length=16)
    owner_kind: str = Field(max_length=16)
    owner_ref: str = Field(min_length=1, max_length=255)
    mode: GrantMode = GrantMode.standing
    role_definition_hash: str | None = Field(default=None, max_length=64)
    secondary_owner_kind: str | None = Field(default=None, max_length=16)
    secondary_owner_ref: str | None = Field(default=None, max_length=255)
    justification: str | None = Field(default=None, max_length=1000)
    reference: str | None = Field(default=None, max_length=500)
    control_reference: str | None = Field(default=None, max_length=64)
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    scope_node_id: int | None = None


class RevokeRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=1000)


class AuthorizationView(BaseModel):
    id: int
    identity_id: int
    role_definition_external_id: str
    role_definition_hash: str | None
    mode: str
    path: list[dict[str, str]]
    owner_kind: str
    owner_ref: str
    secondary_owner_kind: str | None
    secondary_owner_ref: str | None
    authorizer: str
    authorized_at: str
    justification: str | None
    reference: str | None
    control_reference: str | None
    valid_from: str
    valid_until: str | None
    status: str
    supersedes_id: int | None
    entry_path: str


def view(row: Authorization) -> AuthorizationView:
    return AuthorizationView(
        id=row.id,
        identity_id=row.identity_id,
        role_definition_external_id=row.role_definition_external_id,
        role_definition_hash=row.role_definition_hash,
        mode=row.mode,
        path=row.path,
        owner_kind=row.owner_kind,
        owner_ref=row.owner_ref,
        secondary_owner_kind=row.secondary_owner_kind,
        secondary_owner_ref=row.secondary_owner_ref,
        authorizer=row.authorizer_username,
        authorized_at=row.authorized_at.isoformat(timespec="seconds"),
        justification=row.justification,
        reference=row.reference,
        control_reference=row.control_reference,
        valid_from=row.valid_from.isoformat(timespec="seconds"),
        valid_until=(
            row.valid_until.isoformat(timespec="seconds") if row.valid_until else None
        ),
        # What the record says now, with the clock applied: a window
        # that has closed reads expired without anything having run.
        status=authorizations.status_of(row),
        supersedes_id=row.supersedes_id,
        entry_path=row.entry_path,
    )


def _identity_node(db: Session, identity_id: int) -> tuple[Identity, int]:
    identity = db.get(Identity, identity_id)
    if identity is None:
        raise HTTPException(status_code=404, detail="no such identity")
    return identity, identity.scope_node_id


@router.get("/identities/{identity_id}/authorizations")
def list_authorizations(
    identity_id: int,
    db: Annotated[Session, Depends(get_session)],
    _auth: Annotated[
        AuthContext, require_roles("GET /identities/{identity_id}/authorizations")
    ],
) -> list[AuthorizationView]:
    """The whole chain, newest first: what stands now and everything it
    replaced, because a review that cannot see the previous answer
    cannot tell a renewal from a first grant."""
    _identity_node(db, identity_id)
    return [view(row) for row in authorizations.history(db, identity_id)]


@router.post("/identities/{identity_id}/authorizations", status_code=201)
def write_authorization(
    identity_id: int,
    body: AuthorizeRequest,
    db: Annotated[Session, Depends(get_session)],
    auth: Annotated[
        AuthContext, require_roles("POST /identities/{identity_id}/authorizations")
    ],
    _budget: ThrottledWrite,
) -> AuthorizationView:
    identity, node_id = _identity_node(db, identity_id)
    require_scope(
        db, auth, "POST /identities/{identity_id}/authorizations", node_id
    )
    if body.owner_kind not in OWNER_KINDS:
        raise HTTPException(
            status_code=422,
            detail="owner kind is one of: " + ", ".join(OWNER_KINDS),
        )
    # An authorization names a scope; the default is where the identity
    # lives, and naming another is refused unless the caller's binding
    # covers that one too, so a scope field cannot be a way around the
    # check above.
    scope_node_id = body.scope_node_id or node_id
    if scope_node_id != node_id:
        require_scope(
            db, auth, "POST /identities/{identity_id}/authorizations", scope_node_id
        )
    request = authorizations.Request(
        identity_id=identity.id,
        scope_node_id=scope_node_id,
        role_definition_external_id=body.role_definition_external_id,
        role_definition_hash=body.role_definition_hash,
        mode=body.mode.value,
        path=[hop.model_dump() for hop in body.path],
        owner_kind=body.owner_kind,
        owner_ref=body.owner_ref,
        secondary_owner_kind=body.secondary_owner_kind,
        secondary_owner_ref=body.secondary_owner_ref,
        justification=body.justification,
        reference=body.reference,
        control_reference=body.control_reference,
        valid_from=body.valid_from,
        valid_until=body.valid_until,
        entry_path=EntryPath.form,
    )
    try:
        row = authorizations.authorize(db, request, auth.user)
    except authorizations.AuthorizationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    db.commit()
    return view(row)


@router.post("/authorizations/{authorization_id}/revoke", status_code=201)
def revoke_authorization(
    authorization_id: int,
    body: RevokeRequest,
    db: Annotated[Session, Depends(get_session)],
    auth: Annotated[
        AuthContext, require_roles("POST /authorizations/{authorization_id}/revoke")
    ],
) -> AuthorizationView:
    target = db.get(Authorization, authorization_id)
    if target is None:
        raise HTTPException(status_code=404, detail="no such authorization")
    require_scope(
        db, auth, "POST /authorizations/{authorization_id}/revoke", target.scope_node_id
    )
    if target.id in authorizations.superseded_ids(db, target.identity_id):
        raise HTTPException(
            status_code=409,
            detail=(
                "this authorization was already replaced; revoke the one that "
                "stands now"
            ),
        )
    if target.status != "authorized":
        raise HTTPException(status_code=409, detail="this authorization is not live")
    try:
        row = authorizations.revoke(db, target, auth.user, body.reason)
    except authorizations.AuthorizationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    db.commit()
    return view(row)
