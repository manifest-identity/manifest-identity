"""The relationships a page shows, and the act of authorizing one.

The list is the observed doors joined to the authorized ones: every
principal a role trusts, as the newest import saw it, beside whether
anybody has said it should exist and who owns it if they have. A door
nobody has authorized is the row worth reading, which is why it is not
hidden behind a filter.

Writing follows the same discipline as an authorization: the scope is
checked against the caller's binding, the write is budgeted, and the
record is appended rather than edited.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.authorize import lifecycle, relationships
from manifest_identity.authorize.models import AuthorizedRelationship
from manifest_identity.core.db import get_session
from manifest_identity.core.deps import (
    AuthContext,
    ThrottledWrite,
    require_roles,
    require_scope,
)
from manifest_identity.observe import paths
from manifest_identity.observe.models import Identity, ObservedRelationship

router = APIRouter(tags=["relationships"])


class RelationshipView(BaseModel):
    kind: str
    from_ref: str
    from_kind: str
    to_identity_id: int | None
    to_identity: str | None
    authorized: bool
    authorization_id: int | None = None
    owner_kind: str | None = None
    owner_ref: str | None = None
    status: str | None = None
    valid_until: datetime | None = None


class AuthorizeRelationship(BaseModel):
    kind: str = Field(min_length=1, max_length=24)
    to_identity_id: int | None = None
    to_scope_node_id: int | None = None
    from_ref: str = Field(min_length=1, max_length=2048)
    from_kind: str = Field(min_length=1, max_length=24)
    owner_kind: str = Field(min_length=1, max_length=16)
    owner_ref: str = Field(min_length=1, max_length=255)
    justification: str | None = Field(default=None, max_length=1000)
    valid_from: datetime | None = None
    valid_until: datetime | None = None


class RevokeRelationship(BaseModel):
    reason: str = Field(min_length=1, max_length=1000)


def _view(
    *,
    kind: str,
    from_ref: str,
    from_kind: str,
    to_identity_id: int | None,
    to_identity: str | None,
    authorization: AuthorizedRelationship | None,
) -> RelationshipView:
    """One row as a page reads it: the door, and its authorization when
    one stands. A revoked or expired record leaves the door showing as
    unauthorized, which is what it is."""
    standing = (
        authorization is not None
        and lifecycle.status_of(authorization) == "authorized"
    )
    return RelationshipView(
        kind=kind,
        from_ref=from_ref,
        from_kind=from_kind,
        to_identity_id=to_identity_id,
        to_identity=to_identity,
        authorized=standing,
        authorization_id=authorization.id if authorization else None,
        owner_kind=authorization.owner_kind if standing and authorization else None,
        owner_ref=authorization.owner_ref if standing and authorization else None,
        status=lifecycle.status_of(authorization) if authorization else None,
        valid_until=authorization.valid_until if authorization else None,
    )


@router.get("/relationships", dependencies=[require_roles("GET /relationships")])
def list_relationships(
    db: Annotated[Session, Depends(get_session)],
) -> list[RelationshipView]:
    """Every observed door in the estate, with its authorization if it
    has one. Ordered so the unauthorized ones are read first."""
    nodes = {
        identity.scope_node_id for identity in db.execute(select(Identity)).scalars()
    }
    observed: list[ObservedRelationship] = []
    for node_id in nodes:
        newest = paths.newest_import(db, node_id)
        if newest is None:
            continue
        observed.extend(
            db.execute(
                select(ObservedRelationship).where(
                    ObservedRelationship.import_id == newest
                )
            ).scalars()
        )

    names = {
        identity.id: identity.first_display_name
        for identity in db.execute(select(Identity)).scalars()
    }
    active = {
        relationships.door_key(row.kind, row.to_identity_id, row.from_ref): row
        for row in relationships.latest_rows(db)
    }

    views: list[RelationshipView] = []
    for row in observed:
        key = relationships.door_key(row.kind, row.to_identity_id, row.from_ref)
        views.append(_view(
            kind=row.kind,
            from_ref=row.from_ref,
            from_kind=row.from_kind,
            to_identity_id=row.to_identity_id,
            to_identity=names.get(row.to_identity_id or 0),
            authorization=active.get(key),
        ))
    views.sort(key=lambda view: (view.authorized, view.kind, view.from_ref))
    return views


@router.post("/relationships/authorize", status_code=201)
def authorize_relationship(
    body: AuthorizeRelationship,
    db: Annotated[Session, Depends(get_session)],
    auth: Annotated[AuthContext, require_roles("POST /relationships/authorize")],
    _budget: ThrottledWrite,
) -> RelationshipView:
    """Authorize one door. The scope is the one the identity it reaches
    lives in, so a caller bound below cannot authorize a trust above."""
    node_id = body.to_scope_node_id
    identity = None
    if body.to_identity_id is not None:
        identity = db.get(Identity, body.to_identity_id)
        if identity is None:
            raise HTTPException(status_code=404, detail="no such identity")
        node_id = identity.scope_node_id
    if node_id is None:
        raise HTTPException(
            status_code=422,
            detail="a relationship needs what it reaches: an identity or a scope",
        )
    require_scope(db, auth, "POST /relationships/authorize", node_id)

    request = relationships.Request(
        kind=body.kind,
        to_identity_id=body.to_identity_id,
        to_scope_node_id=node_id,
        from_ref=body.from_ref,
        from_kind=body.from_kind,
        owner_kind=body.owner_kind,
        owner_ref=body.owner_ref,
        justification=body.justification,
        valid_from=body.valid_from,
        valid_until=body.valid_until,
    )
    try:
        row = relationships.authorize(db, request, auth.user)
    except relationships.RelationshipError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    db.commit()
    return _view(
        kind=row.kind,
        from_ref=row.from_ref,
        from_kind=row.from_kind,
        to_identity_id=row.to_identity_id,
        to_identity=identity.first_display_name if identity else None,
        authorization=row,
    )


@router.post("/relationships/{authorization_id}/revoke", status_code=201)
def revoke_relationship(
    authorization_id: int,
    body: RevokeRelationship,
    db: Annotated[Session, Depends(get_session)],
    auth: Annotated[
        AuthContext, require_roles("POST /relationships/{authorization_id}/revoke")
    ],
    _budget: ThrottledWrite,
) -> RelationshipView:
    row = db.get(AuthorizedRelationship, authorization_id)
    if row is None:
        raise HTTPException(status_code=404, detail="no such relationship")
    node_id = row.to_scope_node_id
    if node_id is None and row.to_identity_id is not None:
        identity = db.get(Identity, row.to_identity_id)
        node_id = identity.scope_node_id if identity else None
    if node_id is None:
        raise HTTPException(status_code=422, detail="the record names no scope")
    require_scope(
        db, auth, "POST /relationships/{authorization_id}/revoke", node_id
    )
    try:
        closed = relationships.revoke(db, row, auth.user, body.reason)
    except relationships.RelationshipError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    db.commit()
    return _view(
        kind=closed.kind,
        from_ref=closed.from_ref,
        from_kind=closed.from_kind,
        to_identity_id=closed.to_identity_id,
        to_identity=None,
        authorization=closed,
    )

