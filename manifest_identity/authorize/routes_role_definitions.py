"""The custom definitions a page shows, and the act of authorizing one.

The list is every customer-managed definition at each scope's newest
import, beside whether anybody has said it should exist and at what
version. A definition nobody authorized is the row worth reading, and a
definition whose contents moved since it was authorized is the row a
reviewer would otherwise miss, so both are stated on the row rather than
hidden behind a filter.

Writing follows the same discipline as the other two records: the
caller's binding is checked against the scope the definition was
observed in, the write is budgeted, and the record is appended rather
than edited.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.authorize import role_definitions
from manifest_identity.authorize.models import AuthorizedRoleDefinition
from manifest_identity.core.db import get_session
from manifest_identity.core.deps import (
    AuthContext,
    ThrottledWrite,
    require_roles,
    require_scope,
)
from manifest_identity.core.models import ScopeNode
from manifest_identity.observe import paths, policy_analysis
from manifest_identity.observe.models import Grant, RoleDefinition

router = APIRouter(tags=["role-definitions"])


class RoleDefinitionView(BaseModel):
    role_definition_id: int
    display_name: str
    role_ref: str
    contents_hash: str
    account: str
    authorized: bool
    authorization_id: int | None = None
    authorized_hash: str | None = None
    owner_kind: str | None = None
    owner_ref: str | None = None
    status: str | None = None
    valid_until: datetime | None = None
    # Set when the observed version is not the authorized one: what the
    # current version has that the agreed one did not.
    changed_since_authorized: bool = False
    change: str | None = None


class AuthorizeRoleDefinition(BaseModel):
    role_definition_external_id: str = Field(min_length=1, max_length=2048)
    role_definition_hash: str = Field(min_length=64, max_length=64)
    owner_kind: str = Field(min_length=1, max_length=16)
    owner_ref: str = Field(min_length=1, max_length=255)
    justification: str | None = Field(default=None, max_length=1000)
    valid_from: datetime | None = None
    valid_until: datetime | None = None


class RevokeRoleDefinition(BaseModel):
    reason: str = Field(min_length=1, max_length=1000)


def _view(
    definition: RoleDefinition,
    account: str,
    standing: AuthorizedRoleDefinition | None,
    db: Session,
) -> RoleDefinitionView:
    authorized = (
        standing is not None
        and role_definitions.status_of(standing) == "authorized"
    )
    changed = bool(
        authorized and standing and standing.role_definition_hash != definition.contents_hash
    )
    change_text: str | None = None
    if changed and standing:
        agreed = db.execute(
            select(RoleDefinition.contents).where(
                RoleDefinition.external_id == definition.external_id,
                RoleDefinition.contents_hash == standing.role_definition_hash,
            ).limit(1)
        ).scalar()
        change_text = policy_analysis.describe_change(agreed, definition.contents).as_text()
    return RoleDefinitionView(
        role_definition_id=definition.id,
        display_name=definition.display_name_last,
        role_ref=definition.external_id,
        contents_hash=definition.contents_hash,
        account=account,
        authorized=authorized,
        authorization_id=standing.id if standing else None,
        authorized_hash=standing.role_definition_hash if standing else None,
        owner_kind=standing.owner_kind if authorized and standing else None,
        owner_ref=standing.owner_ref if authorized and standing else None,
        status=role_definitions.status_of(standing) if standing else None,
        valid_until=standing.valid_until if standing else None,
        changed_since_authorized=changed,
        change=change_text,
    )


@router.get(
    "/role-definitions", dependencies=[require_roles("GET /role-definitions")]
)
def list_role_definitions(
    db: Annotated[Session, Depends(get_session)],
) -> list[RoleDefinitionView]:
    """Every custom definition in the estate at the newest import, with
    its authorization if one stands. Unauthorized ones first, then the
    ones that moved, then the rest."""
    views: list[RoleDefinitionView] = []
    for node in db.execute(select(ScopeNode)).scalars():
        newest = paths.newest_import(db, node.id)
        if newest is None:
            continue
        definition_ids = {
            definition_id
            for (definition_id,) in db.execute(
                select(Grant.role_definition_id).where(Grant.import_id == newest)
            )
        }
        if not definition_ids:
            continue
        for definition in db.execute(
            select(RoleDefinition).where(
                RoleDefinition.id.in_(definition_ids),
                RoleDefinition.managed_by == role_definitions.CUSTOMER,
            ).order_by(RoleDefinition.display_name_last)
        ).scalars():
            standing = role_definitions.active_for(db, definition.external_id)
            views.append(_view(definition, node.external_id, standing, db))
    views.sort(
        key=lambda view: (view.authorized, not view.changed_since_authorized, view.display_name)
    )
    return views


@router.post("/role-definitions/authorize", status_code=201)
def authorize_role_definition(
    body: AuthorizeRoleDefinition,
    db: Annotated[Session, Depends(get_session)],
    auth: Annotated[AuthContext, require_roles("POST /role-definitions/authorize")],
    _budget: ThrottledWrite,
) -> RoleDefinitionView:
    """Authorize one custom definition at one version. The scope is the
    one it was observed in, so a caller bound below cannot authorize a
    definition above."""
    definition = role_definitions.observed_version(
        db, body.role_definition_external_id, body.role_definition_hash
    )
    if definition is None:
        raise HTTPException(
            status_code=422,
            detail="no import has observed that definition at that version",
        )
    node_id = db.execute(
        select(Grant.scope_node_id)
        .where(Grant.role_definition_id == definition.id)
        .limit(1)
    ).scalar()
    if node_id is None:
        raise HTTPException(
            status_code=422, detail="that definition is held by nobody in any scope"
        )
    require_scope(db, auth, "POST /role-definitions/authorize", node_id)
    request = role_definitions.Request(
        role_definition_external_id=body.role_definition_external_id,
        role_definition_hash=body.role_definition_hash,
        owner_kind=body.owner_kind,
        owner_ref=body.owner_ref,
        justification=body.justification,
        valid_from=body.valid_from,
        valid_until=body.valid_until,
    )
    try:
        row = role_definitions.authorize(db, request, auth.user)
    except role_definitions.RoleDefinitionError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    db.commit()
    node = db.get(ScopeNode, node_id)
    return _view(definition, node.external_id if node else "", row, db)


@router.post("/role-definitions/{authorization_id}/revoke", status_code=201)
def revoke_role_definition(
    authorization_id: int,
    body: RevokeRoleDefinition,
    db: Annotated[Session, Depends(get_session)],
    auth: Annotated[
        AuthContext, require_roles("POST /role-definitions/{authorization_id}/revoke")
    ],
    _budget: ThrottledWrite,
) -> RoleDefinitionView:
    row = db.get(AuthorizedRoleDefinition, authorization_id)
    if row is None:
        raise HTTPException(status_code=404, detail="no such authorization")
    definition = role_definitions.observed_version(
        db, row.role_definition_external_id, row.role_definition_hash
    )
    node_id = (
        db.execute(
            select(Grant.scope_node_id)
            .where(Grant.role_definition_id == definition.id)
            .limit(1)
        ).scalar()
        if definition
        else None
    )
    if node_id is None:
        raise HTTPException(status_code=422, detail="the record names no scope")
    require_scope(
        db, auth, "POST /role-definitions/{authorization_id}/revoke", node_id
    )
    try:
        closed = role_definitions.revoke(db, row, auth.user, body.reason)
    except role_definitions.RoleDefinitionError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    db.commit()
    node = db.get(ScopeNode, node_id)
    assert definition is not None  # noqa: S101  (node_id above proves it)
    return _view(definition, node.external_id if node else "", closed, db)
