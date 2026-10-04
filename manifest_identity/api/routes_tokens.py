"""Minting and revoking integration tokens, an administrator's act.

The plaintext is returned exactly once, in the response to the mint,
and nothing stores it: the row holds a hash, the list shows names and
dates, and a lost token is revoked and minted again rather than
recovered. A revocation is a timestamp on the row rather than a
deletion, so who could read when survives.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.api.models import IntegrationToken
from manifest_identity.core import audit, security
from manifest_identity.core.db import get_session
from manifest_identity.core.deps import AuthContext, SteppedUp, require_roles, require_scope
from manifest_identity.core.models import utcnow

router = APIRouter(prefix="/admin/tokens", tags=["tokens"])


class CreateToken(BaseModel):
    name: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]*$")


class TokenView(BaseModel):
    id: int
    name: str
    created_by: str
    created_at: str
    last_used_at: str | None
    revoked_at: str | None


class MintedToken(TokenView):
    # Shown once. The row keeps a hash, and the list never carries it.
    token: str


class RevokeToken(BaseModel):
    reason: str = Field(min_length=1, max_length=500)


def _view(row: IntegrationToken) -> TokenView:
    return TokenView(
        id=row.id,
        name=row.name,
        created_by=row.created_by_username,
        created_at=row.created_at.isoformat(timespec="seconds"),
        last_used_at=(
            row.last_used_at.isoformat(timespec="seconds") if row.last_used_at else None
        ),
        revoked_at=(
            row.revoked_at.isoformat(timespec="seconds") if row.revoked_at else None
        ),
    )


@router.get("", dependencies=[require_roles("GET /admin/tokens")])
def list_tokens(db: Annotated[Session, Depends(get_session)]) -> list[TokenView]:
    rows = db.execute(select(IntegrationToken).order_by(IntegrationToken.id)).scalars()
    return [_view(row) for row in rows]


@router.post("", status_code=201)
def create_token(
    body: CreateToken,
    db: Annotated[Session, Depends(get_session)],
    auth: Annotated[AuthContext, require_roles("POST /admin/tokens")],
    _stepped: SteppedUp,
) -> MintedToken:
    require_scope(db, auth, "POST /admin/tokens", None)
    if db.execute(
        select(IntegrationToken).where(IntegrationToken.name == body.name)
    ).first():
        raise HTTPException(status_code=409, detail="a token with that name exists")
    token, token_hash = security.new_session_token()
    row = IntegrationToken(
        name=body.name,
        token_hash=token_hash,
        created_by_username=auth.user.username,
    )
    db.add(row)
    db.flush()
    audit.record(
        db,
        actor_user_id=auth.user.id,
        actor_username=auth.user.username,
        action="integration_token_created",
        target=f"token:{row.id}",
        detail=f"{row.name}",
    )
    db.commit()
    return MintedToken(**_view(row).model_dump(), token=token)


@router.post("/{token_id}/revoke", status_code=201)
def revoke_token(
    token_id: int,
    body: RevokeToken,
    db: Annotated[Session, Depends(get_session)],
    auth: Annotated[AuthContext, require_roles("POST /admin/tokens/{token_id}/revoke")],
) -> TokenView:
    require_scope(db, auth, "POST /admin/tokens/{token_id}/revoke", None)
    row = db.get(IntegrationToken, token_id)
    if row is None:
        raise HTTPException(status_code=404, detail="no such token")
    if row.revoked_at is not None:
        raise HTTPException(status_code=409, detail="already revoked")
    row.revoked_at = utcnow()
    audit.record(
        db,
        actor_user_id=auth.user.id,
        actor_username=auth.user.username,
        action="integration_token_revoked",
        target=f"token:{row.id}",
        detail=f"{row.name}: {body.reason}",
    )
    db.commit()
    return _view(row)
