"""User management, administrator only, the minimum that makes roles real.

Create and list. No password change, no disable, no delete yet; each of
those is governance surface that arrives with its own subphase. The
initial password is set by the administrator who creates the user.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity import audit, security
from manifest_identity.db import get_session
from manifest_identity.deps import AuthContext, require_roles
from manifest_identity.models import AuthSession, User, utcnow
from manifest_identity.roles import Role

router = APIRouter(prefix="/admin")


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]+$")
    password: str = Field(max_length=256)
    role: Role


class UserView(BaseModel):
    username: str
    role: str
    created_at: str


@router.get("/users", dependencies=[require_roles("GET /admin/users")])
def list_users(db: Annotated[Session, Depends(get_session)]) -> list[UserView]:
    rows = db.execute(select(User).order_by(User.username)).scalars().all()
    return [
        UserView(username=u.username, role=u.role, created_at=u.created_at.isoformat())
        for u in rows
    ]


@router.post("/users", status_code=201)
def create_user(
    body: CreateUserRequest,
    db: Annotated[Session, Depends(get_session)],
    auth: Annotated[AuthContext, require_roles("POST /admin/users")],
) -> UserView:
    try:
        password_hash = security.hash_password(body.password)
    except security.PasswordPolicyError as exc:
        # States the policy, repeats nothing the caller sent.
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    existing = db.execute(
        select(User).where(User.username == body.username)
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status_code=409, detail="username already exists")
    user = User(
        username=body.username, password_hash=password_hash, role=body.role.value
    )
    db.add(user)
    audit.record(
        db,
        actor_user_id=auth.user.id,
        actor_username=auth.user.username,
        action="user_created",
        target=body.username,
        detail=f"role: {body.role.value}",
    )
    db.commit()
    return UserView(
        username=user.username, role=user.role, created_at=user.created_at.isoformat()
    )


class RevocationView(BaseModel):
    username: str
    sessions_revoked: int


@router.post("/users/{username}/sessions/revoke")
def revoke_user_sessions(
    username: str,
    db: Annotated[Session, Depends(get_session)],
    auth: Annotated[AuthContext, require_roles("POST /admin/users/{username}/sessions/revoke")],
) -> RevocationView:
    """End every live session a user holds, in one act. This is the
    stolen-token answer the threat model promised: a compromised
    account stops working everywhere the moment an administrator says
    so, without rotating anything or ending anyone else's day."""
    user = db.execute(
        select(User).where(User.username == username)
    ).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="no such user")
    now = utcnow()
    live = db.execute(
        select(AuthSession).where(
            AuthSession.user_id == user.id,
            AuthSession.revoked_at.is_(None),
        )
    ).scalars().all()
    for session in live:
        session.revoked_at = now
    audit.record(
        db,
        actor_user_id=auth.user.id,
        actor_username=auth.user.username,
        action="sessions_revoked",
        target=username,
        detail=f"{len(live)} session(s) ended",
    )
    db.commit()
    return RevocationView(username=username, sessions_revoked=len(live))
