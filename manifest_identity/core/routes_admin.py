"""Administration: users, the scope tree, and role bindings.

The minimum that makes scoped roles real (D-070, D-072). A user is
created with one binding; more are added at nodes; a binding is
revoked, never deleted. The tree is listed and grown here. Every act
is the administrator's and is audited. In v0.3 administration is
global: an administrator at a node cannot yet create users or bind
below their node; that arrives with per-team views.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.core import audit, security
from manifest_identity.core.db import get_session
from manifest_identity.core.deps import AuthContext, require_roles, require_scope
from manifest_identity.core.models import (
    AuthSession,
    Partition,
    Provider,
    RoleBinding,
    ScopeNode,
    User,
    utcnow,
)
from manifest_identity.core.roles import Role
from manifest_identity.core.scope import bind, find_or_create_node, global_node, revoke

router = APIRouter(prefix="/admin", tags=["admin"])


class BindingView(BaseModel):
    id: int
    role: str
    scope_node_id: int
    scope: str
    granted_by: str
    granted_at: str
    revoked_at: str | None


class UserView(BaseModel):
    username: str
    roles: list[str]
    bindings: list[BindingView]
    created_at: str


class CreateUser(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]+$")
    password: str = Field(max_length=256)
    role: Role
    # Omitted means global.
    scope_node_id: int | None = None


class CreateBinding(BaseModel):
    role: Role
    scope_node_id: int | None = None


class ScopeNodeView(BaseModel):
    id: int
    provider: str
    partition: str
    kind: str
    external_id: str
    display_name: str
    parent_id: int | None


class CreateScopeNode(BaseModel):
    provider: Provider
    partition: Partition
    kind: str = Field(min_length=1, max_length=32, pattern=r"^[a-z_]+$")
    external_id: str = Field(min_length=1, max_length=255)
    display_name: str = Field(min_length=1, max_length=255)
    parent_id: int | None = None


def _node_or_global(db: Session, node_id: int | None) -> ScopeNode:
    if node_id is None:
        return global_node(db)
    node = db.get(ScopeNode, node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="no such scope node")
    return node


def _binding_view(db: Session, b: RoleBinding) -> BindingView:
    node = db.get(ScopeNode, b.scope_node_id)
    return BindingView(
        id=b.id,
        role=b.role,
        scope_node_id=b.scope_node_id,
        scope=node.display_name if node else "",
        granted_by=b.granted_by_username,
        granted_at=b.granted_at.isoformat(),
        revoked_at=b.revoked_at.isoformat() if b.revoked_at else None,
    )


def _user_view(db: Session, u: User) -> UserView:
    bindings = list(db.execute(select(RoleBinding).where(RoleBinding.user_id == u.id)).scalars())
    return UserView(
        username=u.username,
        roles=sorted({b.role for b in bindings if b.revoked_at is None}),
        bindings=[_binding_view(db, b) for b in bindings],
        created_at=u.created_at.isoformat(),
    )


@router.get("/users", dependencies=[require_roles("GET /admin/users")])
def list_users(db: Annotated[Session, Depends(get_session)]) -> list[UserView]:
    users = db.execute(select(User).order_by(User.username)).scalars().all()
    return [_user_view(db, u) for u in users]


@router.post("/users", status_code=201)
def create_user(
    body: CreateUser,
    db: Annotated[Session, Depends(get_session)],
    auth: Annotated[AuthContext, require_roles("POST /admin/users")],
) -> UserView:
    require_scope(db, auth, "POST /admin/users", None)
    try:
        password_hash = security.hash_password(body.password)
    except security.PasswordPolicyError as exc:
        # States the policy, repeats nothing the caller sent.
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if db.execute(select(User).where(User.username == body.username)).first():
        raise HTTPException(status_code=409, detail="username already exists")
    node = _node_or_global(db, body.scope_node_id)
    user = User(username=body.username, password_hash=password_hash)
    db.add(user)
    db.flush()
    bind(db, user, body.role, node, auth.user)
    audit.record(
        db,
        actor_user_id=auth.user.id,
        actor_username=auth.user.username,
        action="user_created",
        target=user.username,
        detail=f"role: {body.role.value} at {node.display_name}",
    )
    db.commit()
    return _user_view(db, user)


@router.post("/users/{username}/bindings", status_code=201)
def create_binding(
    username: str,
    body: CreateBinding,
    db: Annotated[Session, Depends(get_session)],
    auth: Annotated[AuthContext, require_roles("POST /admin/users/{username}/bindings")],
) -> UserView:
    require_scope(db, auth, "POST /admin/users/{username}/bindings", None)
    user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="no such user")
    node = _node_or_global(db, body.scope_node_id)
    bind(db, user, body.role, node, auth.user)
    audit.record(
        db,
        actor_user_id=auth.user.id,
        actor_username=auth.user.username,
        action="binding_created",
        target=user.username,
        detail=f"role: {body.role.value} at {node.display_name}",
    )
    db.commit()
    return _user_view(db, user)


@router.post("/users/{username}/bindings/{binding_id}/revoke")
def revoke_binding(
    username: str,
    binding_id: int,
    db: Annotated[Session, Depends(get_session)],
    auth: Annotated[
        AuthContext,
        require_roles("POST /admin/users/{username}/bindings/{binding_id}/revoke"),
    ],
) -> UserView:
    require_scope(db, auth, "POST /admin/users/{username}/bindings/{binding_id}/revoke", None)
    user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
    binding = db.get(RoleBinding, binding_id)
    if user is None or binding is None or binding.user_id != user.id:
        raise HTTPException(status_code=404, detail="no such binding")
    if binding.revoked_at is None:
        revoke(db, binding, auth.user)
        audit.record(
            db,
            actor_user_id=auth.user.id,
            actor_username=auth.user.username,
            action="binding_revoked",
            target=user.username,
            detail=f"binding {binding.id}: {binding.role}",
        )
        db.commit()
    return _user_view(db, user)


@router.post("/users/{username}/sessions/revoke")
def revoke_user_sessions(
    username: str,
    db: Annotated[Session, Depends(get_session)],
    auth: Annotated[AuthContext, require_roles("POST /admin/users/{username}/sessions/revoke")],
) -> dict[str, int | str]:
    """End every live session a user holds, in one audited act: the
    stolen-token answer (threat 6)."""
    user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="no such user")
    now = utcnow()
    live = db.execute(
        select(AuthSession).where(
            AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None)
        )
    ).scalars().all()
    for session in live:
        session.revoked_at = now
    audit.record(
        db,
        actor_user_id=auth.user.id,
        actor_username=auth.user.username,
        action="sessions_revoked",
        target=user.username,
        detail=f"{len(live)} session(s)",
    )
    db.commit()
    return {"username": user.username, "sessions_revoked": len(live)}


@router.get("/scopes", dependencies=[require_roles("GET /admin/scopes")])
def list_scopes(db: Annotated[Session, Depends(get_session)]) -> list[ScopeNodeView]:
    global_node(db)
    nodes = db.execute(select(ScopeNode).order_by(ScopeNode.provider, ScopeNode.id)).scalars().all()
    return [ScopeNodeView(**{k: getattr(n, k) for k in ScopeNodeView.model_fields}) for n in nodes]


@router.post("/scopes", status_code=201)
def create_scope(
    body: CreateScopeNode,
    db: Annotated[Session, Depends(get_session)],
    auth: Annotated[AuthContext, require_roles("POST /admin/scopes")],
) -> ScopeNodeView:
    require_scope(db, auth, "POST /admin/scopes", None)
    parent = db.get(ScopeNode, body.parent_id) if body.parent_id is not None else None
    if body.parent_id is not None and parent is None:
        raise HTTPException(status_code=404, detail="no such parent scope node")
    node = find_or_create_node(
        db, body.provider, body.partition, body.kind, body.external_id,
        body.display_name, parent,
    )
    audit.record(
        db,
        actor_user_id=auth.user.id,
        actor_username=auth.user.username,
        action="scope_created",
        target=f"{body.provider.value}:{body.kind}:{body.external_id}",
    )
    db.commit()
    return ScopeNodeView(**{k: getattr(node, k) for k in ScopeNodeView.model_fields})
