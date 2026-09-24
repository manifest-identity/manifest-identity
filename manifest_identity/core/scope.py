"""The scope tree and the one authority question.

Every other part asks core the same thing: does this user hold one of
these roles at this node, at any ancestor of it, or at the global
node, with no revocation (D-070, D-072). It is answered here and
nowhere else, so the matrix test can walk it and the mutation check
can remove it.
"""

from collections.abc import Iterable
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.core.models import (
    GLOBAL_NODE_EXTERNAL_ID,
    Partition,
    Provider,
    RoleBinding,
    ScopeNode,
    User,
    utcnow,
)
from manifest_identity.core.roles import Role


def global_node(db: Session) -> ScopeNode:
    """The single node an organization-wide binding names. Created by
    the first migration; created here too so a test database has it."""
    node = db.execute(
        select(ScopeNode).where(
            ScopeNode.provider == Provider.generic,
            ScopeNode.kind == "global",
            ScopeNode.external_id == GLOBAL_NODE_EXTERNAL_ID,
        )
    ).scalar_one_or_none()
    if node is None:
        node = ScopeNode(
            provider=Provider.generic,
            partition=Partition.none,
            kind="global",
            external_id=GLOBAL_NODE_EXTERNAL_ID,
            display_name="global",
        )
        db.add(node)
        db.flush()
    return node


def ancestors_and_self(db: Session, node_id: int) -> list[int]:
    """The node, its parent, and so on to a root, then the global node."""
    ids: list[int] = []
    current: int | None = node_id
    seen: set[int] = set()
    while current is not None and current not in seen:
        seen.add(current)
        ids.append(current)
        parent = db.execute(
            select(ScopeNode.parent_id).where(ScopeNode.id == current)
        ).scalar_one_or_none()
        current = parent
    ids.append(global_node(db).id)
    return ids


def active_bindings(db: Session, user_id: int) -> list[RoleBinding]:
    return list(
        db.execute(
            select(RoleBinding).where(
                RoleBinding.user_id == user_id,
                RoleBinding.revoked_at.is_(None),
            )
        ).scalars()
    )


def holds(
    db: Session, user: User, roles: Iterable[Role], scope_node_id: int | None
) -> bool:
    """The authority question. A None scope means the route's target
    has no scope, and only a global binding answers it."""
    wanted = {r.value for r in roles}
    covering = (
        ancestors_and_self(db, scope_node_id)
        if scope_node_id is not None
        else [global_node(db).id]
    )
    for binding in active_bindings(db, user.id):
        if binding.role in wanted and binding.scope_node_id in covering:
            return True
    return False


def roles_held(db: Session, user: User) -> set[str]:
    """Every role the user holds anywhere; what the page shows and what
    the matrix consults before the scope question."""
    return {b.role for b in active_bindings(db, user.id)}


def bind(
    db: Session,
    user: User,
    role: Role,
    node: ScopeNode,
    granted_by: User | None,
) -> RoleBinding:
    binding = RoleBinding(
        user_id=user.id,
        role=role.value,
        scope_node_id=node.id,
        granted_by_user_id=granted_by.id if granted_by else None,
        granted_by_username=granted_by.username if granted_by else "system",
    )
    db.add(binding)
    db.flush()
    return binding


def revoke(db: Session, binding: RoleBinding, by: User, at: datetime | None = None) -> None:
    binding.revoked_at = at or utcnow()
    binding.revoked_by_username = by.username
    db.flush()


def find_or_create_node(
    db: Session,
    provider: Provider,
    partition: Partition,
    kind: str,
    external_id: str,
    display_name: str,
    parent: ScopeNode | None,
) -> ScopeNode:
    node = db.execute(
        select(ScopeNode).where(
            ScopeNode.provider == provider.value,
            ScopeNode.kind == kind,
            ScopeNode.external_id == external_id,
        )
    ).scalar_one_or_none()
    if node is None:
        node = ScopeNode(
            provider=provider.value,
            partition=partition.value,
            kind=kind,
            external_id=external_id,
            display_name=display_name,
            parent_id=parent.id if parent else None,
        )
        db.add(node)
        db.flush()
    return node
