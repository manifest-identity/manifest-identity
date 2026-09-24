"""core's tables: who may act where, and the record of every act.

The scope tree is the spine every other object hangs from. Role
bindings are the only source of authority (D-072): a user holds a role
at a node, and the one function in scope.py answers whether a binding
covers a target. Audit events are hash-chained (D-057). Settings are
the administrator's choices with an audit row per change (D-070).
"""

from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from manifest_identity.core.db import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


class Provider(StrEnum):
    """The vocabulary a scope node or an identity speaks."""

    aws = "aws"
    azure = "azure"
    gcp = "gcp"
    github = "github"
    kubernetes = "kubernetes"
    active_directory = "active_directory"
    okta = "okta"
    database = "database"
    saas = "saas"
    generic = "generic"


class Partition(StrEnum):
    """Explicit on every record, so a government estate is labeled and
    an auditor filters on it; never inferred at read."""

    aws_commercial = "aws_commercial"
    aws_govcloud_us = "aws_govcloud_us"
    azure_commercial = "azure_commercial"
    azure_government = "azure_government"
    gcp = "gcp"
    github_com = "github_com"
    on_premises = "on_premises"
    none = "none"


GLOBAL_NODE_EXTERNAL_ID = "global"


class ScopeNode(Base):
    """One place in a provider's hierarchy. The single node of kind
    "global" is the scope an organization-wide binding names."""

    __tablename__ = "scope_nodes"
    __table_args__ = (UniqueConstraint("provider", "kind", "external_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    provider: Mapped[str] = mapped_column(String(24), index=True)
    partition: Mapped[str] = mapped_column(String(24), index=True)
    # partition, organization, organizational_unit, account, tenant,
    # management_group, subscription, resource_group, folder, project,
    # enterprise, repository, cluster, namespace, forest, domain,
    # instance, global.
    kind: Mapped[str] = mapped_column(String(32))
    external_id: Mapped[str] = mapped_column(String(255))
    display_name: Mapped[str] = mapped_column(String(255))
    parent_id: Mapped[int | None] = mapped_column(
        ForeignKey("scope_nodes.id"), default=None, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(72))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )


class AuthSession(Base):
    """Opaque revocable session rows; only the token's hash is stored
    (D-026)."""

    __tablename__ = "auth_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )


class RoleBinding(Base):
    """A user holding a role at a node. Bindings end by revocation and
    are never deleted, so who could act when survives."""

    __tablename__ = "role_bindings"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    role: Mapped[str] = mapped_column(String(16))
    scope_node_id: Mapped[int] = mapped_column(ForeignKey("scope_nodes.id"), index=True)
    granted_by_user_id: Mapped[int | None] = mapped_column(default=None)
    granted_by_username: Mapped[str] = mapped_column(String(64))
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    revoked_by_username: Mapped[str | None] = mapped_column(String(64), default=None)


class Setting(Base):
    """An administrator's choice, one row per key, the current value;
    every change writes an audit row (D-070)."""

    __tablename__ = "settings"

    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(64), unique=True)
    value: Mapped[str] = mapped_column(String(500))
    changed_by_username: Mapped[str] = mapped_column(String(64))
    changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # Attribution survives user deletion: the id may dangle, the
    # username snapshot stays readable.
    actor_user_id: Mapped[int | None] = mapped_column(default=None)
    actor_username: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str | None] = mapped_column(String(255), default=None)
    detail: Mapped[str | None] = mapped_column(String(1000), default=None)
    ip: Mapped[str | None] = mapped_column(String(64), default=None)
    # Tamper evidence: each row carries the hash of its own content and
    # the previous row's hash, so an altered or removed row breaks every
    # hash after it. The chain head is anchored outside the database by
    # the evidence exports (D-057).
    prev_hash: Mapped[str | None] = mapped_column(String(64), default=None)
    row_hash: Mapped[str | None] = mapped_column(String(64), default=None)
