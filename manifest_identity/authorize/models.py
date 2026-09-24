"""authorize's tables: what a person said an identity may hold,
append-only.

An authorization is per grant path (D-068, D-073): what an identity is
supposed to hold, who authorized it, until when. Authorized
relationships are the intended counterparts of observed ones.
Governance records are the identity-level layer role-call built:
owner, purpose, flag, attestation about an identity or a group. Every
row names its authorizer from the session, never from a form
(threat 14).

The word authorization names this record and nothing else (D-073).
The application's own gates are the role matrix and the scope check.
"""

from datetime import datetime
from enum import StrEnum

from sqlalchemy import JSON, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from manifest_identity.core.db import Base
from manifest_identity.core.models import utcnow


class AuthorizationStatus(StrEnum):
    authorized = "authorized"
    expired = "expired"
    revoked = "revoked"


class EntryPath(StrEnum):
    form = "form"
    csv = "csv"
    from_observed = "from_observed"
    campaign = "campaign"
    api = "api"
    email_proposal = "email_proposal"


class GovernanceRecord(Base):
    """What a person recorded about an identity or a group itself:
    owner, purpose, flag, attestation. Superseded or cleared, never
    edited (D-006 applied to people)."""

    __tablename__ = "governance_records"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_type: Mapped[str] = mapped_column(String(16), index=True)
    target_id: Mapped[int] = mapped_column(index=True)
    # owner | purpose | flag | attestation
    kind: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(String(500))
    # Only for kind=owner: team | business_unit | individual | vendor |
    # unknown. An individual owner is the orphan in waiting (D-038).
    owner_type: Mapped[str | None] = mapped_column(String(16), default=None)
    actor_user_id: Mapped[int | None] = mapped_column(default=None)
    actor_username: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    cleared_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    cleared_by: Mapped[str | None] = mapped_column(String(64), default=None)


class Authorization(Base):
    """One grant path a person authorized an identity to hold. A new
    row supersedes the previous one for the same path; the chain is
    the history, and no row is ever edited."""

    __tablename__ = "authorizations"

    id: Mapped[int] = mapped_column(primary_key=True)
    identity_id: Mapped[int] = mapped_column(ForeignKey("identities.id"), index=True)
    role_definition_external_id: Mapped[str] = mapped_column(String(2048))
    role_definition_hash: Mapped[str | None] = mapped_column(String(64), default=None)
    scope_node_id: Mapped[int] = mapped_column(ForeignKey("scope_nodes.id"), index=True)
    mode: Mapped[str] = mapped_column(String(16))
    path: Mapped[list[dict[str, str]]] = mapped_column(JSON)
    owner_kind: Mapped[str] = mapped_column(String(16))
    owner_ref: Mapped[str] = mapped_column(String(255))
    secondary_owner_kind: Mapped[str | None] = mapped_column(String(16), default=None)
    secondary_owner_ref: Mapped[str | None] = mapped_column(String(255), default=None)
    authorizer_user_id: Mapped[int | None] = mapped_column(default=None)
    authorizer_username: Mapped[str] = mapped_column(String(64))
    authorized_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    justification: Mapped[str | None] = mapped_column(String(1000), default=None)
    reference: Mapped[str | None] = mapped_column(String(500), default=None)
    control_reference: Mapped[str | None] = mapped_column(String(64), default=None)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    status: Mapped[str] = mapped_column(String(16), default=AuthorizationStatus.authorized)
    supersedes_id: Mapped[int | None] = mapped_column(
        ForeignKey("authorizations.id"), default=None
    )
    entry_path: Mapped[str] = mapped_column(String(24))
    # Set when the row came through a file, so the mapping that read
    # it is one join away (D-074).
    batch_id: Mapped[int | None] = mapped_column(
        ForeignKey("import_batches.id"), default=None, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )


class AuthorizedRelationship(Base):
    """A relationship someone authorized: a trust, a federation, a
    delegation, with its owner, authorizer, and validity window."""

    __tablename__ = "authorized_relationships"

    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(24))
    to_identity_id: Mapped[int | None] = mapped_column(
        ForeignKey("identities.id"), default=None, index=True
    )
    to_scope_node_id: Mapped[int | None] = mapped_column(
        ForeignKey("scope_nodes.id"), default=None
    )
    from_ref: Mapped[str] = mapped_column(String(2048))
    from_kind: Mapped[str] = mapped_column(String(24))
    owner_kind: Mapped[str] = mapped_column(String(16))
    owner_ref: Mapped[str] = mapped_column(String(255))
    authorizer_user_id: Mapped[int | None] = mapped_column(default=None)
    authorizer_username: Mapped[str] = mapped_column(String(64))
    authorized_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    justification: Mapped[str | None] = mapped_column(String(1000), default=None)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    status: Mapped[str] = mapped_column(String(16), default=AuthorizationStatus.authorized)
    supersedes_id: Mapped[int | None] = mapped_column(
        ForeignKey("authorized_relationships.id"), default=None
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
