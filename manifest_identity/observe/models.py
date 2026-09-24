"""observe's tables: what was seen, append-only, never updated (D-006).

State is derived from these at read time. One row per import per
fact; the newest import's rows are the current picture, and the older
ones are the history. Findings are not stored.
"""

from datetime import datetime
from enum import StrEnum

from sqlalchemy import JSON, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from manifest_identity.core.db import Base
from manifest_identity.core.models import utcnow


class IdentityKind(StrEnum):
    person = "person"
    service = "service"
    group = "group"
    role = "role"
    workload = "workload"
    application = "application"
    external = "external"
    unknown = "unknown"


class Home(StrEnum):
    """Where an identity's account lives. A guest is home != this_directory."""

    this_directory = "this_directory"
    other_tenant = "other_tenant"
    identity_provider = "identity_provider"
    consumer = "consumer"


class CredentialKind(StrEnum):
    access_key = "access_key"
    password = "password"  # noqa: S105
    certificate = "certificate"
    client_secret = "client_secret"  # noqa: S105
    token = "token"  # noqa: S105
    ssh_key = "ssh_key"
    kerberos_key = "kerberos_key"
    api_key = "api_key"


class GrantMode(StrEnum):
    standing = "standing"
    eligible = "eligible"
    session = "session"


class ProviderInstance(Base):
    """One provider an organization observes: which AWS organization,
    which tenant. A row, not a string."""

    __tablename__ = "providers"

    id: Mapped[int] = mapped_column(primary_key=True)
    provider: Mapped[str] = mapped_column(String(24), index=True)
    display_name: Mapped[str] = mapped_column(String(255))
    root_scope_node_id: Mapped[int] = mapped_column(ForeignKey("scope_nodes.id"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )


class Import(Base):
    """One file or pull. captured_at comes from the file's own content,
    never from a filename or a form field (D-008); the same file twice
    is refused."""

    __tablename__ = "imports"
    __table_args__ = (
        UniqueConstraint("scope_node_id", "source_kind", "captured_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    provider_id: Mapped[int] = mapped_column(ForeignKey("providers.id"))
    scope_node_id: Mapped[int] = mapped_column(ForeignKey("scope_nodes.id"), index=True)
    # aws_credential_report, aws_authorization_details, generic_csv,
    # github_export, later the connection.
    source_kind: Mapped[str] = mapped_column(String(32))
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    imported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    imported_by_username: Mapped[str] = mapped_column(String(64))
    source_filename: Mapped[str | None] = mapped_column(String(255), default=None)
    row_count: Mapped[int] = mapped_column(default=0)
    skipped_count: Mapped[int] = mapped_column(default=0)


class Identity(Base):
    """A principal, keyed by the provider's immutable identifier
    (D-016). Groups are identities of kind group: governable privilege
    sources, never actors (D-019)."""

    __tablename__ = "identities"
    __table_args__ = (UniqueConstraint("provider_id", "external_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    provider_id: Mapped[int] = mapped_column(ForeignKey("providers.id"))
    scope_node_id: Mapped[int] = mapped_column(ForeignKey("scope_nodes.id"), index=True)
    external_id: Mapped[str] = mapped_column(String(255), index=True)
    # The provider's own type word: user, role, root, group, service
    # principal, managed identity; the neutral kind is derived from it
    # and the credential shape (D-056) and stored as the last derivation.
    provider_type: Mapped[str] = mapped_column(String(32))
    kind: Mapped[str] = mapped_column(String(16), default=IdentityKind.unknown)
    home: Mapped[str] = mapped_column(String(24), default=Home.this_directory)
    home_ref: Mapped[str | None] = mapped_column(String(255), default=None)
    origin: Mapped[str | None] = mapped_column(String(32), default=None)
    first_display_name: Mapped[str] = mapped_column(String(255))
    # A resurrected name mints a new identity; the provisional key is
    # the standing-in identifier until the provider's arrives (D-029).
    provisional: Mapped[bool] = mapped_column(default=False)
    provisional_key: Mapped[str | None] = mapped_column(
        String(255), default=None, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )


class IdentityObservation(Base):
    """What one import said about one identity that is not a credential
    or a grant: display name, activity, tags, and the provider's raw
    record as bounded JSON, so a later finding can be written without a
    migration."""

    __tablename__ = "identity_observations"
    __table_args__ = (UniqueConstraint("import_id", "identity_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    import_id: Mapped[int] = mapped_column(ForeignKey("imports.id"), index=True)
    identity_id: Mapped[int] = mapped_column(ForeignKey("identities.id"), index=True)
    display_name: Mapped[str] = mapped_column(String(255))
    provider_ref: Mapped[str | None] = mapped_column(String(2048), default=None)
    identity_created_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    mfa_active: Mapped[bool | None] = mapped_column(default=None)
    last_activity: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    last_activity_detail: Mapped[str | None] = mapped_column(String(64), default=None)
    tags: Mapped[dict[str, str] | None] = mapped_column(JSON, default=None)
    raw: Mapped[dict[str, object] | None] = mapped_column(JSON, default=None)


class Credential(Base):
    """One credential as one import saw it. Two keys are two rows."""

    __tablename__ = "credentials"

    id: Mapped[int] = mapped_column(primary_key=True)
    import_id: Mapped[int] = mapped_column(ForeignKey("imports.id"), index=True)
    identity_id: Mapped[int] = mapped_column(ForeignKey("identities.id"), index=True)
    kind: Mapped[str] = mapped_column(String(24))
    # The provider's own id for the credential where one exists; the
    # slot name (first, second) where the provider gives only that.
    external_id: Mapped[str | None] = mapped_column(String(255), default=None)
    active: Mapped[bool] = mapped_column(default=True)
    created_at_provider: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    last_rotated: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    last_used: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    last_used_service: Mapped[str | None] = mapped_column(String(64), default=None)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )


class RoleDefinition(Base):
    """What a grant grants, by the provider's stable id, versioned by
    the hash of its contents. A changed role is a new row."""

    __tablename__ = "role_definitions"
    __table_args__ = (UniqueConstraint("provider_id", "external_id", "contents_hash"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    provider_id: Mapped[int] = mapped_column(ForeignKey("providers.id"))
    external_id: Mapped[str] = mapped_column(String(2048))
    display_name_last: Mapped[str] = mapped_column(String(255))
    # provider or customer; custom roles are customer's.
    managed_by: Mapped[str] = mapped_column(String(16))
    version: Mapped[str | None] = mapped_column(String(64), default=None)
    contents_hash: Mapped[str] = mapped_column(String(64), index=True)
    contents: Mapped[dict[str, object] | None] = mapped_column(JSON, default=None)
    first_seen_import_id: Mapped[int] = mapped_column(ForeignKey("imports.id"))
    last_seen_import_id: Mapped[int] = mapped_column(ForeignKey("imports.id"))


class Grant(Base):
    """An identity holding a role definition at a scope, by a path, in
    a mode. One row per import per grant. The path is a JSON list of
    hops, each {via, ref, mode}; via is direct, membership, trust,
    delegation, or federation."""

    __tablename__ = "grants"

    id: Mapped[int] = mapped_column(primary_key=True)
    import_id: Mapped[int] = mapped_column(ForeignKey("imports.id"), index=True)
    identity_id: Mapped[int] = mapped_column(ForeignKey("identities.id"), index=True)
    role_definition_id: Mapped[int] = mapped_column(
        ForeignKey("role_definitions.id"), index=True
    )
    scope_node_id: Mapped[int] = mapped_column(ForeignKey("scope_nodes.id"))
    mode: Mapped[str] = mapped_column(String(16), default=GrantMode.standing)
    path: Mapped[list[dict[str, str]]] = mapped_column(JSON)
    # The provider's own record of the grant: attachment, inline_policy,
    # group_attachment, group_inline_policy, assignment, binding.
    source_kind: Mapped[str] = mapped_column(String(32))
    source_ref: Mapped[str | None] = mapped_column(String(2048), default=None)


class Membership(Base):
    """An identity's membership in a group identity, as one import saw
    it, with a mode (an eligible membership is PIM for Groups)."""

    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("import_id", "member_id", "group_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    import_id: Mapped[int] = mapped_column(ForeignKey("imports.id"), index=True)
    member_id: Mapped[int] = mapped_column(ForeignKey("identities.id"), index=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("identities.id"), index=True)
    mode: Mapped[str] = mapped_column(String(16), default="active")


class ObservedRelationship(Base):
    """A connection through which access arrives, as seen: a role's
    trust policy, a federation, a delegation. The authorized
    counterpart lives in authorize."""

    __tablename__ = "observed_relationships"

    id: Mapped[int] = mapped_column(primary_key=True)
    import_id: Mapped[int] = mapped_column(ForeignKey("imports.id"), index=True)
    # trust, federation, delegation, cross_tenant, group_nesting
    kind: Mapped[str] = mapped_column(String(24))
    # The identity the relationship grants into (a role with a trust
    # policy), and the principal or scope it grants from, as the
    # provider names it.
    to_identity_id: Mapped[int | None] = mapped_column(
        ForeignKey("identities.id"), default=None, index=True
    )
    from_ref: Mapped[str] = mapped_column(String(2048))
    from_kind: Mapped[str] = mapped_column(String(24))
    document: Mapped[dict[str, object] | None] = mapped_column(JSON, default=None)
