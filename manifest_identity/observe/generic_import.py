"""The observed side read through a mapping, for any provider.

AWS has parsers because AWS publishes exports. Most of an estate does
not: an on-premises directory, a database's own users, a vendor's
console with an export button and no schema. This door takes a table
from any of them through the same mapping mechanism the authorized
side has used since 1.3, with its own field set, and writes the same
neutral rows the AWS parsers write: identities, an observation per
identity, definitions, grants. The delta works on the result the same
day, and the provider earns a native parser later if it earns one at
all.

The rules are the file door's rules. A mapping names fields; the
columns are whatever the organization calls them. A dry run reads
everything and writes nothing. A refused row does not stop the file,
and every refusal comes back with its line. Every written row names
its batch, so which file and which mapping produced a record is a
query rather than a reconstruction.

What this door does not do: read privilege. A definition it writes has
no document, so the capability reading reports nothing about it, and a
grant through it is standing unless the row says otherwise. That is the
stated limit of an observation somebody typed rather than a provider
exported, and the page says so beside the source.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.core import audit
from manifest_identity.core.models import Partition, Provider, ScopeNode, User
from manifest_identity.core.scope import find_or_create_node
from manifest_identity.observe import mapping as tabular
from manifest_identity.observe.importer import (
    CaptureTimeInvalid,
    DuplicateSnapshot,
    contents_hash,
)
from manifest_identity.observe.models import (
    Grant,
    GrantMode,
    Identity,
    IdentityKind,
    IdentityObservation,
    Import,
    ImportBatch,
    ImportMapping,
    ProviderInstance,
    RoleDefinition,
)

SOURCE_KIND = "observed_grants"
IMPORT_SOURCE = "generic_observed"

# Every field this door can read. The mapping names these; their
# columns are whatever the organization already calls them.
FIELDS = frozenset({
    "provider",
    "account",
    "identity_external_id",
    "identity_display_name",
    "identity_type",
    "identity_kind",
    "role_definition_external_id",
    "role_definition_name",
    "mode",
    "path",
})

# Without these a row cannot say who holds what, where.
REQUIRED_FIELDS = frozenset({
    "provider",
    "account",
    "identity_external_id",
    "role_definition_external_id",
})

DATE_FIELDS: frozenset[str] = frozenset()

DEFAULT_MAPPING_NAME = "the shipped observed template"
DEFAULT_FIELDS: dict[str, dict[str, str | None]] = {
    "provider": {"column": "provider"},
    "account": {"column": "account"},
    "identity_external_id": {"column": "identity_id"},
    "identity_display_name": {"column": "identity_name"},
    "identity_type": {"column": "identity_type"},
    "identity_kind": {"column": "identity_kind"},
    "role_definition_external_id": {"column": "role"},
    "role_definition_name": {"column": "role_name"},
    "mode": {"column": "mode"},
    "path": {"column": "path"},
}

# The partition a provider's rows land under when the file does not say.
# A directory, a database, and a cluster are on premises unless a
# native parser learns otherwise; an identity service and the generic
# provider have no partition to name.
PARTITIONS = {
    Provider.aws: Partition.aws_commercial,
    Provider.azure: Partition.azure_commercial,
    Provider.gcp: Partition.gcp,
    Provider.github: Partition.github_com,
    Provider.kubernetes: Partition.none,
    Provider.active_directory: Partition.on_premises,
    Provider.database: Partition.on_premises,
    Provider.okta: Partition.none,
    Provider.saas: Partition.none,
    Provider.generic: Partition.none,
}


@dataclass
class RowOutcome:
    row: int
    identity_external_id: str
    role: str
    mode: str


@dataclass
class Result:
    refusals: list[tabular.RowRefusal] = field(default_factory=list)
    written: list[RowOutcome] = field(default_factory=list)
    ignored_columns: list[str] = field(default_factory=list)
    absent_fields: list[str] = field(default_factory=list)
    row_count: int = 0
    batch_id: int | None = None
    import_id: int | None = None


@dataclass
class Row:
    provider: Provider
    account: str
    identity_external_id: str
    identity_display_name: str
    identity_type: str
    identity_kind: str
    role_definition_external_id: str
    role_definition_name: str
    mode: str
    path: list[dict[str, str]]


def default_mapping(db: Session, actor_username: str = "system") -> ImportMapping:
    """The shipped mapping, created on first use the way the authorized
    side's is."""
    row = db.execute(
        select(ImportMapping).where(
            ImportMapping.source_kind == SOURCE_KIND,
            ImportMapping.name == DEFAULT_MAPPING_NAME,
        ).order_by(ImportMapping.version.desc())
    ).scalars().first()
    if row is None:
        row = ImportMapping(
            name=DEFAULT_MAPPING_NAME,
            source_kind=SOURCE_KIND,
            fields=dict(DEFAULT_FIELDS),
            created_by_username=actor_username,
        )
        db.add(row)
        db.flush()
    return row


def _specs(row: ImportMapping) -> dict[str, tabular.FieldSpec]:
    specs = tabular.parse_specs(row.fields)
    tabular.check_cover(specs, set(FIELDS), set(REQUIRED_FIELDS))
    return specs


def read(row: ImportMapping, data: bytes) -> tabular.Reading:
    specs = _specs(row)
    header, rows = tabular.read_table(data)
    return tabular.apply(specs, header, rows, set(DATE_FIELDS), set(REQUIRED_FIELDS))


def _rows(reading: tabular.Reading) -> tuple[list[tuple[int, Row]], list[tabular.RowRefusal]]:
    """Each read row becomes one typed row, or a refusal naming the
    line. The vocabulary is checked here: a provider or a kind this
    product does not know is refused rather than stored as a string
    that nothing will ever match."""
    rows: list[tuple[int, Row]] = []
    refusals = list(reading.refusals)
    for read_row in reading.rows:
        values = read_row.values
        try:
            provider = Provider(str(values.get("provider") or "").strip().lower())
        except ValueError:
            refusals.append(tabular.RowRefusal(
                row=read_row.row,
                reason="the provider is not one this product knows: "
                + ", ".join(p.value for p in Provider),
            ))
            continue
        kind_text = str(values.get("identity_kind") or "unknown").strip().lower()
        try:
            kind = IdentityKind(kind_text)
        except ValueError:
            refusals.append(tabular.RowRefusal(
                row=read_row.row,
                reason="the identity kind is not one this product knows: "
                + ", ".join(k.value for k in IdentityKind),
            ))
            continue
        mode_text = str(values.get("mode") or GrantMode.standing).strip().lower()
        try:
            mode = GrantMode(mode_text)
        except ValueError:
            refusals.append(tabular.RowRefusal(
                row=read_row.row,
                reason="the mode is standing, eligible, or session",
            ))
            continue
        try:
            path = tabular.parse_path(values.get("path"))
        except ValueError as exc:
            refusals.append(tabular.RowRefusal(row=read_row.row, reason=str(exc)))
            continue
        external_id = str(values.get("identity_external_id") or "").strip()
        role_ref = str(values.get("role_definition_external_id") or "").strip()
        account = str(values.get("account") or "").strip()
        if not external_id or not role_ref or not account:
            refusals.append(tabular.RowRefusal(
                row=read_row.row,
                reason="a row needs an identity, a role, and an account",
            ))
            continue
        rows.append((read_row.row, Row(
            provider=provider,
            account=account[:255],
            identity_external_id=external_id[:255],
            identity_display_name=str(values.get("identity_display_name") or external_id)[:255],
            identity_type=str(values.get("identity_type") or "user")[:32],
            identity_kind=kind.value,
            role_definition_external_id=role_ref[:2048],
            role_definition_name=str(values.get("role_definition_name") or role_ref)[:255],
            mode=mode.value,
            path=path,
        )))
    return rows, refusals


def dry_run(row: ImportMapping, data: bytes) -> Result:
    """Read the file, apply every check the write applies, and write
    nothing."""
    reading = read(row, data)
    rows, refusals = _rows(reading)
    result = Result(
        refusals=refusals,
        ignored_columns=reading.ignored_columns,
        absent_fields=reading.absent_fields,
        row_count=reading.row_count,
    )
    for number, typed in rows:
        result.written.append(RowOutcome(
            row=number,
            identity_external_id=typed.identity_external_id,
            role=typed.role_definition_external_id,
            mode=typed.mode,
        ))
    result.refusals.sort(key=lambda r: r.row)
    return result


def _scope_for(
    db: Session, provider: Provider, account: str
) -> tuple[ProviderInstance, ScopeNode]:
    """The provider's root node and the account node beneath it, made
    on first sight the way the AWS importer makes them."""
    partition = PARTITIONS.get(provider, Partition.none)
    root = find_or_create_node(
        db, provider, partition, "provider", provider.value, provider.value, None
    )
    node = find_or_create_node(db, provider, partition, "account", account, account, root)
    instance = db.execute(
        select(ProviderInstance).where(
            ProviderInstance.provider == provider.value,
            ProviderInstance.root_scope_node_id == root.id,
        )
    ).scalar_one_or_none()
    if instance is None:
        instance = ProviderInstance(
            provider=provider.value, display_name=provider.value, root_scope_node_id=root.id
        )
        db.add(instance)
        db.flush()
    return instance, node


def write(
    db: Session,
    row: ImportMapping,
    data: bytes,
    captured_at: datetime,
    actor: User,
    filename: str | None,
) -> Result:
    """Read it again and commit what passes. One file is one account's
    snapshot at one time, so every typed row must name the same
    provider and account; a file mixing two is refused whole, because a
    snapshot of two accounts is not a snapshot of either."""
    if captured_at.tzinfo is None:
        raise CaptureTimeInvalid("captured_at must carry a timezone")
    reading = read(row, data)
    rows, refusals = _rows(reading)
    result = Result(
        refusals=refusals,
        ignored_columns=reading.ignored_columns,
        absent_fields=reading.absent_fields,
        row_count=reading.row_count,
    )
    if not rows:
        return result
    scopes = {(typed.provider, typed.account) for _, typed in rows}
    if len(scopes) > 1:
        raise tabular.MappingError(
            "the file names more than one provider or account; one file is "
            "one account's snapshot"
        )
    provider, account = next(iter(scopes))
    instance, node = _scope_for(db, provider, account)
    if db.execute(
        select(Import).where(
            Import.scope_node_id == node.id,
            Import.source_kind == IMPORT_SOURCE,
            Import.captured_at == captured_at,
        )
    ).scalar_one_or_none() is not None:
        raise DuplicateSnapshot("this account, source, and capture time were already imported")

    batch = ImportBatch(
        source_kind=SOURCE_KIND,
        mapping_id=row.id,
        source_filename=filename,
        row_count=reading.row_count,
        ignored_columns=reading.ignored_columns,
        imported_by_username=actor.username,
    )
    db.add(batch)
    db.flush()
    snapshot = Import(
        provider_id=instance.id,
        scope_node_id=node.id,
        source_kind=IMPORT_SOURCE,
        captured_at=captured_at,
        imported_by_username=actor.username,
        source_filename=(filename or "")[:255] or None,
        row_count=reading.row_count,
        skipped_count=len(refusals),
    )
    db.add(snapshot)
    db.flush()
    result.batch_id = batch.id
    result.import_id = snapshot.id

    identities: dict[str, Identity] = {
        identity.external_id: identity
        for identity in db.execute(
            select(Identity).where(Identity.scope_node_id == node.id)
        ).scalars()
    }
    observed: set[int] = set()
    definitions: dict[tuple[str, str], RoleDefinition] = {}
    for number, typed in rows:
        identity = identities.get(typed.identity_external_id)
        if identity is None:
            identity = Identity(
                provider_id=instance.id,
                scope_node_id=node.id,
                external_id=typed.identity_external_id,
                provider_type=typed.identity_type,
                kind=typed.identity_kind,
                first_display_name=typed.identity_display_name,
                provisional=False,
            )
            db.add(identity)
            db.flush()
            identities[typed.identity_external_id] = identity
        if identity.id not in observed:
            observed.add(identity.id)
            db.add(IdentityObservation(
                import_id=snapshot.id,
                identity_id=identity.id,
                display_name=typed.identity_display_name,
                provider_ref=typed.identity_external_id,
            ))
        # A definition this door writes has no document, so its hash is
        # the hash of nothing and its contents stay empty; the reading
        # above says what that means.
        digest = contents_hash(None)
        key = (typed.role_definition_external_id, digest)
        definition = definitions.get(key)
        if definition is None:
            definition = db.execute(
                select(RoleDefinition).where(
                    RoleDefinition.provider_id == instance.id,
                    RoleDefinition.external_id == typed.role_definition_external_id,
                    RoleDefinition.contents_hash == digest,
                )
            ).scalar_one_or_none()
            if definition is None:
                definition = RoleDefinition(
                    provider_id=instance.id,
                    external_id=typed.role_definition_external_id,
                    display_name_last=typed.role_definition_name,
                    managed_by="customer",
                    contents_hash=digest,
                    contents=None,
                    first_seen_import_id=snapshot.id,
                    last_seen_import_id=snapshot.id,
                )
                db.add(definition)
                db.flush()
            else:
                definition.last_seen_import_id = snapshot.id
            definitions[key] = definition
        db.add(Grant(
            import_id=snapshot.id,
            identity_id=identity.id,
            role_definition_id=definition.id,
            scope_node_id=node.id,
            mode=typed.mode,
            path=typed.path,
            source_kind="mapped_row",
            source_ref=f"batch {batch.id} row {number}",
        ))
        result.written.append(RowOutcome(
            row=number,
            identity_external_id=typed.identity_external_id,
            role=typed.role_definition_external_id,
            mode=typed.mode,
        ))

    audit.record(
        db,
        actor_user_id=actor.id,
        actor_username=actor.username,
        action="snapshot_imported",
        target=f"{provider.value} {account}",
        detail=(
            f"source {IMPORT_SOURCE} through mapping {row.id}, captured "
            f"{captured_at.isoformat()}, {len(result.written)} grants, "
            f"{len(observed)} identities, {len(refusals)} refused"
        ),
    )
    result.refusals.sort(key=lambda r: r.row)
    return result
