"""The file door into the authorization record (D-074).

A file becomes authorizations through exactly the code the form uses:
every row is turned into the same Request the form builds and passed
to the same `authorize`, so the required-field settings, the
person-owner rule, and the lifetime bound cannot differ by which door
a record came through. A value the form refuses is refused here, with
the row number attached.

Reading and writing are two routes. The dry run reads, reports, and
writes nothing; the write route reads the same way and then commits.
The importer is the attributed authorizer of every row that lands, so
confirming a dry run is putting your name on all of it.
"""

from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.authorize import authorizations, fields
from manifest_identity.authorize.models import EntryPath
from manifest_identity.core import audit
from manifest_identity.core.models import User
from manifest_identity.observe import mapping as tabular
from manifest_identity.observe.models import Identity, ImportBatch, ImportMapping

SOURCE_KIND = "authorizations"

# Every field this door can read. The mapping names these; their
# columns are whatever the organization already calls them.
FIELDS = frozenset({
    "identity_external_id",
    "role_definition_external_id",
    "role_definition_hash",
    "mode",
    "path",
    "owner_kind",
    "owner_ref",
    "secondary_owner_kind",
    "secondary_owner_ref",
    "justification",
    "reference",
    "control_reference",
    "valid_from",
    "valid_until",
})

# Without these a row cannot name what it authorizes or who owns it,
# so a mapping missing one refuses the file before a row is read. The
# organization's own required fields (justification and the rest) are
# enforced per row by `authorize`, because they are settings that can
# change between one import and the next.
REQUIRED_FIELDS = frozenset({
    "identity_external_id",
    "role_definition_external_id",
    "owner_kind",
    "owner_ref",
})

DATE_FIELDS = frozenset({"valid_from", "valid_until"})

# The shipped default lives in fields.py, a module with no imports,
# so the sample generator can read it without the database layer.
DEFAULT_MAPPING_NAME = fields.DEFAULT_MAPPING_NAME
DEFAULT_FIELDS = fields.DEFAULT_FIELDS


@dataclass
class RowOutcome:
    row: int
    identity_external_id: str
    role: str
    owner: str
    valid_until: str | None


@dataclass
class Result:
    """What a dry run says, and what a write did. The same shape both
    times on purpose: a person confirms a reading and gets back the
    reading they confirmed."""

    written: list[RowOutcome] = dataclass_field(default_factory=list)
    refusals: list[tabular.RowRefusal] = dataclass_field(default_factory=list)
    ignored_columns: list[str] = dataclass_field(default_factory=list)
    absent_fields: list[str] = dataclass_field(default_factory=list)
    row_count: int = 0
    batch_id: int | None = None


def default_mapping(db: Session, actor_username: str = "system") -> ImportMapping:
    """The shipped mapping for authorization files."""
    return tabular.shipped_mapping(
        db, SOURCE_KIND, DEFAULT_MAPPING_NAME, DEFAULT_FIELDS, actor_username
    )


def read(db: Session, row: ImportMapping, data: bytes) -> tabular.Reading:
    return tabular.read_mapped(row, data, FIELDS, REQUIRED_FIELDS, DATE_FIELDS)


def _requests(
    db: Session, reading: tabular.Reading
) -> tuple[list[tuple[int, authorizations.Request]], list[tabular.RowRefusal]]:
    """Every row becomes the same Request the form builds, or a
    refusal naming the row and the rule."""
    out: list[tuple[int, authorizations.Request]] = []
    refusals: list[tabular.RowRefusal] = list(reading.refusals)
    identities: dict[str, Identity] = {}
    for read_row in reading.rows:
        number, values = read_row.row, read_row.values
        external_id = values.get("identity_external_id") or ""
        identity = identities.get(external_id)
        if identity is None:
            found = db.execute(
                select(Identity).where(Identity.external_id == external_id)
            ).scalars().first()
            if found is None:
                refusals.append(tabular.RowRefusal(
                    row=number,
                    reason=(
                        "no identity in this system carries that identifier; "
                        "import the account before authorizing it"
                    ),
                ))
                continue
            identities[external_id] = found
            identity = found
        try:
            path = tabular.parse_path(values.get("path"))
        except ValueError as exc:
            refusals.append(tabular.RowRefusal(row=number, reason=str(exc)))
            continue
        out.append((number, authorizations.Request(
            identity_id=identity.id,
            scope_node_id=identity.scope_node_id,
            role_definition_external_id=values.get("role_definition_external_id") or "",
            role_definition_hash=values.get("role_definition_hash"),
            mode=values.get("mode") or "standing",
            path=path,
            owner_kind=values.get("owner_kind") or "",
            owner_ref=values.get("owner_ref") or "",
            secondary_owner_kind=values.get("secondary_owner_kind"),
            secondary_owner_ref=values.get("secondary_owner_ref"),
            justification=values.get("justification"),
            reference=values.get("reference"),
            control_reference=values.get("control_reference"),
            valid_from=_moment(values.get("valid_from")),
            valid_until=_moment(values.get("valid_until")),
            entry_path=EntryPath.csv,
        )))
    return out, refusals


def _moment(text: str | None) -> datetime | None:
    return datetime.fromisoformat(text) if text else None


def dry_run(db: Session, row: ImportMapping, data: bytes) -> Result:
    """Read the file, apply every check the write path applies, and
    write nothing. The session is rolled back rather than trusted to
    be clean, because `authorize` adds rows to make its checks."""
    reading = read(db, row, data)
    requests, refusals = _requests(db, reading)
    result = Result(
        refusals=refusals,
        ignored_columns=reading.ignored_columns,
        absent_fields=reading.absent_fields,
        row_count=reading.row_count,
    )
    for number, request in requests:
        try:
            authorizations.check_only(db, request)
        except authorizations.AuthorizationError as exc:
            result.refusals.append(tabular.RowRefusal(row=number, reason=str(exc)))
            continue
        result.written.append(RowOutcome(
            row=number,
            identity_external_id=_external_id(db, request.identity_id),
            role=request.role_definition_external_id,
            owner=request.owner_ref,
            valid_until=request.valid_until.isoformat() if request.valid_until else None,
        ))
    result.refusals.sort(key=lambda r: r.row)
    return result


def _external_id(db: Session, identity_id: int) -> str:
    identity = db.get(Identity, identity_id)
    return identity.external_id if identity else ""


def write(
    db: Session,
    row: ImportMapping,
    data: bytes,
    actor: User,
    filename: str | None,
) -> Result:
    """Read it again and commit what passes. A refused row does not
    stop the file: the record is better with the rows that were right
    than with none of them, and every refusal comes back named."""
    reading = read(db, row, data)
    requests, refusals = _requests(db, reading)
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
    result = Result(
        refusals=refusals,
        ignored_columns=reading.ignored_columns,
        absent_fields=reading.absent_fields,
        row_count=reading.row_count,
        batch_id=batch.id,
    )
    for number, request in requests:
        try:
            written = authorizations.authorize(db, request, actor)
        except authorizations.AuthorizationError as exc:
            result.refusals.append(tabular.RowRefusal(row=number, reason=str(exc)))
            continue
        written.batch_id = batch.id
        result.written.append(RowOutcome(
            row=number,
            identity_external_id=_external_id(db, request.identity_id),
            role=request.role_definition_external_id,
            owner=request.owner_ref,
            valid_until=(
                written.valid_until.isoformat() if written.valid_until else None
            ),
        ))
    batch.written_count = len(result.written)
    batch.refused_count = len(result.refusals)
    audit.record(
        db,
        actor_user_id=actor.id,
        actor_username=actor.username,
        action="authorizations_imported",
        target=f"batch:{batch.id}",
        detail=(
            f"mapping {row.name} version {row.version}: "
            f"{batch.written_count} written, {batch.refused_count} refused"
        ),
    )
    result.refusals.sort(key=lambda r: r.row)
    return result
