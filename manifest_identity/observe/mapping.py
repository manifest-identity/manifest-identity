"""Reading a file that keeps its own shape (D-074).

This module holds the machinery both doors use: the bounded table
reader, the mapping applied to a row, and the refusals. It knows
nothing about authorizations or identities; the field names belong to
whichever part is reading, which is what lets the observed side join
at 1.11 without a second implementation.

Three rules carry most of the value.

Nothing is guessed. A mapping that does not cover a required field
refuses the file whole before a row is read, and a column nobody
mapped is ignored explicitly and counted, so an ignored column is a
number a person sees rather than a silence.

A date is parsed by a format the mapping declares. 03/04/2026 is the
third of April in one country and the fourth of March in another, and
a product whose record is about when access ends cannot pick one and
hope. A date column with no declared format is a refusal, not a guess.

Refusals name the row and the rule and repeat nothing the file said.
An error message that echoes a cell is a reflection surface, and the
person reading it is the operator.
"""

import csv
import io
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import UTC, datetime

MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_ROWS = 50_000
MAX_COLUMNS = 128
MAX_FIELD_CHARS = 2048
# The preview is a sample a person reads, not a second copy of the
# file; a hundred rows is more than anyone checks by eye.
PREVIEW_ROWS = 20


class MappingError(ValueError):
    """The file or the mapping is refused whole, before any row."""


@dataclass(frozen=True)
class FieldSpec:
    """Where one field's value comes from: a column in their file, or
    a constant for something their file does not carry."""

    column: str | None = None
    constant: str | None = None
    # A date field declares its format, in the strftime vocabulary.
    format: str | None = None


@dataclass
class RowRefusal:
    # One-based and counting the header, so the number matches what a
    # spreadsheet shows in its left margin.
    row: int
    reason: str


@dataclass
class ReadRow:
    """One row's values, carrying the number the spreadsheet shows, so
    a refusal further down the pipeline can still name the line."""

    row: int
    values: dict[str, str | None]


@dataclass
class Reading:
    """What a file became when read through a mapping, before anything
    is written. The dry run returns this; the write path uses the same
    object, so a person confirms exactly what lands."""

    rows: list[ReadRow] = dataclass_field(default_factory=list)
    refusals: list[RowRefusal] = dataclass_field(default_factory=list)
    ignored_columns: list[str] = dataclass_field(default_factory=list)
    # Optional fields whose column this file does not have. Reported
    # rather than refused, and reported rather than silent, because a
    # mapping with a misspelled column name looks exactly like a file
    # that legitimately omits it.
    absent_fields: list[str] = dataclass_field(default_factory=list)
    row_count: int = 0

    @property
    def preview(self) -> list[ReadRow]:
        return self.rows[:PREVIEW_ROWS]


def parse_specs(raw: dict[str, dict[str, str | None]]) -> dict[str, FieldSpec]:
    specs: dict[str, FieldSpec] = {}
    for name, body in raw.items():
        if not isinstance(body, dict):
            raise MappingError(f"the mapping for {name} is not a field definition")
        spec = FieldSpec(
            column=body.get("column"),
            constant=body.get("constant"),
            format=body.get("format"),
        )
        if spec.column and spec.constant is not None:
            raise MappingError(
                f"{name} names both a column and a constant; it takes one"
            )
        if not spec.column and spec.constant is None:
            raise MappingError(f"{name} names neither a column nor a constant")
        specs[name] = spec
    return specs


def check_cover(
    specs: dict[str, FieldSpec], known: set[str], required: set[str]
) -> None:
    """Refuse before reading: an unknown field means the mapping was
    written against a different door, and a missing required field
    means every row would fail the same way."""
    unknown = sorted(set(specs) - known)
    if unknown:
        raise MappingError(
            "the mapping names fields this import does not have: "
            + ", ".join(unknown)
        )
    missing = sorted(required - set(specs))
    if missing:
        raise MappingError(
            "the mapping does not cover every required field: " + ", ".join(missing)
        )


def read_table(data: bytes) -> tuple[list[str], list[list[str]]]:
    """The bounded read, in memory, in the style the two AWS parsers
    already hold to: every axis has a limit and a limit reached is a
    refusal of the whole file rather than a truncation nobody sees."""
    if len(data) > MAX_FILE_BYTES:
        raise MappingError("file exceeds the size bound")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise MappingError("file is not valid UTF-8") from exc
    try:
        reader = csv.reader(io.StringIO(text))
        header = next(reader)
    except StopIteration as exc:
        raise MappingError("file is empty") from exc
    except csv.Error as exc:
        raise MappingError("file is not parseable as CSV") from exc
    if len(header) > MAX_COLUMNS:
        raise MappingError("file exceeds the column bound")
    header = [cell.strip() for cell in header]
    if len(set(header)) != len(header):
        raise MappingError("file has two columns with the same name")
    rows: list[list[str]] = []
    try:
        for row in reader:
            if len(rows) + 1 > MAX_ROWS:
                raise MappingError("file exceeds the row bound")
            if any(len(cell) > MAX_FIELD_CHARS for cell in row):
                raise MappingError("file has a cell beyond the length bound")
            rows.append(row)
    except csv.Error as exc:
        raise MappingError("file is not parseable as CSV") from exc
    return header, rows


def parse_date(value: str, fmt: str | None) -> datetime:
    if not fmt:
        raise ValueError(
            "this column holds a date and the mapping declares no format for it"
        )
    try:
        parsed = datetime.strptime(value, fmt)
    except ValueError as exc:
        raise ValueError(f"a date did not match the declared format {fmt}") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def apply(
    specs: dict[str, FieldSpec],
    header: list[str],
    rows: list[list[str]],
    date_fields: set[str],
    required: set[str] | None = None,
) -> Reading:
    """Turn the file into one dictionary per row, refusing rows rather
    than files once the shape has been accepted. A row that cannot be
    read does not stop the ones after it, because a person fixing a
    spreadsheet wants every problem at once.

    A required field whose column the file lacks refuses the file: every
    row would fail the same way and a person should hear that once. An
    optional field whose column the file lacks is dropped and named in
    the reading, because a shipped mapping covers more columns than a
    small file carries, and refusing that would put us back to
    prescribing a schema."""
    required = required or set()
    present = set(header)
    missing_required = sorted(
        name for name, spec in specs.items()
        if name in required and spec.column and spec.column not in present
    )
    if missing_required:
        raise MappingError(
            "the file does not have the columns the mapping needs: "
            + ", ".join(
                sorted(
                    str(specs[name].column) for name in missing_required
                )
            )
        )
    absent = sorted(
        name for name, spec in specs.items()
        if spec.column and spec.column not in present
    )
    specs = {name: spec for name, spec in specs.items() if name not in absent}
    index = {name: position for position, name in enumerate(header)}
    mapped = {spec.column for spec in specs.values() if spec.column}
    reading = Reading(
        ignored_columns=[name for name in header if name not in mapped],
        absent_fields=absent,
        row_count=len(rows),
    )
    for offset, row in enumerate(rows):
        number = offset + 2  # the header is row one
        if not any(cell.strip() for cell in row):
            continue
        values: dict[str, str | None] = {}
        try:
            for name, spec in specs.items():
                if spec.column:
                    position = index[spec.column]
                    if position >= len(row):
                        raise ValueError(
                            f"the row has no cell for the column {spec.column}"
                        )
                    raw = row[position].strip()
                else:
                    raw = (spec.constant or "").strip()
                if raw and name in date_fields:
                    values[name] = parse_date(raw, spec.format).isoformat()
                else:
                    values[name] = raw or None
        except ValueError as exc:
            reading.refusals.append(RowRefusal(row=number, reason=str(exc)))
            continue
        reading.rows.append(ReadRow(row=number, values=values))
    return reading
