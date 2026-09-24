"""The IAM credential report parser.

The first untrusted input surface, held to D-008: bounded on every
axis, parsed in memory, verified against its own claims, and no error
it raises ever repeats a value from the file. Field semantics were
verified against the provider's documentation at build time, August
18, 2026: booleans are TRUE and FALSE, absent values are N/A,
no_information, or not_supported, timestamps are ISO 8601, the first
row is the root account named <root_account>, and the content carries
neither a generation timestamp nor any immutable unique identifier,
which is why capture time is operator-attested and identity keys from
this file are provisional (D-029).
"""

import csv
import hashlib
import io
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_ROWS = 50_000
MAX_FIELD_CHARS = 2048

# The columns this parser requires; the provider may append new ones,
# which are tolerated and ignored by name.
REQUIRED_COLUMNS = (
    "user",
    "arn",
    "user_creation_time",
    "password_enabled",
    "password_last_used",
    "password_last_changed",
    "mfa_active",
    "access_key_1_active",
    "access_key_1_last_rotated",
    "access_key_1_last_used_date",
    "access_key_1_last_used_service",
    "access_key_2_active",
    "access_key_2_last_rotated",
    "access_key_2_last_used_date",
    "access_key_2_last_used_service",
    "cert_1_active",
    "cert_2_active",
)

ROOT_USER = "<root_account>"
_ABSENT = frozenset({"n/a", "no_information", "not_supported", ""})
_ARN_ACCOUNT = re.compile(r"^arn:[^:]*:iam::(\d{12}):")


class ParseError(ValueError):
    """File-level rejection. Messages state the rule that failed and a
    position, never a value from the file."""


@dataclass
class ParsedRow:
    display_name: str
    arn: str
    is_root: bool
    provisional_key: str
    identity_created_at: datetime | None
    password_enabled: bool | None
    password_last_used: datetime | None
    password_last_changed: datetime | None
    mfa_active: bool | None
    key1_active: bool | None
    key1_last_rotated: datetime | None
    key1_last_used: datetime | None
    key1_last_service: str | None
    key2_active: bool | None
    key2_last_rotated: datetime | None
    key2_last_used: datetime | None
    key2_last_service: str | None
    cert1_active: bool | None
    cert2_active: bool | None


@dataclass
class ParsedReport:
    account_id: str
    rows: list[ParsedRow] = field(default_factory=list)
    skipped: int = 0


def _parse_bool(raw: str) -> bool | None:
    lowered = raw.strip().lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered in _ABSENT:
        return None
    raise ValueError("not a boolean")


def _parse_time(raw: str) -> datetime | None:
    lowered = raw.strip().lower()
    if lowered in _ABSENT:
        return None
    parsed = datetime.fromisoformat(raw.strip())
    # A timestamp without a timezone cannot order history (D-008).
    if parsed.tzinfo is None:
        raise ValueError("timestamp lacks a timezone")
    return parsed.astimezone(UTC)


def provisional_key(arn: str, created: datetime | None) -> str:
    """The D-029 provisional identity key.

    Built from the only immutable content the file offers: the ARN
    paired with the creation time, which a recreated principal cannot
    reproduce. Opaque and fixed-length by hashing; upgraded to the
    provider's real identifier when a source that carries one arrives.
    """
    created_part = created.isoformat() if created else "unknown"
    digest = hashlib.sha256(f"{arn}|{created_part}".encode()).hexdigest()
    return f"cr:{digest[:32]}"


def parse_credential_report(data: bytes) -> ParsedReport:
    if len(data) > MAX_FILE_BYTES:
        raise ParseError("file exceeds the size bound")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ParseError("file is not valid UTF-8") from exc
    if text.startswith("﻿"):
        text = text[1:]

    reader = csv.reader(io.StringIO(text))
    try:
        header = next(reader)
    except StopIteration as exc:
        raise ParseError("file is empty") from exc
    except csv.Error as exc:
        raise ParseError("file is not parseable as CSV") from exc

    columns = {name.strip(): position for position, name in enumerate(header)}
    missing = [c for c in REQUIRED_COLUMNS if c not in columns]
    if missing:
        # Names our own contract, never content: the required column
        # names are this parser's, not the file's.
        raise ParseError(
            "header lacks required columns: " + ", ".join(sorted(missing))
        )

    report = ParsedReport(account_id="")
    row_number = 1
    try:
        for row in reader:
            row_number += 1
            if row_number - 1 > MAX_ROWS:
                raise ParseError("file exceeds the row bound")
            if not row or all(not cell.strip() for cell in row):
                continue
            if len(row) < len(header):
                report.skipped += 1
                continue
            if any(len(cell) > MAX_FIELD_CHARS for cell in row):
                report.skipped += 1
                continue

            def cell(name: str, row: list[str] = row) -> str:
                return row[columns[name]]

            arn = cell("arn").strip()
            account_match = _ARN_ACCOUNT.match(arn)
            if account_match is None:
                report.skipped += 1
                continue
            account = account_match.group(1)
            if report.account_id == "":
                report.account_id = account
            elif account != report.account_id:
                # One account per file is a claim the file must prove
                # (D-008); a second account is a whole-file rejection,
                # not a skip, because the claim itself failed.
                raise ParseError(
                    f"file mixes accounts (first difference at row {row_number})"
                )

            display_name = cell("user").strip()
            if not display_name:
                report.skipped += 1
                continue

            try:
                created = _parse_time(cell("user_creation_time"))
                parsed = ParsedRow(
                    display_name=display_name[:255],
                    arn=arn,
                    is_root=display_name == ROOT_USER,
                    provisional_key=provisional_key(arn, created),
                    identity_created_at=created,
                    password_enabled=_parse_bool(cell("password_enabled")),
                    password_last_used=_parse_time(cell("password_last_used")),
                    password_last_changed=_parse_time(cell("password_last_changed")),
                    mfa_active=_parse_bool(cell("mfa_active")),
                    key1_active=_parse_bool(cell("access_key_1_active")),
                    key1_last_rotated=_parse_time(cell("access_key_1_last_rotated")),
                    key1_last_used=_parse_time(cell("access_key_1_last_used_date")),
                    key1_last_service=_service(cell("access_key_1_last_used_service")),
                    key2_active=_parse_bool(cell("access_key_2_active")),
                    key2_last_rotated=_parse_time(cell("access_key_2_last_rotated")),
                    key2_last_used=_parse_time(cell("access_key_2_last_used_date")),
                    key2_last_service=_service(cell("access_key_2_last_used_service")),
                    cert1_active=_parse_bool(cell("cert_1_active")),
                    cert2_active=_parse_bool(cell("cert_2_active")),
                )
            except ValueError:
                report.skipped += 1
                continue
            report.rows.append(parsed)
    except csv.Error as exc:
        raise ParseError(
            f"file is not parseable as CSV (near row {row_number})"
        ) from exc

    if report.account_id == "" or not report.rows:
        raise ParseError("file contains no usable rows")
    return report


def _service(raw: str) -> str | None:
    lowered = raw.strip().lower()
    if lowered in _ABSENT:
        return None
    return raw.strip()[:64]
