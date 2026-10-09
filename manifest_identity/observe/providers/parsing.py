"""The readers every provider parser shares.

Each parser reads a file somebody else produced, so every value is
checked for type and size before it is used. These checks were once
copied into each parser and had begun to drift apart in wording and in
which limit applied; they live here so that a change to a bound lands
in every parser at once. A parser binds its own limits through
`Limits` and keeps only the readers its format needs alone.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime


class ParseError(ValueError):
    """File-level rejection; messages carry rules and names of our own
    contract, never values from the file."""


@dataclass(frozen=True)
class Limits:
    """The bounds one provider's format allows."""

    max_entries: int
    max_text: int

    def read_list(self, raw: object, where: str) -> list[object]:
        if raw is None:
            return []
        if not isinstance(raw, list):
            raise ParseError(f"{where}: must be a list")
        if len(raw) > self.max_entries:
            raise ParseError(f"{where}: more than {self.max_entries} entries")
        return raw

    def read_text(self, raw: object, where: str, default: str | None = None) -> str:
        if raw is None and default is not None:
            return default
        if not isinstance(raw, str) or not raw or len(raw) > self.max_text:
            raise ParseError(f"{where}: text is missing or longer than {self.max_text}")
        if any(ord(c) < 32 for c in raw):
            raise ParseError(f"{where}: text carries a control character")
        return raw


def read_record(raw: object, where: str) -> dict[str, object]:
    if not isinstance(raw, dict):
        raise ParseError(f"{where}: must be an object")
    return raw


def read_time(raw: object, where: str) -> datetime | None:
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise ParseError(f"{where}: a timestamp must be a string")
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ParseError(f"{where}: a timestamp is not ISO 8601") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def read_bool(raw: object, where: str, default: bool | None = None) -> bool | None:
    if raw is None:
        return default
    if not isinstance(raw, bool):
        raise ParseError(f"{where}: must be true or false")
    return raw


def read_choice(raw: object, allowed: frozenset[str], where: str, what: str) -> str:
    if not isinstance(raw, str) or raw not in allowed:
        raise ParseError(f"{where}: {what} is not one the format defines")
    return raw


def read_document(data: bytes, max_bytes: int) -> dict[str, object]:
    """The opening every JSON export parser shares: refuse a file past
    its size bound before parsing it, refuse what is not JSON, and
    refuse a document that is not an object."""
    if len(data) > max_bytes:
        raise ParseError(f"file exceeds {max_bytes} bytes")
    try:
        document = json.loads(data)
    except ValueError as exc:
        raise ParseError("file is not valid JSON") from exc
    if not isinstance(document, dict):
        raise ParseError("file must be a JSON object")
    return document
