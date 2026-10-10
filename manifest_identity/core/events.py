"""Announcements one part makes for a part above it to answer.

A lower part says what happened, and a part above it decides what to do
about it, so the lower part never imports the higher one (D-096). An
authorization written or revoked is announced here, and decide answers
with the alert people must hear.

An announcement nothing answers is refused rather than dropped, because
a dropped one is an alert that silently never fired. Registering the
same listener twice, as reloading a module does, keeps one copy, so an
alert never fires twice.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from sqlalchemy.orm import Session


@dataclass(frozen=True)
class AuthorizationChange:
    """An authorization written or revoked, with what an alert needs."""

    kind: str
    authorization_id: int
    summary: str
    owners: tuple[str | None, str | None]


Listener = Callable[[Session, AuthorizationChange], None]
_listeners: dict[str, dict[str, Listener]] = {}


def listen(kind: str, listener: Listener) -> None:
    _listeners.setdefault(kind, {})[f"{listener.__module__}.{listener.__qualname__}"] = listener


def announce(db: Session, change: AuthorizationChange) -> None:
    listeners = _listeners.get(change.kind)
    if not listeners:
        raise RuntimeError(f"nothing listens for {change.kind}; the announcement would be lost")
    for listener in listeners.values():
        listener(db, change)
