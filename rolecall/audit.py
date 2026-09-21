"""The audit spine.

record() adds a row to the caller's open transaction and never commits:
the action and its audit line share one transaction, so neither can
exist without the other. A caller that forgets to commit loses both,
which is the correct failure.

Each row is chained to the one before it (issue 39): row_hash is the
SHA-256 of the row's own content and prev_hash, so altering or
removing any row breaks every hash after it. verify() walks the chain
and names the first row that does not match. The chain head travels
in the campaign evidence exports, which is what makes tampering
detectable by someone who does not trust the database: a chain nobody
anchors outside the store only catches casual tampering.

Never pass secret material in any field. The attempted username on a
failed login is stored capped at the column length; the audit table is
readable only through administrator surfaces.
"""

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from rolecall.models import AuditEvent, utcnow

GENESIS = "0" * 64


def row_digest(
    prev_hash: str, at: str, actor_user_id: int | None, actor_username: str,
    action: str, target: str | None, detail: str | None, ip: str | None,
) -> str:
    """The hash of one row: every stored field in a fixed order, each
    separated so a value cannot slide into its neighbour's slot, over
    the previous row's hash."""
    parts = [prev_hash, at, "" if actor_user_id is None else str(actor_user_id),
             actor_username, action, target or "", detail or "", ip or ""]
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()


def _stamp(at: datetime) -> str:
    """The timestamp as the hash sees it: UTC, whole seconds, fixed
    form. A store that drops the timezone or the microseconds on the
    way back, as SQLite does, must still reproduce the same digest."""
    if at.tzinfo is None:
        at = at.replace(tzinfo=UTC)
    return at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _digest_of(row: AuditEvent, prev_hash: str) -> str:
    return row_digest(
        prev_hash, _stamp(row.at), row.actor_user_id,
        row.actor_username, row.action, row.target, row.detail, row.ip,
    )


def chain_head(db: Session) -> str:
    """The newest row's hash, or the genesis value for an empty trail."""
    last = db.execute(
        select(AuditEvent.row_hash).order_by(AuditEvent.id.desc()).limit(1)
    ).scalar_one_or_none()
    return last or GENESIS


def record(
    db: Session,
    *,
    actor_username: str,
    action: str,
    actor_user_id: int | None = None,
    target: str | None = None,
    detail: str | None = None,
    ip: str | None = None,
) -> None:
    event = AuditEvent(
        actor_user_id=actor_user_id,
        actor_username=actor_username[:64],
        action=action,
        target=target[:255] if target else None,
        detail=detail[:1000] if detail else None,
        ip=ip[:64] if ip else None,
    )
    # The timestamp is fixed here rather than at flush, so the hash
    # covers the value the row will actually carry.
    event.at = utcnow().replace(microsecond=0)
    event.prev_hash = chain_head(db)
    event.row_hash = _digest_of(event, event.prev_hash)
    db.add(event)
    # Flush so the next record() in the same transaction sees this
    # row as the head; otherwise two writes in one transaction would
    # both chain to the same predecessor.
    db.flush()


@dataclass
class Verification:
    rows: int
    ok: bool
    first_bad_id: int | None
    head: str


def verify(db: Session) -> Verification:
    """Walk the whole trail in id order and recompute every hash. Rows
    written before chaining existed carry no hash and are reported as
    the trail's unchained prefix rather than as tampering."""
    prev = GENESIS
    rows = 0
    for row in db.execute(select(AuditEvent).order_by(AuditEvent.id)).scalars():
        rows += 1
        if row.row_hash is None:
            continue  # pre-chain row; the chain starts at the first hashed row
        if row.prev_hash != prev or _digest_of(row, row.prev_hash) != row.row_hash:
            return Verification(rows=rows, ok=False, first_bad_id=row.id, head=prev)
        prev = row.row_hash
    return Verification(rows=rows, ok=True, first_bad_id=None, head=prev)
