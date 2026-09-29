"""Telling people, and proving they were told.

An alert is a record of something people must hear: an authorization
written, an authorization revoked, an authorization entering its expiry
window, a revocation recommended by a review. Each delivery to each
recipient is its own record with its result, so "nobody told me" is
answerable either way: what fired, who it went to, by which channel,
and whether it arrived (threat 16).

Delivery sits behind one narrow interface. This release records and
does not send. The one deliverer here writes a structured log line and
reports that it did, which is enough to build and test the failure
paths and the per-recipient limits before any mail server is involved
(the product plan's open question on mail, deferred on purpose). When
sending arrives it is one class implementing the same interface, and
nothing that raises an alert changes.

Two rules hold whatever the deliverer. A delivery that fails is recorded
as failed and never breaks the action that raised the alert, because a
mail outage must not stop an authorization from being written. And the
alert row is written in the same transaction as the action, so a failed
action leaves no record claiming somebody was told.
"""

from __future__ import annotations

from typing import Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.core.logs import log_event
from manifest_identity.core.models import RoleBinding, User
from manifest_identity.core.roles import Role
from manifest_identity.decide.models import Alert, AlertDelivery

# What can fire. The vocabulary a page and a filter read back.
AUTHORIZATION_WRITTEN = "authorization_written"
AUTHORIZATION_REVOKED = "authorization_revoked"
EXPIRY_APPROACHING = "expiry_approaching"
REVOCATION_RECOMMENDED = "revocation_recommended"

EVENT_KINDS = (
    AUTHORIZATION_WRITTEN,
    AUTHORIZATION_REVOKED,
    EXPIRY_APPROACHING,
    REVOCATION_RECOMMENDED,
)

# How many recipients one alert reaches. A finding that fans out to
# hundreds of people has told nobody, and an unbounded list is how a
# delivery loop turns one event into an outage.
MAX_RECIPIENTS = 20

CHANNEL_RECORD = "record"

RESULT_RECORDED = "recorded"
RESULT_FAILED = "failed"


class Deliverer(Protocol):
    """The one interface delivery sits behind."""

    channel: str

    def deliver(self, alert: Alert, recipient: str) -> str:
        """Deliver one alert to one recipient. Returns a short detail
        string on success and raises on failure; the caller records
        either outcome and never lets the failure out."""


class RecordingDeliverer:
    """Records and does not send. The structured log line is the
    delivery, which makes the whole path observable before it reaches
    anyone's inbox."""

    channel = CHANNEL_RECORD

    def deliver(self, alert: Alert, recipient: str) -> str:
        # The log allowlist is a control and stays narrow, so the line
        # uses the fields it already permits: what fired as the source,
        # and the subject and recipient in the detail.
        log_event(
            "alert_recorded",
            source=alert.event_kind,
            detail=f"{alert.subject_kind}:{alert.subject_ref} to {recipient}",
        )
        return "written to the log"


_deliverer: Deliverer = RecordingDeliverer()


def set_deliverer(deliverer: Deliverer) -> None:
    """Swap the delivery implementation. Tests use it to plant a
    failure; a later release uses it to install a sender."""
    global _deliverer  # noqa: PLW0603
    _deliverer = deliverer


def administrators(db: Session) -> list[str]:
    """Every user holding an unrevoked administrator binding anywhere.
    Administrators hear everything, because they are the ones who can
    act on any of it."""
    rows = db.execute(
        select(User.username)
        .join(RoleBinding, RoleBinding.user_id == User.id)
        .where(
            RoleBinding.role == Role.administrator.value,
            RoleBinding.revoked_at.is_(None),
        )
        .distinct()
        .order_by(User.username)
    ).scalars()
    return list(rows)


def recipients_for(db: Session, *named: str | None) -> list[str]:
    """Administrators plus whoever the record names, deduplicated in
    order, bounded. An owner is a name the record carries and not
    necessarily a user here, so it is kept as written: the deliverer
    that sends mail is the one that resolves it to an address."""
    seen: list[str] = []
    for recipient in [*administrators(db), *named]:
        if recipient and recipient not in seen:
            seen.append(recipient)
    return seen[:MAX_RECIPIENTS]


def raise_alert(
    db: Session,
    *,
    event_kind: str,
    subject_kind: str,
    subject_ref: str,
    detail: str | None,
    recipients: list[str],
) -> Alert:
    """Write the alert and one delivery row per recipient, in the
    caller's transaction. The caller commits."""
    if event_kind not in EVENT_KINDS:
        raise ValueError(f"not an event kind: {event_kind}")
    alert = Alert(
        event_kind=event_kind,
        subject_kind=subject_kind,
        subject_ref=subject_ref[:255],
        detail=detail[:1000] if detail else None,
    )
    db.add(alert)
    db.flush()
    for recipient in recipients[:MAX_RECIPIENTS]:
        try:
            outcome = _deliverer.deliver(alert, recipient)
            result, note = RESULT_RECORDED, outcome
        except Exception as problem:  # noqa: BLE001  (every failure is a row, none escapes)
            result, note = RESULT_FAILED, f"{type(problem).__name__}: {problem}"[:500]
        db.add(AlertDelivery(
            alert_id=alert.id,
            recipient=recipient[:255],
            channel=_deliverer.channel,
            result=result,
            detail=note[:500] if note else None,
        ))
    return alert
