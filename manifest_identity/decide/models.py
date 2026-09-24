"""decide's tables: campaigns and their decisions, alerts and their
deliveries.

A campaign freezes a population into items at creation; one item,
one decision; no bulk operation anywhere (D-039). A decision writes
intent through authorize and never touches a cloud (D-024). An alert
is a record, and each delivery to each recipient is a record, so
"who was told, and did it arrive" is answerable (threat 16).
"""

from datetime import datetime
from enum import StrEnum

from sqlalchemy import JSON, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from manifest_identity.core.db import Base
from manifest_identity.core.models import utcnow


class CampaignTrigger(StrEnum):
    manual = "manual"
    expiry = "expiry"
    delta = "delta"


class Campaign(Base):
    __tablename__ = "campaigns"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    # The population statement, frozen into items at creation:
    # everything, privileged, flagged, or one identity type.
    scope: Mapped[str] = mapped_column(String(32))
    trigger: Mapped[str] = mapped_column(String(16), default=CampaignTrigger.manual)
    scope_node_id: Mapped[int | None] = mapped_column(
        ForeignKey("scope_nodes.id"), default=None
    )
    due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # none | monthly | quarterly | yearly; a preset the next cycle is
    # created from, never an automatic creation (people decide).
    recurrence: Mapped[str] = mapped_column(String(16), default="none")
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    closed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    closed_by: Mapped[str | None] = mapped_column(String(64), default=None)


class CampaignItem(Base):
    """One identity or group inside one campaign, carrying the evidence
    as it stood at creation and exactly one human disposition."""

    __tablename__ = "campaign_items"
    __table_args__ = (UniqueConstraint("campaign_id", "target_type", "target_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey("campaigns.id"), index=True)
    target_type: Mapped[str] = mapped_column(String(16))
    target_id: Mapped[int] = mapped_column()
    display_name: Mapped[str] = mapped_column(String(255))
    recommendation: Mapped[str] = mapped_column(String(32))
    recommendation_reasons: Mapped[list[str] | None] = mapped_column(
        JSON, default=None
    )
    evidence: Mapped[dict[str, object] | None] = mapped_column(JSON, default=None)
    # The authorization or delta finding the item came from, when the
    # trigger was expiry or delta.
    origin_kind: Mapped[str | None] = mapped_column(String(24), default=None)
    origin_ref: Mapped[str | None] = mapped_column(String(255), default=None)
    # certify | revoke_recommended | insufficient_evidence | delegated
    disposition: Mapped[str | None] = mapped_column(String(32), default=None)
    disposition_note: Mapped[str | None] = mapped_column(String(500), default=None)
    disposed_by: Mapped[str | None] = mapped_column(String(64), default=None)
    disposed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )


class Alert(Base):
    """Something people or automations must hear: an approval, a
    revocation, an expiry."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    event_kind: Mapped[str] = mapped_column(String(32))
    subject_kind: Mapped[str] = mapped_column(String(24))
    subject_ref: Mapped[str] = mapped_column(String(255))
    detail: Mapped[str | None] = mapped_column(String(1000), default=None)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )


class AlertDelivery(Base):
    """One attempt to deliver one alert to one recipient by one
    channel, with its result."""

    __tablename__ = "alert_deliveries"

    id: Mapped[int] = mapped_column(primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), index=True)
    recipient: Mapped[str] = mapped_column(String(255))
    channel: Mapped[str] = mapped_column(String(16))
    attempted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    result: Mapped[str] = mapped_column(String(32))
    detail: Mapped[str | None] = mapped_column(String(500), default=None)
