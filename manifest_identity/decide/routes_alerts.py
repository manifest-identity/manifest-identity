"""The alerts a page shows: what fired, who it went to, and whether it
arrived, newest first."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.core.db import get_session
from manifest_identity.core.deps import require_roles
from manifest_identity.decide.models import Alert, AlertDelivery

router = APIRouter(tags=["alerts"])


class DeliveryView(BaseModel):
    recipient: str
    channel: str
    attempted_at: str
    result: str
    detail: str | None


class AlertView(BaseModel):
    id: int
    event_kind: str
    subject_kind: str
    subject_ref: str
    detail: str | None
    created_at: str
    deliveries: list[DeliveryView]


@router.get("/alerts", dependencies=[require_roles("GET /alerts")])
def list_alerts(
    db: Annotated[Session, Depends(get_session)],
    limit: int = 200,
) -> list[AlertView]:
    """Newest first, bounded, each with every delivery it produced."""
    limit = max(1, min(limit, 1000))
    alerts = db.execute(
        select(Alert).order_by(Alert.created_at.desc(), Alert.id.desc()).limit(limit)
    ).scalars().all()
    ids = [alert.id for alert in alerts]
    deliveries: dict[int, list[AlertDelivery]] = {}
    if ids:
        for row in db.execute(
            select(AlertDelivery)
            .where(AlertDelivery.alert_id.in_(ids))
            .order_by(AlertDelivery.id)
        ).scalars():
            deliveries.setdefault(row.alert_id, []).append(row)
    return [
        AlertView(
            id=alert.id,
            event_kind=alert.event_kind,
            subject_kind=alert.subject_kind,
            subject_ref=alert.subject_ref,
            detail=alert.detail,
            created_at=alert.created_at.isoformat(timespec="seconds"),
            deliveries=[
                DeliveryView(
                    recipient=d.recipient,
                    channel=d.channel,
                    attempted_at=d.attempted_at.isoformat(timespec="seconds"),
                    result=d.result,
                    detail=d.detail,
                )
                for d in deliveries.get(alert.id, [])
            ],
        )
        for alert in alerts
    ]
