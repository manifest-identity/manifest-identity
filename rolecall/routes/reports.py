"""Report and export routes: the three artifacts, plus campaign evidence.

Every route here is a read over the shared assessment or the campaign
tables; nothing is a second computation of a figure shown elsewhere.
The CSV and the report download as files; the JSON exports return as
responses a client parses.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from rolecall import audit
from rolecall.assessment import assess_groups, assess_identities
from rolecall.db import get_session
from rolecall.deps import require_roles
from rolecall.models import Campaign, CampaignItem, Snapshot, utcnow
from rolecall.reports import (
    evidence_to_csv,
    group_row,
    identity_row,
    rank,
    render_report,
    to_csv,
)

router = APIRouter()


def _as_of(db: Session) -> str | None:
    newest = db.execute(select(func.max(Snapshot.captured_at))).scalar()
    return newest.isoformat(timespec="seconds") if newest else None


@router.get("/export.csv", dependencies=[require_roles("GET /export.csv")])
def export_csv(db: Annotated[Session, Depends(get_session)]) -> Response:
    rows = [identity_row(a) for a in assess_identities(db)]
    return Response(
        content=to_csv(rows),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": 'attachment; filename="role-call.csv"'
        },
    )


class ExportEnvelope(BaseModel):
    as_of: str | None
    identities: list[dict[str, object]]
    groups: list[dict[str, object]]


@router.get("/export.json", dependencies=[require_roles("GET /export.json")])
def export_json(
    db: Annotated[Session, Depends(get_session)],
) -> ExportEnvelope:
    return ExportEnvelope(
        as_of=_as_of(db),
        identities=rank([identity_row(a) for a in assess_identities(db)]),
        groups=[group_row(g) for g in assess_groups(db)],
    )


@router.get("/report.html", dependencies=[require_roles("GET /report.html")])
def report_html(db: Annotated[Session, Depends(get_session)]) -> Response:
    html = render_report(
        [identity_row(a) for a in assess_identities(db)],
        [group_row(g) for g in assess_groups(db)],
        _as_of(db),
    )
    return Response(
        content=html,
        media_type="text/html; charset=utf-8",
        headers={
            "Content-Disposition": (
                'attachment; filename="role-call-report.html"'
            )
        },
    )


class EvidenceDecision(BaseModel):
    display_name: str
    target_type: str
    recommendation: str
    recommendation_reasons: list[str]
    evidence: dict[str, object]
    disposition: str | None
    disposition_note: str | None
    disposed_by: str | None
    disposed_at: str | None


class EvidenceExport(BaseModel):
    campaign: str
    scope: str
    population_statement: str
    created_by: str
    created_at: str
    due_at: str
    closed_at: str | None
    closed_by: str | None
    total: int
    decided: int
    coverage: str
    exported_at: str
    # The audit trail's chain head at export time (issue 39). A copy of
    # this file held outside the database anchors the trail: every row
    # up to this head is bound to it, so a later alteration of history
    # is detectable by anyone holding the export.
    audit_chain_head: str
    decisions: list[EvidenceDecision]


@router.get(
    "/campaigns/{campaign_id}/evidence",
    dependencies=[require_roles("GET /campaigns/{campaign_id}/evidence")],
)
def campaign_evidence(
    campaign_id: int, db: Annotated[Session, Depends(get_session)]
) -> EvidenceExport:
    """The per-campaign evidence file: the population statement, the
    coverage, and every decision with its actor and time. This is what
    gets handed to whoever asks how the review was done."""
    campaign = db.get(Campaign, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="no such campaign")
    items = list(
        db.execute(
            select(CampaignItem)
            .where(CampaignItem.campaign_id == campaign.id)
            .order_by(CampaignItem.display_name, CampaignItem.id)
        ).scalars()
    )
    decided = sum(1 for i in items if i.disposition is not None)
    return EvidenceExport(
        campaign=campaign.name,
        scope=campaign.scope,
        population_statement=(
            f"every target matching scope '{campaign.scope}' at "
            f"{campaign.created_at.isoformat(timespec='seconds')}, frozen "
            f"at creation: {len(items)} item(s)"
        ),
        created_by=campaign.created_by,
        created_at=campaign.created_at.isoformat(timespec="seconds"),
        due_at=campaign.due_at.isoformat(timespec="seconds"),
        closed_at=(
            campaign.closed_at.isoformat(timespec="seconds")
            if campaign.closed_at
            else None
        ),
        closed_by=campaign.closed_by,
        total=len(items),
        decided=decided,
        coverage=f"{decided} of {len(items)}",
        exported_at=utcnow().isoformat(timespec="seconds"),
        audit_chain_head=audit.chain_head(db),
        decisions=[
            EvidenceDecision(
                display_name=i.display_name,
                target_type=i.target_type,
                recommendation=i.recommendation,
                recommendation_reasons=list(i.recommendation_reasons or []),
                evidence=dict(i.evidence or {}),
                disposition=i.disposition,
                disposition_note=i.disposition_note,
                disposed_by=i.disposed_by,
                disposed_at=(
                    i.disposed_at.isoformat(timespec="seconds")
                    if i.disposed_at
                    else None
                ),
            )
            for i in items
        ],
    )


@router.get(
    "/campaigns/{campaign_id}/evidence.csv",
    dependencies=[require_roles("GET /campaigns/{campaign_id}/evidence.csv")],
)
def campaign_evidence_csv(
    campaign_id: int, db: Annotated[Session, Depends(get_session)]
) -> Response:
    """The same evidence file for people who live in spreadsheets
    (issue 58): built from the JSON export, never a second read, so
    the two artifacts cannot disagree about the population or a
    decision."""
    export = campaign_evidence(campaign_id, db)
    return Response(
        content=evidence_to_csv(export.model_dump()),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": (
                f'attachment; filename="evidence-{campaign_id}.csv"'
            )
        },
    )
