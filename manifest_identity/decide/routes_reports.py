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

from manifest_identity.core import audit
from manifest_identity.core.db import get_session
from manifest_identity.core.deps import SteppedUp, require_roles
from manifest_identity.decide.reports import (
    evidence_to_csv,
    group_row,
    identity_row,
    rank,
    render_report,
    to_csv,
)
from manifest_identity.models import Campaign, CampaignItem, Import, utcnow
from manifest_identity.observe.assessment import assess_groups, assess_identities

router = APIRouter()


def _as_of(db: Session) -> str | None:
    newest = db.execute(select(func.max(Import.captured_at))).scalar()
    return newest.isoformat(timespec="seconds") if newest else None


def _disclosed(db: Session, auth: SteppedUp, target: str, detail: str) -> None:
    """Every export is a disclosure, and a disclosure leaves a record
    of who took what (D-089)."""
    audit.record(
        db, actor_user_id=auth.user.id, actor_username=auth.user.username,
        action="export", target=target, detail=detail,
    )
    db.commit()


@router.get("/export.csv", dependencies=[require_roles("GET /export.csv")])
def export_csv(db: Annotated[Session, Depends(get_session)], auth: SteppedUp) -> Response:
    rows = [identity_row(a) for a in assess_identities(db)]
    _disclosed(db, auth, "export.csv", f"{len(rows)} identities")
    return Response(
        content=to_csv(rows),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": 'attachment; filename="manifest-identity.csv"'
        },
    )


class ExportEnvelope(BaseModel):
    as_of: str | None
    identities: list[dict[str, object]]
    groups: list[dict[str, object]]


@router.get("/export.json", dependencies=[require_roles("GET /export.json")])
def export_json(
    db: Annotated[Session, Depends(get_session)], auth: SteppedUp,
) -> ExportEnvelope:
    envelope = ExportEnvelope(
        as_of=_as_of(db),
        identities=rank([identity_row(a) for a in assess_identities(db)]),
        groups=[group_row(g) for g in assess_groups(db)],
    )
    _disclosed(
        db, auth, "export.json",
        f"{len(envelope.identities)} identities, {len(envelope.groups)} groups",
    )
    return envelope


@router.get("/report.html", dependencies=[require_roles("GET /report.html")])
def report_html(db: Annotated[Session, Depends(get_session)], auth: SteppedUp) -> Response:
    identities = [identity_row(a) for a in assess_identities(db)]
    html = render_report(identities, [group_row(g) for g in assess_groups(db)], _as_of(db))
    _disclosed(db, auth, "report.html", f"{len(identities)} identities")
    return Response(
        content=html,
        media_type="text/html; charset=utf-8",
        headers={
            "Content-Disposition": (
                'attachment; filename="manifest-identity-report.html"'
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
    campaign_id: int, db: Annotated[Session, Depends(get_session)], auth: SteppedUp
) -> EvidenceExport:
    """The per-campaign evidence file: the population statement, the
    coverage, and every decision with its actor and time. This is what
    gets handed to whoever asks how the review was done."""
    _record_evidence(db, auth, campaign_id, "evidence")
    return _evidence(campaign_id, db)


def _record_evidence(db: Session, auth: SteppedUp, campaign_id: int, kind: str) -> None:
    """The export records itself before it reads the chain head, so the
    head the file carries includes its own disclosure."""
    if db.get(Campaign, campaign_id) is None:
        raise HTTPException(status_code=404, detail="no such campaign")
    total = db.scalar(
        select(func.count())
        .select_from(CampaignItem)
        .where(CampaignItem.campaign_id == campaign_id)
    )
    _disclosed(db, auth, f"campaign:{campaign_id}", f"{kind}, {total} items")


def _evidence(campaign_id: int, db: Session) -> EvidenceExport:
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
    campaign_id: int, db: Annotated[Session, Depends(get_session)], auth: SteppedUp
) -> Response:
    """The same evidence file for people who live in spreadsheets
    (issue 58): built from the JSON export, never a second read, so
    the two artifacts cannot disagree about the population or a
    decision."""
    _record_evidence(db, auth, campaign_id, "evidence csv")
    export = _evidence(campaign_id, db)
    return Response(
        content=evidence_to_csv(export.model_dump()),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": (
                f'attachment; filename="evidence-{campaign_id}.csv"'
            )
        },
    )
