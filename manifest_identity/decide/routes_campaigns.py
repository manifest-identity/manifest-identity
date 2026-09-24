"""Campaign routes: create, read, dispose one item at a time, close.

The population freezes at creation, every disposition is one item by
one person with the note where the disposition demands one, and close
refuses while any item is unanswered, because an access review that
skipped rows is not an access review with gaps, it is a population
statement that is false (D-039). Recurrence is a preset the next cycle
is created from by a person; nothing here creates work on its own.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.core import audit
from manifest_identity.core.db import get_session
from manifest_identity.core.deps import AuthContext, ThrottledWrite, require_roles, require_scope
from manifest_identity.decide.campaigns import (
    Recommendation,
    evidence_delta,
    recommend,
)
from manifest_identity.models import Campaign, CampaignItem, Identity, utcnow
from manifest_identity.observe.assessment import (
    AssessedGroup,
    AssessedIdentity,
    assess_groups,
    assess_identities,
)
from manifest_identity.observe.derive import MIN_OBSERVATION_DAYS

router = APIRouter()


class CreateCampaignRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    scope: Literal["everything", "privileged", "flagged", "users", "roles"]
    due_at: datetime
    recurrence: Literal["none", "monthly", "quarterly", "yearly"] = "none"


class DispositionRequest(BaseModel):
    disposition: Literal[
        "certify", "revoke_recommended", "insufficient_evidence", "delegated"
    ]
    note: str | None = Field(default=None, min_length=1, max_length=500)

    @model_validator(mode="after")
    def note_where_meaning_needs_it(self) -> DispositionRequest:
        if self.disposition == "insufficient_evidence" and self.note is None:
            raise ValueError(
                "insufficient evidence must name what was missing"
            )
        if self.disposition == "delegated" and self.note is None:
            raise ValueError("a delegation must name who holds it now")
        return self


class ItemView(BaseModel):
    id: int
    target_type: str
    target_id: int
    display_name: str
    recommendation: str
    recommendation_reasons: list[str]
    evidence: dict[str, object]
    delta: list[str]
    disposition: str | None
    disposition_note: str | None
    disposed_by: str | None
    disposed_at: str | None


class CampaignView(BaseModel):
    id: int
    name: str
    scope: str
    due_at: str
    recurrence: str
    created_by: str
    created_at: str
    closed_at: str | None
    closed_by: str | None
    total: int
    disposed: int
    by_disposition: dict[str, int]


class CampaignDetail(CampaignView):
    next_due: str | None
    items: list[ItemView]


class RollupEntry(BaseModel):
    campaign: str
    display_name: str
    target_type: str
    note: str
    disposed_by: str
    disposed_at: str


def _next_due(due_at: datetime, recurrence: str) -> datetime | None:
    """The suggested due date for the next cycle. A suggestion only:
    creating that cycle stays a human act."""
    steps = {"monthly": 31, "quarterly": 92, "yearly": 365}
    if recurrence not in steps:
        return None
    return due_at + timedelta(days=steps[recurrence])


def _finding_rows(findings: list[object]) -> list[dict[str, str]]:
    return [
        {"code": f.code, "tier": f.tier, "explanation": f.explanation}  # type: ignore[attr-defined]
        for f in findings
    ]


def _identity_evidence(a: AssessedIdentity) -> dict[str, object]:
    return {
        "finding_codes": sorted(f.code for f in a.findings),
        "findings": _finding_rows(list(a.findings)),
        "owner": a.owner.name if a.owner else None,
        "owner_type": a.owner.owner_type if a.owner else None,
        "privilege_sources": (
            [s.describe() for s in a.picture.sources] if a.picture else []
        ),
        "last_activity": (
            a.state.last_activity.isoformat()
            if a.state and a.state.last_activity
            else None
        ),
        "observed_days": a.state.observed_days if a.state else 0,
        "as_of": a.state.as_of.isoformat() if a.state else None,
    }


def _group_evidence(g: AssessedGroup) -> dict[str, object]:
    return {
        "finding_codes": sorted(f.code for f in g.findings),
        "findings": _finding_rows(list(g.findings)),
        "owner": g.owner.name if g.owner else None,
        "owner_type": g.owner.owner_type if g.owner else None,
        "privilege_sources": [],
        "members": g.members,
        "privileged": g.privileged,
    }


def _in_scope_identity(a: AssessedIdentity, scope: str) -> bool:
    if scope == "users":
        return a.identity.provider_type == "user"
    if scope == "roles":
        return a.identity.provider_type == "role"
    if scope == "privileged":
        return bool(a.picture and a.picture.combined.privileged)
    if scope == "flagged":
        return a.flagged
    return True


def _in_scope_group(g: AssessedGroup, scope: str) -> bool:
    if scope in ("users", "roles"):
        return False
    if scope == "privileged":
        return g.privileged
    if scope == "flagged":
        return g.flagged
    return True


def _counts(items: list[CampaignItem]) -> tuple[int, dict[str, int]]:
    by: dict[str, int] = {}
    disposed = 0
    for item in items:
        if item.disposition is not None:
            disposed += 1
            by[item.disposition] = by.get(item.disposition, 0) + 1
    return disposed, by


def _campaign_view(campaign: Campaign, items: list[CampaignItem]) -> CampaignView:
    disposed, by = _counts(items)
    return CampaignView(
        id=campaign.id,
        name=campaign.name,
        scope=campaign.scope,
        due_at=campaign.due_at.isoformat(timespec="seconds"),
        recurrence=campaign.recurrence,
        created_by=campaign.created_by,
        created_at=campaign.created_at.isoformat(timespec="seconds"),
        closed_at=(
            campaign.closed_at.isoformat(timespec="seconds")
            if campaign.closed_at
            else None
        ),
        closed_by=campaign.closed_by,
        total=len(items),
        disposed=disposed,
        by_disposition=by,
    )


def build_campaign(
    db: Session,
    *,
    name: str,
    scope: str,
    due_at: datetime,
    recurrence: str,
    created_by: str,
) -> tuple[Campaign, list[CampaignItem]]:
    """The campaign and its frozen population, one builder for every
    caller: the route and the demo command both create campaigns
    through this, so a scope means the same population everywhere."""
    campaign = Campaign(
        name=name,
        scope=scope,
        due_at=due_at,
        recurrence=recurrence,
        created_by=created_by,
    )
    db.add(campaign)
    db.flush()
    items: list[CampaignItem] = []
    for a in assess_identities(db):
        if not _in_scope_identity(a, scope):
            continue
        rec: Recommendation = recommend(
            a.findings, a.state.observed_days if a.state else 0
        )
        items.append(CampaignItem(
            campaign_id=campaign.id,
            target_type="identity",
            target_id=a.identity.id,
            display_name=a.identity.first_display_name,
            recommendation=rec.verdict,
            recommendation_reasons=rec.reasons,
            evidence=_identity_evidence(a),
        ))
    for g in assess_groups(db):
        if g.group_id is None or not _in_scope_group(g, scope):
            continue
        rec = recommend(g.findings, MIN_OBSERVATION_DAYS)
        items.append(CampaignItem(
            campaign_id=campaign.id,
            target_type="group",
            target_id=g.group_id,
            display_name=g.name,
            recommendation=rec.verdict,
            recommendation_reasons=rec.reasons,
            evidence=_group_evidence(g),
        ))
    return campaign, items


@router.post("/campaigns", status_code=201)
def create_campaign(
    body: CreateCampaignRequest,
    db: Annotated[Session, Depends(get_session)],
    auth: Annotated[AuthContext, require_roles("POST /campaigns")],
    _budget: ThrottledWrite,
) -> CampaignView:
    campaign, items = build_campaign(
        db,
        name=body.name,
        scope=body.scope,
        due_at=body.due_at,
        recurrence=body.recurrence,
        created_by=auth.user.username,
    )
    if not items:
        raise HTTPException(
            status_code=422,
            detail="the scope matches nothing; a campaign needs a population",
        )
    db.add_all(items)
    audit.record(
        db,
        actor_user_id=auth.user.id,
        actor_username=auth.user.username,
        action="campaign_created",
        target=f"campaign:{campaign.id}",
        detail=f"{body.name}: scope {body.scope}, {len(items)} item(s)",
    )
    db.commit()
    return _campaign_view(campaign, items)


@router.get("/campaigns", dependencies=[require_roles("GET /campaigns")])
def list_campaigns(
    db: Annotated[Session, Depends(get_session)],
) -> list[CampaignView]:
    campaigns = db.execute(
        select(Campaign).order_by(Campaign.created_at.desc(), Campaign.id.desc())
    ).scalars().all()
    items_by_campaign: dict[int, list[CampaignItem]] = {}
    for item in db.execute(select(CampaignItem)).scalars():
        items_by_campaign.setdefault(item.campaign_id, []).append(item)
    return [
        _campaign_view(c, items_by_campaign.get(c.id, [])) for c in campaigns
    ]


@router.get(
    "/campaigns/rollup", dependencies=[require_roles("GET /campaigns/rollup")]
)
def insufficient_evidence_rollup(
    db: Annotated[Session, Depends(get_session)],
) -> list[RollupEntry]:
    """Every insufficient-evidence answer across every campaign, with
    what was missing. One recurring line here is a reviewer's problem;
    the same line across a column is the program's problem."""
    rows = db.execute(
        select(CampaignItem, Campaign)
        .join(Campaign, CampaignItem.campaign_id == Campaign.id)
        .where(CampaignItem.disposition == "insufficient_evidence")
        .order_by(CampaignItem.disposed_at.desc())
    ).all()
    return [
        RollupEntry(
            campaign=campaign.name,
            display_name=item.display_name,
            target_type=item.target_type,
            note=item.disposition_note or "",
            disposed_by=item.disposed_by or "",
            disposed_at=(
                item.disposed_at.isoformat(timespec="seconds")
                if item.disposed_at
                else ""
            ),
        )
        for item, campaign in rows
    ]


def _last_certified_evidence(
    db: Session, item: CampaignItem
) -> dict[str, object] | None:
    previous = db.execute(
        select(CampaignItem)
        .where(
            CampaignItem.target_type == item.target_type,
            CampaignItem.target_id == item.target_id,
            CampaignItem.campaign_id != item.campaign_id,
            CampaignItem.disposition == "certify",
        )
        .order_by(CampaignItem.disposed_at.desc())
    ).scalars().first()
    return previous.evidence if previous is not None else None


@router.get(
    "/campaigns/{campaign_id}",
    dependencies=[require_roles("GET /campaigns/{campaign_id}")],
)
def campaign_detail(
    campaign_id: int, db: Annotated[Session, Depends(get_session)]
) -> CampaignDetail:
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
    base = _campaign_view(campaign, items)
    next_due = _next_due(campaign.due_at, campaign.recurrence)
    return CampaignDetail(
        **base.model_dump(),
        next_due=next_due.isoformat(timespec="seconds") if next_due else None,
        items=[
            ItemView(
                id=item.id,
                target_type=item.target_type,
                target_id=item.target_id,
                display_name=item.display_name,
                recommendation=item.recommendation,
                recommendation_reasons=list(item.recommendation_reasons or []),
                evidence=dict(item.evidence or {}),
                delta=evidence_delta(
                    _last_certified_evidence(db, item), item.evidence
                ),
                disposition=item.disposition,
                disposition_note=item.disposition_note,
                disposed_by=item.disposed_by,
                disposed_at=(
                    item.disposed_at.isoformat(timespec="seconds")
                    if item.disposed_at
                    else None
                ),
            )
            for item in items
        ],
    )


@router.post("/campaigns/{campaign_id}/items/{item_id}/disposition")
def dispose_item(
    campaign_id: int,
    item_id: int,
    body: DispositionRequest,
    db: Annotated[Session, Depends(get_session)],
    auth: Annotated[
        AuthContext,
        require_roles("POST /campaigns/{campaign_id}/items/{item_id}/disposition"),
    ],
) -> ItemView:
    campaign = db.get(Campaign, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="no such campaign")
    if campaign.closed_at is not None:
        raise HTTPException(
            status_code=409, detail="the campaign is closed"
        )
    item = db.get(CampaignItem, item_id)
    if item is None or item.campaign_id != campaign.id:
        raise HTTPException(status_code=404, detail="no such item")
    target = db.get(Identity, item.target_id)
    require_scope(
        db, auth, "POST /campaigns/{campaign_id}/items/{item_id}/disposition",
        target.scope_node_id if target else None,
    )
    if item.disposition is not None:
        raise HTTPException(
            status_code=409,
            detail=(
                "already decided; a review decision is not edited, and a "
                "changed mind is the next campaign's decision"
            ),
        )
    item.disposition = body.disposition
    item.disposition_note = body.note
    item.disposed_by = auth.user.username
    item.disposed_at = utcnow()
    audit.record(
        db,
        actor_user_id=auth.user.id,
        actor_username=auth.user.username,
        action="item_disposed",
        target=f"campaign:{campaign.id}/item:{item.id}",
        detail=f"{item.display_name}: {body.disposition}"
        + (f" ({body.note})" if body.note else ""),
    )
    db.commit()
    return ItemView(
        id=item.id,
        target_type=item.target_type,
        target_id=item.target_id,
        display_name=item.display_name,
        recommendation=item.recommendation,
        recommendation_reasons=list(item.recommendation_reasons or []),
        evidence=dict(item.evidence or {}),
        delta=[],
        disposition=item.disposition,
        disposition_note=item.disposition_note,
        disposed_by=item.disposed_by,
        disposed_at=(
            item.disposed_at.isoformat(timespec="seconds")
            if item.disposed_at
            else None
        ),
    )


@router.post("/campaigns/{campaign_id}/close")
def close_campaign(
    campaign_id: int,
    db: Annotated[Session, Depends(get_session)],
    auth: Annotated[AuthContext, require_roles("POST /campaigns/{campaign_id}/close")],
) -> CampaignView:
    campaign = db.get(Campaign, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="no such campaign")
    if campaign.closed_at is not None:
        raise HTTPException(status_code=409, detail="already closed")
    items = list(
        db.execute(
            select(CampaignItem).where(CampaignItem.campaign_id == campaign.id)
        ).scalars()
    )
    open_items = [i for i in items if i.disposition is None]
    if open_items:
        raise HTTPException(
            status_code=409,
            detail=(
                f"{len(open_items)} item(s) undecided; a campaign closes "
                "when every item is answered, because the population "
                "statement is the evidence"
            ),
        )
    campaign.closed_at = utcnow()
    campaign.closed_by = auth.user.username
    audit.record(
        db,
        actor_user_id=auth.user.id,
        actor_username=auth.user.username,
        action="campaign_closed",
        target=f"campaign:{campaign.id}",
        detail=f"{campaign.name}: {len(items)} item(s) decided",
    )
    db.commit()
    return _campaign_view(campaign, items)
