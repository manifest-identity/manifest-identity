"""The identity inventory, now with derived state and findings.

Everything here is computed at read from observations (D-006): the list
carries tier counts per identity, and the detail route walks the
observation timeline with every finding explaining itself. The as-of
time is the account's newest snapshot capture, never the wall clock.
"""

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from manifest_identity.assessment import (
    AssessedIdentity,
    assess_groups,
    assess_identities,
    observation_pairs,
    privilege_context,
)
from manifest_identity.db import get_session
from manifest_identity.deps import require_roles
from manifest_identity.derive import classify, derive
from manifest_identity.findings import evaluate
from manifest_identity.governance import (
    active_records,
    apply_owner_governance,
    record_history,
    resolve_owner,
)
from manifest_identity.models import Account, Identity, Snapshot
from manifest_identity.privilege import evaluate_privilege, read_identity_privilege
from manifest_identity.routes.governance import RecordView, record_view

router = APIRouter()


class IdentityView(BaseModel):
    id: int
    account: str
    display_name: str
    identity_type: str
    provisional: bool
    observations: int
    name_reused: bool
    flagged: bool
    owner: str | None
    kind: str
    critical: int
    warning: int
    notice: int
    # The highest-tier finding's own explanation, one line, so the
    # list page teaches before a click; None when the identity is
    # quiet (issue 57).
    top_finding: str | None


class FindingView(BaseModel):
    code: str
    tier: str
    anchor: str
    explanation: str


class ObservationView(BaseModel):
    captured_at: str
    source: str
    fields_present: int


class IdentityDetail(BaseModel):
    id: int
    account: str
    display_name: str
    identity_type: str
    provisional: bool
    name_reused: bool
    as_of: str
    observed_days: int
    last_activity: str | None
    owner: str | None
    owner_type: str | None
    owner_source: str | None
    kind: str
    kind_reason: str
    privilege_sources: list[str]
    findings: list[FindingView]
    governance: list[RecordView]
    timeline: list[ObservationView]


class InventoryTiles(BaseModel):
    """Account-wide counts by an identity's worst tier, independent of
    any filter, so the dashboard reads the same on every page."""

    identities: int
    critical: int
    warning: int
    notice: int
    quiet: int


class InventoryPage(BaseModel):
    tiles: InventoryTiles
    matched: int
    offset: int
    limit: int
    rows: list[IdentityView]


def _worst_tier(tiers: dict[str, int]) -> str:
    for tier in ("critical", "warning", "notice"):
        if tiers[tier]:
            return tier
    return "quiet"


def _top_finding(assessed: AssessedIdentity) -> str | None:
    # The first finding at the worst tier, in the engine's own order;
    # one line by contract, so the list payload stays bounded.
    for tier in ("critical", "warning", "notice"):
        for finding in assessed.findings:
            if finding.tier == tier:
                return finding.explanation
    return None


@router.get("/identities", dependencies=[require_roles("GET /identities")])
def list_identities(
    db: Annotated[Session, Depends(get_session)],
    q: Annotated[str | None, Query(max_length=255)] = None,
    identity_type: Annotated[
        str | None, Query(alias="type", max_length=16)
    ] = None,
    tier: Literal["critical", "warning", "notice", "quiet"] | None = None,
    kind: Literal["person", "service", "mixed", "unknown"] | None = None,
    sort: Literal[
        "name", "type", "account", "kind", "critical", "warning", "notice"
    ] | None = None,
    direction: Literal["asc", "desc"] = "asc",
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> InventoryPage:
    """A page of the inventory, bounded at any account size (issue 38).

    State stays derived at read (D-006), so the assessment pass still
    covers the account; what is bounded is what leaves it: filters
    apply here rather than in the browser, at most one page of rows is
    built and serialized, and the tiles come from the per-identity
    tier counts the pass already holds, never from materialized rows.
    Sorting also happens here, over the whole matched set before the
    page is cut, because a page that sorts only itself would claim an
    order the account does not have.
    """
    assessed = assess_identities(db)
    tier_by_id = {a.identity.id: _worst_tier(a.tier_counts()) for a in assessed}
    kind_by_id = {
        a.identity.id: (classify(a.state).kind if a.state else "unknown")
        for a in assessed
    }
    tiles = InventoryTiles(
        identities=len(assessed),
        critical=sum(1 for t in tier_by_id.values() if t == "critical"),
        warning=sum(1 for t in tier_by_id.values() if t == "warning"),
        notice=sum(1 for t in tier_by_id.values() if t == "notice"),
        quiet=sum(1 for t in tier_by_id.values() if t == "quiet"),
    )
    needle = q.lower() if q else None
    matched = [
        a for a in assessed
        if (needle is None or needle in a.identity.first_display_name.lower())
        and (identity_type is None or a.identity.identity_type == identity_type)
        and (tier is None or tier_by_id[a.identity.id] == tier)
        and (kind is None or kind_by_id[a.identity.id] == kind)
    ]
    if sort is not None:
        sort_keys: dict[str, object] = {
            "name": lambda a: a.identity.first_display_name.lower(),
            "type": lambda a: a.identity.identity_type,
            "account": lambda a: a.account,
            "kind": lambda a: kind_by_id[a.identity.id],
            "critical": lambda a: a.tier_counts()["critical"],
            "warning": lambda a: a.tier_counts()["warning"],
            "notice": lambda a: a.tier_counts()["notice"],
        }
        matched.sort(key=sort_keys[sort], reverse=direction == "desc")  # type: ignore[arg-type]
    rows = []
    for a in matched[offset:offset + limit]:
        tiers = a.tier_counts()
        rows.append(IdentityView(
            id=a.identity.id,
            account=a.account,
            display_name=a.identity.first_display_name,
            identity_type=a.identity.identity_type,
            provisional=a.identity.provisional,
            observations=a.observations,
            name_reused=a.name_reused,
            flagged=a.flagged,
            owner=a.owner.name if a.owner else None,
            kind=kind_by_id[a.identity.id],
            critical=tiers["critical"],
            warning=tiers["warning"],
            notice=tiers["notice"],
            top_finding=_top_finding(a),
        ))
    return InventoryPage(
        tiles=tiles, matched=len(matched), offset=offset, limit=limit, rows=rows
    )


@router.get(
    "/identities/{identity_id}",
    dependencies=[require_roles("GET /identities/{identity_id}")],
)
def identity_detail(
    identity_id: int, db: Annotated[Session, Depends(get_session)]
) -> IdentityDetail:
    row = db.execute(
        select(Identity, Account.provider_account_id)
        .join(Account, Identity.account_id == Account.id)
        .where(Identity.id == identity_id)
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="no such identity")
    identity, account = row
    pairs = observation_pairs(db, [identity.id])
    mine = sorted(pairs.get(identity.id, []), key=lambda p: p[1])
    if not mine:
        raise HTTPException(status_code=404, detail="no observations recorded")
    as_of = db.execute(
        select(func.max(Snapshot.captured_at))
        .where(Snapshot.account_id == identity.account_id)
    ).scalar_one()
    state = derive(mine, as_of)
    state.identity_type = identity.identity_type
    findings = evaluate(state)
    index, groups, _ = privilege_context(db, identity.account_id)
    picture = read_identity_privilege(
        identity_key=identity.provider_identifier,
        tags=state.tags,
        attached=state.attached_raw,
        group_names=state.group_names,
        trust_policy=state.trust_policy,
        account_id=account,
        index=index,
        groups=groups,
    )
    findings = findings + evaluate_privilege(picture)
    assigned = next(
        (
            r
            for r in active_records(db, "identity", identity.id)
            if r.kind == "owner"
        ),
        None,
    )
    effective = resolve_owner(assigned, picture.owner)
    findings = apply_owner_governance(
        findings, effective, picture.owner, picture.combined.privileged
    )
    reused = db.execute(
        select(func.count()).select_from(Identity).where(
            Identity.account_id == identity.account_id,
            Identity.first_display_name == identity.first_display_name,
        )
    ).scalar_one() > 1
    # Keyed by snapshot, never by capture time: the two sources import
    # at the same instant, so a time-keyed lookup silently labels half
    # the timeline with the other source's name.
    sources: dict[int, str] = dict(
        db.execute(
            select(Snapshot.id, Snapshot.source)
            .where(Snapshot.account_id == identity.account_id)
        ).tuples().all()
    )
    return IdentityDetail(
        id=identity.id,
        account=account,
        display_name=identity.first_display_name,
        identity_type=identity.identity_type,
        provisional=identity.provisional,
        name_reused=reused,
        as_of=as_of.isoformat(),
        observed_days=state.observed_days,
        last_activity=(
            state.last_activity.isoformat() if state.last_activity else None
        ),
        owner=effective.name if effective else None,
        owner_type=effective.owner_type if effective else None,
        owner_source=effective.source if effective else None,
        kind=classify(state).kind,
        kind_reason=classify(state).reason,
        privilege_sources=[source.describe() for source in picture.sources],
        findings=[FindingView(**vars(f)) for f in findings],
        governance=[
            record_view(r) for r in record_history(db, "identity", identity.id)
        ],
        timeline=[
            ObservationView(
                captured_at=captured.isoformat(),
                source=sources.get(obs.snapshot_id, ""),
                fields_present=sum(
                    1 for c in (
                        "password_enabled","mfa_active","key1_active",
                        "key2_active","trust_policy","tags",
                        "attached_policies","group_names",
                    ) if getattr(obs, c) is not None
                ),
            )
            for obs, captured in mine
        ],
    )


class GroupView(BaseModel):
    id: int | None
    account: str
    name: str
    members: int
    privileged: bool
    owner: str | None
    flagged: bool
    findings: list[FindingView]
    governance: list[RecordView]


@router.get("/groups", dependencies=[require_roles("GET /groups")])
def list_groups(db: Annotated[Session, Depends(get_session)]) -> list[GroupView]:
    """Groups as governed privilege sources (D-019): what each grants,
    who is in it, what changed since the previous snapshot, and who
    answers for it."""
    return [
        GroupView(
            id=g.group_id,
            account=g.account,
            name=g.name,
            members=g.members,
            privileged=g.privileged,
            owner=g.owner.name if g.owner else None,
            flagged=g.flagged,
            findings=[FindingView(**vars(f)) for f in g.findings],
            governance=[record_view(r) for r in g.records],
        )
        for g in assess_groups(db)
    ]
