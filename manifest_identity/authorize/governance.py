"""The governance layer: owner, purpose, flag, and attestation.

Two rules give this module its shape. Records are superseded or
cleared, never edited, so the human history stands the way the machine
history does. And the owner is typed, with teams as the default the
interface encourages, because an individual owner is the orphan in
waiting: the person leaves, nothing in the provider changes, and the
identity keeps its keys with nobody accountable, which is the finding
class this tool opens with (D-038).

An assigned owner outranks the owner tag for governance, because it is
the deliberate human input this table exists to hold, while the tag is
an observation like every other imported field. A disagreement between
them is surfaced rather than resolved silently: it usually means the
tag is stale or the assignment was a guess, and both deserve a look.
"""

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.models import GovernanceRecord, utcnow
from manifest_identity.observe.findings import Finding

KINDS = ("owner", "purpose", "flag", "attestation")

# Owner and purpose answer a question with one current answer; setting
# a new record supersedes the old. Flags and attestations are events
# that accumulate and are cleared one by one.
SINGLE_ACTIVE_KINDS = ("owner", "purpose")

OWNER_TYPES = ("team", "business_unit", "individual", "vendor", "unknown")


@dataclass
class EffectiveOwner:
    """Who answers for a target right now, and on what authority."""

    name: str
    # One of OWNER_TYPES for an assigned owner; "unknown" for a tag
    # owner, because a tag carries a string and no claim about what
    # kind of thing the string names.
    owner_type: str
    # "assigned" (a governance record) or "tag" (imported observation).
    source: str


def active_records(
    db: Session, target_type: str, target_id: int
) -> list[GovernanceRecord]:
    return list(
        db.execute(
            select(GovernanceRecord)
            .where(
                GovernanceRecord.target_type == target_type,
                GovernanceRecord.target_id == target_id,
                GovernanceRecord.cleared_at.is_(None),
            )
            .order_by(GovernanceRecord.created_at, GovernanceRecord.id)
        ).scalars()
    )


def record_history(
    db: Session, target_type: str, target_id: int
) -> list[GovernanceRecord]:
    return list(
        db.execute(
            select(GovernanceRecord)
            .where(
                GovernanceRecord.target_type == target_type,
                GovernanceRecord.target_id == target_id,
            )
            .order_by(GovernanceRecord.created_at.desc(), GovernanceRecord.id.desc())
        ).scalars()
    )


def active_owners_by_target(
    db: Session, target_type: str
) -> dict[int, GovernanceRecord]:
    """The active owner record per target, for list views that must
    agree with the detail view instead of recomputing differently."""
    out: dict[int, GovernanceRecord] = {}
    rows = db.execute(
        select(GovernanceRecord)
        .where(
            GovernanceRecord.target_type == target_type,
            GovernanceRecord.kind == "owner",
            GovernanceRecord.cleared_at.is_(None),
        )
    ).scalars()
    for row in rows:
        out[row.target_id] = row
    return out


def supersede(
    db: Session,
    *,
    target_type: str,
    target_id: int,
    kind: str,
    actor_username: str,
    now: datetime | None = None,
) -> None:
    """Close the active record of a single-answer kind, attributing the
    closure to whoever is writing the replacement."""
    stamp = now or utcnow()
    for row in active_records(db, target_type, target_id):
        if row.kind == kind:
            row.cleared_at = stamp
            row.cleared_by = actor_username


def resolve_owner(
    assigned: GovernanceRecord | None, tag_owner: str | None
) -> EffectiveOwner | None:
    if assigned is not None:
        return EffectiveOwner(
            name=assigned.value,
            owner_type=assigned.owner_type or "unknown",
            source="assigned",
        )
    if tag_owner:
        return EffectiveOwner(name=tag_owner, owner_type="unknown", source="tag")
    return None


def apply_owner_governance(
    findings: list[Finding],
    effective: EffectiveOwner | None,
    tag_owner: str | None,
    privileged: bool,
) -> list[Finding]:
    """Adjust the machine findings in the light of the human record.

    An assigned owner answers the unowned finding, which is what makes
    that finding clearable by governance rather than only by re-tagging
    the provider. The remaining owner findings are notices: they state
    an exposure and leave the judgment to the reader.
    """
    out = list(findings)
    if effective is not None and effective.source == "assigned":
        out = [
            f
            for f in out
            if f.code not in ("unowned_privileged", "unowned_privileged_group")
        ]
        if tag_owner and tag_owner.strip().lower() != effective.name.strip().lower():
            out.append(
                Finding(
                    code="owner_tag_disagreement",
                    tier="notice",
                    anchor="NHI1",
                    explanation=(
                        f"the assigned owner is {effective.name} but the "
                        f"provider tag says {tag_owner}; one of them is "
                        "stale, and neither will notice on its own"
                    ),
                )
            )
    if (
        effective is not None
        and effective.owner_type == "individual"
        and privileged
    ):
        out.append(
            Finding(
                code="individually_owned_privileged",
                tier="notice",
                anchor="NHI1",
                explanation=(
                    f"carries privilege and is owned by an individual, "
                    f"{effective.name}; when that person leaves, nothing "
                    "in the provider changes, and a team owner would "
                    "survive the departure"
                ),
            )
        )
    return out
