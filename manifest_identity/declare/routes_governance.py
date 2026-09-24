"""Governance writes: set and clear, attributed, audited, in one transaction.

Setting a record and writing its audit row share a commit, so neither
can exist without the other (the audit spine's rule). Owner and purpose
supersede their previous answer; flags and attestations accumulate and
clear one by one. Attestation is open to every role, because saying "I
looked at this and it is still needed" is exactly the reviewer's act;
changing who owns a thing is the operator's.
"""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.core import audit
from manifest_identity.core.db import get_session
from manifest_identity.core.deps import AuthContext, require_roles, require_scope
from manifest_identity.declare.governance import SINGLE_ACTIVE_KINDS, supersede
from manifest_identity.models import GovernanceRecord, Identity, utcnow

router = APIRouter()


class SetRecordRequest(BaseModel):
    kind: Literal["owner", "purpose", "flag"]
    value: str = Field(min_length=1, max_length=500)
    # Required for owner, forbidden otherwise; the team default is the
    # design speaking (D-038), not a convenience.
    owner_type: (
        Literal["team", "business_unit", "individual", "vendor", "unknown"] | None
    ) = None

    @model_validator(mode="after")
    def owner_type_matches_kind(self) -> SetRecordRequest:
        if self.kind == "owner" and self.owner_type is None:
            raise ValueError(
                "an owner needs an owner_type: team, business_unit, "
                "individual, vendor, or unknown"
            )
        if self.kind != "owner" and self.owner_type is not None:
            raise ValueError("owner_type belongs only on an owner record")
        return self


class AttestRequest(BaseModel):
    value: str = Field(default="still needed", min_length=1, max_length=500)


class RecordView(BaseModel):
    id: int
    kind: str
    value: str
    owner_type: str | None
    actor: str
    created_at: str
    cleared_at: str | None
    cleared_by: str | None


def record_view(r: GovernanceRecord) -> RecordView:
    return RecordView(
        id=r.id,
        kind=r.kind,
        value=r.value,
        owner_type=r.owner_type,
        actor=r.actor_username,
        # Whole seconds, matching every other time the page shows.
        created_at=r.created_at.isoformat(timespec="seconds"),
        cleared_at=(
            r.cleared_at.isoformat(timespec="seconds") if r.cleared_at else None
        ),
        cleared_by=r.cleared_by,
    )


def _require_target(db: Session, target_type: str, target_id: int) -> int:
    """The target must exist and be the kind named, and the caller
    learns nothing about scope until it does: 404 before 403, so a
    probe cannot map the tree by asking. Returns the target's node."""
    # Groups are identities of kind group (D-019); a governance target
    # named as a group must be one, and one named as an identity must
    # not be.
    row = db.execute(
        select(Identity.kind, Identity.scope_node_id).where(Identity.id == target_id)
    ).first()
    wanted_group = target_type == "group"
    if row is None or (row[0] == "group") != wanted_group:
        raise HTTPException(status_code=404, detail=f"no such {target_type}")
    return int(row[1])


def _set_record(
    db: Session,
    auth: AuthContext,
    *,
    route_key: str,
    target_type: str,
    target_id: int,
    kind: str,
    value: str,
    owner_type: str | None,
) -> RecordView:
    node_id = _require_target(db, target_type, target_id)
    require_scope(db, auth, route_key, node_id)
    if kind in SINGLE_ACTIVE_KINDS:
        supersede(
            db,
            target_type=target_type,
            target_id=target_id,
            kind=kind,
            actor_username=auth.user.username,
        )
    record = GovernanceRecord(
        target_type=target_type,
        target_id=target_id,
        kind=kind,
        value=value,
        owner_type=owner_type,
        actor_user_id=auth.user.id,
        actor_username=auth.user.username,
    )
    db.add(record)
    audit.record(
        db,
        actor_user_id=auth.user.id,
        actor_username=auth.user.username,
        action="governance_set",
        target=f"{target_type}:{target_id}",
        detail=f"{kind}: {value}" + (f" ({owner_type})" if owner_type else ""),
    )
    db.commit()
    return record_view(record)


@router.post(
    "/identities/{identity_id}/governance",
    status_code=201,
)
def set_identity_record(
    identity_id: int,
    body: SetRecordRequest,
    db: Annotated[Session, Depends(get_session)],
    auth: Annotated[AuthContext, require_roles("POST /identities/{identity_id}/governance")],
) -> RecordView:
    return _set_record(
        db,
        auth,
        route_key="POST /identities/{identity_id}/governance",
        target_type="identity",
        target_id=identity_id,
        kind=body.kind,
        value=body.value,
        owner_type=body.owner_type,
    )


@router.post(
    "/groups/{group_id}/governance",
    status_code=201,
)
def set_group_record(
    group_id: int,
    body: SetRecordRequest,
    db: Annotated[Session, Depends(get_session)],
    auth: Annotated[AuthContext, require_roles("POST /groups/{group_id}/governance")],
) -> RecordView:
    return _set_record(
        db,
        auth,
        route_key="POST /groups/{group_id}/governance",
        target_type="group",
        target_id=group_id,
        kind=body.kind,
        value=body.value,
        owner_type=body.owner_type,
    )


@router.post(
    "/identities/{identity_id}/attest",
    status_code=201,
)
def attest_identity(
    identity_id: int,
    body: AttestRequest,
    db: Annotated[Session, Depends(get_session)],
    auth: Annotated[AuthContext, require_roles("POST /identities/{identity_id}/attest")],
) -> RecordView:
    return _set_record(
        db,
        auth,
        route_key="POST /identities/{identity_id}/attest",
        target_type="identity",
        target_id=identity_id,
        kind="attestation",
        value=body.value,
        owner_type=None,
    )


@router.post(
    "/groups/{group_id}/attest",
    status_code=201,
)
def attest_group(
    group_id: int,
    body: AttestRequest,
    db: Annotated[Session, Depends(get_session)],
    auth: Annotated[AuthContext, require_roles("POST /groups/{group_id}/attest")],
) -> RecordView:
    return _set_record(
        db,
        auth,
        route_key="POST /groups/{group_id}/attest",
        target_type="group",
        target_id=group_id,
        kind="attestation",
        value=body.value,
        owner_type=None,
    )


@router.delete("/governance/{record_id}")
def clear_record(
    record_id: int,
    db: Annotated[Session, Depends(get_session)],
    auth: Annotated[AuthContext, require_roles("DELETE /governance/{record_id}")],
) -> RecordView:
    record = db.execute(
        select(GovernanceRecord).where(
            GovernanceRecord.id == record_id,
            GovernanceRecord.cleared_at.is_(None),
        )
    ).scalar_one_or_none()
    if record is None:
        raise HTTPException(status_code=404, detail="no active record with that id")
    node_id = _require_target(db, record.target_type, record.target_id)
    require_scope(db, auth, "DELETE /governance/{record_id}", node_id)
    record.cleared_at = utcnow()
    record.cleared_by = auth.user.username
    audit.record(
        db,
        actor_user_id=auth.user.id,
        actor_username=auth.user.username,
        action="governance_cleared",
        target=f"{record.target_type}:{record.target_id}",
        detail=f"{record.kind}: {record.value}",
    )
    db.commit()
    return record_view(record)
