"""The delta routes: the whole estate, and one identity.

Reads for every role. A reviewer who cannot see the difference cannot
review anything, and the delta writes nothing by construction, so
there is no scoped write here to check.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from manifest_identity.compare import delta
from manifest_identity.core.db import get_session
from manifest_identity.core.deps import AuthContext, require_roles
from manifest_identity.observe.models import Identity

router = APIRouter(tags=["compare"])


class DeltaFindingView(BaseModel):
    kind: str
    title: str
    identity_id: int
    identity_external_id: str
    display_name: str
    account: str
    role: str
    path: list[dict[str, str]]
    detail: str
    authorization_id: int | None
    # Both sides' last word, beside every finding, because a finding
    # computed from a month-old import is true about a month-old world
    # and saying so is the difference between a delta and a claim.
    observed_as_of: str | None
    authorized_as_of: str | None


class DeltaView(BaseModel):
    counts: dict[str, int]
    titles: dict[str, str]
    findings: list[DeltaFindingView]


def view(finding: delta.DeltaFinding) -> DeltaFindingView:
    return DeltaFindingView(
        kind=finding.kind,
        title=finding.title,
        identity_id=finding.identity_id,
        identity_external_id=finding.identity_external_id,
        display_name=finding.display_name,
        account=finding.account,
        role=finding.role,
        path=finding.path,
        detail=finding.detail,
        authorization_id=finding.authorization_id,
        observed_as_of=(
            finding.observed_as_of.isoformat(timespec="seconds")
            if finding.observed_as_of else None
        ),
        authorized_as_of=(
            finding.authorized_as_of.isoformat(timespec="seconds")
            if finding.authorized_as_of else None
        ),
    )


@router.get("/delta")
def estate_delta(
    db: Annotated[Session, Depends(get_session)],
    _auth: Annotated[AuthContext, require_roles("GET /delta")],
) -> DeltaView:
    findings = delta.for_estate(db)
    return DeltaView(
        counts=delta.counts(findings),
        titles=dict(delta.TITLES),
        findings=[view(f) for f in findings],
    )


@router.get("/identities/{identity_id}/delta")
def identity_delta(
    identity_id: int,
    db: Annotated[Session, Depends(get_session)],
    _auth: Annotated[AuthContext, require_roles("GET /identities/{identity_id}/delta")],
) -> DeltaView:
    identity = db.get(Identity, identity_id)
    if identity is None:
        raise HTTPException(status_code=404, detail="no such identity")
    findings = delta.for_identity(db, identity)
    return DeltaView(
        counts=delta.counts(findings),
        titles=dict(delta.TITLES),
        findings=[view(f) for f in findings],
    )
