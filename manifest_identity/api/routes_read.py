"""The read-only surface an integration consumes.

Three things, under a token and nothing else: the identities, paged
from a cursor; the delta, both halves; and a change feed that walks the
audit record from a cursor and hands back the next one, so a consumer
follows decisions as they happen rather than polling a full dump. The
audit record is the feed because it already is one: append-only,
hash-chained, one row per act with who did it and to what.

Nothing here writes, and nothing here takes a session. Every response
is bounded, every page says where the next page starts, and a cursor
past the end returns an empty page rather than an error, because a
consumer that has caught up is the normal case.

Demonstration-grade, stated as such in the documents.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.api.deps import CurrentToken
from manifest_identity.compare import delta
from manifest_identity.core.db import get_session
from manifest_identity.core.models import AuditEvent, ScopeNode
from manifest_identity.observe.models import Identity

router = APIRouter(prefix="/api/v1", tags=["read-api"])

PAGE_LIMIT = 200


class IdentityRow(BaseModel):
    id: int
    external_id: str
    display_name: str
    provider_type: str
    kind: str
    home: str
    account: str


class IdentityPage(BaseModel):
    items: list[IdentityRow]
    # The id to pass as the next cursor, or nothing when this is the
    # last page. Ids only ever grow, so the cursor never skips a row
    # that arrived while a consumer was paging.
    next_cursor: int | None


class DeltaRow(BaseModel):
    kind: str
    title: str
    subject: str
    account: str
    role: str
    detail: str
    observed_as_of: str | None
    authorized_as_of: str | None


class DeltaPage(BaseModel):
    items: list[DeltaRow]
    offset: int
    total: int


class ChangeRow(BaseModel):
    id: int
    at: str
    actor: str
    action: str
    target: str | None
    detail: str | None


class ChangePage(BaseModel):
    items: list[ChangeRow]
    # The last id in this page, to pass as the next cursor. Unchanged
    # when the page is empty, so a consumer can keep asking.
    next_cursor: int


def _limit(limit: int) -> int:
    return max(1, min(limit, PAGE_LIMIT))


def _stamp(moment: datetime | None) -> str | None:
    return moment.isoformat(timespec="seconds") if moment else None


@router.get("/identities")
def identities(
    _token: CurrentToken,
    db: Annotated[Session, Depends(get_session)],
    cursor: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=PAGE_LIMIT)] = 100,
) -> IdentityPage:
    rows = db.execute(
        select(Identity, ScopeNode.external_id)
        .join(ScopeNode, Identity.scope_node_id == ScopeNode.id)
        .where(Identity.id > cursor)
        .order_by(Identity.id)
        .limit(_limit(limit) + 1)
    ).all()
    page = rows[: _limit(limit)]
    more = len(rows) > len(page)
    return IdentityPage(
        items=[
            IdentityRow(
                id=identity.id,
                external_id=identity.external_id,
                display_name=identity.first_display_name,
                provider_type=identity.provider_type,
                kind=identity.kind,
                home=identity.home,
                account=account,
            )
            for identity, account in page
        ],
        next_cursor=page[-1][0].id if more and page else None,
    )


@router.get("/delta")
def estate_delta(
    _token: CurrentToken,
    db: Annotated[Session, Depends(get_session)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=PAGE_LIMIT)] = 100,
) -> DeltaPage:
    """The delta is computed at read and has no ids, so it pages by
    offset over a list that is stable within one request."""
    rows: list[DeltaRow] = [
        DeltaRow(
            kind=f.kind,
            title=f.title,
            subject=f.display_name,
            account=f.account,
            role=f.role,
            detail=f.detail,
            observed_as_of=_stamp(f.observed_as_of),
            authorized_as_of=_stamp(f.authorized_as_of),
        )
        for f in delta.for_estate(db)
    ] + [
        DeltaRow(
            kind=f.kind,
            title=f.title,
            subject=f.role,
            account=f.account,
            role=f.role_ref,
            detail=f.detail,
            observed_as_of=_stamp(f.observed_as_of),
            authorized_as_of=_stamp(f.authorized_as_of),
        )
        for f in delta.for_definitions(db)
    ]
    return DeltaPage(items=rows[offset : offset + _limit(limit)], offset=offset, total=len(rows))


@router.get("/changes")
def changes(
    _token: CurrentToken,
    db: Annotated[Session, Depends(get_session)],
    cursor: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=PAGE_LIMIT)] = 100,
) -> ChangePage:
    rows = db.execute(
        select(AuditEvent)
        .where(AuditEvent.id > cursor)
        .order_by(AuditEvent.id)
        .limit(_limit(limit))
    ).scalars().all()
    return ChangePage(
        items=[
            ChangeRow(
                id=row.id,
                at=row.at.isoformat(timespec="seconds"),
                actor=row.actor_username,
                action=row.action,
                target=row.target,
                detail=row.detail,
            )
            for row in rows
        ],
        next_cursor=rows[-1].id if rows else cursor,
    )
