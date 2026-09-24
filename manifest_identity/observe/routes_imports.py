"""Snapshot import and the import history.

The upload is bounded before parsing: the route reads one byte past
the parser's limit and rejects on overflow, so an oversized body never
fully enters memory. Parser and importer error messages are safe for
responses by contract: they state rules and positions, never file
content.
"""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, UploadFile
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.core.db import get_session
from manifest_identity.core.deps import AuthContext, ThrottledWrite, require_roles, require_scope
from manifest_identity.core.models import Provider, ScopeNode
from manifest_identity.observe.importer import (
    CaptureTimeInvalid,
    DuplicateSnapshot,
    import_authorization_details,
    import_credential_report,
)
from manifest_identity.observe.models import Import
from manifest_identity.observe.providers.aws import authorization_details as authz
from manifest_identity.observe.providers.aws.credential_report import (
    MAX_FILE_BYTES,
    ParseError,
    parse_credential_report,
)

router = APIRouter(prefix="/imports")


class ImportResponse(BaseModel):
    account: str
    captured_at: str
    identities_new: int
    identities_known: int
    observations: int
    skipped_rows: int


class SnapshotView(BaseModel):
    account: str
    source: str
    captured_at: str
    imported_at: str
    row_count: int
    skipped_count: int



def _account_node_id(db: Session, account_id: str) -> int | None:
    """The scope the file's own account names, if it has been seen; a
    first import of a new account needs a binding above it (the
    partition or global), which None asks for."""
    return db.execute(
        select(ScopeNode.id).where(
            ScopeNode.provider == Provider.aws.value,
            ScopeNode.kind == "account",
            ScopeNode.external_id == account_id,
        )
    ).scalar_one_or_none()


@router.post("/credential-report", status_code=201)
def import_report(
    file: UploadFile,
    captured_at: Annotated[datetime, Form()],
    db: Annotated[Session, Depends(get_session)],
    auth: Annotated[AuthContext, require_roles("POST /imports/credential-report")],
    _budget: ThrottledWrite,
) -> ImportResponse:
    data = file.file.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise HTTPException(status_code=413, detail="file exceeds the size bound")
    try:
        report = parse_credential_report(data)
    except ParseError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    require_scope(
        db, auth, "POST /imports/credential-report", _account_node_id(db, report.account_id)
    )
    try:
        result = import_credential_report(
            db,
            report=report,
            captured_at=captured_at,
            source_filename=file.filename,
            actor_user_id=auth.user.id,
            actor_username=auth.user.username,
        )
    except CaptureTimeInvalid as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except DuplicateSnapshot as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return ImportResponse(
        account=result.account,
        captured_at=result.captured_at.isoformat(),
        identities_new=result.identities_new,
        identities_known=result.identities_known,
        observations=result.observations,
        skipped_rows=result.skipped_rows,
    )


@router.post("/authorization-details", status_code=201)
def import_authorization(
    file: UploadFile,
    captured_at: Annotated[datetime, Form()],
    db: Annotated[Session, Depends(get_session)],
    auth: Annotated[AuthContext, require_roles("POST /imports/authorization-details")],
    _budget: ThrottledWrite,
) -> ImportResponse:
    data = file.file.read(authz.MAX_FILE_BYTES + 1)
    if len(data) > authz.MAX_FILE_BYTES:
        raise HTTPException(status_code=413, detail="file exceeds the size bound")
    try:
        report = authz.parse_authorization_details(data)
    except authz.ParseError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    require_scope(
        db, auth, "POST /imports/authorization-details",
        _account_node_id(db, report.account_id),
    )
    try:
        result = import_authorization_details(
            db,
            report=report,
            captured_at=captured_at,
            source_filename=file.filename,
            actor_user_id=auth.user.id,
            actor_username=auth.user.username,
        )
    except CaptureTimeInvalid as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except DuplicateSnapshot as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return ImportResponse(
        account=result.account,
        captured_at=result.captured_at.isoformat(),
        identities_new=result.identities_new,
        identities_known=result.identities_known,
        observations=result.observations,
        skipped_rows=result.skipped_rows,
    )


@router.get("", dependencies=[require_roles("GET /imports")])
def list_imports(db: Annotated[Session, Depends(get_session)]) -> list[SnapshotView]:
    rows = db.execute(
        select(Import, ScopeNode)
        .join(ScopeNode, Import.scope_node_id == ScopeNode.id)
        .order_by(Import.imported_at.desc())
    ).all()
    return [
        SnapshotView(
            account=account.external_id,
            source=snapshot.source_kind,
            captured_at=snapshot.captured_at.isoformat(),
            imported_at=snapshot.imported_at.isoformat(),
            row_count=snapshot.row_count,
            skipped_count=snapshot.skipped_count,
        )
        for snapshot, account in rows
    ]
