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
from manifest_identity.observe import generic_import, github_importer, kubernetes_importer
from manifest_identity.observe import mapping as tabular
from manifest_identity.observe.importer import (
    SHAPE_AUTHORIZATION,
    SHAPE_CREDENTIAL,
    SHAPE_GITHUB,
    SHAPE_KUBERNETES,
    SHAPE_TABLE,
    CaptureTimeInvalid,
    DuplicateSnapshot,
    detect_source,
    import_authorization_details,
    import_credential_report,
)
from manifest_identity.observe.models import Import, ImportMapping
from manifest_identity.observe.providers.aws import authorization_details as authz
from manifest_identity.observe.providers.aws.credential_report import (
    MAX_FILE_BYTES,
    ParseError,
    parse_credential_report,
)
from manifest_identity.observe.providers.github import organization_export as github_export
from manifest_identity.observe.providers.kubernetes import rbac_dump

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


SHAPE_NAMES = {
    SHAPE_AUTHORIZATION: "an AWS authorization details export",
    SHAPE_CREDENTIAL: "an AWS credential report",
    SHAPE_GITHUB: "a GitHub organization export",
    SHAPE_KUBERNETES: "a Kubernetes role-based access control dump",
    SHAPE_TABLE: "a table for a mapping",
}


def _refuse_mismatch(data: bytes, expected: str) -> None:
    """The source selector's other half: the route knows what it was
    told the file is, the file says what it is, and a disagreement is
    refused with both named rather than parsed into an error about the
    third column."""
    found = detect_source(data)
    if found is not None and found != expected:
        raise HTTPException(
            status_code=422,
            detail=(
                f"this file is shaped like {SHAPE_NAMES[found]}, not "
                f"{SHAPE_NAMES[expected]}; import it as that source"
            ),
        )


class ObservedRowView(BaseModel):
    row: int
    identity_external_id: str
    role: str
    mode: str


class ObservedRefusalView(BaseModel):
    row: int
    reason: str


class ObservedReadingView(BaseModel):
    mapping_id: int
    mapping_name: str
    row_count: int
    written: list[ObservedRowView]
    refusals: list[ObservedRefusalView]
    ignored_columns: list[str]
    absent_fields: list[str]
    batch_id: int | None
    import_id: int | None


def _observed_mapping(db: Session, mapping_id: int | None) -> ImportMapping:
    if mapping_id is None:
        shipped = generic_import.default_mapping(db)
        db.commit()
        return shipped
    found = db.get(ImportMapping, mapping_id)
    if found is None or found.source_kind != generic_import.SOURCE_KIND:
        raise HTTPException(status_code=404, detail="no such observed mapping")
    return found


def _observed_view(row: ImportMapping, result: generic_import.Result) -> ObservedReadingView:
    return ObservedReadingView(
        mapping_id=row.id,
        mapping_name=row.name,
        row_count=result.row_count,
        written=[ObservedRowView(**vars(w)) for w in result.written],
        refusals=[ObservedRefusalView(row=r.row, reason=r.reason) for r in result.refusals],
        ignored_columns=result.ignored_columns,
        absent_fields=result.absent_fields,
        batch_id=result.batch_id,
        import_id=result.import_id,
    )


@router.post("/observed/dry-run")
def dry_run_observed(
    file: UploadFile,
    db: Annotated[Session, Depends(get_session)],
    _auth: Annotated[AuthContext, require_roles("POST /imports/observed/dry-run")],
    mapping_id: Annotated[int | None, Form()] = None,
) -> ObservedReadingView:
    """Read a table through an observed mapping and write nothing."""
    row = _observed_mapping(db, mapping_id)
    data = file.file.read(tabular.MAX_FILE_BYTES + 1)
    _refuse_mismatch(data, SHAPE_TABLE)
    try:
        result = generic_import.dry_run(row, data)
    except tabular.MappingError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    finally:
        db.rollback()
    return _observed_view(row, result)


@router.post("/observed", status_code=201)
def import_observed(
    file: UploadFile,
    captured_at: Annotated[datetime, Form()],
    db: Annotated[Session, Depends(get_session)],
    auth: Annotated[AuthContext, require_roles("POST /imports/observed")],
    _budget: ThrottledWrite,
    mapping_id: Annotated[int | None, Form()] = None,
) -> ObservedReadingView:
    """Any provider's table becomes observed rows. The scope is the
    account the file names, made on first sight, so a first import of a
    new provider needs a global binding, which is what None asks for."""
    row = _observed_mapping(db, mapping_id)
    data = file.file.read(tabular.MAX_FILE_BYTES + 1)
    _refuse_mismatch(data, SHAPE_TABLE)
    require_scope(db, auth, "POST /imports/observed", None)
    try:
        result = generic_import.write(db, row, data, captured_at, auth.user, file.filename)
    except tabular.MappingError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except CaptureTimeInvalid as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except DuplicateSnapshot as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    db.commit()
    return _observed_view(row, result)


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
    _refuse_mismatch(data, SHAPE_CREDENTIAL)
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
    _refuse_mismatch(data, SHAPE_AUTHORIZATION)
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


@router.post("/github-organization", status_code=201)
def import_github(
    file: UploadFile,
    captured_at: Annotated[datetime, Form()],
    db: Annotated[Session, Depends(get_session)],
    auth: Annotated[AuthContext, require_roles("POST /imports/github-organization")],
    _budget: ThrottledWrite,
) -> ImportResponse:
    """The second provider's door (1.12): the same shape check, the
    same scope check against the organization's node, the same
    transaction, a different parser."""
    data = file.file.read(github_export.MAX_FILE_BYTES + 1)
    if len(data) > github_export.MAX_FILE_BYTES:
        raise HTTPException(status_code=413, detail="file exceeds the size bound")
    _refuse_mismatch(data, SHAPE_GITHUB)
    try:
        export = github_export.parse_organization_export(data)
    except github_export.ParseError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    require_scope(
        db, auth, "POST /imports/github-organization",
        github_importer.organization_node_id(db, export.login),
    )
    try:
        result = github_importer.import_github_organization(
            db,
            export=export,
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


@router.post("/kubernetes-rbac", status_code=201)
def import_kubernetes(
    file: UploadFile,
    captured_at: Annotated[datetime, Form()],
    cluster: Annotated[str, Form(min_length=1, max_length=253, pattern=r"^[a-z0-9][a-z0-9.-]*$")],
    db: Annotated[Session, Depends(get_session)],
    auth: Annotated[AuthContext, require_roles("POST /imports/kubernetes-rbac")],
    _budget: ThrottledWrite,
) -> ImportResponse:
    """The third provider's door (1.14b). The cluster's name arrives as
    a form field because nothing in a kubectl dump names the cluster;
    it is client input the way the capture time is, and it is checked
    against the scope the person may write to."""
    data = file.file.read(rbac_dump.MAX_FILE_BYTES + 1)
    if len(data) > rbac_dump.MAX_FILE_BYTES:
        raise HTTPException(status_code=413, detail="file exceeds the size bound")
    _refuse_mismatch(data, SHAPE_KUBERNETES)
    try:
        dump = rbac_dump.parse_rbac_dump(data)
    except rbac_dump.ParseError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    require_scope(
        db, auth, "POST /imports/kubernetes-rbac",
        kubernetes_importer.cluster_node_id(db, cluster),
    )
    try:
        result = kubernetes_importer.import_rbac_dump(
            db,
            dump=dump,
            cluster=cluster,
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
