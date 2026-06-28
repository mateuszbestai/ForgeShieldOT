"""Asset inventory API — reference CRUD/filter/search/CSV pattern for all domains."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Response, UploadFile
from fastapi.responses import PlainTextResponse
from sqlmodel import Session

from app.api.deps import (
    WRITE_OPERATIONS,
    AuthenticatedUser,
    get_current_user,
    require_role,
)
from app.core.config import settings
from app.core.db import get_session
from app.core.enums import AssetType, AuditAction, Criticality
from app.core.exceptions import ValidationAppError
from app.schemas.asset import AssetCreate, AssetFilter, AssetUpdate
from app.schemas.common import PaginationParams, pagination
from app.services import asset_service, csv_io
from app.services.audit_service import record_audit

router = APIRouter(prefix="/assets", tags=["assets"])


@router.get("")
def list_assets(
    page: PaginationParams = Depends(pagination),
    site_id: uuid.UUID | None = Query(None),
    zone_id: uuid.UUID | None = Query(None),
    asset_type: AssetType | None = Query(None),
    criticality: Criticality | None = Query(None),
    risk_band: str | None = Query(None),
    purdue_level: int | None = Query(None, ge=0, le=5),
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> dict:
    filters = AssetFilter(
        site_id=site_id,
        zone_id=zone_id,
        asset_type=asset_type,
        criticality=criticality,
        risk_band=risk_band,
        purdue_level=purdue_level,
    )
    items, total = asset_service.list_assets(session, filters=filters, page=page)
    return {
        "items": [a.model_dump() for a in items],
        "total": total,
        "limit": page.limit,
        "offset": page.offset,
        "is_demo_environment": True,
    }


@router.get("/export", response_class=PlainTextResponse)
def export_assets(
    user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> str:
    record_audit(
        session,
        action=AuditAction.ASSET_EXPORT,
        actor_user_id=user.id,
        actor_email=user.email,
        entity_type="asset",
        summary="Exported asset inventory to CSV",
    )
    return csv_io.export_assets_csv(session)


@router.post("/import")
async def import_assets(
    file: UploadFile,
    user: AuthenticatedUser = Depends(require_role(*WRITE_OPERATIONS)),
    session: Session = Depends(get_session),
) -> dict:
    if file.content_type not in {"text/csv", "application/vnd.ms-excel", "application/octet-stream", None}:
        raise ValidationAppError(f"Unsupported file type: {file.content_type}")
    content = await file.read()
    if len(content) > settings.max_upload_bytes:
        raise ValidationAppError("File exceeds maximum allowed size")
    result = csv_io.import_assets_csv(session, content, user)
    record_audit(
        session,
        action=AuditAction.ASSET_IMPORT,
        actor_user_id=user.id,
        actor_email=user.email,
        entity_type="asset",
        summary=f"Imported assets (created={result['created']}, updated={result['updated']})",
        meta=result,
    )
    return result


@router.get("/filters")
def filter_values(
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> dict:
    return asset_service.distinct_filter_values(session)


@router.post("", status_code=201)
def create_asset(
    data: AssetCreate,
    user: AuthenticatedUser = Depends(require_role(*WRITE_OPERATIONS)),
    session: Session = Depends(get_session),
) -> dict:
    return asset_service.create_asset(session, data, user).model_dump()


@router.get("/{asset_id}")
def get_asset(
    asset_id: uuid.UUID,
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> dict:
    asset = asset_service.get_asset(session, asset_id)
    return asset_service.asset_detail(session, asset)


@router.patch("/{asset_id}")
def update_asset(
    asset_id: uuid.UUID,
    data: AssetUpdate,
    user: AuthenticatedUser = Depends(require_role(*WRITE_OPERATIONS)),
    session: Session = Depends(get_session),
) -> dict:
    return asset_service.update_asset(session, asset_id, data, user).model_dump()


@router.delete("/{asset_id}", status_code=204)
def delete_asset(
    asset_id: uuid.UUID,
    user: AuthenticatedUser = Depends(require_role(*WRITE_OPERATIONS)),
    session: Session = Depends(get_session),
) -> Response:
    asset_service.delete_asset(session, asset_id, user)
    return Response(status_code=204)
