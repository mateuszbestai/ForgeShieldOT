"""Configuration & change management API — snapshots, baselines, change review."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse
from sqlmodel import Session

from app.ai.service import run_ai_query
from app.api.deps import (
    WRITE_OPERATIONS,
    AuthenticatedUser,
    get_current_user,
    require_role,
)
from app.core.db import get_session
from app.core.enums import AIUseCase, ChangeDisposition
from app.schemas.ai import AIChatResponse
from app.schemas.common import PaginationParams, pagination
from app.schemas.config_mgmt import (
    ChangeFilter,
    CompareRequest,
    DispositionRequest,
    SnapshotCreate,
)
from app.services import config_service

router = APIRouter(prefix="/config", tags=["config-management"])


@router.get("/snapshots")
def list_snapshots(
    asset_id: uuid.UUID | None = Query(None),
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> dict:
    items = config_service.list_snapshots(session, asset_id)
    return {"items": [s.model_dump() for s in items], "total": len(items)}


@router.post("/snapshots", status_code=201)
def create_snapshot(
    data: SnapshotCreate,
    user: AuthenticatedUser = Depends(require_role(*WRITE_OPERATIONS)),
    session: Session = Depends(get_session),
) -> dict:
    return config_service.create_snapshot(session, data, user).model_dump()


@router.post("/snapshots/{snapshot_id}/baseline")
def set_baseline(
    snapshot_id: uuid.UUID,
    user: AuthenticatedUser = Depends(require_role(*WRITE_OPERATIONS)),
    session: Session = Depends(get_session),
) -> dict:
    return config_service.set_baseline(session, snapshot_id, user).model_dump()


@router.post("/compare")
def compare_snapshots(
    body: CompareRequest,
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> dict:
    diff = config_service.diff_snapshots(session, body.from_snapshot_id, body.to_snapshot_id)
    return {
        "from_snapshot_id": str(body.from_snapshot_id),
        "to_snapshot_id": str(body.to_snapshot_id),
        "diff": diff,
    }


@router.post("/import", status_code=201)
def import_snapshot(
    data: SnapshotCreate,
    user: AuthenticatedUser = Depends(require_role(*WRITE_OPERATIONS)),
    session: Session = Depends(get_session),
) -> dict:
    return config_service.import_and_compare(session, data, user).model_dump()


@router.get("/changes")
def list_changes(
    page: PaginationParams = Depends(pagination),
    asset_id: uuid.UUID | None = Query(None),
    disposition: ChangeDisposition | None = Query(None),
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> dict:
    filters = ChangeFilter(asset_id=asset_id, disposition=disposition)
    items, total = config_service.list_changes(session, filters=filters, page=page)
    return {
        "items": [c.model_dump() for c in items],
        "total": total,
        "limit": page.limit,
        "offset": page.offset,
        "is_demo_environment": True,
    }


@router.get("/changes/{change_id}")
def get_change(
    change_id: uuid.UUID,
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> dict:
    return config_service.get_change(session, change_id).model_dump()


@router.post("/changes/{change_id}/disposition")
def set_disposition(
    change_id: uuid.UUID,
    body: DispositionRequest,
    user: AuthenticatedUser = Depends(require_role(*WRITE_OPERATIONS)),
    session: Session = Depends(get_session),
) -> dict:
    return config_service.set_disposition(session, change_id, body, user).model_dump()


@router.get("/changes/{change_id}/evidence-report", response_class=PlainTextResponse)
def change_evidence_report(
    change_id: uuid.UUID,
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> str:
    change = config_service.get_change(session, change_id)
    return config_service.change_evidence_report(session, change)


@router.post("/changes/{change_id}/ai-explain")
def ai_explain_change(
    change_id: uuid.UUID,
    user: AuthenticatedUser = Depends(require_role(*WRITE_OPERATIONS)),
    session: Session = Depends(get_session),
) -> AIChatResponse:
    change = config_service.get_change(session, change_id)
    return run_ai_query(
        session,
        user_id=user.id,
        actor_email=user.email,
        use_case=AIUseCase.CONFIG_CHANGE,
        entity_id=change.id,
        question="Explain this configuration change and whether it appears authorized.",
        conversation_id=None,
    )
