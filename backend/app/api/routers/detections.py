"""Detections API — defensive triage of simulated OT/ICS detections."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlmodel import Session

from app.ai.service import run_ai_query
from app.api.deps import (
    SOC_OPERATIONS,
    WRITE_OPERATIONS,
    AuthenticatedUser,
    get_current_user,
    require_role,
)
from app.core.db import get_session
from app.core.enums import AIUseCase, DetectionStatus, DetectionType, Severity
from app.schemas.ai import AIChatResponse
from app.schemas.common import PaginationParams, pagination
from app.schemas.detection import (
    DetectionCreate,
    DetectionFilter,
    DetectionUpdate,
    EvidenceCreate,
)
from app.services import detection_service

router = APIRouter(prefix="/detections", tags=["detections"])


@router.get("")
def list_detections(
    page: PaginationParams = Depends(pagination),
    status: DetectionStatus | None = Query(None),
    severity: Severity | None = Query(None),
    detection_type: DetectionType | None = Query(None),
    asset_id: uuid.UUID | None = Query(None),
    site_id: uuid.UUID | None = Query(None),
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> dict:
    filters = DetectionFilter(
        status=status,
        severity=severity,
        detection_type=detection_type,
        asset_id=asset_id,
        site_id=site_id,
    )
    items, total = detection_service.list_detections(session, filters=filters, page=page)
    return {
        "items": [d.model_dump() for d in items],
        "total": total,
        "limit": page.limit,
        "offset": page.offset,
        "is_demo_environment": True,
    }


@router.get("/stats")
def detection_stats(
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> dict:
    return detection_service.detection_stats(session)


@router.post("", status_code=201)
def create_detection(
    data: DetectionCreate,
    user: AuthenticatedUser = Depends(require_role(*WRITE_OPERATIONS)),
    session: Session = Depends(get_session),
) -> dict:
    return detection_service.create_detection(session, data, user).model_dump()


@router.get("/{detection_id}")
def get_detection(
    detection_id: uuid.UUID,
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> dict:
    detection = detection_service.get_detection(session, detection_id)
    return detection_service.detection_detail(session, detection)


@router.patch("/{detection_id}")
def update_detection(
    detection_id: uuid.UUID,
    data: DetectionUpdate,
    user: AuthenticatedUser = Depends(require_role(*SOC_OPERATIONS)),
    session: Session = Depends(get_session),
) -> dict:
    return detection_service.update_detection(session, detection_id, data, user).model_dump()


@router.post("/{detection_id}/evidence", status_code=201)
def add_evidence(
    detection_id: uuid.UUID,
    data: EvidenceCreate,
    user: AuthenticatedUser = Depends(require_role(*SOC_OPERATIONS)),
    session: Session = Depends(get_session),
) -> dict:
    return detection_service.add_evidence(session, detection_id, data, user).model_dump()


@router.post("/{detection_id}/ai-translate")
def ai_translate_detection(
    detection_id: uuid.UUID,
    user: AuthenticatedUser = Depends(require_role(*SOC_OPERATIONS)),
    session: Session = Depends(get_session),
) -> AIChatResponse:
    """Translate a technical detection into plain language a plant manager can act on."""
    detection = detection_service.get_detection(session, detection_id)
    response = run_ai_query(
        session,
        user_id=user.id,
        actor_email=user.email,
        use_case=AIUseCase.ALERT_TRANSLATE,
        entity_id=detection.id,
        question="Translate this alert into plain language for a plant manager.",
        conversation_id=None,
    )
    detection.ai_summary = response.summary
    session.add(detection)
    session.commit()
    return response


@router.post("/{detection_id}/ai-next-action")
def ai_next_action_detection(
    detection_id: uuid.UUID,
    user: AuthenticatedUser = Depends(require_role(*SOC_OPERATIONS)),
    session: Session = Depends(get_session),
) -> AIChatResponse:
    detection = detection_service.get_detection(session, detection_id)
    return run_ai_query(
        session,
        user_id=user.id,
        actor_email=user.email,
        use_case=AIUseCase.NEXT_ACTION,
        entity_id=detection.id,
        question="Recommend the single best defensive next action for this detection.",
        conversation_id=None,
    )
