"""Incident & case management API — incidents, timeline, links and AI summaries."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlmodel import Session

from app.ai.service import run_ai_query
from app.api.deps import (
    SOC_OPERATIONS,
    AuthenticatedUser,
    get_current_user,
    require_role,
)
from app.core.db import get_session
from app.core.enums import AIUseCase, IncidentStatus, Severity
from app.schemas.ai import AIChatResponse
from app.schemas.common import PaginationParams, pagination
from app.schemas.incident import (
    FromDetectionRequest,
    IncidentCreate,
    IncidentFilter,
    IncidentUpdate,
    LinkCreate,
    TimelineEventCreate,
)
from app.services import incident_service

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("")
def list_incidents(
    page: PaginationParams = Depends(pagination),
    status: IncidentStatus | None = Query(None),
    severity: Severity | None = Query(None),
    site_id: uuid.UUID | None = Query(None),
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> dict:
    filters = IncidentFilter(
        status=status, severity=severity, site_id=site_id, search=page.search
    )
    items, total = incident_service.list_incidents(session, filters=filters, page=page)
    return {
        "items": [i.model_dump() for i in items],
        "total": total,
        "limit": page.limit,
        "offset": page.offset,
        "is_demo_environment": True,
    }


@router.get("/stats")
def incident_stats(
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> dict:
    return incident_service.stats(session)


@router.get("/checklist")
def safe_ot_checklist(
    _user: AuthenticatedUser = Depends(get_current_user),
) -> dict:
    return {"safe_ot_response_checklist": incident_service.SAFE_OT_RESPONSE_CHECKLIST}


@router.get("/{incident_id}")
def get_incident(
    incident_id: uuid.UUID,
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> dict:
    incident = incident_service.get_incident(session, incident_id)
    return incident_service.incident_detail(session, incident)


@router.post("", status_code=201)
def create_incident(
    data: IncidentCreate,
    user: AuthenticatedUser = Depends(require_role(*SOC_OPERATIONS)),
    session: Session = Depends(get_session),
) -> dict:
    return incident_service.create_incident(session, data, user).model_dump()


@router.post("/from-detection", status_code=201)
def create_from_detection(
    body: FromDetectionRequest,
    user: AuthenticatedUser = Depends(require_role(*SOC_OPERATIONS)),
    session: Session = Depends(get_session),
) -> dict:
    return incident_service.create_from_detection(session, body.detection_id, user).model_dump()


@router.patch("/{incident_id}")
def update_incident(
    incident_id: uuid.UUID,
    data: IncidentUpdate,
    user: AuthenticatedUser = Depends(require_role(*SOC_OPERATIONS)),
    session: Session = Depends(get_session),
) -> dict:
    return incident_service.update_incident(session, incident_id, data, user).model_dump()


@router.post("/{incident_id}/timeline", status_code=201)
def add_timeline_event(
    incident_id: uuid.UUID,
    data: TimelineEventCreate,
    user: AuthenticatedUser = Depends(require_role(*SOC_OPERATIONS)),
    session: Session = Depends(get_session),
) -> dict:
    return incident_service.add_timeline_event(session, incident_id, data, user).model_dump()


@router.post("/{incident_id}/links", status_code=201)
def add_link(
    incident_id: uuid.UUID,
    data: LinkCreate,
    user: AuthenticatedUser = Depends(require_role(*SOC_OPERATIONS)),
    session: Session = Depends(get_session),
) -> dict:
    return incident_service.add_link(session, incident_id, data, user).model_dump()


@router.post("/{incident_id}/ai-summary")
def ai_incident_summary(
    incident_id: uuid.UUID,
    user: AuthenticatedUser = Depends(require_role(*SOC_OPERATIONS)),
    session: Session = Depends(get_session),
) -> AIChatResponse:
    incident = incident_service.get_incident(session, incident_id)
    response = run_ai_query(
        session,
        user_id=user.id,
        actor_email=user.email,
        use_case=AIUseCase.INCIDENT_SUMMARY,
        entity_id=incident.id,
        question="Summarize this incident, its impact and the current response status.",
        conversation_id=None,
    )
    incident.ai_summary = response.summary
    session.add(incident)
    session.commit()
    return response


@router.post("/{incident_id}/ai-exec-summary")
def ai_incident_exec_summary(
    incident_id: uuid.UUID,
    user: AuthenticatedUser = Depends(require_role(*SOC_OPERATIONS)),
    session: Session = Depends(get_session),
) -> AIChatResponse:
    incident = incident_service.get_incident(session, incident_id)
    response = run_ai_query(
        session,
        user_id=user.id,
        actor_email=user.email,
        use_case=AIUseCase.EXEC_SUMMARY,
        entity_id=incident.id,
        question="Write a concise executive summary of this incident for leadership.",
        conversation_id=None,
    )
    incident.executive_summary = response.summary
    session.add(incident)
    session.commit()
    return response
