"""Policy compliance API — frameworks, controls, evidence and gap reporting."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlmodel import Session

from app.ai.service import run_ai_query
from app.api.deps import (
    COMPLIANCE_OPERATIONS,
    AuthenticatedUser,
    get_current_user,
    require_role,
)
from app.core.db import get_session
from app.core.enums import AIUseCase, ControlStatus
from app.schemas.ai import AIChatResponse
from app.schemas.common import PaginationParams, pagination
from app.schemas.compliance import ControlFilter, ControlUpdate, EvidenceCreate
from app.services import compliance_service

router = APIRouter(prefix="/compliance", tags=["compliance"])


@router.get("/frameworks")
def list_frameworks(
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> dict:
    frameworks = compliance_service.list_frameworks(session)
    items = [
        {**fw.model_dump(), "readiness": compliance_service.framework_readiness(session, fw)}
        for fw in frameworks
    ]
    return {"items": items, "total": len(items), "is_demo_environment": True}


@router.get("/frameworks/mapping")
def framework_mapping(
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> dict:
    table = compliance_service.framework_mapping_table(session)
    return {"items": table, "total": len(table), "is_demo_environment": True}


@router.get("/controls")
def list_controls(
    page: PaginationParams = Depends(pagination),
    framework_id: uuid.UUID | None = Query(None),
    status: ControlStatus | None = Query(None),
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> dict:
    filters = ControlFilter(framework_id=framework_id, status=status, search=page.search)
    items, total = compliance_service.list_controls(session, filters=filters, page=page)
    return {
        "items": [c.model_dump() for c in items],
        "total": total,
        "limit": page.limit,
        "offset": page.offset,
        "is_demo_environment": True,
    }


@router.get("/controls/{control_id}")
def get_control(
    control_id: uuid.UUID,
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> dict:
    control = compliance_service.get_control(session, control_id)
    return compliance_service.control_detail(session, control)


@router.patch("/controls/{control_id}")
def update_control(
    control_id: uuid.UUID,
    data: ControlUpdate,
    user: AuthenticatedUser = Depends(require_role(*COMPLIANCE_OPERATIONS)),
    session: Session = Depends(get_session),
) -> dict:
    return compliance_service.update_control(session, control_id, data, user).model_dump()


@router.post("/controls/{control_id}/ai-gap")
def ai_control_gap(
    control_id: uuid.UUID,
    user: AuthenticatedUser = Depends(require_role(*COMPLIANCE_OPERATIONS)),
    session: Session = Depends(get_session),
) -> AIChatResponse:
    control = compliance_service.get_control(session, control_id)
    response = run_ai_query(
        session,
        user_id=user.id,
        actor_email=user.email,
        use_case=AIUseCase.COMPLIANCE_GAP,
        entity_id=control.id,
        question="Summarize the compliance gap for this control and the evidence still required.",
        conversation_id=None,
    )
    control.ai_gap_summary = response.summary
    session.add(control)
    session.commit()
    return response


@router.post("/controls/{control_id}/ai-evidence-map")
def ai_control_evidence_map(
    control_id: uuid.UUID,
    user: AuthenticatedUser = Depends(require_role(*COMPLIANCE_OPERATIONS)),
    session: Session = Depends(get_session),
) -> AIChatResponse:
    """Map the control's available evidence to its requirements and flag remaining gaps."""
    control = compliance_service.get_control(session, control_id)
    return run_ai_query(
        session,
        user_id=user.id,
        actor_email=user.email,
        use_case=AIUseCase.EVIDENCE_MAP,
        entity_id=control.id,
        question="Map the available evidence to this control's requirements and flag any gaps.",
        conversation_id=None,
    )


@router.post("/evidence", status_code=201)
def add_evidence(
    data: EvidenceCreate,
    user: AuthenticatedUser = Depends(require_role(*COMPLIANCE_OPERATIONS)),
    session: Session = Depends(get_session),
) -> dict:
    return compliance_service.add_evidence(session, data, user).model_dump()


@router.post("/auto-link")
def auto_link_evidence(
    user: AuthenticatedUser = Depends(require_role(*COMPLIANCE_OPERATIONS)),
    session: Session = Depends(get_session),
) -> dict:
    created = compliance_service.auto_link_evidence(session, user)
    return {"created": created}


@router.get("/gap-report")
def gap_report(
    framework_id: uuid.UUID | None = Query(None),
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> dict:
    report = compliance_service.gap_report(session, framework_id)
    return {"items": report, "total": len(report), "is_demo_environment": True}
