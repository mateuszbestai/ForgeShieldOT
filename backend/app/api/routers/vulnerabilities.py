"""Vulnerability management API — catalog, asset matching, OT-aware workflow."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlmodel import Session

from app.ai.service import run_ai_query
from app.api.deps import (
    WRITE_OPERATIONS,
    AuthenticatedUser,
    get_current_user,
    require_role,
)
from app.core.db import get_session
from app.core.enums import AIUseCase
from app.schemas.ai import AIChatResponse
from app.schemas.common import PaginationParams, pagination
from app.schemas.vuln import (
    MatchRequest,
    StatusChangeRequest,
    VulnerabilityCreate,
    VulnerabilityUpdate,
    VulnFilter,
)
from app.services import vuln_service

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


@router.get("")
def list_vulnerabilities(
    page: PaginationParams = Depends(pagination),
    vendor: str | None = Query(None),
    known_exploited: bool | None = Query(None),
    min_cvss: float | None = Query(None, ge=0, le=10),
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> dict:
    filters = VulnFilter(
        vendor=vendor,
        known_exploited=known_exploited,
        min_cvss=min_cvss,
        search=page.search,
    )
    items, total = vuln_service.list_vulns(session, filters=filters, page=page)
    return {
        "items": [v.model_dump() for v in items],
        "total": total,
        "limit": page.limit,
        "offset": page.offset,
        "is_demo_environment": True,
    }


@router.get("/stats")
def vulnerability_stats(
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> dict:
    return vuln_service.stats(session)


@router.post("", status_code=201)
def create_vulnerability(
    data: VulnerabilityCreate,
    user: AuthenticatedUser = Depends(require_role(*WRITE_OPERATIONS)),
    session: Session = Depends(get_session),
) -> dict:
    return vuln_service.create_vuln(session, data, user).model_dump()


@router.get("/{vuln_id}")
def get_vulnerability(
    vuln_id: uuid.UUID,
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> dict:
    vuln = vuln_service.get_vuln(session, vuln_id)
    return {
        "vulnerability": vuln.model_dump(),
        "affected_assets": vuln_service.assets_for_vuln(session, vuln),
    }


@router.patch("/{vuln_id}")
def update_vulnerability(
    vuln_id: uuid.UUID,
    data: VulnerabilityUpdate,
    user: AuthenticatedUser = Depends(require_role(*WRITE_OPERATIONS)),
    session: Session = Depends(get_session),
) -> dict:
    return vuln_service.update_vuln(session, vuln_id, data, user).model_dump()


@router.post("/{vuln_id}/match")
def match_vulnerability(
    vuln_id: uuid.UUID,
    _body: MatchRequest | None = None,
    user: AuthenticatedUser = Depends(require_role(*WRITE_OPERATIONS)),
    session: Session = Depends(get_session),
) -> dict:
    vuln = vuln_service.get_vuln(session, vuln_id)
    created = vuln_service.match_vuln_to_assets(session, vuln)
    return {
        "matched": created,
        "affected_assets": vuln_service.assets_for_vuln(session, vuln),
    }


@router.get("/{vuln_id}/assets")
def vulnerability_assets(
    vuln_id: uuid.UUID,
    page: PaginationParams = Depends(pagination),
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> dict:
    vuln = vuln_service.get_vuln(session, vuln_id)
    items = vuln_service.assets_for_vuln(session, vuln)
    return {
        "items": items,
        "total": len(items),
        "limit": page.limit,
        "offset": page.offset,
    }


@router.post("/asset-links/{link_id}/status")
def set_link_status(
    link_id: uuid.UUID,
    body: StatusChangeRequest,
    user: AuthenticatedUser = Depends(require_role(*WRITE_OPERATIONS)),
    session: Session = Depends(get_session),
) -> dict:
    av = vuln_service.set_status(
        session, link_id, body.status, user, acceptance=body.acceptance
    )
    return av.model_dump()


@router.post("/{vuln_id}/remediation-plan")
def remediation_plan(
    vuln_id: uuid.UUID,
    user: AuthenticatedUser = Depends(require_role(*WRITE_OPERATIONS)),
    session: Session = Depends(get_session),
) -> dict:
    vuln = vuln_service.get_vuln(session, vuln_id)
    plan = vuln_service.generate_remediation_plan(session, vuln)
    return {"vuln_id": str(vuln.id), "remediation_plan": plan}


@router.post("/{vuln_id}/ai-explain")
def ai_explain_vulnerability(
    vuln_id: uuid.UUID,
    user: AuthenticatedUser = Depends(require_role(*WRITE_OPERATIONS)),
    session: Session = Depends(get_session),
) -> AIChatResponse:
    vuln = vuln_service.get_vuln(session, vuln_id)
    return run_ai_query(
        session,
        user_id=user.id,
        actor_email=user.email,
        use_case=AIUseCase.VULN_IMPACT,
        entity_id=vuln.id,
        question=f"Explain the impact of {vuln.cve_id} in this OT environment.",
        conversation_id=None,
    )


@router.post("/{vuln_id}/ai-remediation")
def ai_remediation_vulnerability(
    vuln_id: uuid.UUID,
    user: AuthenticatedUser = Depends(require_role(*WRITE_OPERATIONS)),
    session: Session = Depends(get_session),
) -> AIChatResponse:
    vuln = vuln_service.get_vuln(session, vuln_id)
    return run_ai_query(
        session,
        user_id=user.id,
        actor_email=user.email,
        use_case=AIUseCase.REMEDIATION_PLAN,
        entity_id=vuln.id,
        question=(
            f"Propose a safe, OT-aware remediation plan for {vuln.cve_id} "
            "preferring compensating controls where patching is unsafe."
        ),
        conversation_id=None,
    )
