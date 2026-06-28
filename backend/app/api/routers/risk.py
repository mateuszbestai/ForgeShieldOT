"""Explainable risk scoring API."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlmodel import Session, select

from app.api.deps import WRITE_OPERATIONS, AuthenticatedUser, get_current_user, require_role
from app.core.db import get_session
from app.core.enums import AuditAction, RiskBand
from app.models.asset import Asset
from app.schemas.risk import AssetRiskResponse, RiskRollup
from app.services import asset_service
from app.services.audit_service import record_audit
from app.services.risk_engine import build_risk_input, compute_risk, recompute_all

router = APIRouter(prefix="/risk", tags=["risk"])


@router.get("/asset/{asset_id}", response_model=AssetRiskResponse)
def asset_risk(
    asset_id: uuid.UUID,
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> AssetRiskResponse:
    asset = asset_service.get_asset(session, asset_id)
    result = compute_risk(build_risk_input(session, asset))
    return AssetRiskResponse(
        asset_id=str(asset.id),
        asset_tag=asset.asset_tag,
        **result.model_dump(),
    )


@router.get("/rollup", response_model=RiskRollup)
def risk_rollup(
    site_id: uuid.UUID | None = Query(None),
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> RiskRollup:
    stmt = select(Asset)
    scope = "global"
    if site_id:
        stmt = stmt.where(Asset.site_id == site_id)
        scope = f"site:{site_id}"
    assets = session.exec(stmt).all()
    band_counts = {b.value: 0 for b in RiskBand}
    total = 0
    max_score = 0
    for a in assets:
        band_counts[a.risk_band.value] += 1
        total += a.risk_score
        max_score = max(max_score, a.risk_score)
    count = len(assets)
    return RiskRollup(
        scope=scope,
        asset_count=count,
        average_score=round(total / count, 1) if count else 0.0,
        max_score=max_score,
        band_counts=band_counts,
    )


@router.post("/recompute")
def recompute(
    user: AuthenticatedUser = Depends(require_role(*WRITE_OPERATIONS)),
    session: Session = Depends(get_session),
) -> dict:
    n = recompute_all(session)
    record_audit(
        session,
        action=AuditAction.RISK_RECOMPUTE,
        actor_user_id=user.id,
        actor_email=user.email,
        summary=f"Recomputed risk for {n} assets",
    )
    return {"recomputed": n}
