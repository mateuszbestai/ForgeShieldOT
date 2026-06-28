"""Audit log API (read-only)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlmodel import Session, select

from app.api.deps import AuthenticatedUser, get_current_user
from app.core.db import get_session
from app.core.enums import AuditAction
from app.models.audit import AuditLog
from app.schemas.common import PaginationParams, pagination

router = APIRouter(prefix="/audit-log", tags=["audit"])


@router.get("")
def list_audit(
    page: PaginationParams = Depends(pagination),
    action: AuditAction | None = Query(None),
    entity_type: str | None = Query(None),
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> dict:
    stmt = select(AuditLog)
    count_stmt = select(func.count()).select_from(AuditLog)
    if action:
        stmt = stmt.where(AuditLog.action == action)
        count_stmt = count_stmt.where(AuditLog.action == action)
    if entity_type:
        stmt = stmt.where(AuditLog.entity_type == entity_type)
        count_stmt = count_stmt.where(AuditLog.entity_type == entity_type)
    total = session.exec(count_stmt).one()
    rows = session.exec(
        stmt.order_by(AuditLog.created_at.desc()).offset(page.offset).limit(page.limit)  # type: ignore[attr-defined]
    ).all()
    return {
        "items": [r.model_dump() for r in rows],
        "total": int(total),
        "limit": page.limit,
        "offset": page.offset,
    }
