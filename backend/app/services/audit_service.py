"""Centralized audit logging — used by every mutating operation."""
from __future__ import annotations

import uuid

from sqlmodel import Session

from app.core.enums import AuditAction
from app.models.audit import AuditLog


def record_audit(
    session: Session,
    *,
    action: AuditAction,
    actor_user_id: uuid.UUID | None = None,
    actor_email: str | None = None,
    entity_type: str | None = None,
    entity_id: str | uuid.UUID | None = None,
    summary: str = "",
    meta: dict | None = None,
    ip_address: str | None = None,
    commit: bool = True,
) -> AuditLog:
    entry = AuditLog(
        action=action,
        actor_user_id=actor_user_id,
        actor_email=actor_email,
        entity_type=entity_type,
        entity_id=str(entity_id) if entity_id is not None else None,
        summary=summary,
        meta=meta or {},
        ip_address=ip_address,
    )
    session.add(entry)
    if commit:
        session.commit()
        session.refresh(entry)
    return entry
