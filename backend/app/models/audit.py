"""Immutable audit log."""
from __future__ import annotations

import uuid

from sqlalchemy import Index
from sqlmodel import Field

from app.core.enums import AuditAction
from app.models.base import TimestampMixin, UUIDMixin, json_column


class AuditLog(UUIDMixin, TimestampMixin, table=True):
    __tablename__ = "audit_log"
    __table_args__ = (
        Index("ix_audit_entity", "entity_type", "entity_id"),
        Index("ix_audit_action_created", "action", "created_at"),
    )

    actor_user_id: uuid.UUID | None = Field(default=None, foreign_key="app_user.id", index=True)
    actor_email: str | None = None
    action: AuditAction = Field(index=True)
    entity_type: str | None = Field(default=None)
    entity_id: str | None = Field(default=None)
    summary: str = ""
    meta: dict = Field(default_factory=dict, sa_column=json_column())
    ip_address: str | None = None
