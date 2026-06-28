"""Incident & case management request/response schemas."""
from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel

from app.core.enums import IncidentLinkType, IncidentStatus, Severity, TimelineEventKind


class IncidentCreate(BaseModel):
    title: str
    severity: Severity = Severity.MEDIUM
    site_id: uuid.UUID | None = None
    summary: str | None = None
    attck_ics_technique: str | None = None
    lead_owner: str | None = None


class IncidentUpdate(BaseModel):
    status: IncidentStatus | None = None
    summary: str | None = None
    lead_owner: str | None = None
    containment_actions: list[str] | None = None
    recovery_actions: list[str] | None = None
    lessons_learned: str | None = None
    compliance_impact: str | None = None


class TimelineEventCreate(BaseModel):
    kind: TimelineEventKind = TimelineEventKind.NOTE
    description: str = ""
    occurred_at: datetime | None = None
    ref: str | None = None


class LinkCreate(BaseModel):
    link_type: IncidentLinkType
    entity_id: uuid.UUID


class FromDetectionRequest(BaseModel):
    detection_id: uuid.UUID


class IncidentFilter(BaseModel):
    status: IncidentStatus | None = None
    severity: Severity | None = None
    site_id: uuid.UUID | None = None
    search: str | None = None
