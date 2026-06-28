"""Incident and case management."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Index
from sqlmodel import Field

from app.core.enums import IncidentLinkType, IncidentStatus, Severity, TimelineEventKind
from app.models.base import DemoMixin, TimestampMixin, UUIDMixin, json_column


class Incident(UUIDMixin, TimestampMixin, DemoMixin, table=True):
    __tablename__ = "incident"
    __table_args__ = (Index("ix_incident_status_sev", "status", "severity"),)

    reference: str = Field(index=True, unique=True)  # e.g. INC-2026-0001
    title: str
    severity: Severity = Field(default=Severity.MEDIUM, index=True)
    status: IncidentStatus = Field(default=IncidentStatus.OPEN, index=True)
    site_id: uuid.UUID | None = Field(default=None, foreign_key="site.id", index=True)

    summary: str = ""
    attck_ics_technique: str | None = None
    lead_owner: str | None = None

    containment_actions: list[str] = Field(default_factory=list, sa_column=json_column())
    recovery_actions: list[str] = Field(default_factory=list, sa_column=json_column())
    lessons_learned: str | None = None
    compliance_impact: str | None = None

    ai_summary: str | None = None
    executive_summary: str | None = None

    opened_at: datetime | None = None
    closed_at: datetime | None = None


class IncidentTimelineEvent(UUIDMixin, TimestampMixin, DemoMixin, table=True):
    __tablename__ = "incident_timeline_event"
    __table_args__ = (Index("ix_timeline_incident_time", "incident_id", "occurred_at"),)

    incident_id: uuid.UUID = Field(foreign_key="incident.id", index=True)
    kind: TimelineEventKind = Field(default=TimelineEventKind.NOTE)
    description: str = ""
    author: str | None = None
    occurred_at: datetime | None = None
    ref: str | None = None


class IncidentLink(UUIDMixin, TimestampMixin, table=True):
    """Polymorphic link from an incident to a detection/asset/vuln/change."""

    __tablename__ = "incident_link"

    incident_id: uuid.UUID = Field(foreign_key="incident.id", index=True)
    link_type: IncidentLinkType = Field(default=IncidentLinkType.DETECTION)
    entity_id: uuid.UUID = Field(index=True)
