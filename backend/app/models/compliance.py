"""Compliance frameworks, controls and evidence."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Index
from sqlmodel import Field

from app.core.enums import ControlStatus, EvidenceSourceType, FrameworkKey
from app.models.base import DemoMixin, TimestampMixin, UUIDMixin


class ComplianceFramework(UUIDMixin, TimestampMixin, DemoMixin, table=True):
    __tablename__ = "compliance_framework"

    key: FrameworkKey = Field(index=True, unique=True)
    name: str = ""
    version: str = ""
    description: str = ""
    is_placeholder: bool = Field(default=False)


class ComplianceControl(UUIDMixin, TimestampMixin, DemoMixin, table=True):
    __tablename__ = "compliance_control"
    __table_args__ = (Index("ix_control_framework_status", "framework_id", "status"),)

    framework_id: uuid.UUID = Field(foreign_key="compliance_framework.id", index=True)
    control_ref: str = Field(index=True)
    title: str = ""
    description: str = ""
    evidence_required: str = ""
    status: ControlStatus = Field(default=ControlStatus.NOT_STARTED, index=True)
    owner: str | None = None
    due_date: datetime | None = None
    last_reviewed: datetime | None = None
    ai_gap_summary: str | None = None


class ComplianceEvidence(UUIDMixin, TimestampMixin, DemoMixin, table=True):
    """Evidence linked to a control. May be auto-linked from other modules."""

    __tablename__ = "compliance_evidence"

    control_id: uuid.UUID = Field(foreign_key="compliance_control.id", index=True)
    source_type: EvidenceSourceType = Field(default=EvidenceSourceType.MANUAL)
    source_id: uuid.UUID | None = None  # id of the linked asset/detection/change/vuln/incident
    description: str = ""
    file_name: str | None = None
    file_note: str | None = None  # metadata only — no raw file bytes stored in MVP
    auto_linked: bool = Field(default=False)
    uploaded_by: str | None = None
