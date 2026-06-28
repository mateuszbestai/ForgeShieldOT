"""Detections (defensive-only) and their evidence."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Index
from sqlmodel import Field

from app.core.enums import (
    Confidence,
    DetectionStatus,
    DetectionType,
    EvidenceKind,
    Severity,
    SourceType,
)
from app.models.base import DemoMixin, TimestampMixin, UUIDMixin, json_column


class Detection(UUIDMixin, TimestampMixin, DemoMixin, table=True):
    __tablename__ = "detection"
    __table_args__ = (
        Index("ix_detection_status_sev", "status", "severity"),
        Index("ix_detection_asset", "asset_id"),
    )

    title: str
    detection_type: DetectionType = Field(index=True)
    severity: Severity = Field(default=Severity.MEDIUM, index=True)
    confidence: Confidence = Field(default=Confidence.MEDIUM)
    status: DetectionStatus = Field(default=DetectionStatus.NEW, index=True)

    asset_id: uuid.UUID | None = Field(default=None, foreign_key="asset.id", index=True)
    site_id: uuid.UUID | None = Field(default=None, foreign_key="site.id", index=True)

    description: str = ""
    # MITRE ATT&CK for ICS technique id(s), e.g. "T0883", "T0866"
    attck_ics_technique: str | None = None
    attck_ics_tactic: str | None = None

    triage_steps: list[str] = Field(default_factory=list, sa_column=json_column())
    safe_containment_steps: list[str] = Field(default_factory=list, sa_column=json_column())
    ai_summary: str | None = None

    source: SourceType = Field(default=SourceType.SEED)
    detected_at: datetime | None = Field(default=None, index=True)


class DetectionEvidence(UUIDMixin, TimestampMixin, DemoMixin, table=True):
    __tablename__ = "detection_evidence"

    detection_id: uuid.UUID = Field(foreign_key="detection.id", index=True)
    kind: EvidenceKind = Field(default=EvidenceKind.LOG)
    label: str = ""
    # Untrusted data (sanitized before any AI use).
    data: dict = Field(default_factory=dict, sa_column=json_column())
