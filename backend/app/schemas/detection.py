"""Detection request/response schemas (defensive-only)."""
from __future__ import annotations

import uuid

from pydantic import BaseModel

from app.core.enums import (
    Confidence,
    DetectionStatus,
    DetectionType,
    EvidenceKind,
    Severity,
    SourceType,
)


class DetectionCreate(BaseModel):
    title: str
    detection_type: DetectionType
    severity: Severity | None = None
    confidence: Confidence | None = None
    asset_id: uuid.UUID | None = None
    site_id: uuid.UUID | None = None
    description: str = ""
    source: SourceType = SourceType.SEED


class DetectionUpdate(BaseModel):
    status: DetectionStatus | None = None
    severity: Severity | None = None
    confidence: Confidence | None = None
    triage_notes: str | None = None
    triage_steps: list[str] | None = None


class DetectionFilter(BaseModel):
    status: DetectionStatus | None = None
    severity: Severity | None = None
    detection_type: DetectionType | None = None
    asset_id: uuid.UUID | None = None
    site_id: uuid.UUID | None = None


class EvidenceCreate(BaseModel):
    kind: EvidenceKind = EvidenceKind.LOG
    label: str = ""
    data: dict = {}
