"""Compliance request/response schemas."""
from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel

from app.core.enums import ControlStatus, EvidenceSourceType


class ControlUpdate(BaseModel):
    status: ControlStatus | None = None
    owner: str | None = None
    due_date: datetime | None = None
    ai_gap_summary: str | None = None


class EvidenceCreate(BaseModel):
    control_id: uuid.UUID
    source_type: EvidenceSourceType = EvidenceSourceType.MANUAL
    source_id: uuid.UUID | None = None
    description: str = ""
    file_name: str | None = None
    file_note: str | None = None


class ControlFilter(BaseModel):
    framework_id: uuid.UUID | None = None
    status: ControlStatus | None = None
    search: str | None = None
