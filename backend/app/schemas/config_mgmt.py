"""Configuration & change management request/response schemas."""
from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.core.enums import ChangeDisposition, SnapshotKind


class SnapshotCreate(BaseModel):
    asset_id: uuid.UUID
    label: str = ""
    kind: SnapshotKind = SnapshotKind.PLC_PROGRAM
    content: dict = Field(default_factory=dict)
    captured_at: datetime | None = None


class DispositionRequest(BaseModel):
    disposition: ChangeDisposition
    change_ticket: str | None = None
    within_approved_window: bool | None = None


class CompareRequest(BaseModel):
    from_snapshot_id: uuid.UUID
    to_snapshot_id: uuid.UUID


class ChangeFilter(BaseModel):
    asset_id: uuid.UUID | None = None
    disposition: ChangeDisposition | None = None
