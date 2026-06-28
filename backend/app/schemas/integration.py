"""Integration connector request/response schemas (all mock / read-only)."""
from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.core.enums import IntegrationDirection, IntegrationKind


class IntegrationToggle(BaseModel):
    enabled: bool


class ExportRequest(BaseModel):
    """Optional filters for a simulated export. No data is sent anywhere."""

    since: datetime | None = None
    limit: int = Field(default=50, ge=1, le=500)


class IntegrationRead(BaseModel):
    """Light read view of an integration connector."""

    id: uuid.UUID
    kind: IntegrationKind
    name: str
    direction: IntegrationDirection
    enabled: bool
    is_mock: bool
    description: str
    config: dict
    last_sync_summary: str | None
    created_at: datetime
