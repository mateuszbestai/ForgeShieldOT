"""Report generation request/response schemas."""
from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.core.enums import ReportFormat, ReportType


class GenerateReportRequest(BaseModel):
    report_type: ReportType
    params: dict = Field(default_factory=dict)
    fmt: ReportFormat = ReportFormat.MARKDOWN


class ReportRead(BaseModel):
    """Light read view of a generated report (includes rendered content)."""

    id: uuid.UUID
    report_type: ReportType
    title: str
    fmt: ReportFormat
    summary: str
    content: str
    params: dict
    is_demo: bool
    generated_by: uuid.UUID | None
    created_at: datetime
