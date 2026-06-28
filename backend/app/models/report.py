"""Generated reports (rendered Markdown / HTML, optional PDF)."""
from __future__ import annotations

import uuid

from sqlmodel import Field

from app.core.enums import ReportFormat, ReportType
from app.models.base import DemoMixin, TimestampMixin, UUIDMixin, json_column


class Report(UUIDMixin, TimestampMixin, DemoMixin, table=True):
    __tablename__ = "report"

    report_type: ReportType = Field(index=True)
    title: str = ""
    fmt: ReportFormat = Field(default=ReportFormat.MARKDOWN)
    content: str = ""  # rendered Markdown or HTML
    params: dict = Field(default_factory=dict, sa_column=json_column())
    generated_by: uuid.UUID | None = Field(default=None, foreign_key="app_user.id")
    summary: str = ""
