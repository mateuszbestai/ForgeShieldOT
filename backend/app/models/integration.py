"""Integration connectors (all mock / read-only in MVP)."""
from __future__ import annotations

from sqlmodel import Field

from app.core.enums import IntegrationDirection, IntegrationKind
from app.models.base import DemoMixin, TimestampMixin, UUIDMixin, json_column


class Integration(UUIDMixin, TimestampMixin, DemoMixin, table=True):
    __tablename__ = "integration"

    kind: IntegrationKind = Field(index=True)
    name: str = ""
    direction: IntegrationDirection = Field(default=IntegrationDirection.EXPORT)
    enabled: bool = Field(default=False)
    is_mock: bool = Field(default=True)  # always true in MVP
    # Non-secret configuration only (endpoints, labels). Never store credentials here.
    config: dict = Field(default_factory=dict, sa_column=json_column())
    description: str = ""
    last_sync_summary: str | None = None
