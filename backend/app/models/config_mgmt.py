"""Configuration snapshots and change tracking (simulated)."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Index
from sqlmodel import Field

from app.core.enums import ChangeDisposition, SnapshotKind, SourceType
from app.models.base import DemoMixin, TimestampMixin, UUIDMixin, json_column


class ConfigSnapshot(UUIDMixin, TimestampMixin, DemoMixin, table=True):
    __tablename__ = "config_snapshot"
    __table_args__ = (Index("ix_snapshot_asset_baseline", "asset_id", "is_baseline"),)

    asset_id: uuid.UUID = Field(foreign_key="asset.id", index=True)
    label: str = ""
    kind: SnapshotKind = Field(default=SnapshotKind.PLC_PROGRAM)
    is_baseline: bool = Field(default=False, index=True)
    # Normalized key/value content used for diffing (e.g. firmware, logic_hash, rules...).
    content: dict = Field(default_factory=dict, sa_column=json_column())
    content_hash: str = ""
    captured_at: datetime | None = None
    source: SourceType = Field(default=SourceType.SEED)


class ConfigChange(UUIDMixin, TimestampMixin, DemoMixin, table=True):
    __tablename__ = "config_change"
    __table_args__ = (Index("ix_change_asset_disp", "asset_id", "disposition"),)

    asset_id: uuid.UUID = Field(foreign_key="asset.id", index=True)
    from_snapshot_id: uuid.UUID | None = Field(default=None, foreign_key="config_snapshot.id")
    to_snapshot_id: uuid.UUID | None = Field(default=None, foreign_key="config_snapshot.id")

    summary: str = ""
    # List of {field, before, after} dicts.
    diff: list[dict] = Field(default_factory=list, sa_column=json_column())
    disposition: ChangeDisposition = Field(default=ChangeDisposition.UNREVIEWED, index=True)
    change_ticket: str | None = None
    within_approved_window: bool = Field(default=True)
    detected_at: datetime | None = None
    reviewed_by: str | None = None
    ai_explanation: str | None = None
