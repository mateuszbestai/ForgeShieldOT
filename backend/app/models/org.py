"""Site and Zone models (plants and Purdue network zones / conduits)."""
from __future__ import annotations

import uuid

from sqlmodel import Field

from app.core.enums import PurdueLevel
from app.models.base import DemoMixin, TimestampMixin, UUIDMixin


class Site(UUIDMixin, TimestampMixin, DemoMixin, table=True):
    __tablename__ = "site"

    name: str = Field(index=True)
    code: str = Field(index=True)
    location: str = ""
    industry: str = ""  # e.g. "Energy", "Automotive manufacturing"
    description: str = ""


class Zone(UUIDMixin, TimestampMixin, DemoMixin, table=True):
    __tablename__ = "zone"

    site_id: uuid.UUID = Field(foreign_key="site.id", index=True)
    name: str = Field(index=True)
    purdue_level: PurdueLevel = Field(default=PurdueLevel.L2, index=True)
    conduit: str | None = None
    internet_exposed: bool = Field(default=False, index=True)
    it_reachable: bool = Field(default=False)
    description: str = ""
