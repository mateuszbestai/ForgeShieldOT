"""Shared model mixins and helpers.

Design choice: models use explicit foreign-key columns and are queried via
explicit ``select()`` in services rather than ORM ``Relationship()`` objects.
With ~25 interlinked tables (several with multiple FKs to the same table, e.g.
AssetRelationship.src/dst -> Asset) this avoids fragile mapper configuration and
keeps behavior predictable across PostgreSQL and the SQLite test database.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, Column
from sqlmodel import Field, SQLModel


def utcnow() -> datetime:
    """Naive UTC timestamp (consistent across PostgreSQL and SQLite)."""
    return datetime.now(UTC).replace(tzinfo=None)


def new_uuid() -> uuid.UUID:
    return uuid.uuid4()


def json_column() -> Column:
    """A JSON column usable on both PostgreSQL and SQLite."""
    return Column(JSON, nullable=True)


class UUIDMixin(SQLModel):
    id: uuid.UUID = Field(default_factory=new_uuid, primary_key=True, index=True)


class TimestampMixin(SQLModel):
    created_at: datetime = Field(default_factory=utcnow, nullable=False)
    updated_at: datetime = Field(
        default_factory=utcnow,
        nullable=False,
        sa_column_kwargs={"onupdate": utcnow},
    )


class DemoMixin(SQLModel):
    # Every seedable record is flagged so the UI/AI can clearly label simulated data.
    is_demo: bool = Field(default=False, index=True)
