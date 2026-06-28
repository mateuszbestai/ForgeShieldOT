"""Shared request/response schemas."""
from __future__ import annotations

from typing import Generic, TypeVar

from fastapi import Query
from pydantic import BaseModel

T = TypeVar("T")


class Message(BaseModel):
    message: str


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    limit: int
    offset: int


class PaginationParams(BaseModel):
    limit: int = 50
    offset: int = 0
    search: str | None = None


def pagination(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    search: str | None = Query(None, max_length=200),
) -> PaginationParams:
    return PaginationParams(limit=limit, offset=offset, search=search)


class DemoNotice(BaseModel):
    """Returned on list endpoints to make simulated data unmistakable in the UI."""

    is_demo_environment: bool = True
    notice: str = "Data shown is simulated/demo data for evaluation purposes."
