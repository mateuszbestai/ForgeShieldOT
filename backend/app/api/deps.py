"""Shared API dependencies and helpers."""
from __future__ import annotations

import uuid
from typing import TypeVar

from sqlmodel import Session, SQLModel

from app.core.exceptions import NotFoundError

# Re-export the common auth/pagination dependencies for routers.
from app.core.security import (  # noqa: F401
    COMPLIANCE_OPERATIONS,
    SOC_OPERATIONS,
    WRITE_OPERATIONS,
    AuthenticatedUser,
    get_current_user,
    get_optional_user,
    require_role,
)
from app.schemas.common import PaginationParams, pagination  # noqa: F401

T = TypeVar("T", bound=SQLModel)


def get_or_404(session: Session, model: type[T], obj_id: uuid.UUID, name: str | None = None) -> T:
    obj = session.get(model, obj_id)
    if obj is None:
        raise NotFoundError(f"{name or model.__name__} not found")
    return obj
