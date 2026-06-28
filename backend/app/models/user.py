"""User / Role / UserRole models.

Supabase owns authentication and password hashing. These tables mirror Supabase
users for ownership references, RBAC and auditing. ``User.role`` is the runtime
RBAC source (synced from the JWT ``app_metadata.role`` claim); the Role/UserRole
tables provide the normalized role catalog and assignments required by the data model.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlmodel import Field

from app.core.enums import RoleName
from app.models.base import TimestampMixin, UUIDMixin


class Role(UUIDMixin, TimestampMixin, table=True):
    __tablename__ = "role"

    name: RoleName = Field(unique=True, index=True)
    description: str = ""


class User(UUIDMixin, TimestampMixin, table=True):
    __tablename__ = "app_user"

    supabase_id: str = Field(index=True, unique=True)
    email: str = Field(index=True)
    full_name: str = "Unknown"
    role: RoleName = Field(default=RoleName.VIEWER, index=True)
    is_active: bool = True
    last_login: datetime | None = None


class UserRole(UUIDMixin, table=True):
    """Normalized role assignment (catalog completeness; runtime RBAC uses User.role)."""

    __tablename__ = "user_role"

    user_id: uuid.UUID = Field(foreign_key="app_user.id", index=True)
    role_id: uuid.UUID = Field(foreign_key="role.id", index=True)
