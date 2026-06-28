"""Auth schemas."""
from __future__ import annotations

import uuid

from pydantic import BaseModel

from app.core.enums import RoleName


class AuthConfig(BaseModel):
    supabase_url: str
    supabase_anon_key: str
    configured: bool


class CurrentUser(BaseModel):
    id: uuid.UUID
    email: str
    full_name: str
    role: RoleName
