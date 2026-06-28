"""Auth endpoints. Tokens are issued by Supabase; the backend only verifies them."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlmodel import Session

from app.core.config import settings
from app.core.db import get_session
from app.core.enums import AuditAction
from app.core.security import AuthenticatedUser, get_current_user
from app.models.base import utcnow
from app.models.user import User
from app.schemas.auth import AuthConfig, CurrentUser
from app.services.audit_service import record_audit

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/config", response_model=AuthConfig)
def auth_config() -> AuthConfig:
    """Public, non-secret Supabase config for the SPA (anon key is browser-safe)."""
    return AuthConfig(
        supabase_url=settings.supabase_url,
        supabase_anon_key=settings.supabase_anon_key,
        configured=bool(settings.supabase_url and settings.supabase_anon_key),
    )


@router.get("/me", response_model=CurrentUser)
def me(
    user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> CurrentUser:
    # Update last_login on identity checks and audit the session.
    db_user = session.get(User, user.id)
    if db_user is not None:
        db_user.last_login = utcnow()
        session.add(db_user)
        session.commit()
    record_audit(
        session,
        action=AuditAction.LOGIN,
        actor_user_id=user.id,
        actor_email=user.email,
        entity_type="app_user",
        entity_id=user.id,
        summary="Authenticated session verified",
    )
    return CurrentUser(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
    )
