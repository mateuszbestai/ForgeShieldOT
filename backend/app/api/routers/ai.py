"""AI analyst API — grounded, cited, advisory-only. Rate-limited."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlmodel import Session, select

from app.ai.factory import get_provider
from app.ai.service import run_ai_query
from app.api.deps import AuthenticatedUser, get_current_user
from app.core.config import settings
from app.core.db import get_session
from app.core.rate_limit import ai_rate_limiter
from app.models.ai import AIConversation, AIMessage
from app.schemas.ai import (
    AIChatRequest,
    AIChatResponse,
    AIConversationRead,
    AIHealth,
    AIMessageRead,
)

router = APIRouter(prefix="/ai", tags=["ai"])


@router.post("/chat", response_model=AIChatResponse)
def chat(
    body: AIChatRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
    _rl: None = Depends(ai_rate_limiter),
) -> AIChatResponse:
    return run_ai_query(
        session,
        user_id=user.id,
        actor_email=user.email,
        use_case=body.use_case,
        entity_id=body.entity_id,
        question=body.question,
        conversation_id=body.conversation_id,
    )


@router.get("/health", response_model=AIHealth)
def ai_health(_user: AuthenticatedUser = Depends(get_current_user)) -> AIHealth:
    provider = get_provider()
    healthy = provider.health()
    note = (
        "Provider endpoint reachable."
        if healthy
        else "Provider endpoint not reachable. Set AI_BASE_URL/AI_API_KEY/AI_MODEL_NAME or use AI_PROVIDER=mock."
    )
    return AIHealth(
        provider=settings.ai_provider.value,
        model=provider.model_name,
        healthy=healthy,
        note=note,
    )


@router.get("/conversations", response_model=list[AIConversationRead])
def list_conversations(
    user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> list[AIConversation]:
    return list(
        session.exec(
            select(AIConversation)
            .where(AIConversation.user_id == user.id)
            .order_by(AIConversation.created_at.desc())  # type: ignore[attr-defined]
            .limit(50)
        ).all()
    )


@router.get("/conversations/{conversation_id}/messages", response_model=list[AIMessageRead])
def conversation_messages(
    conversation_id: uuid.UUID,
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> list[AIMessage]:
    return list(
        session.exec(
            select(AIMessage)
            .where(AIMessage.conversation_id == conversation_id)
            .order_by(AIMessage.created_at.asc())  # type: ignore[attr-defined]
        ).all()
    )
