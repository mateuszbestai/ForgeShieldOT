"""AI conversations and messages (full prompt/response retained for audit)."""
from __future__ import annotations

import uuid

from sqlmodel import Field

from app.core.enums import AIUseCase, MessageRole
from app.models.base import TimestampMixin, UUIDMixin, json_column


class AIConversation(UUIDMixin, TimestampMixin, table=True):
    __tablename__ = "ai_conversation"

    user_id: uuid.UUID | None = Field(default=None, foreign_key="app_user.id", index=True)
    title: str = "New conversation"
    use_case: AIUseCase = Field(default=AIUseCase.CHAT)


class AIMessage(UUIDMixin, TimestampMixin, table=True):
    __tablename__ = "ai_message"

    conversation_id: uuid.UUID = Field(foreign_key="ai_conversation.id", index=True)
    role: MessageRole = Field(default=MessageRole.USER)
    content: str = ""
    # For assistant messages: structured AIAnswer fields for traceability.
    citations: list[dict] = Field(default_factory=list, sa_column=json_column())
    confidence: str | None = None
    assumptions: list[str] = Field(default_factory=list, sa_column=json_column())
    safe_ot_actions: list[str] = Field(default_factory=list, sa_column=json_column())
    # Defensive attack-path steps (ATTACK_PATH/THREAT_SCENARIO use cases only).
    attack_path: list[dict] = Field(default_factory=list, sa_column=json_column())
    # The model's reasoning trace, captured when the server exposes it.
    reasoning: str | None = None
    provider_name: str | None = None
    model_name: str | None = None
    latency_ms: int | None = None
    use_case: AIUseCase = Field(default=AIUseCase.CHAT)
