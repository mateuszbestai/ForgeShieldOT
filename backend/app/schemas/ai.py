"""AI chat request/response schemas."""
from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.ai.schema import Citation
from app.core.enums import AIUseCase


class AIChatRequest(BaseModel):
    question: str = Field(default="", max_length=2000)
    use_case: AIUseCase = AIUseCase.CHAT
    entity_id: uuid.UUID | None = None
    conversation_id: uuid.UUID | None = None


class AIChatResponse(BaseModel):
    conversation_id: uuid.UUID
    message_id: uuid.UUID
    use_case: AIUseCase
    summary: str
    findings: list[str]
    citations: list[Citation]
    confidence: str
    assumptions: list[str]
    safe_ot_actions: list[str]
    disclaimer: str
    provider_name: str
    model_name: str
    latency_ms: int


class AIMessageRead(BaseModel):
    id: uuid.UUID
    role: str
    content: str
    citations: list[dict]
    confidence: str | None
    assumptions: list[str]
    safe_ot_actions: list[str]
    use_case: AIUseCase
    created_at: datetime


class AIConversationRead(BaseModel):
    id: uuid.UUID
    title: str
    use_case: AIUseCase
    created_at: datetime


class AIHealth(BaseModel):
    provider: str
    model: str
    healthy: bool
    note: str
