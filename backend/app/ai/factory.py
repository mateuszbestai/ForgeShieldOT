"""Selects the active AI provider from configuration."""
from __future__ import annotations

from app.ai.providers.base import AIProvider
from app.ai.providers.local_foundation_sec import LocalFoundationSecProvider
from app.ai.providers.mock import MockProvider
from app.ai.providers.openai_compatible import OpenAICompatibleProvider
from app.core.config import settings
from app.core.enums import AIProviderKind


def get_provider(kind: AIProviderKind | None = None) -> AIProvider:
    kind = kind or settings.ai_provider
    if kind == AIProviderKind.MOCK:
        return MockProvider()
    if kind == AIProviderKind.OPENAI_COMPATIBLE:
        return OpenAICompatibleProvider()
    return LocalFoundationSecProvider()
