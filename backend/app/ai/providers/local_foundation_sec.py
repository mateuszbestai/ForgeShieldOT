"""Cisco Foundation-Sec-8B-Reasoning provider (local, OpenAI-compatible endpoint).

Foundation-Sec is a reasoning model; some deployments emit a <think>...</think>
block before the final answer. We request JSON output and strip reasoning blocks
before downstream parsing. Configuration comes from AI_BASE_URL / AI_API_KEY /
AI_MODEL_NAME (default: Foundation-Sec-8B-Reasoning).
"""
from __future__ import annotations

import re

from app.ai.providers.base import ChatMessage
from app.ai.providers.openai_compatible import OpenAICompatibleProvider
from app.core.config import settings

_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


class LocalFoundationSecProvider(OpenAICompatibleProvider):
    provider_name = "local_foundation_sec"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Default model name per the product brief.
        self.model_name = kwargs.get("model_name") or settings.ai_model_name or "Foundation-Sec-8B-Reasoning"

    def complete(
        self,
        messages: list[ChatMessage],
        *,
        temperature: float = 0.2,
        max_tokens: int = 1400,
        response_format: dict | None = None,
    ) -> str:
        # Prefer JSON object output when the server supports it.
        if response_format is None:
            response_format = {"type": "json_object"}
        raw = super().complete(
            messages,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format=response_format,
        )
        return _THINK_RE.sub("", raw).strip()
