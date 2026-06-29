"""Cisco Foundation-Sec-8B-Reasoning provider (local, OpenAI-compatible endpoint).

Foundation-Sec-8B-Reasoning is a *reasoning* model: it emits a ``<think>...</think>``
block and then the final answer. We let it reason freely (no output grammar by
default) and rely on the system prompt + ``validate_answer`` to extract the JSON,
which preserves the model's security reasoning quality. A served llama.cpp instance
launched with ``--reasoning-format`` returns the reasoning separately as
``reasoning_content`` (captured by the base provider); for servers that don't, we
strip the inline ``<think>`` block here and keep it as the reasoning trace.

Output strategy is configurable via ``AI_JSON_MODE``:

* ``off`` (default) — no grammar; best for this reasoning model.
* ``json_object`` — request ``{"type": "json_object"}`` (grammar from token 0;
  only suitable for non-reasoning servers).
* ``json_schema`` — request a schema-constrained object.

Configuration comes from ``AI_BASE_URL`` / ``AI_API_KEY`` / ``AI_MODEL_NAME``
(default model: ``Foundation-Sec-8B-Reasoning``).
"""
from __future__ import annotations

import re

from app.ai.providers.base import ChatMessage
from app.ai.providers.openai_compatible import OpenAICompatibleProvider
from app.ai.schema import AIAnswer
from app.core.config import settings

_THINK_RE = re.compile(r"<think>(.*?)</think>", re.DOTALL | re.IGNORECASE)


def _response_format_for(mode: str) -> dict | None:
    mode = (mode or "off").strip().lower()
    if mode == "json_object":
        return {"type": "json_object"}
    if mode == "json_schema":
        return {
            "type": "json_schema",
            "json_schema": {"name": "ai_answer", "schema": AIAnswer.model_json_schema()},
        }
    return None  # "off": let the reasoning model think, then emit JSON.


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
        max_tokens: int = 2048,
        response_format: dict | None = None,
    ) -> str:
        if response_format is None:
            response_format = _response_format_for(settings.ai_json_mode)
        raw = super().complete(
            messages,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format=response_format,
        )
        # When the server didn't split reasoning out, recover it from the inline
        # <think> block so the reasoning trace is still available for audit/UI.
        if not self.last_reasoning:
            think = _THINK_RE.search(raw)
            if think and think.group(1).strip():
                self.last_reasoning = think.group(1).strip()
        return _THINK_RE.sub("", raw).strip()
