"""Generic OpenAI-compatible chat-completions provider (vLLM / TGI / Ollama / etc.)."""
from __future__ import annotations

import httpx

from app.ai.providers.base import AIProvider, ChatMessage
from app.core.config import settings
from app.core.exceptions import ConfigurationError
from app.core.logging import get_logger

log = get_logger("forgeshield.ai")


class OpenAICompatibleProvider(AIProvider):
    provider_name = "openai_compatible"
    # Set after each ``complete`` call to the model's reasoning trace when the server
    # returns one (llama.cpp ``--reasoning-format`` exposes ``reasoning_content``).
    last_reasoning: str | None = None

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        model_name: str | None = None,
        timeout: int | None = None,
    ):
        self.base_url = (base_url or settings.ai_base_url).rstrip("/")
        self.api_key = api_key or settings.ai_api_key
        self.model_name = model_name or settings.ai_model_name
        self.timeout = timeout or settings.ai_timeout_seconds
        self.last_reasoning = None

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key and self.api_key.lower() not in {"", "not-needed-for-local"}:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def complete(
        self,
        messages: list[ChatMessage],
        *,
        temperature: float = 0.2,
        max_tokens: int = 1400,
        response_format: dict | None = None,
    ) -> str:
        payload: dict = {
            "model": self.model_name,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False,
        }
        if response_format is not None:
            payload["response_format"] = response_format
        url = f"{self.base_url}/chat/completions"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, json=payload, headers=self._headers())
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPError as exc:
            log.warning("ai_provider_error", url=url, error=str(exc))
            raise ConfigurationError(
                f"AI provider request to {self.base_url} failed: {exc}. "
                "Confirm the model endpoint is reachable (AI_BASE_URL / AI_API_KEY / AI_MODEL_NAME)."
            ) from exc
        try:
            message = data["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ConfigurationError(f"Unexpected AI response shape: {exc}") from exc
        # Capture the reasoning trace when the server separates it (non-fatal if absent).
        reasoning = message.get("reasoning_content") if isinstance(message, dict) else None
        self.last_reasoning = reasoning.strip() if isinstance(reasoning, str) and reasoning.strip() else None
        return message.get("content") or ""

    def health(self) -> bool:
        try:
            with httpx.Client(timeout=5) as client:
                resp = client.get(f"{self.base_url}/models", headers=self._headers())
                return resp.status_code < 500
        except httpx.HTTPError:
            return False
