"""AI provider abstraction."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TypedDict


class ChatMessage(TypedDict):
    role: str  # "system" | "user" | "assistant"
    content: str


class AIProvider(ABC):
    """A chat-completion provider. Returns the model's raw text (ideally JSON)."""

    model_name: str = "unknown"
    provider_name: str = "base"

    @abstractmethod
    def complete(
        self,
        messages: list[ChatMessage],
        *,
        temperature: float = 0.2,
        max_tokens: int = 1400,
        response_format: dict | None = None,
    ) -> str:
        ...

    @abstractmethod
    def health(self) -> bool:
        ...

    def name(self) -> str:
        return self.provider_name
