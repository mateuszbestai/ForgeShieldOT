"""Prompt-injection neutralization for untrusted data fed to the AI.

Defense-in-depth only — the primary guarantees are structural (delimited untrusted
block, citation allow-listing, JSON validation). This module reduces the chance that
attacker-controlled text in logs/notes/uploads is interpreted as instructions.
"""
from __future__ import annotations

import re
from typing import Any

_MAX_FIELD_LEN = 1200

# Patterns commonly used to hijack an assistant. Neutralized, not just dropped, so the
# analyst can still see (and flag) that an injection attempt occurred.
_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts?)", re.I),
    re.compile(r"disregard\s+(the\s+)?(system|previous|above)", re.I),
    re.compile(r"you\s+are\s+now\b", re.I),
    re.compile(r"new\s+instructions?\s*:", re.I),
    re.compile(r"\b(system|assistant|developer)\s*:", re.I),
    re.compile(r"</?(system|assistant|user|s|im_start|im_end)\b[^>]*>", re.I),
    re.compile(r"<\|.*?\|>", re.S),
    re.compile(r"\bBEGIN\s+SYSTEM\b", re.I),
    re.compile(r"override\s+(the\s+)?(safety|rules|guardrails)", re.I),
]

_REDACTION = "[neutralized-instruction]"


def sanitize_text(value: str) -> str:
    text = value
    for pattern in _INJECTION_PATTERNS:
        text = pattern.sub(_REDACTION, text)
    # Collapse the delimiter tokens so untrusted text can't fake the data fence.
    text = text.replace("<<UNTRUSTED_DATA", "<<data").replace("UNTRUSTED_DATA>>", "data>>")
    if len(text) > _MAX_FIELD_LEN:
        text = text[:_MAX_FIELD_LEN] + "…[truncated]"
    return text


def sanitize_value(value: Any) -> Any:
    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, dict):
        return {k: sanitize_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_value(v) for v in value][:50]
    return value
