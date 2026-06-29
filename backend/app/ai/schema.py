"""AI answer contract + retrieval-context structures.

Every AI answer — regardless of provider — is coerced into ``AIAnswer`` and
validated: citations are restricted to the retrieval allow-list, and the safety
disclaimer is always present. This is the server-side guarantee that the AI stays
grounded and advisory-only.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ValidationError

from app.core.enums import AIUseCase

DEFAULT_DISCLAIMER = (
    "Advisory only. Based on simulated/demo data in this environment. "
    "No actions are executed by the AI. Validate all recommendations with a "
    "qualified OT engineer before acting on safety-critical systems."
)

DATA_OPEN = "<<UNTRUSTED_DATA"
DATA_CLOSE = "UNTRUSTED_DATA>>"


class Citation(BaseModel):
    ref: str
    label: str = ""


class AttackPathStep(BaseModel):
    """One conceptual stage of a DEFENSIVE attack-path analysis (ATT&CK for ICS).

    Populated only for the ATTACK_PATH / THREAT_SCENARIO use cases; always
    blue-team framing (no exploit code, commands or active steps).
    """

    stage: str = ""  # e.g. "Initial Access", "Lateral Movement", "Impact"
    technique_id: str = ""  # ATT&CK for ICS id, e.g. "T0883"
    technique_name: str = ""
    rationale: str = ""  # which internal record makes this plausible
    detection_gap: str = ""  # where current monitoring would miss this
    mitigation: str = ""  # prioritized passive/safe mitigation


class AIAnswer(BaseModel):
    summary: str
    findings: list[str] = []
    citations: list[Citation] = []
    confidence: Literal["High", "Medium", "Low"] = "Low"
    assumptions: list[str] = []
    safe_ot_actions: list[str] = []
    attack_path: list[AttackPathStep] = []  # only set for ATTACK_PATH/THREAT_SCENARIO
    disclaimer: str = DEFAULT_DISCLAIMER


@dataclass
class EvidenceRecord:
    ref: str  # e.g. "asset:<uuid>", "vuln:CVE-..."
    label: str
    fields: dict[str, Any] = field(default_factory=dict)


@dataclass
class RetrievalContext:
    use_case: AIUseCase
    question: str
    headline: str
    records: list[EvidenceRecord] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def allowed_citations(self) -> set[str]:
        return {r.ref for r in self.records}

    def to_data_payload(self) -> dict[str, Any]:
        return {
            "use_case": self.use_case.value,
            "headline": self.headline,
            "records": [{"ref": r.ref, "label": r.label, "fields": r.fields} for r in self.records],
            "allowed_citations": sorted(self.allowed_citations),
            "notes": self.notes,
        }

    def render_data_block(self) -> str:
        payload = json.dumps(self.to_data_payload(), default=str, indent=2)
        return f"{DATA_OPEN}\n{payload}\n{DATA_CLOSE}"


def _extract_json_object(text: str) -> dict[str, Any] | None:
    """Best-effort extraction of the first top-level JSON object from model text."""
    # Strip reasoning blocks and code fences.
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"```(?:json)?", "", text)
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    for i in range(start, len(text)):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                snippet = text[start : i + 1]
                try:
                    return json.loads(snippet)
                except json.JSONDecodeError:
                    return None
    return None


def _salvage_attack_path(raw: Any) -> list[AttackPathStep]:
    """Best-effort coercion of an attack_path list when full validation failed."""
    steps: list[AttackPathStep] = []
    if not isinstance(raw, list):
        return steps
    for item in raw[:12]:
        if not isinstance(item, dict):
            continue
        try:
            steps.append(AttackPathStep.model_validate(item))
        except ValidationError:
            continue
    return steps


def validate_answer(raw: str, allowed_citations: set[str]) -> AIAnswer:
    """Parse a provider's raw output into a safe, grounded ``AIAnswer``.

    - If JSON parsing fails, wrap the text as a Low-confidence summary.
    - Drop any citation not present in the retrieval allow-list (anti-fabrication).
    - Always force the safety disclaimer.
    """
    data = _extract_json_object(raw)
    if data is None:
        answer = AIAnswer(summary=raw.strip()[:4000] or "No answer produced.", confidence="Low")
    else:
        try:
            answer = AIAnswer.model_validate(data)
        except ValidationError:
            answer = AIAnswer(
                summary=str(data.get("summary") or raw)[:4000],
                findings=[str(x) for x in (data.get("findings") or [])][:20],
                attack_path=_salvage_attack_path(data.get("attack_path")),
                confidence="Low",
            )
    # Citation allow-listing — the core anti-hallucination guarantee.
    answer.citations = [c for c in answer.citations if c.ref in allowed_citations]
    # Force the disclaimer.
    answer.disclaimer = DEFAULT_DISCLAIMER
    return answer
