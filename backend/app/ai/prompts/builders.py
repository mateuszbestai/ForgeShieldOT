"""Per-use-case prompt construction.

Each use case contributes a short task instruction; the shared system prompt enforces
grounding, safety and the JSON output contract. The retrieval context is rendered as a
single delimited UNTRUSTED_DATA block.
"""
from __future__ import annotations

from app.ai.providers.base import ChatMessage
from app.ai.schema import RetrievalContext
from app.ai.system_prompt import build_system_prompt
from app.core.enums import AIUseCase

USE_CASE_INSTRUCTIONS: dict[AIUseCase, str] = {
    AIUseCase.CHAT: (
        "Answer the analyst's question about this OT environment using only the provided "
        "records. If the question cannot be answered from the evidence, say so."
    ),
    AIUseCase.ASSET_RISK: (
        "Explain this asset's risk: what drives it, which vulnerabilities/detections/changes "
        "matter most, and the single safest next action."
    ),
    AIUseCase.DAILY_BRIEF: (
        "Produce a concise daily OT security posture brief for an OT security engineer: key "
        "risks, new detections, unauthorized changes, KEV exposure, and recommended priorities."
    ),
    AIUseCase.VULN_IMPACT: (
        "Explain this vulnerability's impact in the OT context for a plant manager: what it is, "
        "which assets are affected, real-world exploitability, and safety implications."
    ),
    AIUseCase.REMEDIATION_PLAN: (
        "Draft a safe, staged remediation plan for this vulnerability across affected assets, "
        "preferring OT compensating controls where patching is unsafe. Advisory only."
    ),
    AIUseCase.COMPLIANCE_GAP: (
        "Summarize the gap for this compliance control: what evidence is missing and what is "
        "needed to reach an implemented state."
    ),
    AIUseCase.CONFIG_CHANGE: (
        "Explain what changed in this configuration and why it matters operationally and for "
        "safety. Note whether it appears authorized."
    ),
    AIUseCase.INCIDENT_SUMMARY: (
        "Summarize this incident: what happened, affected assets, ATT&CK for ICS mapping, and "
        "the current safe response status."
    ),
    AIUseCase.EXEC_SUMMARY: (
        "Write a brief, non-technical executive summary of this incident for leadership, "
        "emphasizing business/safety impact and status."
    ),
    AIUseCase.ALERT_TRANSLATE: (
        "Translate this technical alert into plain language a plant manager can act on."
    ),
    AIUseCase.NEXT_ACTION: (
        "Recommend the single next-best DEFENSIVE action, with justification grounded in the "
        "evidence."
    ),
    AIUseCase.EVIDENCE_MAP: (
        "Map the available evidence to the relevant compliance control requirements."
    ),
}


def build_messages(context: RetrievalContext, question: str | None = None) -> list[ChatMessage]:
    instruction = USE_CASE_INSTRUCTIONS.get(context.use_case, USE_CASE_INSTRUCTIONS[AIUseCase.CHAT])
    user_question = (question or context.question or "").strip()
    user_content = (
        f"TASK: {instruction}\n\n"
        f"ANALYST QUESTION: {user_question or '(none provided)'}\n\n"
        f"{context.render_data_block()}\n\n"
        "Respond with the JSON object only."
    )
    return [
        {"role": "system", "content": build_system_prompt()},
        {"role": "user", "content": user_content},
    ]
