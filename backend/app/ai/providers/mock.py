"""Deterministic, offline AI provider.

Reads the structured UNTRUSTED_DATA block from the prompt and templates a valid,
grounded ``AIAnswer`` JSON — citing only allow-listed records. Used for tests/CI and
as an offline fallback so every AI feature works without a served model.
"""
from __future__ import annotations

import json

from app.ai.providers.base import AIProvider, ChatMessage
from app.ai.schema import DATA_CLOSE, DATA_OPEN


def _extract_data_block(messages: list[ChatMessage]) -> dict:
    blob = "\n".join(m["content"] for m in messages)
    start = blob.find(DATA_OPEN)
    end = blob.find(DATA_CLOSE)
    if start == -1 or end == -1:
        return {}
    inner = blob[start + len(DATA_OPEN) : end].strip()
    try:
        return json.loads(inner)
    except json.JSONDecodeError:
        return {}


def _confidence(n_records: int) -> str:
    if n_records >= 3:
        return "High"
    if n_records >= 1:
        return "Medium"
    return "Low"


_USE_CASE_ACTIONS = {
    "ASSET_RISK": [
        "Confirm the asset's network segmentation and remove any IT/internet reachability.",
        "Verify a current configuration backup exists for this asset.",
        "Assign or confirm an accountable asset owner.",
    ],
    "DAILY_BRIEF": [
        "Triage new high/critical detections first; open incidents where warranted.",
        "Review unauthorized configuration changes against approved baselines.",
        "Prioritize known-exploited vulnerabilities on OT-reachable assets.",
    ],
    "VULN_IMPACT": [
        "Where patching is unsafe, apply OT compensating controls (segmentation, monitoring).",
        "Schedule remediation within an approved maintenance window.",
    ],
    "REMEDIATION_PLAN": [
        "Stage and validate patches in a test environment before any production change.",
        "Coordinate downtime via the formal change-management process.",
        "Maintain passive monitoring until remediation completes.",
    ],
    "COMPLIANCE_GAP": [
        "Attach the missing evidence to the control record.",
        "Assign an owner and a due date to close the gap.",
    ],
    "CONFIG_CHANGE": [
        "Compare the change against the approved baseline.",
        "Confirm an associated, approved change ticket before acting.",
    ],
    "INCIDENT_SUMMARY": [
        "Follow the safe OT response checklist; do not alter PLC logic.",
        "Preserve forensic evidence and keep the incident timeline current.",
    ],
}

_DEFAULT_ACTIONS = [
    "Maintain passive monitoring of the affected assets.",
    "Validate findings with a qualified OT engineer before any change.",
]


class MockProvider(AIProvider):
    provider_name = "mock"
    model_name = "forgeshield-mock-analyst"

    def complete(
        self,
        messages: list[ChatMessage],
        *,
        temperature: float = 0.2,
        max_tokens: int = 1400,
        response_format: dict | None = None,
    ) -> str:
        data = _extract_data_block(messages)
        use_case = str(data.get("use_case", "CHAT"))
        headline = str(data.get("headline", "OT security analysis"))
        records = data.get("records", []) or []
        allowed = data.get("allowed_citations", []) or []

        findings: list[str] = []
        for rec in records[:6]:
            label = rec.get("label", rec.get("ref", "record"))
            fields = rec.get("fields", {}) or {}
            highlight = (
                fields.get("risk_band")
                or fields.get("severity")
                or fields.get("status")
                or fields.get("cvss_base")
                or fields.get("cve_id")
            )
            if highlight is not None:
                findings.append(f"{label}: {highlight}")
            else:
                findings.append(label)

        if records:
            summary = (
                f"{headline}. Based on {len(records)} internal record(s), "
                "the most relevant evidence is summarized below with citations. "
                "All recommendations are passive and safe for OT operations."
            )
        else:
            summary = (
                f"{headline}. There is insufficient internal evidence to answer confidently. "
                "Please provide a more specific asset, vulnerability, detection, control, or "
                "incident reference."
            )

        citations = [
            {"ref": ref, "label": next((r.get("label", "") for r in records if r.get("ref") == ref), "")}
            for ref in allowed[:12]
        ]
        actions = _USE_CASE_ACTIONS.get(use_case, _DEFAULT_ACTIONS)
        assumptions = [
            "Analysis is limited to the internal records provided in this environment.",
            "Data shown is simulated/demo data for evaluation.",
        ]

        answer = {
            "summary": summary,
            "findings": findings,
            "citations": citations,
            "confidence": _confidence(len(records)),
            "assumptions": assumptions,
            "safe_ot_actions": actions,
        }
        return json.dumps(answer)

    def health(self) -> bool:
        return True
