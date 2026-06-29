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
    "ALERT_TRANSLATE": [
        "Notify the responsible plant engineer with the plain-language summary.",
        "Confirm whether the activity was part of an approved maintenance window.",
    ],
    "NEXT_ACTION": [
        "Take the single highest-priority passive action first, then re-assess.",
        "Validate the recommended action with a qualified OT engineer before acting.",
    ],
    "EVIDENCE_MAP": [
        "Attach the mapped evidence to the corresponding control record.",
        "Flag any control requirement that still lacks supporting evidence.",
    ],
    "ATTACK_PATH": [
        "Verify segmentation on every conduit the path traverses; remove any IT/internet reachability.",
        "Prioritize detection coverage for the techniques highlighted along the path.",
        "Confirm current, tested backups exist for the targeted safety/critical assets.",
    ],
    "THREAT_SCENARIO": [
        "Run a tabletop over the modeled scenario with OT and SOC stakeholders.",
        "Close the detection-coverage gaps identified for the in-scope assets.",
    ],
}

_DEFAULT_ACTIONS = [
    "Maintain passive monitoring of the affected assets.",
    "Validate findings with a qualified OT engineer before any change.",
]

_ATTACK_STAGES = ["Initial Access", "Lateral Movement", "Impact"]


def _build_attack_path(records: list[dict]) -> list[dict]:
    """Derive a deterministic, grounded DEFENSIVE attack path from the evidence.

    Each step cites the technique already present on a record (detections/incidents
    carry ``attck_ics_technique``) and frames everything as blue-team mitigation —
    never offensive content.
    """
    steps: list[dict] = []
    for idx, rec in enumerate(records[:3]):
        fields = rec.get("fields", {}) or {}
        technique = fields.get("attck_ics_technique") or ""
        label = rec.get("label", rec.get("ref", "record"))
        steps.append(
            {
                "stage": _ATTACK_STAGES[idx % len(_ATTACK_STAGES)],
                "technique_id": str(technique) if technique else "",
                "technique_name": "",
                "rationale": f"Plausible based on internal record {label}.",
                "detection_gap": "Confirm monitoring covers this conduit/technique.",
                "mitigation": "Apply passive segmentation and monitoring; no active or offensive steps.",
            }
        )
    return steps


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
        if use_case in {"ATTACK_PATH", "THREAT_SCENARIO"} and records:
            answer["attack_path"] = _build_attack_path(records)
        return json.dumps(answer)

    def health(self) -> bool:
        return True
