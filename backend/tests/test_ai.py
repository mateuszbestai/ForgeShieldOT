"""Grounded, cited, advisory-only AI analyst."""
from __future__ import annotations

import json
import re

import pytest

from app.ai.schema import DEFAULT_DISCLAIMER, validate_answer

# A citation ref always looks like ``<type>:<id>`` for an internal record type.
_INTERNAL_REF = re.compile(
    r"^(asset|vuln|detection|control|config_change|incident|evidence):.+"
)


def _first_asset_id(client, auth) -> str:
    assets = client.get("/api/assets?limit=1", headers=auth("ADMIN")).json()
    return assets["items"][0]["id"]


def test_chat_use_case_returns_grounded_answer(client, auth):
    resp = client.post(
        "/api/ai/chat",
        json={"question": "What are the top OT risks?", "use_case": "CHAT"},
        headers=auth("ADMIN"),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["confidence"] in {"High", "Medium", "Low"}
    assert body["disclaimer"].startswith("Advisory only")
    assert body["safe_ot_actions"]
    for citation in body["citations"]:
        assert _INTERNAL_REF.match(citation["ref"]), citation["ref"]


def test_asset_risk_use_case_is_grounded_in_the_asset(client, auth):
    asset_id = _first_asset_id(client, auth)
    resp = client.post(
        "/api/ai/chat",
        json={"question": "Why is this asset risky?", "use_case": "ASSET_RISK", "entity_id": asset_id},
        headers=auth("ADMIN"),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["confidence"] in {"High", "Medium", "Low"}
    assert body["disclaimer"].startswith("Advisory only")
    assert body["safe_ot_actions"]
    refs = {c["ref"] for c in body["citations"]}
    # The asset itself must be among the allowed/cited records.
    assert f"asset:{asset_id}" in refs
    for ref in refs:
        assert _INTERNAL_REF.match(ref), ref


def test_validate_answer_drops_out_of_allowlist_citations_and_forces_disclaimer():
    raw = json.dumps(
        {
            "summary": "Test summary.",
            "findings": ["finding one"],
            "citations": [
                {"ref": "asset:allowed-1", "label": "ok"},
                {"ref": "vuln:CVE-FAKE-9999", "label": "fabricated"},
            ],
            "confidence": "High",
            "safe_ot_actions": ["Maintain passive monitoring."],
            "disclaimer": "I am a custom disclaimer that should be overridden.",
        }
    )
    answer = validate_answer(raw, allowed_citations={"asset:allowed-1"})
    cited = {c.ref for c in answer.citations}
    assert cited == {"asset:allowed-1"}
    assert "vuln:CVE-FAKE-9999" not in cited
    # The disclaimer is always forced to the safe default.
    assert answer.disclaimer == DEFAULT_DISCLAIMER


def test_validate_answer_wraps_non_json_as_low_confidence():
    answer = validate_answer("this is not json at all", allowed_citations=set())
    assert answer.confidence == "Low"
    assert answer.disclaimer == DEFAULT_DISCLAIMER
    assert answer.citations == []
