"""Report generation across multiple report types."""
from __future__ import annotations

import pytest

# Banner substring every Markdown report must carry (see report_service._DEMO_BANNER).
_DEMO_BANNER = "SIMULATED / DEMO DATA."

# Report types that need no params and render against the seeded dataset.
_REPORT_TYPES = [
    "EXEC_RISK_SUMMARY",
    "ASSET_INVENTORY",
    "VULN_REMEDIATION_PLAN",
    "COMPLIANCE_GAP",
    "IEC62443_EVIDENCE",
    "AI_DAILY_BRIEF",
]


@pytest.mark.parametrize("report_type", _REPORT_TYPES)
def test_generate_report(client, auth, report_type):
    resp = client.post(
        "/api/reports/generate",
        json={"report_type": report_type, "params": {}, "fmt": "MARKDOWN"},
        headers=auth("ADMIN"),
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["report_type"] == report_type
    assert body["fmt"] == "MARKDOWN"
    content = body["content"]
    assert content and len(content) > 50
    assert _DEMO_BANNER in content


def test_at_least_five_distinct_report_types_succeed(client, auth):
    ok = 0
    for report_type in _REPORT_TYPES:
        resp = client.post(
            "/api/reports/generate",
            json={"report_type": report_type, "params": {}, "fmt": "MARKDOWN"},
            headers=auth("ADMIN"),
        )
        if resp.status_code == 201 and _DEMO_BANNER in resp.json()["content"]:
            ok += 1
    assert ok >= 5


def test_report_generation_requires_write_role(client, auth):
    resp = client.post(
        "/api/reports/generate",
        json={"report_type": "ASSET_INVENTORY", "params": {}, "fmt": "MARKDOWN"},
        headers=auth("VIEWER"),
    )
    assert resp.status_code == 403
