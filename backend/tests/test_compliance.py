"""Compliance frameworks, controls, evidence auto-linking and gap reporting."""
from __future__ import annotations


def test_frameworks_count_is_nine(client, auth):
    resp = client.get("/api/compliance/frameworks", headers=auth("ADMIN"))
    assert resp.status_code == 200
    assert resp.json()["total"] == 9


def test_controls_list_is_non_empty(client, auth):
    resp = client.get("/api/compliance/controls?limit=200", headers=auth("ADMIN"))
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] >= 1
    assert len(body["items"]) >= 1


def test_auto_link_returns_a_count(client, auth):
    resp = client.post("/api/compliance/auto-link", headers=auth("COMPLIANCE_OFFICER"))
    assert resp.status_code == 200
    body = resp.json()
    assert "created" in body
    assert isinstance(body["created"], int)
    assert body["created"] >= 0


def test_auto_link_is_idempotent(client, auth):
    # After the first auto-link the second adds nothing new.
    client.post("/api/compliance/auto-link", headers=auth("COMPLIANCE_OFFICER"))
    second = client.post("/api/compliance/auto-link", headers=auth("COMPLIANCE_OFFICER"))
    assert second.status_code == 200
    assert second.json()["created"] == 0


def test_gap_report_returns_gaps(client, auth):
    resp = client.get("/api/compliance/gap-report", headers=auth("ADMIN"))
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] >= 1
    # Every reported framework section carries at least one open gap control.
    assert any(section["gap_count"] >= 1 for section in body["items"])
    for section in body["items"]:
        assert section["gaps"]
