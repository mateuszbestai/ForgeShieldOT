"""Authentication and role-based access control."""
from __future__ import annotations

import uuid

import pytest


def _a_site_id(client, auth) -> str:
    """Pick an existing seeded site id via an asset (assets carry site_id)."""
    resp = client.get("/api/assets?limit=1", headers=auth("ADMIN"))
    assert resp.status_code == 200
    return resp.json()["items"][0]["site_id"]


def _asset_payload(site_id: str) -> dict:
    return {
        "asset_tag": f"TEST-{uuid.uuid4().hex[:10]}",
        "site_id": site_id,
        "asset_type": "PLC",
        "criticality": "MEDIUM",
    }


def test_health_ok(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.parametrize(
    "role",
    ["ADMIN", "OT_SECURITY_ENGINEER", "SOC_ANALYST", "COMPLIANCE_OFFICER", "VIEWER"],
)
def test_auth_me_returns_role(client, auth, role):
    resp = client.get("/api/auth/me", headers=auth(role))
    assert resp.status_code == 200
    assert resp.json()["role"] == role


def test_missing_token_is_unauthorized(client):
    assert client.get("/api/auth/me").status_code == 401


def test_viewer_cannot_create_asset(client, auth):
    site_id = _a_site_id(client, auth)
    resp = client.post("/api/assets", json=_asset_payload(site_id), headers=auth("VIEWER"))
    assert resp.status_code == 403


@pytest.mark.parametrize("role", ["ADMIN", "OT_SECURITY_ENGINEER"])
def test_write_roles_can_create_asset(client, auth, role):
    site_id = _a_site_id(client, auth)
    resp = client.post("/api/assets", json=_asset_payload(site_id), headers=auth(role))
    assert resp.status_code == 201
    body = resp.json()
    assert body["asset_tag"].startswith("TEST-")
    # Risk should have been computed and persisted on creation.
    assert "risk_band" in body


def test_soc_analyst_cannot_create_asset(client, auth):
    site_id = _a_site_id(client, auth)
    resp = client.post("/api/assets", json=_asset_payload(site_id), headers=auth("SOC_ANALYST"))
    assert resp.status_code == 403


def test_compliance_officer_cannot_create_asset(client, auth):
    site_id = _a_site_id(client, auth)
    resp = client.post("/api/assets", json=_asset_payload(site_id), headers=auth("COMPLIANCE_OFFICER"))
    assert resp.status_code == 403


def test_compliance_officer_can_update_control(client, auth):
    controls = client.get("/api/compliance/controls?limit=1", headers=auth("ADMIN")).json()
    control_id = controls["items"][0]["id"]
    resp = client.patch(
        f"/api/compliance/controls/{control_id}",
        json={"owner": "Compliance QA"},
        headers=auth("COMPLIANCE_OFFICER"),
    )
    assert resp.status_code == 200
    assert resp.json()["owner"] == "Compliance QA"


def test_viewer_cannot_update_control(client, auth):
    controls = client.get("/api/compliance/controls?limit=1", headers=auth("ADMIN")).json()
    control_id = controls["items"][0]["id"]
    resp = client.patch(
        f"/api/compliance/controls/{control_id}",
        json={"owner": "Nope"},
        headers=auth("VIEWER"),
    )
    assert resp.status_code == 403
