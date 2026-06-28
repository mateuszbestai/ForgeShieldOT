"""Vulnerability-to-asset matching and OT-aware prioritization."""
from __future__ import annotations

import uuid


def _site_id(client, auth) -> str:
    return client.get("/api/assets?limit=1", headers=auth("ADMIN")).json()["items"][0]["site_id"]


def _create_asset(client, auth, **overrides) -> dict:
    site_id = _site_id(client, auth)
    payload = {
        "asset_tag": f"VM-{uuid.uuid4().hex[:10]}",
        "site_id": site_id,
        "asset_type": "PLC",
        "criticality": "MEDIUM",
        "vendor": "AcmeTest",
        "model": "WidgetController",
        "firmware_version": "1.0",
    }
    payload.update(overrides)
    resp = client.post("/api/assets", json=payload, headers=auth("ADMIN"))
    assert resp.status_code == 201, resp.text
    return resp.json()


def _create_vuln(client, auth, **overrides) -> dict:
    payload = {
        "cve_id": f"CVE-TEST-{uuid.uuid4().hex[:8]}",
        "title": "Test vuln",
        "cvss_base": 5.0,
        "vendor": "AcmeTest",
        "product": "WidgetController",
        "affected_versions": [],
    }
    payload.update(overrides)
    resp = client.post("/api/vulnerabilities", json=payload, headers=auth("ADMIN"))
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_match_creates_a_link(client, auth):
    _create_asset(client, auth, vendor="MatchCo", model="CtrlX")
    vuln = _create_vuln(client, auth, vendor="MatchCo", product="CtrlX")
    resp = client.post(f"/api/vulnerabilities/{vuln['id']}/match", headers=auth("ADMIN"))
    assert resp.status_code == 200
    body = resp.json()
    assert body["matched"] >= 1
    assert len(body["affected_assets"]) >= 1


def test_match_requires_write_role(client, auth):
    vuln = _create_vuln(client, auth, vendor="RbacCo", product="CtrlR")
    resp = client.post(f"/api/vulnerabilities/{vuln['id']}/match", headers=auth("VIEWER"))
    assert resp.status_code == 403


def test_kev_high_cvss_yields_higher_priority_than_benign(client, auth):
    # Dangerous: KEV, max CVSS, safety-critical + internet-reachable asset.
    _create_asset(
        client,
        auth,
        vendor="DangerCo",
        model="DangerCtrl",
        criticality="SAFETY_CRITICAL",
        safety_impact="HIGH",
        internet_reachable=True,
    )
    dangerous = _create_vuln(
        client,
        auth,
        vendor="DangerCo",
        product="DangerCtrl",
        cvss_base=9.8,
        known_exploited=True,
        safety_impact="HIGH",
    )
    client.post(f"/api/vulnerabilities/{dangerous['id']}/match", headers=auth("ADMIN"))
    dangerous_links = client.get(
        f"/api/vulnerabilities/{dangerous['id']}/assets", headers=auth("ADMIN")
    ).json()["items"]
    assert dangerous_links
    dangerous_priority = max(item["link"]["priority_score"] for item in dangerous_links)

    # Benign: no KEV, low CVSS, low criticality, fully isolated.
    _create_asset(
        client,
        auth,
        vendor="CalmCo",
        model="CalmCtrl",
        criticality="LOW",
        safety_impact="NONE",
        internet_reachable=False,
        it_reachable=False,
    )
    benign = _create_vuln(
        client,
        auth,
        vendor="CalmCo",
        product="CalmCtrl",
        cvss_base=3.1,
        known_exploited=False,
        safety_impact="NONE",
    )
    client.post(f"/api/vulnerabilities/{benign['id']}/match", headers=auth("ADMIN"))
    benign_links = client.get(
        f"/api/vulnerabilities/{benign['id']}/assets", headers=auth("ADMIN")
    ).json()["items"]
    assert benign_links
    benign_priority = max(item["link"]["priority_score"] for item in benign_links)

    assert dangerous_priority > benign_priority
