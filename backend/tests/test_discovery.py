"""Simulated passive-discovery ingestion."""
from __future__ import annotations


def _network_obs_sample(client, auth) -> dict:
    sources = client.get("/api/ingest/sources", headers=auth("ADMIN")).json()["sources"]
    for src in sources:
        if src["source"] == "NETWORK_OBS":
            return src["sample_payload"]
    raise AssertionError("NETWORK_OBS sample payload not found")


def test_network_obs_ingest_creates_assets_and_records(client, auth):
    payload = _network_obs_sample(client, auth)
    resp = client.post("/api/ingest/network_obs", json=payload, headers=auth("OT_SECURITY_ENGINEER"))
    assert resp.status_code == 200
    summary = resp.json()
    assert summary["source"] == "NETWORK_OBS"
    assert summary["events_processed"] >= 1
    # A comm observation (it has a peer_ip) creates the source + peer assets and
    # records the protocol and a relationship between them.
    assert summary["assets_created"] >= 1
    assert summary["protocols_recorded"] >= 1
    assert summary["relationships_recorded"] >= 1


def test_network_obs_ingest_is_idempotent_on_reingest(client, auth):
    payload = _network_obs_sample(client, auth)
    first = client.post("/api/ingest/network_obs", json=payload, headers=auth("ADMIN"))
    assert first.status_code == 200
    # Re-ingesting the same payload must not crash and should not re-create assets.
    second = client.post("/api/ingest/network_obs", json=payload, headers=auth("ADMIN"))
    assert second.status_code == 200
    assert second.json()["assets_created"] == 0


def test_unknown_ingest_source_is_rejected(client, auth):
    resp = client.post("/api/ingest/not_a_source", json={}, headers=auth("ADMIN"))
    assert resp.status_code == 422


def test_ingest_requires_write_role(client, auth):
    payload = _network_obs_sample(client, auth)
    resp = client.post("/api/ingest/network_obs", json=payload, headers=auth("VIEWER"))
    assert resp.status_code == 403
