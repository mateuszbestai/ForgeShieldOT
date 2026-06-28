"""CSV export / import round-trip for the asset inventory."""
from __future__ import annotations


def test_export_returns_csv_with_asset_tag_header(client, auth):
    resp = client.get("/api/assets/export", headers=auth("ADMIN"))
    assert resp.status_code == 200
    body = resp.text
    header = body.splitlines()[0]
    assert "asset_tag" in header.split(",")
    # There should be at least one data row from the seeded inventory.
    assert len(body.splitlines()) >= 2


def test_round_trip_import_of_exported_csv(client, auth):
    csv_text = client.get("/api/assets/export", headers=auth("ADMIN")).text

    files = {"file": ("assets.csv", csv_text, "text/csv")}
    resp = client.post("/api/assets/import", files=files, headers=auth("ADMIN"))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "created" in body and "updated" in body
    # Re-importing the current inventory updates existing rows (matched by
    # asset_tag); it must not error out.
    assert body["updated"] >= 1
    assert isinstance(body.get("errors", []), list)


def test_import_requires_write_role(client, auth):
    csv_text = client.get("/api/assets/export", headers=auth("ADMIN")).text
    files = {"file": ("assets.csv", csv_text, "text/csv")}
    resp = client.post("/api/assets/import", files=files, headers=auth("VIEWER"))
    assert resp.status_code == 403
