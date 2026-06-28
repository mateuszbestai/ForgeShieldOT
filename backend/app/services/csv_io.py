"""CSV import/export for assets, with validation."""
from __future__ import annotations

import csv
import io
import uuid

from sqlmodel import Session, select

from app.core.enums import (
    AssetType,
    Criticality,
    DiscoverySource,
    ImpactLevel,
    PatchStatus,
    PurdueLevel,
    SupportStatus,
)
from app.core.exceptions import ValidationAppError
from app.core.security import AuthenticatedUser
from app.models.asset import Asset
from app.schemas.asset import AssetCreate, AssetUpdate
from app.services.asset_service import create_asset, update_asset

CSV_COLUMNS = [
    "asset_tag",
    "hostname",
    "ip_address",
    "mac_address",
    "vendor",
    "model",
    "firmware_version",
    "software_version",
    "serial_number",
    "site_id",
    "zone_id",
    "area",
    "process_line",
    "purdue_level",
    "asset_type",
    "criticality",
    "safety_impact",
    "business_impact",
    "owner",
    "support_status",
    "patch_status",
    "os_name",
    "backup_available",
    "config_available",
    "internet_reachable",
    "it_reachable",
    "remote_access_enabled",
    "risk_score",
    "risk_band",
    "notes",
]


def export_assets_csv(session: Session) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for asset in session.exec(select(Asset)).all():
        row = asset.model_dump()
        row["purdue_level"] = int(asset.purdue_level)
        writer.writerow({k: row.get(k, "") for k in CSV_COLUMNS})
    return buf.getvalue()


def _to_bool(value: str | None) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def import_assets_csv(
    session: Session, content: bytes, user: AuthenticatedUser | None
) -> dict:
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValidationAppError("CSV must be UTF-8 encoded") from exc

    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None or "asset_tag" not in reader.fieldnames:
        raise ValidationAppError("CSV must include an 'asset_tag' column")

    created, updated, errors = 0, 0, []
    for i, raw in enumerate(reader, start=2):
        tag = (raw.get("asset_tag") or "").strip()
        if not tag:
            errors.append(f"Row {i}: missing asset_tag")
            continue
        try:
            site_id = raw.get("site_id")
            existing = session.exec(select(Asset).where(Asset.asset_tag == tag)).first()
            if existing is None:
                if not site_id:
                    errors.append(f"Row {i}: site_id is required for new asset '{tag}'")
                    continue
                payload = AssetCreate(
                    asset_tag=tag,
                    hostname=raw.get("hostname") or None,
                    ip_address=raw.get("ip_address") or None,
                    mac_address=raw.get("mac_address") or None,
                    vendor=raw.get("vendor") or None,
                    model=raw.get("model") or None,
                    firmware_version=raw.get("firmware_version") or None,
                    software_version=raw.get("software_version") or None,
                    serial_number=raw.get("serial_number") or None,
                    site_id=uuid.UUID(site_id),
                    zone_id=uuid.UUID(raw["zone_id"]) if raw.get("zone_id") else None,
                    area=raw.get("area") or None,
                    process_line=raw.get("process_line") or None,
                    purdue_level=PurdueLevel(int(raw.get("purdue_level") or 2)),
                    asset_type=AssetType(raw.get("asset_type") or "OEM_VENDOR_SYSTEM"),
                    criticality=Criticality((raw.get("criticality") or "MEDIUM").upper()),
                    safety_impact=ImpactLevel((raw.get("safety_impact") or "NONE").upper()),
                    business_impact=ImpactLevel((raw.get("business_impact") or "LOW").upper()),
                    owner=raw.get("owner") or None,
                    discovery_source=DiscoverySource.CSV_IMPORT,
                    support_status=SupportStatus((raw.get("support_status") or "UNKNOWN").upper()),
                    patch_status=PatchStatus((raw.get("patch_status") or "UNKNOWN").upper()),
                    os_name=raw.get("os_name") or None,
                    backup_available=_to_bool(raw.get("backup_available")),
                    config_available=_to_bool(raw.get("config_available")),
                    internet_reachable=_to_bool(raw.get("internet_reachable")),
                    it_reachable=_to_bool(raw.get("it_reachable")),
                    remote_access_enabled=_to_bool(raw.get("remote_access_enabled")),
                    notes=raw.get("notes") or None,
                )
                create_asset(session, payload, user)
                created += 1
            else:
                upd = AssetUpdate(
                    hostname=raw.get("hostname") or None,
                    ip_address=raw.get("ip_address") or None,
                    vendor=raw.get("vendor") or None,
                    model=raw.get("model") or None,
                    owner=raw.get("owner") or None,
                    notes=raw.get("notes") or None,
                )
                update_asset(session, existing.id, upd, user)  # type: ignore[arg-type]
                updated += 1
        except (ValueError, KeyError) as exc:
            errors.append(f"Row {i} ('{tag}'): {exc}")

    return {"created": created, "updated": updated, "errors": errors}
