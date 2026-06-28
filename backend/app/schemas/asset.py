"""Asset request/response schemas."""
from __future__ import annotations

import uuid

from pydantic import BaseModel

from app.core.enums import (
    AssetType,
    Criticality,
    DiscoverySource,
    ImpactLevel,
    PatchStatus,
    PurdueLevel,
    SupportStatus,
)


class AssetCreate(BaseModel):
    asset_tag: str
    hostname: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    vendor: str | None = None
    model: str | None = None
    firmware_version: str | None = None
    software_version: str | None = None
    serial_number: str | None = None
    site_id: uuid.UUID
    zone_id: uuid.UUID | None = None
    area: str | None = None
    process_line: str | None = None
    purdue_level: PurdueLevel = PurdueLevel.L2
    conduit: str | None = None
    asset_type: AssetType
    criticality: Criticality = Criticality.MEDIUM
    safety_impact: ImpactLevel = ImpactLevel.NONE
    business_impact: ImpactLevel = ImpactLevel.LOW
    owner: str | None = None
    discovery_source: DiscoverySource = DiscoverySource.MANUAL
    support_status: SupportStatus = SupportStatus.UNKNOWN
    patch_status: PatchStatus = PatchStatus.UNKNOWN
    os_name: str | None = None
    backup_available: bool = False
    config_available: bool = False
    internet_reachable: bool = False
    it_reachable: bool = False
    remote_access_enabled: bool = False
    compliance_tags: list[str] = []
    notes: str | None = None


class AssetUpdate(BaseModel):
    hostname: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    vendor: str | None = None
    model: str | None = None
    firmware_version: str | None = None
    software_version: str | None = None
    serial_number: str | None = None
    zone_id: uuid.UUID | None = None
    area: str | None = None
    process_line: str | None = None
    purdue_level: PurdueLevel | None = None
    conduit: str | None = None
    asset_type: AssetType | None = None
    criticality: Criticality | None = None
    safety_impact: ImpactLevel | None = None
    business_impact: ImpactLevel | None = None
    owner: str | None = None
    support_status: SupportStatus | None = None
    patch_status: PatchStatus | None = None
    os_name: str | None = None
    backup_available: bool | None = None
    config_available: bool | None = None
    internet_reachable: bool | None = None
    it_reachable: bool | None = None
    remote_access_enabled: bool | None = None
    endpoint_protection_installed: bool | None = None
    endpoint_protection_healthy: bool | None = None
    compliance_tags: list[str] | None = None
    notes: str | None = None


class AssetFilter(BaseModel):
    site_id: uuid.UUID | None = None
    zone_id: uuid.UUID | None = None
    asset_type: AssetType | None = None
    criticality: Criticality | None = None
    risk_band: str | None = None
    purdue_level: int | None = None
    unknown_only: bool = False
