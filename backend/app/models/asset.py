"""Asset inventory, communication relationships and protocol observations."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Index
from sqlmodel import Field

from app.core.enums import (
    AssetType,
    Criticality,
    DiscoverySource,
    ImpactLevel,
    NormalizedProtocol,
    PatchStatus,
    ProtocolDirection,
    PurdueLevel,
    RelationshipType,
    RiskBand,
    SourceType,
    SupportStatus,
)
from app.models.base import DemoMixin, TimestampMixin, UUIDMixin, json_column, utcnow


class Asset(UUIDMixin, TimestampMixin, DemoMixin, table=True):
    __tablename__ = "asset"
    __table_args__ = (
        Index("ix_asset_site_type", "site_id", "asset_type"),
        Index("ix_asset_risk", "risk_band", "risk_score"),
    )

    # Identity
    asset_tag: str = Field(index=True, unique=True)
    hostname: str | None = Field(default=None, index=True)
    ip_address: str | None = Field(default=None, index=True)
    mac_address: str | None = Field(default=None, index=True)

    # Hardware / software
    vendor: str | None = Field(default=None, index=True)
    model: str | None = Field(default=None, index=True)
    firmware_version: str | None = None
    software_version: str | None = None
    serial_number: str | None = None

    # Placement
    site_id: uuid.UUID = Field(foreign_key="site.id", index=True)
    zone_id: uuid.UUID | None = Field(default=None, foreign_key="zone.id", index=True)
    area: str | None = None
    process_line: str | None = None
    purdue_level: PurdueLevel = Field(default=PurdueLevel.L2, index=True)
    conduit: str | None = None

    # Classification
    asset_type: AssetType = Field(index=True)
    criticality: Criticality = Field(default=Criticality.MEDIUM, index=True)
    safety_impact: ImpactLevel = Field(default=ImpactLevel.NONE)
    business_impact: ImpactLevel = Field(default=ImpactLevel.LOW)

    # Ownership / lifecycle
    owner: str | None = None
    last_seen: datetime | None = Field(default=None, index=True)
    discovery_source: DiscoverySource = Field(default=DiscoverySource.MANUAL)
    support_status: SupportStatus = Field(default=SupportStatus.UNKNOWN)
    patch_status: PatchStatus = Field(default=PatchStatus.UNKNOWN)
    os_name: str | None = None  # e.g. "Windows Server 2012" — drives unsupported-OS detection

    # Resilience
    backup_available: bool = Field(default=False)
    config_available: bool = Field(default=False)

    # Network posture (derived/declared; feeds risk engine)
    internet_reachable: bool = Field(default=False)
    it_reachable: bool = Field(default=False)
    remote_access_enabled: bool = Field(default=False)

    # Endpoint protection (only meaningful for host-agent-capable types)
    endpoint_protection_installed: bool = Field(default=False)
    endpoint_protection_healthy: bool = Field(default=False)
    last_scan_at: datetime | None = None

    # Risk (denormalized; recomputed by the risk engine)
    risk_score: int = Field(default=0, index=True)
    risk_band: RiskBand = Field(default=RiskBand.LOW, index=True)

    # Tags / notes — compliance_tags is an untrusted free-form list (sanitized before AI use).
    compliance_tags: list[str] = Field(default_factory=list, sa_column=json_column())
    notes: str | None = None


class AssetRelationship(UUIDMixin, TimestampMixin, DemoMixin, table=True):
    """Observed communication path / conduit between two assets."""

    __tablename__ = "asset_relationship"
    __table_args__ = (
        Index("ix_rel_src_dst_proto", "src_asset_id", "dst_asset_id", "protocol", unique=True),
        Index("ix_rel_unknown", "is_unknown"),
    )

    src_asset_id: uuid.UUID = Field(foreign_key="asset.id", index=True)
    dst_asset_id: uuid.UUID = Field(foreign_key="asset.id", index=True)
    protocol: NormalizedProtocol | None = Field(default=None)
    relationship_type: RelationshipType = Field(default=RelationshipType.COMM)
    is_unknown: bool = Field(default=False)
    is_internet_path: bool = Field(default=False)
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    observation_count: int = Field(default=1)


class ProtocolObservation(UUIDMixin, TimestampMixin, DemoMixin, table=True):
    """A protocol observed on an asset (passive fingerprinting)."""

    __tablename__ = "protocol_observation"
    __table_args__ = (Index("ix_proto_asset", "asset_id", "protocol", unique=True),)

    asset_id: uuid.UUID = Field(foreign_key="asset.id", index=True)
    protocol: NormalizedProtocol = Field(index=True)
    port: int | None = None
    direction: ProtocolDirection = Field(default=ProtocolDirection.BIDIRECTIONAL)
    observation_count: int = Field(default=1)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    source: SourceType = Field(default=SourceType.SEED)
