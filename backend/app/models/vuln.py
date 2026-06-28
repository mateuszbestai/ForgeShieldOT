"""Vulnerability catalog and asset-vulnerability matches."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Index
from sqlmodel import Field

from app.core.enums import (
    ImpactLevel,
    MatchBasis,
    PatchRisk,
    VulnRemediationStatus,
)
from app.models.base import DemoMixin, TimestampMixin, UUIDMixin, json_column


class Vulnerability(UUIDMixin, TimestampMixin, DemoMixin, table=True):
    __tablename__ = "vulnerability"
    __table_args__ = (Index("ix_vuln_kev_cvss", "known_exploited", "cvss_base"),)

    cve_id: str = Field(index=True, unique=True)
    title: str = ""
    description: str = ""
    cvss_base: float = Field(default=0.0)
    cvss_vector: str | None = None
    epss: float | None = None  # placeholder probability score
    known_exploited: bool = Field(default=False, index=True)  # CISA KEV
    advisory_url: str | None = None

    vendor: str | None = Field(default=None, index=True)
    product: str | None = Field(default=None, index=True)
    affected_versions: list[str] = Field(default_factory=list, sa_column=json_column())

    remediation: str | None = None
    workaround: str | None = None
    patch_available: bool = Field(default=False)
    patch_risk: PatchRisk = Field(default=PatchRisk.MEDIUM)
    required_downtime: str | None = None
    ot_compensating_controls: list[str] = Field(default_factory=list, sa_column=json_column())
    safety_impact: ImpactLevel = Field(default=ImpactLevel.NONE)


class AssetVulnerability(UUIDMixin, TimestampMixin, DemoMixin, table=True):
    """Association of a vulnerability to an asset, with OT-aware workflow state."""

    __tablename__ = "asset_vulnerability"
    __table_args__ = (
        Index("ix_av_asset_vuln", "asset_id", "vuln_id", unique=True),
        Index("ix_av_status", "status"),
    )

    asset_id: uuid.UUID = Field(foreign_key="asset.id", index=True)
    vuln_id: uuid.UUID = Field(foreign_key="vulnerability.id", index=True)
    status: VulnRemediationStatus = Field(default=VulnRemediationStatus.OPEN, index=True)
    match_basis: MatchBasis = Field(default=MatchBasis.VENDOR_MODEL_VERSION)
    exploitability_in_context: str | None = None
    asset_exposure_note: str | None = None
    priority_score: int = Field(default=0)  # computed by vuln_service
    detected_at: datetime | None = None

    # Risk-acceptance record
    risk_accepted_by: str | None = None
    risk_acceptance_reason: str | None = None
    risk_accepted_until: datetime | None = None
    remediation_plan: str | None = None
