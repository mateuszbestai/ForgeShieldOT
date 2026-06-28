"""Vulnerability management request/response schemas."""
from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.core.enums import ImpactLevel, PatchRisk, VulnRemediationStatus


class VulnerabilityCreate(BaseModel):
    cve_id: str
    title: str = ""
    description: str = ""
    cvss_base: float = 0.0
    cvss_vector: str | None = None
    epss: float | None = None
    known_exploited: bool = False
    advisory_url: str | None = None
    vendor: str | None = None
    product: str | None = None
    affected_versions: list[str] = Field(default_factory=list)
    remediation: str | None = None
    workaround: str | None = None
    patch_available: bool = False
    patch_risk: PatchRisk = PatchRisk.MEDIUM
    required_downtime: str | None = None
    ot_compensating_controls: list[str] = Field(default_factory=list)
    safety_impact: ImpactLevel = ImpactLevel.NONE


class VulnerabilityUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    cvss_base: float | None = None
    cvss_vector: str | None = None
    epss: float | None = None
    known_exploited: bool | None = None
    advisory_url: str | None = None
    vendor: str | None = None
    product: str | None = None
    affected_versions: list[str] | None = None
    remediation: str | None = None
    workaround: str | None = None
    patch_available: bool | None = None
    patch_risk: PatchRisk | None = None
    required_downtime: str | None = None
    ot_compensating_controls: list[str] | None = None
    safety_impact: ImpactLevel | None = None


class VulnFilter(BaseModel):
    vendor: str | None = None
    known_exploited: bool | None = None
    min_cvss: float | None = None
    search: str | None = None


class RiskAcceptanceRequest(BaseModel):
    reason: str
    accepted_by: str
    accepted_until: datetime | None = None


class StatusChangeRequest(BaseModel):
    status: VulnRemediationStatus
    acceptance: RiskAcceptanceRequest | None = None


class MatchRequest(BaseModel):
    """Optional body for triggering an asset match for a vulnerability."""

    asset_ids: list[uuid.UUID] | None = None
