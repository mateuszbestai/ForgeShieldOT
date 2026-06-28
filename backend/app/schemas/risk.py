"""Risk-scoring DTOs."""
from __future__ import annotations

from pydantic import BaseModel

from app.core.enums import RiskBand


class RiskFactor(BaseModel):
    key: str
    label: str
    points: float
    max_points: float
    detail: str
    record_refs: list[str] = []


class RiskResult(BaseModel):
    score: int
    band: RiskBand
    factors: list[RiskFactor]
    top_factors: list[str]
    recommended_action: str


class AssetRiskResponse(RiskResult):
    asset_id: str
    asset_tag: str


class RiskRollup(BaseModel):
    scope: str  # "global" | "site:<id>" | "zone:<id>"
    asset_count: int
    average_score: float
    max_score: int
    band_counts: dict[str, int]
