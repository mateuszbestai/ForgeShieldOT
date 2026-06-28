"""Aggregates all domain routers under the API prefix."""
from __future__ import annotations

from fastapi import APIRouter

from app.api.routers import (
    ai,
    assets,
    audit,
    auth,
    compliance,
    config_mgmt,
    detections,
    incidents,
    ingestion,
    integrations,
    network_map,
    reports,
    risk,
    sites,
    vulnerabilities,
)

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(assets.router)
api_router.include_router(sites.router)
api_router.include_router(network_map.router)
api_router.include_router(detections.router)
api_router.include_router(vulnerabilities.router)
api_router.include_router(config_mgmt.router)
api_router.include_router(compliance.router)
api_router.include_router(incidents.router)
api_router.include_router(reports.router)
api_router.include_router(integrations.router)
api_router.include_router(risk.router)
api_router.include_router(ai.router)
api_router.include_router(audit.router)
api_router.include_router(ingestion.router)
