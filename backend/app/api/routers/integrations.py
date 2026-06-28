"""Integrations API — mock, read-only connectors (export/import are simulated)."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlmodel import Session

from app.api.deps import (
    WRITE_OPERATIONS,
    AuthenticatedUser,
    get_current_user,
    require_role,
)
from app.core.db import get_session
from app.schemas.integration import ExportRequest, IntegrationToggle
from app.services import integration_service

router = APIRouter(prefix="/integrations", tags=["integrations"])


@router.get("")
def list_integrations(
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> dict:
    # Lazy bootstrap so the page is never empty in a fresh environment.
    integration_service.ensure_default_integrations(session)
    items = integration_service.list_integrations(session)
    return {
        "items": [_integration_dict(i) for i in items],
        "total": len(items),
        "is_demo_environment": True,
        "notice": (
            "All integrations are simulated/mock and read-only. No data is sent "
            "to or read from any external system."
        ),
    }


@router.get("/{integration_id}")
def get_integration(
    integration_id: uuid.UUID,
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> dict:
    integration = integration_service.get_integration(session, integration_id)
    return _integration_dict(integration)


@router.post("/{integration_id}/toggle")
def toggle_integration(
    integration_id: uuid.UUID,
    data: IntegrationToggle,
    user: AuthenticatedUser = Depends(require_role(*WRITE_OPERATIONS)),
    session: Session = Depends(get_session),
) -> dict:
    integration = integration_service.toggle(session, integration_id, data.enabled, user)
    return _integration_dict(integration)


@router.post("/{integration_id}/export")
def export_integration(
    integration_id: uuid.UUID,
    data: ExportRequest | None = None,
    user: AuthenticatedUser = Depends(require_role(*WRITE_OPERATIONS)),
    session: Session = Depends(get_session),
) -> dict:
    integration = integration_service.get_integration(session, integration_id)
    return integration_service.export(session, integration, data or ExportRequest(), user)


@router.post("/{integration_id}/import")
def import_integration(
    integration_id: uuid.UUID,
    user: AuthenticatedUser = Depends(require_role(*WRITE_OPERATIONS)),
    session: Session = Depends(get_session),
) -> dict:
    integration = integration_service.get_integration(session, integration_id)
    return integration_service.simulate_import(session, integration, user)


def _integration_dict(integration) -> dict:
    return {
        "id": str(integration.id),
        "kind": integration.kind.value,
        "name": integration.name,
        "direction": integration.direction.value,
        "enabled": integration.enabled,
        "is_mock": integration.is_mock,
        "description": integration.description,
        "config": integration.config,
        "last_sync_summary": integration.last_sync_summary,
        "created_at": integration.created_at.isoformat() if integration.created_at else None,
    }
