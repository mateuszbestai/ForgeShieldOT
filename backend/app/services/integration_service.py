"""Integration connector business logic.

All connectors are MOCK and read-only: nothing is ever sent to an external
system and no credentials are stored. Exports build a representative simulated
payload shaped like the target platform (Splunk HEC event, Sentinel/Log
Analytics record, ServiceNow incident, Jira issue) and RETURN it to the caller;
imports return a simulated summary and do not modify any data. Every simulated
record is explicitly marked with ``"_simulated": true``.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import func
from sqlmodel import Session, select

from app.core.enums import (
    AuditAction,
    IntegrationDirection,
    IntegrationKind,
)
from app.core.exceptions import NotFoundError, ValidationAppError
from app.core.security import AuthenticatedUser
from app.models.asset import Asset
from app.models.base import utcnow
from app.models.detection import Detection
from app.models.incident import Incident
from app.models.integration import Integration
from app.schemas.integration import ExportRequest
from app.services.audit_service import record_audit

# --------------------------------------------------------------------------- #
# Default mock connectors (the seed module owns DB seeding; this is only the
# template used by the lazy bootstrap ``ensure_default_integrations``).
# --------------------------------------------------------------------------- #
DEFAULT_INTEGRATIONS: list[dict] = [
    {
        "kind": IntegrationKind.SIEM_WEBHOOK,
        "name": "Generic SIEM Webhook",
        "direction": IntegrationDirection.EXPORT,
        "description": "Forward detections/incidents to a generic SIEM webhook (simulated).",
        "is_mock": True,
        "enabled": True,
    },
    {
        "kind": IntegrationKind.SPLUNK,
        "name": "Splunk HEC",
        "direction": IntegrationDirection.EXPORT,
        "description": "Export events to Splunk via HTTP Event Collector (simulated).",
        "is_mock": True,
        "enabled": True,
    },
    {
        "kind": IntegrationKind.SENTINEL,
        "name": "Microsoft Sentinel",
        "direction": IntegrationDirection.EXPORT,
        "description": "Export records to Azure Sentinel / Log Analytics (simulated).",
        "is_mock": True,
        "enabled": False,
    },
    {
        "kind": IntegrationKind.SERVICENOW,
        "name": "ServiceNow ITSM",
        "direction": IntegrationDirection.EXPORT,
        "description": "Raise ServiceNow incident tickets from incidents (simulated).",
        "is_mock": True,
        "enabled": False,
    },
    {
        "kind": IntegrationKind.JIRA,
        "name": "Jira",
        "direction": IntegrationDirection.EXPORT,
        "description": "Create Jira issues from incidents/detections (simulated).",
        "is_mock": True,
        "enabled": False,
    },
    {
        "kind": IntegrationKind.DEFENDER,
        "name": "Microsoft Defender for Endpoint",
        "direction": IntegrationDirection.IMPORT,
        "description": "Import EDR alerts/endpoints from Microsoft Defender (simulated).",
        "is_mock": True,
        "enabled": False,
    },
    {
        "kind": IntegrationKind.OT_PLATFORM_IMPORT,
        "name": "OT Visibility Platform (Claroty / Nozomi / Dragos)",
        "direction": IntegrationDirection.IMPORT,
        "description": "Import asset & comm inventory from an OT platform (simulated placeholder).",
        "is_mock": True,
        "enabled": False,
    },
    {
        "kind": IntegrationKind.VULN_SCANNER_IMPORT,
        "name": "Vulnerability Scanner (Tenable / Qualys / Rapid7)",
        "direction": IntegrationDirection.IMPORT,
        "description": "Import vulnerability findings from a scanner (simulated placeholder).",
        "is_mock": True,
        "enabled": False,
    },
    {
        "kind": IntegrationKind.OEM_IMPORT,
        "name": "OEM Vendor Feed (Siemens / Rockwell / Schneider / ABB / Honeywell / Emerson)",
        "direction": IntegrationDirection.IMPORT,
        "description": "Import OEM asset/advisory data from a vendor feed (simulated placeholder).",
        "is_mock": True,
        "enabled": False,
    },
]

# Human-readable vendor names used in simulated import summaries.
_IMPORT_VENDORS: dict[IntegrationKind, str] = {
    IntegrationKind.DEFENDER: "Microsoft Defender for Endpoint",
    IntegrationKind.OT_PLATFORM_IMPORT: "Claroty / Nozomi / Dragos",
    IntegrationKind.VULN_SCANNER_IMPORT: "Tenable / Qualys / Rapid7",
    IntegrationKind.OEM_IMPORT: "Siemens / Rockwell / Schneider / ABB / Honeywell / Emerson",
}


# --------------------------------------------------------------------------- #
# Bootstrap / reads
# --------------------------------------------------------------------------- #
def ensure_default_integrations(session: Session) -> int:
    """Idempotently create the default mock connectors if none exist.

    Used as a lazy bootstrap by the integrations list endpoint so the page is
    never empty. The seed module remains the source of truth for full DB
    seeding; this only fires when the table is empty.
    """
    existing = int(session.exec(select(func.count()).select_from(Integration)).one())
    if existing:
        return 0
    created = 0
    for spec in DEFAULT_INTEGRATIONS:
        session.add(Integration(**spec, config={}))
        created += 1
    if created:
        session.commit()
    return created


def list_integrations(session: Session) -> list[Integration]:
    return list(
        session.exec(select(Integration).order_by(Integration.kind)).all()  # type: ignore[arg-type]
    )


def get_integration(session: Session, integration_id: uuid.UUID) -> Integration:
    integration = session.get(Integration, integration_id)
    if integration is None:
        raise NotFoundError("Integration not found")
    return integration


def toggle(
    session: Session,
    integration_id: uuid.UUID,
    enabled: bool,
    user: AuthenticatedUser | None,
) -> Integration:
    integration = get_integration(session, integration_id)
    integration.enabled = enabled
    session.add(integration)
    session.commit()
    session.refresh(integration)
    record_audit(
        session,
        action=AuditAction.INTEGRATION_EXPORT
        if integration.direction == IntegrationDirection.EXPORT
        else AuditAction.INTEGRATION_IMPORT,
        actor_user_id=user.id if user else None,
        actor_email=user.email if user else None,
        entity_type="integration",
        entity_id=integration.id,
        summary=f"{'Enabled' if enabled else 'Disabled'} integration {integration.name}",
    )
    return integration


# --------------------------------------------------------------------------- #
# Export (simulated; returns the payload, sends nothing)
# --------------------------------------------------------------------------- #
def export(
    session: Session,
    integration: Integration,
    req: ExportRequest,
    user: AuthenticatedUser | None,
) -> dict:
    if integration.direction != IntegrationDirection.EXPORT:
        raise ValidationAppError(
            f"Integration '{integration.name}' is an import connector and cannot export."
        )

    detections = _recent_detections(session, req)
    incidents = _recent_incidents(session, req)

    builder = _EXPORT_BUILDERS.get(integration.kind, _build_siem_webhook_payload)
    events = builder(detections, incidents)

    payload = {
        "_simulated": True,
        "integration": integration.kind.value,
        "target": integration.name,
        "generated_at": utcnow().isoformat(),
        "event_count": len(events),
        "events": events,
        "notice": (
            "Simulated export. No data was transmitted to any external system. "
            "All records are derived from the ForgeShield OT demo dataset."
        ),
    }

    integration.last_sync_summary = (
        f"Simulated export of {len(events)} record(s) at {utcnow().isoformat()}"
    )
    session.add(integration)
    session.commit()

    record_audit(
        session,
        action=AuditAction.INTEGRATION_EXPORT,
        actor_user_id=user.id if user else None,
        actor_email=user.email if user else None,
        entity_type="integration",
        entity_id=integration.id,
        summary=f"Simulated export of {len(events)} record(s) via {integration.name}",
        meta={"kind": integration.kind.value, "event_count": len(events)},
    )
    return payload


def _recent_detections(session: Session, req: ExportRequest) -> list[Detection]:
    stmt = select(Detection)
    if req.since is not None:
        stmt = stmt.where(Detection.detected_at >= req.since)  # type: ignore[arg-type]
    stmt = stmt.order_by(Detection.detected_at.desc()).limit(req.limit)  # type: ignore[attr-defined]
    return list(session.exec(stmt).all())


def _recent_incidents(session: Session, req: ExportRequest) -> list[Incident]:
    stmt = select(Incident)
    if req.since is not None:
        stmt = stmt.where(Incident.opened_at >= req.since)  # type: ignore[arg-type]
    stmt = stmt.order_by(Incident.opened_at.desc()).limit(req.limit)  # type: ignore[attr-defined]
    return list(session.exec(stmt).all())


def _ts(value: datetime | None) -> str:
    return (value or utcnow()).isoformat()


def _build_splunk_payload(
    detections: list[Detection], incidents: list[Incident]
) -> list[dict]:
    """Splunk HTTP Event Collector (HEC) event shape."""
    events: list[dict] = []
    for d in detections:
        events.append(
            {
                "_simulated": True,
                "time": _ts(d.detected_at),
                "host": "forgeshield-ot",
                "source": "forgeshield:detection",
                "sourcetype": "forgeshield:ot:detection",
                "event": {
                    "id": str(d.id),
                    "title": d.title,
                    "detection_type": d.detection_type.value,
                    "severity": d.severity.value,
                    "status": d.status.value,
                    "asset_id": str(d.asset_id) if d.asset_id else None,
                    "attck_ics_technique": d.attck_ics_technique,
                },
            }
        )
    return events


def _build_sentinel_payload(
    detections: list[Detection], incidents: list[Incident]
) -> list[dict]:
    """Azure Sentinel / Log Analytics custom-log record shape."""
    events: list[dict] = []
    for d in detections:
        events.append(
            {
                "_simulated": True,
                "TimeGenerated": _ts(d.detected_at),
                "Type": "ForgeShieldOTDetection_CL",
                "DetectionId_g": str(d.id),
                "Title_s": d.title,
                "DetectionType_s": d.detection_type.value,
                "Severity_s": d.severity.value,
                "Status_s": d.status.value,
                "AssetId_g": str(d.asset_id) if d.asset_id else None,
                "Technique_s": d.attck_ics_technique,
            }
        )
    return events


def _build_servicenow_payload(
    detections: list[Detection], incidents: list[Incident]
) -> list[dict]:
    """ServiceNow incident ticket shape."""
    tickets: list[dict] = []
    for inc in incidents:
        tickets.append(
            {
                "_simulated": True,
                "short_description": f"[OT] {inc.title}",
                "description": inc.summary or inc.title,
                "category": "ot_security",
                "impact": _severity_to_snow(inc.severity.value),
                "urgency": _severity_to_snow(inc.severity.value),
                "state": "New",
                "correlation_id": inc.reference,
                "u_forgeshield_incident_id": str(inc.id),
            }
        )
    return tickets


def _build_jira_payload(
    detections: list[Detection], incidents: list[Incident]
) -> list[dict]:
    """Jira issue (create) shape."""
    issues: list[dict] = []
    for inc in incidents:
        issues.append(
            {
                "_simulated": True,
                "fields": {
                    "project": {"key": "OTSEC"},
                    "summary": f"[OT] {inc.title}",
                    "description": inc.summary or inc.title,
                    "issuetype": {"name": "Incident"},
                    "priority": {"name": _severity_to_jira(inc.severity.value)},
                    "labels": ["forgeshield-ot", "simulated"],
                    "customfield_reference": inc.reference,
                },
            }
        )
    return issues


def _build_siem_webhook_payload(
    detections: list[Detection], incidents: list[Incident]
) -> list[dict]:
    """Generic SIEM webhook event shape (detections + incidents)."""
    events: list[dict] = []
    for d in detections:
        events.append(
            {
                "_simulated": True,
                "event_type": "detection",
                "id": str(d.id),
                "timestamp": _ts(d.detected_at),
                "title": d.title,
                "detection_type": d.detection_type.value,
                "severity": d.severity.value,
                "status": d.status.value,
            }
        )
    for inc in incidents:
        events.append(
            {
                "_simulated": True,
                "event_type": "incident",
                "id": str(inc.id),
                "timestamp": _ts(inc.opened_at),
                "reference": inc.reference,
                "title": inc.title,
                "severity": inc.severity.value,
                "status": inc.status.value,
            }
        )
    return events


def _severity_to_snow(severity: str) -> str:
    return {
        "CRITICAL": "1 - High",
        "HIGH": "1 - High",
        "MEDIUM": "2 - Medium",
        "LOW": "3 - Low",
        "INFO": "3 - Low",
    }.get(severity, "2 - Medium")


def _severity_to_jira(severity: str) -> str:
    return {
        "CRITICAL": "Highest",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low",
        "INFO": "Lowest",
    }.get(severity, "Medium")


_EXPORT_BUILDERS = {
    IntegrationKind.SPLUNK: _build_splunk_payload,
    IntegrationKind.SENTINEL: _build_sentinel_payload,
    IntegrationKind.SERVICENOW: _build_servicenow_payload,
    IntegrationKind.JIRA: _build_jira_payload,
    IntegrationKind.SIEM_WEBHOOK: _build_siem_webhook_payload,
}


# --------------------------------------------------------------------------- #
# Import (simulated; does not modify data)
# --------------------------------------------------------------------------- #
def simulate_import(
    session: Session,
    integration: Integration,
    user: AuthenticatedUser | None,
) -> dict:
    if integration.direction != IntegrationDirection.IMPORT:
        raise ValidationAppError(
            f"Integration '{integration.name}' is an export connector and cannot import."
        )

    vendor = _IMPORT_VENDORS.get(integration.kind, integration.name)
    asset_count = int(session.exec(select(func.count()).select_from(Asset)).one())

    # Deterministic, representative simulated counts (no data is modified).
    if integration.kind == IntegrationKind.DEFENDER:
        items = {
            "edr_alerts": 12,
            "endpoints": 8,
        }
        narrative = f"Would import 12 EDR alerts and 8 endpoints from {vendor}."
    elif integration.kind == IntegrationKind.OT_PLATFORM_IMPORT:
        items = {"assets": 25, "communication_paths": 40}
        narrative = (
            f"Would import 25 assets and 40 communication paths from {vendor}."
        )
    elif integration.kind == IntegrationKind.VULN_SCANNER_IMPORT:
        items = {"vulnerabilities": 30, "asset_matches": 55}
        narrative = (
            f"Would import 30 vulnerabilities and 55 asset matches from {vendor}."
        )
    elif integration.kind == IntegrationKind.OEM_IMPORT:
        items = {"assets": 10, "advisories": 6}
        narrative = f"Would import 10 OEM assets and 6 advisories from {vendor}."
    else:  # pragma: no cover - defensive
        items = {"records": 0}
        narrative = f"Would import records from {vendor}."

    summary = {
        "_simulated": True,
        "integration": integration.kind.value,
        "vendor": vendor,
        "generated_at": utcnow().isoformat(),
        "would_import": items,
        "narrative": narrative,
        "data_modified": False,
        "notice": (
            "Simulated import. No data was read from any external system and no "
            "records were created or modified. Existing inventory has "
            f"{asset_count} assets."
        ),
    }

    integration.last_sync_summary = f"Simulated import at {utcnow().isoformat()}: {narrative}"
    session.add(integration)
    session.commit()

    record_audit(
        session,
        action=AuditAction.INTEGRATION_IMPORT,
        actor_user_id=user.id if user else None,
        actor_email=user.email if user else None,
        entity_type="integration",
        entity_id=integration.id,
        summary=f"Simulated import via {integration.name}: {narrative}",
        meta={"kind": integration.kind.value, "would_import": items},
    )
    return summary
