"""Incident & case management business logic.

Incidents carry a human-readable reference (INC-YYYY-NNNN), an ordered timeline,
and polymorphic links to detections/assets/vulns/changes. Response guidance is
strictly passive and OT-safe: never alter PLC logic; isolate only via pre-approved
controls; preserve evidence.
"""
from __future__ import annotations

import uuid

from sqlalchemy import func
from sqlmodel import Session, or_, select

from app.core.enums import (
    AuditAction,
    IncidentLinkType,
    IncidentStatus,
    Severity,
    TimelineEventKind,
)
from app.core.exceptions import NotFoundError
from app.core.security import AuthenticatedUser
from app.models.asset import Asset
from app.models.base import utcnow
from app.models.detection import Detection
from app.models.incident import Incident, IncidentLink, IncidentTimelineEvent
from app.models.vuln import AssetVulnerability, Vulnerability
from app.schemas.common import PaginationParams
from app.schemas.incident import (
    IncidentCreate,
    IncidentFilter,
    IncidentUpdate,
    LinkCreate,
    TimelineEventCreate,
)
from app.services.audit_service import record_audit

# Statuses that close an incident (and stamp closed_at).
_CLOSED_STATUSES: frozenset[IncidentStatus] = frozenset(
    {IncidentStatus.RESOLVED, IncidentStatus.CLOSED}
)

# Static, passive, OT-safe incident-response checklist surfaced on every incident.
SAFE_OT_RESPONSE_CHECKLIST: list[str] = [
    "Identify the affected assets, zones and conduits from the incident links.",
    "Isolate impacted systems only via pre-approved network controls (firewall/ACL); "
    "do not improvise network changes.",
    "Preserve evidence: capture logs, configuration snapshots and process state before "
    "any change.",
    "Do NOT alter PLC/RTU logic or download programs as part of response.",
    "Coordinate with process/operations engineers before any containment that could "
    "affect safety or availability.",
    "Notify the SOC lead, asset owner and, where required, regulators per the incident "
    "response plan.",
    "Maintain a chronological timeline of all observations and actions taken.",
    "Validate backups and recovery readiness before attempting any restoration.",
    "Only restore approved baselines during an authorized maintenance window.",
    "Capture lessons learned and update detections, controls and playbooks after closure.",
]


# --------------------------------------------------------------------------- #
# References
# --------------------------------------------------------------------------- #
def next_reference(session: Session) -> str:
    """Sequential reference for the current year: INC-YYYY-NNNN (4-digit, padded)."""
    year = utcnow().year
    prefix = f"INC-{year}-"
    count = session.exec(
        select(func.count())
        .select_from(Incident)
        .where(Incident.reference.like(f"{prefix}%"))  # type: ignore[attr-defined]
    ).one()
    return f"{prefix}{int(count) + 1:04d}"


# --------------------------------------------------------------------------- #
# Creation
# --------------------------------------------------------------------------- #
def create_incident(
    session: Session, data: IncidentCreate, user: AuthenticatedUser | None
) -> Incident:
    incident = Incident(
        reference=next_reference(session),
        title=data.title,
        severity=data.severity,
        status=IncidentStatus.OPEN,
        site_id=data.site_id,
        summary=data.summary or "",
        attck_ics_technique=data.attck_ics_technique,
        lead_owner=data.lead_owner,
        opened_at=utcnow(),
    )
    session.add(incident)
    session.commit()
    session.refresh(incident)
    record_audit(
        session,
        action=AuditAction.INCIDENT_CREATE,
        actor_user_id=user.id if user else None,
        actor_email=user.email if user else None,
        entity_type="incident",
        entity_id=incident.id,
        summary=f"Created incident {incident.reference}: {incident.title}",
    )
    return incident


def create_from_detection(
    session: Session, detection_id: uuid.UUID, user: AuthenticatedUser | None
) -> Incident:
    detection = session.get(Detection, detection_id)
    if detection is None:
        raise NotFoundError("Detection not found")

    incident = Incident(
        reference=next_reference(session),
        title=f"Incident from detection: {detection.title}",
        severity=detection.severity,
        status=IncidentStatus.OPEN,
        site_id=detection.site_id,
        summary=detection.description or "",
        attck_ics_technique=detection.attck_ics_technique,
        opened_at=utcnow(),
    )
    session.add(incident)
    session.commit()
    session.refresh(incident)

    # Links: always the detection; the asset too when known.
    assert incident.id is not None
    session.add(
        IncidentLink(
            incident_id=incident.id,
            link_type=IncidentLinkType.DETECTION,
            entity_id=detection_id,
        )
    )
    if detection.asset_id is not None:
        session.add(
            IncidentLink(
                incident_id=incident.id,
                link_type=IncidentLinkType.ASSET,
                entity_id=detection.asset_id,
            )
        )

    # Seed an initial timeline note.
    session.add(
        IncidentTimelineEvent(
            incident_id=incident.id,
            kind=TimelineEventKind.NOTE,
            description=(
                f"Incident opened from detection '{detection.title}' "
                f"({detection.detection_type.value})."
            ),
            author=user.email if user else None,
            occurred_at=utcnow(),
            ref=str(detection_id),
        )
    )
    session.commit()
    session.refresh(incident)

    record_audit(
        session,
        action=AuditAction.INCIDENT_CREATE,
        actor_user_id=user.id if user else None,
        actor_email=user.email if user else None,
        entity_type="incident",
        entity_id=incident.id,
        summary=f"Created incident {incident.reference} from detection {detection_id}",
    )
    return incident


# --------------------------------------------------------------------------- #
# Read / list
# --------------------------------------------------------------------------- #
def get_incident(session: Session, incident_id: uuid.UUID) -> Incident:
    incident = session.get(Incident, incident_id)
    if incident is None:
        raise NotFoundError("Incident not found")
    return incident


def list_incidents(
    session: Session, *, filters: IncidentFilter, page: PaginationParams
) -> tuple[list[Incident], int]:
    stmt = select(Incident)
    count_stmt = select(func.count()).select_from(Incident)

    conditions = []
    if filters.status:
        conditions.append(Incident.status == filters.status)
    if filters.severity:
        conditions.append(Incident.severity == filters.severity)
    if filters.site_id:
        conditions.append(Incident.site_id == filters.site_id)
    search = filters.search or page.search
    if search:
        term = f"%{search}%"
        conditions.append(
            or_(
                Incident.title.ilike(term),  # type: ignore[attr-defined]
                Incident.reference.ilike(term),  # type: ignore[attr-defined]
            )
        )
    for cond in conditions:
        stmt = stmt.where(cond)
        count_stmt = count_stmt.where(cond)

    total = session.exec(count_stmt).one()
    stmt = stmt.order_by(Incident.created_at.desc()).offset(page.offset).limit(page.limit)  # type: ignore[attr-defined]
    items = session.exec(stmt).all()
    return list(items), int(total)


def stats(session: Session) -> dict:
    by_status_rows = session.exec(
        select(Incident.status, func.count()).group_by(Incident.status)  # type: ignore[arg-type]
    ).all()
    by_severity_rows = session.exec(
        select(Incident.severity, func.count()).group_by(Incident.severity)  # type: ignore[arg-type]
    ).all()
    by_status = {status.value: 0 for status in IncidentStatus}
    for status, count in by_status_rows:
        by_status[status.value] = int(count)
    by_severity = {severity.value: 0 for severity in Severity}
    for severity, count in by_severity_rows:
        by_severity[severity.value] = int(count)
    total = sum(by_status.values())
    return {"total": total, "by_status": by_status, "by_severity": by_severity}


def _link_summary(session: Session, link: IncidentLink) -> dict | None:
    if link.link_type == IncidentLinkType.DETECTION:
        det = session.get(Detection, link.entity_id)
        if det is not None:
            return {"title": det.title, "detection_type": det.detection_type.value}
    elif link.link_type == IncidentLinkType.ASSET:
        asset = session.get(Asset, link.entity_id)
        if asset is not None:
            return {"asset_tag": asset.asset_tag, "asset_type": asset.asset_type.value}
    elif link.link_type == IncidentLinkType.VULN:
        av = session.get(AssetVulnerability, link.entity_id)
        if av is not None:
            vuln = session.get(Vulnerability, av.vuln_id)
            return {
                "status": av.status.value,
                "cve_id": vuln.cve_id if vuln else None,
            }
        vuln = session.get(Vulnerability, link.entity_id)
        if vuln is not None:
            return {"cve_id": vuln.cve_id, "title": vuln.title}
    return None


def incident_detail(session: Session, incident: Incident) -> dict:
    assert incident.id is not None
    timeline = session.exec(
        select(IncidentTimelineEvent)
        .where(IncidentTimelineEvent.incident_id == incident.id)
        .order_by(IncidentTimelineEvent.occurred_at)  # type: ignore[arg-type]
    ).all()
    link_rows = session.exec(
        select(IncidentLink).where(IncidentLink.incident_id == incident.id)
    ).all()
    links = [
        {"link": link.model_dump(), "summary": _link_summary(session, link)}
        for link in link_rows
    ]
    return {
        "incident": incident.model_dump(),
        "timeline": [t.model_dump() for t in timeline],
        "links": links,
        "safe_ot_response_checklist": SAFE_OT_RESPONSE_CHECKLIST,
    }


# --------------------------------------------------------------------------- #
# Mutations
# --------------------------------------------------------------------------- #
def update_incident(
    session: Session, incident_id: uuid.UUID, data: IncidentUpdate, user: AuthenticatedUser | None
) -> Incident:
    incident = get_incident(session, incident_id)
    fields = data.model_dump(exclude_unset=True)
    new_status = fields.get("status")
    for key, value in fields.items():
        setattr(incident, key, value)

    # Stamp / clear closed_at on resolving status transitions.
    if new_status is not None:
        if new_status in _CLOSED_STATUSES and incident.closed_at is None:
            incident.closed_at = utcnow()
        elif new_status not in _CLOSED_STATUSES:
            incident.closed_at = None

    session.add(incident)
    session.commit()
    session.refresh(incident)
    record_audit(
        session,
        action=AuditAction.INCIDENT_UPDATE,
        actor_user_id=user.id if user else None,
        actor_email=user.email if user else None,
        entity_type="incident",
        entity_id=incident.id,
        summary=f"Updated incident {incident.reference} (status={incident.status.value})",
    )
    return incident


def add_timeline_event(
    session: Session,
    incident_id: uuid.UUID,
    data: TimelineEventCreate,
    user: AuthenticatedUser | None,
) -> IncidentTimelineEvent:
    get_incident(session, incident_id)
    event = IncidentTimelineEvent(
        incident_id=incident_id,
        kind=data.kind,
        description=data.description,
        author=user.email if user else None,
        occurred_at=data.occurred_at or utcnow(),
        ref=data.ref,
    )
    session.add(event)
    session.commit()
    session.refresh(event)
    record_audit(
        session,
        action=AuditAction.INCIDENT_UPDATE,
        actor_user_id=user.id if user else None,
        actor_email=user.email if user else None,
        entity_type="incident",
        entity_id=incident_id,
        summary=f"Added {data.kind.value} timeline event to incident {incident_id}",
    )
    return event


def add_link(
    session: Session, incident_id: uuid.UUID, data: LinkCreate, user: AuthenticatedUser | None
) -> IncidentLink:
    get_incident(session, incident_id)
    link = IncidentLink(
        incident_id=incident_id,
        link_type=data.link_type,
        entity_id=data.entity_id,
    )
    session.add(link)
    session.commit()
    session.refresh(link)
    record_audit(
        session,
        action=AuditAction.INCIDENT_UPDATE,
        actor_user_id=user.id if user else None,
        actor_email=user.email if user else None,
        entity_type="incident",
        entity_id=incident_id,
        summary=f"Linked {data.link_type.value} {data.entity_id} to incident {incident_id}",
    )
    return link
