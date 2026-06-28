"""Policy compliance business logic.

Frameworks are scored by readiness; controls carry a workflow status, owner and
evidence. Evidence can be attached manually or auto-linked heuristically from the
other domains (assets, config changes, vulnerabilities, incidents, detections).
"""
from __future__ import annotations

import uuid

from sqlalchemy import func
from sqlmodel import Session, or_, select

from app.core.enums import (
    GAP_CONTROL_STATUSES,
    AuditAction,
    ControlStatus,
    EvidenceSourceType,
)
from app.core.exceptions import NotFoundError
from app.core.security import AuthenticatedUser
from app.models.asset import Asset
from app.models.base import utcnow
from app.models.compliance import (
    ComplianceControl,
    ComplianceEvidence,
    ComplianceFramework,
)
from app.models.config_mgmt import ConfigChange
from app.models.detection import Detection
from app.models.incident import Incident
from app.models.vuln import AssetVulnerability
from app.schemas.common import PaginationParams
from app.schemas.compliance import ControlFilter, ControlUpdate, EvidenceCreate
from app.services.audit_service import record_audit


# --------------------------------------------------------------------------- #
# Frameworks & readiness
# --------------------------------------------------------------------------- #
def list_frameworks(session: Session) -> list[ComplianceFramework]:
    stmt = select(ComplianceFramework).order_by(ComplianceFramework.key)  # type: ignore[arg-type]
    return list(session.exec(stmt).all())


def _status_counts(session: Session, framework_id: uuid.UUID) -> dict[ControlStatus, int]:
    rows = session.exec(
        select(ComplianceControl.status, func.count())
        .where(ComplianceControl.framework_id == framework_id)
        .group_by(ComplianceControl.status)  # type: ignore[arg-type]
    ).all()
    counts: dict[ControlStatus, int] = {status: 0 for status in ControlStatus}
    for status, count in rows:
        counts[status] = int(count)
    return counts


def framework_readiness(session: Session, framework: ComplianceFramework) -> dict:
    assert framework.id is not None
    counts = _status_counts(session, framework.id)
    implemented = counts[ControlStatus.IMPLEMENTED]
    partial = counts[ControlStatus.PARTIAL]
    not_started = counts[ControlStatus.NOT_STARTED]
    not_applicable = counts[ControlStatus.NOT_APPLICABLE]
    total = implemented + partial + not_started + not_applicable
    scored = total - not_applicable
    readiness_pct = round(implemented / scored * 100, 1) if scored > 0 else 0.0
    return {
        "implemented": implemented,
        "partial": partial,
        "not_started": not_started,
        "not_applicable": not_applicable,
        "total": total,
        "readiness_pct": readiness_pct,
    }


def framework_mapping_table(session: Session) -> list[dict]:
    """One row per framework: name, control counts by status, readiness_pct."""
    table: list[dict] = []
    for fw in list_frameworks(session):
        readiness = framework_readiness(session, fw)
        table.append(
            {
                "framework_id": str(fw.id),
                "key": fw.key.value,
                "name": fw.name,
                "version": fw.version,
                "counts": {
                    "implemented": readiness["implemented"],
                    "partial": readiness["partial"],
                    "not_started": readiness["not_started"],
                    "not_applicable": readiness["not_applicable"],
                    "total": readiness["total"],
                },
                "readiness_pct": readiness["readiness_pct"],
            }
        )
    return table


# --------------------------------------------------------------------------- #
# Controls
# --------------------------------------------------------------------------- #
def list_controls(
    session: Session, *, filters: ControlFilter, page: PaginationParams
) -> tuple[list[ComplianceControl], int]:
    stmt = select(ComplianceControl)
    count_stmt = select(func.count()).select_from(ComplianceControl)

    conditions = []
    if filters.framework_id:
        conditions.append(ComplianceControl.framework_id == filters.framework_id)
    if filters.status:
        conditions.append(ComplianceControl.status == filters.status)
    search = filters.search or page.search
    if search:
        term = f"%{search}%"
        conditions.append(
            or_(
                ComplianceControl.control_ref.ilike(term),  # type: ignore[attr-defined]
                ComplianceControl.title.ilike(term),  # type: ignore[attr-defined]
                ComplianceControl.description.ilike(term),  # type: ignore[attr-defined]
            )
        )
    for cond in conditions:
        stmt = stmt.where(cond)
        count_stmt = count_stmt.where(cond)

    total = session.exec(count_stmt).one()
    stmt = (
        stmt.order_by(ComplianceControl.control_ref)  # type: ignore[arg-type]
        .offset(page.offset)
        .limit(page.limit)
    )
    items = session.exec(stmt).all()
    return list(items), int(total)


def get_control(session: Session, control_id: uuid.UUID) -> ComplianceControl:
    control = session.get(ComplianceControl, control_id)
    if control is None:
        raise NotFoundError("Compliance control not found")
    return control


def _evidence_source_summary(session: Session, ev: ComplianceEvidence) -> dict | None:
    """Resolve the small source-record summary for a piece of evidence."""
    if ev.source_id is None:
        return None
    if ev.source_type == EvidenceSourceType.ASSET:
        asset = session.get(Asset, ev.source_id)
        if asset is not None:
            return {"asset_tag": asset.asset_tag, "asset_type": asset.asset_type.value}
    elif ev.source_type == EvidenceSourceType.DETECTION:
        det = session.get(Detection, ev.source_id)
        if det is not None:
            return {"title": det.title, "detection_type": det.detection_type.value}
    elif ev.source_type == EvidenceSourceType.CONFIG_CHANGE:
        change = session.get(ConfigChange, ev.source_id)
        if change is not None:
            return {"summary": change.summary, "disposition": change.disposition.value}
    elif ev.source_type == EvidenceSourceType.VULN:
        av = session.get(AssetVulnerability, ev.source_id)
        if av is not None:
            return {"status": av.status.value, "asset_id": str(av.asset_id)}
    elif ev.source_type == EvidenceSourceType.INCIDENT:
        inc = session.get(Incident, ev.source_id)
        if inc is not None:
            return {"reference": inc.reference, "title": inc.title}
    return None


def control_detail(session: Session, control: ComplianceControl) -> dict:
    assert control.id is not None
    framework = session.get(ComplianceFramework, control.framework_id)
    evidence_rows = session.exec(
        select(ComplianceEvidence)
        .where(ComplianceEvidence.control_id == control.id)
        .order_by(ComplianceEvidence.created_at.desc())  # type: ignore[attr-defined]
    ).all()
    evidence = [
        {
            "evidence": ev.model_dump(),
            "source": _evidence_source_summary(session, ev),
        }
        for ev in evidence_rows
    ]
    return {
        "control": control.model_dump(),
        "framework_key": framework.key.value if framework else None,
        "framework_name": framework.name if framework else None,
        "evidence": evidence,
        "is_gap": control.status in GAP_CONTROL_STATUSES,
    }


def update_control(
    session: Session, control_id: uuid.UUID, data: ControlUpdate, user: AuthenticatedUser | None
) -> ComplianceControl:
    control = get_control(session, control_id)
    for key, value in data.model_dump(exclude_unset=True).items():
        setattr(control, key, value)
    control.last_reviewed = utcnow()
    session.add(control)
    session.commit()
    session.refresh(control)
    record_audit(
        session,
        action=AuditAction.CONTROL_STATUS_CHANGE,
        actor_user_id=user.id if user else None,
        actor_email=user.email if user else None,
        entity_type="compliance_control",
        entity_id=control.id,
        summary=f"Updated control {control.control_ref} (status={control.status.value})",
    )
    return control


# --------------------------------------------------------------------------- #
# Evidence
# --------------------------------------------------------------------------- #
def add_evidence(
    session: Session, data: EvidenceCreate, user: AuthenticatedUser | None
) -> ComplianceEvidence:
    # Validate the control exists.
    get_control(session, data.control_id)
    evidence = ComplianceEvidence(
        control_id=data.control_id,
        source_type=data.source_type,
        source_id=data.source_id,
        description=data.description,
        file_name=data.file_name,
        file_note=data.file_note,
        auto_linked=False,
        uploaded_by=user.email if user else None,
    )
    session.add(evidence)
    session.commit()
    session.refresh(evidence)
    record_audit(
        session,
        action=AuditAction.COMPLIANCE_EVIDENCE_UPLOAD,
        actor_user_id=user.id if user else None,
        actor_email=user.email if user else None,
        entity_type="compliance_evidence",
        entity_id=evidence.id,
        summary=f"Added evidence to control {data.control_id} ({data.source_type.value})",
    )
    return evidence


# Keyword heuristics mapping control text -> an evidence source type.
_AUTO_LINK_KEYWORDS: list[tuple[EvidenceSourceType, tuple[str, ...]]] = [
    (EvidenceSourceType.ASSET, ("asset inventory", "inventory", "asset management")),
    (
        EvidenceSourceType.CONFIG_CHANGE,
        ("configuration", "change management", "change control", "baseline"),
    ),
    (
        EvidenceSourceType.VULN,
        ("vulnerability", "patch", "patching", "flaw remediation"),
    ),
    (
        EvidenceSourceType.INCIDENT,
        ("incident response", "incident", "case management", "response plan"),
    ),
    (
        EvidenceSourceType.DETECTION,
        ("monitoring", "segmentation", "detection", "anomaly", "network monitoring"),
    ),
]


def _control_text(control: ComplianceControl) -> str:
    return f"{control.title} {control.description} {control.evidence_required}".lower()


def _existing_auto_link(
    session: Session,
    control_id: uuid.UUID,
    source_type: EvidenceSourceType,
    source_id: uuid.UUID | None,
) -> bool:
    stmt = (
        select(ComplianceEvidence)
        .where(ComplianceEvidence.control_id == control_id)
        .where(ComplianceEvidence.source_type == source_type)
        .where(ComplianceEvidence.auto_linked == True)  # noqa: E712
    )
    if source_id is None:
        stmt = stmt.where(ComplianceEvidence.source_id == None)  # noqa: E711
    else:
        stmt = stmt.where(ComplianceEvidence.source_id == source_id)
    return session.exec(stmt).first() is not None


def _first_id(session: Session, model: type) -> uuid.UUID | None:
    row = session.exec(select(model.id)).first()  # type: ignore[attr-defined]
    return row


def auto_link_evidence(session: Session, user: AuthenticatedUser | None) -> int:
    """Heuristically attach evidence to controls based on keyword matches plus the
    presence of relevant records. Idempotent: an identical auto-link is never
    duplicated. Returns the number of evidence records created."""
    created = 0
    controls = session.exec(select(ComplianceControl)).all()

    # Cache presence/representative ids of each source domain.
    representatives: dict[EvidenceSourceType, uuid.UUID | None] = {
        EvidenceSourceType.ASSET: _first_id(session, Asset),
        EvidenceSourceType.CONFIG_CHANGE: _first_id(session, ConfigChange),
        EvidenceSourceType.VULN: _first_id(session, AssetVulnerability),
        EvidenceSourceType.INCIDENT: _first_id(session, Incident),
        EvidenceSourceType.DETECTION: _first_id(session, Detection),
    }

    for control in controls:
        assert control.id is not None
        text = _control_text(control)
        for source_type, keywords in _AUTO_LINK_KEYWORDS:
            if not any(kw in text for kw in keywords):
                continue
            source_id = representatives.get(source_type)
            if source_id is None:
                continue  # no relevant records to evidence with
            if _existing_auto_link(session, control.id, source_type, source_id):
                continue
            evidence = ComplianceEvidence(
                control_id=control.id,
                source_type=source_type,
                source_id=source_id,
                description=(
                    f"Auto-linked {source_type.value} evidence for control "
                    f"{control.control_ref}"
                ),
                auto_linked=True,
                uploaded_by=user.email if user else None,
            )
            session.add(evidence)
            created += 1

    if created:
        session.commit()
        record_audit(
            session,
            action=AuditAction.COMPLIANCE_EVIDENCE_UPLOAD,
            actor_user_id=user.id if user else None,
            actor_email=user.email if user else None,
            entity_type="compliance_evidence",
            summary=f"Auto-linked {created} evidence record(s) to controls",
            meta={"created": created},
        )
    return created


# --------------------------------------------------------------------------- #
# Gap reporting
# --------------------------------------------------------------------------- #
def _has_evidence(session: Session, control_id: uuid.UUID) -> bool:
    count = session.exec(
        select(func.count())
        .select_from(ComplianceEvidence)
        .where(ComplianceEvidence.control_id == control_id)
    ).one()
    return int(count) > 0


def gap_report(session: Session, framework_id: uuid.UUID | None = None) -> list[dict]:
    """Open gaps (NOT_STARTED / PARTIAL) grouped by framework, each annotated with a
    missing-evidence note."""
    frameworks = list_frameworks(session)
    if framework_id is not None:
        frameworks = [fw for fw in frameworks if fw.id == framework_id]

    report: list[dict] = []
    for fw in frameworks:
        assert fw.id is not None
        controls = session.exec(
            select(ComplianceControl)
            .where(ComplianceControl.framework_id == fw.id)
            .where(ComplianceControl.status.in_(tuple(GAP_CONTROL_STATUSES)))  # type: ignore[attr-defined]
            .order_by(ComplianceControl.control_ref)  # type: ignore[arg-type]
        ).all()
        if not controls:
            continue
        gaps = []
        for control in controls:
            assert control.id is not None
            has_evidence = _has_evidence(session, control.id)
            gaps.append(
                {
                    "control": control.model_dump(),
                    "missing_evidence": not has_evidence,
                    "evidence_note": (
                        "No evidence attached" if not has_evidence else "Evidence present"
                    ),
                }
            )
        report.append(
            {
                "framework_id": str(fw.id),
                "framework_key": fw.key.value,
                "framework_name": fw.name,
                "gap_count": len(gaps),
                "gaps": gaps,
            }
        )
    return report
