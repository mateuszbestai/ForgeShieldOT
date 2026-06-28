"""Deterministic, structured retrieval (RAG) over the application's own records.

Builds a typed evidence bundle per use case. Every record contributes a citation
ref; the AI may only cite refs present here (enforced by ``validate_answer``). All
free-form/untrusted text is sanitized before entering the bundle.
"""
from __future__ import annotations

import uuid

from sqlmodel import Session, or_, select

from app.ai.sanitize import sanitize_text, sanitize_value
from app.ai.schema import EvidenceRecord, RetrievalContext
from app.core.enums import (
    AIUseCase,
    ChangeDisposition,
    DetectionStatus,
)
from app.models.asset import Asset, ProtocolObservation
from app.models.compliance import ComplianceControl, ComplianceEvidence, ComplianceFramework
from app.models.config_mgmt import ConfigChange
from app.models.detection import Detection
from app.models.incident import Incident, IncidentTimelineEvent
from app.models.vuln import AssetVulnerability, Vulnerability

_MAX_RECORDS = 30


# --------------------------------------------------------------------------- #
# Record builders
# --------------------------------------------------------------------------- #
def asset_record(asset: Asset) -> EvidenceRecord:
    return EvidenceRecord(
        ref=f"asset:{asset.id}",
        label=f"{asset.asset_tag} ({asset.asset_type.value})",
        fields={
            "hostname": asset.hostname,
            "ip": asset.ip_address,
            "vendor": asset.vendor,
            "model": asset.model,
            "purdue_level": int(asset.purdue_level),
            "criticality": asset.criticality.value,
            "safety_impact": asset.safety_impact.value,
            "risk_score": asset.risk_score,
            "risk_band": asset.risk_band.value,
            "support_status": asset.support_status.value,
            "patch_status": asset.patch_status.value,
            "internet_reachable": asset.internet_reachable,
            "it_reachable": asset.it_reachable,
            "owner": asset.owner,
            "backup_available": asset.backup_available,
            "notes": sanitize_text(asset.notes or ""),
        },
    )


def vuln_record(vuln: Vulnerability) -> EvidenceRecord:
    return EvidenceRecord(
        ref=f"vuln:{vuln.cve_id}",
        label=f"{vuln.cve_id} — {vuln.title}",
        fields={
            "cve_id": vuln.cve_id,
            "cvss_base": vuln.cvss_base,
            "known_exploited": vuln.known_exploited,
            "vendor": vuln.vendor,
            "product": vuln.product,
            "patch_available": vuln.patch_available,
            "safety_impact": vuln.safety_impact.value,
            "remediation": sanitize_text(vuln.remediation or ""),
        },
    )


def detection_record(det: Detection) -> EvidenceRecord:
    return EvidenceRecord(
        ref=f"detection:{det.id}",
        label=f"{det.title}",
        fields={
            "type": det.detection_type.value,
            "severity": det.severity.value,
            "confidence": det.confidence.value,
            "status": det.status.value,
            "attck_ics_technique": det.attck_ics_technique,
            "description": sanitize_text(det.description or ""),
        },
    )


def control_record(ctrl: ComplianceControl, framework_key: str | None = None) -> EvidenceRecord:
    return EvidenceRecord(
        ref=f"control:{ctrl.control_ref}",
        label=f"{ctrl.control_ref} — {ctrl.title}",
        fields={
            "framework": framework_key,
            "status": ctrl.status.value,
            "owner": ctrl.owner,
            "evidence_required": sanitize_text(ctrl.evidence_required or ""),
            "description": sanitize_text(ctrl.description or ""),
        },
    )


def change_record(change: ConfigChange) -> EvidenceRecord:
    return EvidenceRecord(
        ref=f"config_change:{change.id}",
        label=f"Config change on asset {change.asset_id}",
        fields={
            "summary": sanitize_text(change.summary or ""),
            "disposition": change.disposition.value,
            "within_approved_window": change.within_approved_window,
            "change_ticket": change.change_ticket,
            "diff": sanitize_value(change.diff or []),
        },
    )


def incident_record(inc: Incident) -> EvidenceRecord:
    return EvidenceRecord(
        ref=f"incident:{inc.reference}",
        label=f"{inc.reference} — {inc.title}",
        fields={
            "severity": inc.severity.value,
            "status": inc.status.value,
            "attck_ics_technique": inc.attck_ics_technique,
            "summary": sanitize_text(inc.summary or ""),
        },
    )


# --------------------------------------------------------------------------- #
# Per-use-case context assembly
# --------------------------------------------------------------------------- #
def _asset_risk_context(session: Session, asset_id: uuid.UUID, question: str) -> RetrievalContext:
    asset = session.get(Asset, asset_id)
    records: list[EvidenceRecord] = []
    headline = "Asset risk analysis"
    if asset is None:
        return RetrievalContext(AIUseCase.ASSET_RISK, question, "Asset not found", [])
    records.append(asset_record(asset))
    headline = f"Risk analysis for {asset.asset_tag}"

    protos = session.exec(
        select(ProtocolObservation).where(ProtocolObservation.asset_id == asset_id)
    ).all()
    if protos:
        records[0].fields["protocols_observed"] = [p.protocol.value for p in protos]

    av_rows = session.exec(
        select(AssetVulnerability, Vulnerability)
        .where(AssetVulnerability.asset_id == asset_id)
        .where(AssetVulnerability.vuln_id == Vulnerability.id)
    ).all()
    for _av, vuln in av_rows[:8]:
        records.append(vuln_record(vuln))

    dets = session.exec(select(Detection).where(Detection.asset_id == asset_id)).all()
    for det in dets[:8]:
        records.append(detection_record(det))

    changes = session.exec(
        select(ConfigChange)
        .where(ConfigChange.asset_id == asset_id)
        .where(ConfigChange.disposition == ChangeDisposition.UNAUTHORIZED)
    ).all()
    for ch in changes[:5]:
        records.append(change_record(ch))

    return RetrievalContext(AIUseCase.ASSET_RISK, question, headline, records[:_MAX_RECORDS])


def _daily_brief_context(session: Session, question: str) -> RetrievalContext:
    records: list[EvidenceRecord] = []
    top_assets = session.exec(
        select(Asset).order_by(Asset.risk_score.desc()).limit(8)  # type: ignore[attr-defined]
    ).all()
    for a in top_assets:
        records.append(asset_record(a))
    open_dets = session.exec(
        select(Detection)
        .where(Detection.status.in_([DetectionStatus.NEW, DetectionStatus.TRIAGING]))  # type: ignore[attr-defined]
        .limit(10)
    ).all()
    for d in open_dets:
        records.append(detection_record(d))
    changes = session.exec(
        select(ConfigChange).where(ConfigChange.disposition == ChangeDisposition.UNAUTHORIZED).limit(5)
    ).all()
    for ch in changes:
        records.append(change_record(ch))
    kev = session.exec(select(Vulnerability).where(Vulnerability.known_exploited == True).limit(6)).all()  # noqa: E712
    for v in kev:
        records.append(vuln_record(v))
    return RetrievalContext(
        AIUseCase.DAILY_BRIEF, question, "Daily OT security posture brief", records[:_MAX_RECORDS]
    )


def _vuln_context(session: Session, vuln_id: uuid.UUID, use_case: AIUseCase, question: str) -> RetrievalContext:
    vuln = session.get(Vulnerability, vuln_id)
    if vuln is None:
        return RetrievalContext(use_case, question, "Vulnerability not found", [])
    records = [vuln_record(vuln)]
    av_rows = session.exec(
        select(AssetVulnerability, Asset)
        .where(AssetVulnerability.vuln_id == vuln_id)
        .where(AssetVulnerability.asset_id == Asset.id)
    ).all()
    for _av, asset in av_rows[:12]:
        records.append(asset_record(asset))
    return RetrievalContext(use_case, question, f"Impact of {vuln.cve_id}", records[:_MAX_RECORDS])


def _compliance_context(session: Session, control_id: uuid.UUID, question: str) -> RetrievalContext:
    ctrl = session.get(ComplianceControl, control_id)
    if ctrl is None:
        return RetrievalContext(AIUseCase.COMPLIANCE_GAP, question, "Control not found", [])
    fw = session.get(ComplianceFramework, ctrl.framework_id)
    records = [control_record(ctrl, fw.key.value if fw else None)]
    evs = session.exec(
        select(ComplianceEvidence).where(ComplianceEvidence.control_id == control_id)
    ).all()
    for ev in evs[:10]:
        records.append(
            EvidenceRecord(
                ref=f"evidence:{ev.id}",
                label=f"Evidence: {ev.description[:60]}",
                fields={
                    "source_type": ev.source_type.value,
                    "auto_linked": ev.auto_linked,
                    "description": sanitize_text(ev.description or ""),
                },
            )
        )
    return RetrievalContext(
        AIUseCase.COMPLIANCE_GAP, question, f"Compliance gap for {ctrl.control_ref}", records[:_MAX_RECORDS]
    )


def _config_change_context(session: Session, change_id: uuid.UUID, question: str) -> RetrievalContext:
    change = session.get(ConfigChange, change_id)
    if change is None:
        return RetrievalContext(AIUseCase.CONFIG_CHANGE, question, "Change not found", [])
    records = [change_record(change)]
    asset = session.get(Asset, change.asset_id)
    if asset:
        records.append(asset_record(asset))
    return RetrievalContext(
        AIUseCase.CONFIG_CHANGE, question, "Configuration change explanation", records[:_MAX_RECORDS]
    )


def _incident_context(session: Session, incident_id: uuid.UUID, use_case: AIUseCase, question: str) -> RetrievalContext:
    inc = session.get(Incident, incident_id)
    if inc is None:
        return RetrievalContext(use_case, question, "Incident not found", [])
    records = [incident_record(inc)]
    events = session.exec(
        select(IncidentTimelineEvent).where(IncidentTimelineEvent.incident_id == incident_id)
    ).all()
    if events:
        records[0].fields["timeline"] = [
            {"kind": e.kind.value, "description": sanitize_text(e.description or "")} for e in events[:15]
        ]
    return RetrievalContext(use_case, question, f"Incident {inc.reference}", records[:_MAX_RECORDS])


def _chat_context(session: Session, question: str) -> RetrievalContext:
    records: list[EvidenceRecord] = []
    term = f"%{question.strip()[:80]}%" if question.strip() else "%"

    assets = session.exec(
        select(Asset)
        .where(
            or_(
                Asset.asset_tag.ilike(term),  # type: ignore[attr-defined]
                Asset.hostname.ilike(term),  # type: ignore[attr-defined]
                Asset.vendor.ilike(term),  # type: ignore[attr-defined]
                Asset.model.ilike(term),  # type: ignore[attr-defined]
                Asset.ip_address.ilike(term),  # type: ignore[attr-defined]
            )
        )
        .limit(6)
    ).all()
    for a in assets:
        records.append(asset_record(a))

    vulns = session.exec(
        select(Vulnerability)
        .where(or_(Vulnerability.cve_id.ilike(term), Vulnerability.title.ilike(term)))  # type: ignore[attr-defined]
        .limit(6)
    ).all()
    for v in vulns:
        records.append(vuln_record(v))

    dets = session.exec(
        select(Detection).where(Detection.title.ilike(term)).limit(6)  # type: ignore[attr-defined]
    ).all()
    for d in dets:
        records.append(detection_record(d))

    incs = session.exec(
        select(Incident)
        .where(or_(Incident.title.ilike(term), Incident.reference.ilike(term)))  # type: ignore[attr-defined]
        .limit(4)
    ).all()
    for i in incs:
        records.append(incident_record(i))

    # If nothing matched, fall back to the highest-risk assets so the analyst still gets grounded context.
    if not records:
        for a in session.exec(select(Asset).order_by(Asset.risk_score.desc()).limit(5)).all():  # type: ignore[attr-defined]
            records.append(asset_record(a))

    return RetrievalContext(AIUseCase.CHAT, question, "OT environment query", records[:_MAX_RECORDS])


def build_context(
    session: Session,
    *,
    use_case: AIUseCase,
    entity_id: uuid.UUID | None = None,
    question: str = "",
) -> RetrievalContext:
    if use_case == AIUseCase.ASSET_RISK and entity_id:
        return _asset_risk_context(session, entity_id, question)
    if use_case == AIUseCase.DAILY_BRIEF:
        return _daily_brief_context(session, question)
    if use_case in (AIUseCase.VULN_IMPACT, AIUseCase.REMEDIATION_PLAN) and entity_id:
        return _vuln_context(session, entity_id, use_case, question)
    if use_case == AIUseCase.COMPLIANCE_GAP and entity_id:
        return _compliance_context(session, entity_id, question)
    if use_case == AIUseCase.CONFIG_CHANGE and entity_id:
        return _config_change_context(session, entity_id, question)
    if use_case in (AIUseCase.INCIDENT_SUMMARY, AIUseCase.EXEC_SUMMARY) and entity_id:
        return _incident_context(session, entity_id, use_case, question)
    # Default: free-form chat grounded by keyword retrieval.
    return _chat_context(session, question)
