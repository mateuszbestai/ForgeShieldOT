"""Detection business logic, the rule-template registry, and the template
factory reused by passive discovery and seeding.

Everything here is DEFENSIVE and SIMULATED. Containment guidance is strictly
PASSIVE/SAFE: no PLC writes, no automated blocking, no offensive actions.
"""
from __future__ import annotations

import uuid

from sqlalchemy import func
from sqlmodel import Session, or_, select

from app.core.enums import (
    AuditAction,
    Confidence,
    DetectionStatus,
    DetectionType,
    Severity,
    SourceType,
)
from app.core.exceptions import NotFoundError
from app.core.security import AuthenticatedUser
from app.models.asset import Asset
from app.models.base import utcnow
from app.models.detection import Detection, DetectionEvidence
from app.schemas.common import PaginationParams
from app.schemas.detection import DetectionCreate, DetectionFilter, DetectionUpdate, EvidenceCreate
from app.services.audit_service import record_audit
from app.services.risk_engine import OPEN_DETECTION_STATUSES, score_asset

# Detection statuses that, when reached, warrant recomputing the linked asset's risk.
RISK_AFFECTING_STATUSES: frozenset[DetectionStatus] = frozenset(
    {DetectionStatus.CONFIRMED, DetectionStatus.RESOLVED, DetectionStatus.FALSE_POSITIVE}
)


# --------------------------------------------------------------------------- #
# Rule templates — per DetectionType defaults (severity / confidence /
# MITRE ATT&CK for ICS mapping / triage + safe passive containment / AI summary)
# --------------------------------------------------------------------------- #
# ATT&CK for ICS technique IDs referenced below (all real techniques):
#   T0883 Internet Accessible Device
#   T0866 Exploitation of Remote Services
#   T0822 External Remote Services
#   T0886 Remote Services
#   T0846 Remote System Discovery
#   T0847 Replication Through Removable Media
#   T0867 Lateral Tool Transfer
#   T0863 User Execution
#   T0859 Valid Accounts
#   T0843 Program Download
#   T0858 Change Operating Mode
#   T0889 Modify Program
#   T0857 Program Organization Units
#   T0865 Spearphishing Attachment
#   T0807 Command-Line Interface
DETECTION_RULE_TEMPLATES: dict[DetectionType, dict] = {
    DetectionType.EW_TO_PLC: {
        "title": "Engineering workstation to controller interaction",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "attck_ics_tactic": "Lateral Movement",
        "attck_ics_technique": "T0843",  # Program Download
        "triage_steps": [
            "Confirm the engineering workstation and target controller from the observed flow.",
            "Verify whether an approved change window or work order covers this interaction.",
            "Compare current controller program/config against the approved baseline.",
            "Interview the assigned engineer to validate intent.",
        ],
        "safe_containment_steps": [
            "Increase passive monitoring of the engineering workstation and conduit.",
            "If unauthorized, request a firewall/ACL review to restrict EW->controller paths to approved hosts (change-managed).",
            "Preserve flow records and engineering-tool logs as evidence.",
        ],
        "ai_summary": "An engineering workstation was observed communicating to a controller over an OT control protocol; validate against approved change activity before concluding.",
    },
    DetectionType.OUT_OF_WINDOW_CHANGE: {
        "title": "Controller change outside approved window",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "attck_ics_tactic": "Impair Process Control",
        "attck_ics_technique": "T0889",  # Modify Program
        "triage_steps": [
            "Identify the controller and the time of the observed change.",
            "Check the maintenance/change calendar for an approved window covering that time.",
            "Diff the new program/config snapshot against the last approved baseline.",
            "Confirm operator/engineer who performed the change.",
        ],
        "safe_containment_steps": [
            "Flag the related configuration change for disposition review.",
            "Snapshot the current configuration for evidence (read-only).",
            "Notify the change-management owner; do not roll back logic without authorization.",
        ],
        "ai_summary": "A controller program/configuration change was observed outside an approved maintenance window; confirm authorization before any action.",
    },
    DetectionType.NEW_DEVICE_IN_ZONE: {
        "title": "New device observed in OT zone",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "attck_ics_tactic": "Discovery",
        "attck_ics_technique": "T0846",  # Remote System Discovery
        "triage_steps": [
            "Identify the new device (IP/MAC/hostname) and the zone/Purdue level it appeared in.",
            "Determine whether it matches an approved asset onboarding request.",
            "Identify the switch port / conduit where it was first seen.",
            "Classify the device type and intended function.",
        ],
        "safe_containment_steps": [
            "Add the device to the inventory as 'unverified' pending confirmation.",
            "Increase passive monitoring of the device's communications.",
            "If unapproved, request a port/ACL review through the change process.",
        ],
        "ai_summary": "A previously unseen device appeared in a low-level OT zone; verify it is an approved asset and not an unauthorized connection.",
    },
    DetectionType.USB_INSERTION: {
        "title": "Removable media (USB) inserted on OT endpoint",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
        "attck_ics_tactic": "Lateral Movement",
        "attck_ics_technique": "T0847",  # Replication Through Removable Media
        "triage_steps": [
            "Identify the host, user, and the USB device descriptor.",
            "Determine whether removable media is permitted on this host per policy.",
            "Review EDR/AV scan results for files accessed from the device.",
            "Confirm the activity with the on-site operator.",
        ],
        "safe_containment_steps": [
            "Request the operator safely remove the device if unauthorized.",
            "Run an on-demand AV/EDR scan of the host.",
            "Preserve USB and host event logs as evidence.",
        ],
        "ai_summary": "Removable media was inserted on an OT endpoint; confirm it is sanctioned and scan for introduced files.",
    },
    DetectionType.MALWARE: {
        "title": "Malware detected on OT endpoint",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "attck_ics_tactic": "Execution",
        "attck_ics_technique": "T0863",  # User Execution
        "triage_steps": [
            "Identify the host, detection name, and file path/hash.",
            "Confirm whether the file executed or was quarantined on write.",
            "Check for lateral movement or persistence indicators.",
            "Determine business/safety impact of the affected host.",
        ],
        "safe_containment_steps": [
            "Isolate the endpoint using existing, pre-approved network controls (do not alter PLC logic).",
            "Preserve forensic evidence (memory/disk artifacts) before remediation.",
            "Open an incident and notify the OT security lead.",
        ],
        "ai_summary": "Malware was detected on an OT host; isolate via approved controls, preserve evidence, and assess process impact.",
    },
    DetectionType.UNUSUAL_OUTBOUND: {
        "title": "Unusual outbound connection from OT host",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "attck_ics_tactic": "Command and Control",
        "attck_ics_technique": "T0884",  # Connection Proxy
        "triage_steps": [
            "Identify the source host and the destination IP/domain/port.",
            "Determine whether the destination is a known/approved service.",
            "Review the volume, frequency, and timing of the connection.",
            "Correlate with any endpoint detections on the same host.",
        ],
        "safe_containment_steps": [
            "Increase passive monitoring of the host's egress.",
            "If malicious, request a firewall egress-rule review (change-managed) to block the destination.",
            "Preserve flow and DNS records as evidence.",
        ],
        "ai_summary": "An OT host made an unusual outbound connection; validate the destination and inspect for beaconing or exfiltration.",
    },
    DetectionType.RDP_FROM_UNAPPROVED: {
        "title": "RDP from non-approved source",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "attck_ics_tactic": "Lateral Movement",
        "attck_ics_technique": "T0886",  # Remote Services
        "triage_steps": [
            "Identify the RDP source and destination hosts.",
            "Check whether the source is on the approved remote-access allowlist.",
            "Verify the authenticating account and session timing.",
            "Confirm whether a jump host / gateway was bypassed.",
        ],
        "safe_containment_steps": [
            "Increase monitoring of the destination host's sessions.",
            "If unapproved, request an ACL review to restrict RDP to approved sources/gateways (change-managed).",
            "Preserve authentication and session logs as evidence.",
        ],
        "ai_summary": "An RDP session originated from a source outside the approved remote-access path; verify the source and account.",
    },
    DetectionType.FIREWALL_EXPOSURE: {
        "title": "Firewall rule exposes OT asset",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "attck_ics_tactic": "Initial Access",
        "attck_ics_technique": "T0883",  # Internet Accessible Device
        "triage_steps": [
            "Identify the firewall rule and the OT asset/service it exposes.",
            "Determine the exposure scope (internet vs IT) and the protocol/port.",
            "Check for a documented business justification for the rule.",
            "Assess the criticality of the exposed asset.",
        ],
        "safe_containment_steps": [
            "Flag the rule for review by the firewall/change-management owner.",
            "Recommend restricting the rule to approved sources or removing it (change-managed).",
            "Increase monitoring of traffic to the exposed asset.",
        ],
        "ai_summary": "A firewall rule exposes an OT asset more broadly than expected; review the rule's justification and tighten scope.",
    },
    DetectionType.UNSUPPORTED_OS: {
        "title": "Unsupported OS on critical endpoint",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
        "attck_ics_tactic": "Persistence",
        "attck_ics_technique": "T0859",  # Valid Accounts
        "triage_steps": [
            "Confirm the OS name/version and end-of-support status.",
            "Assess the asset's criticality and exposure.",
            "Identify available compensating controls (segmentation, monitoring).",
            "Check for a migration/upgrade plan.",
        ],
        "safe_containment_steps": [
            "Document the platform as unsupported in the inventory.",
            "Recommend network segmentation and increased monitoring as interim controls.",
            "Plan a supported-platform migration with the asset owner.",
        ],
        "ai_summary": "A critical endpoint runs an unsupported/end-of-life OS; apply compensating controls and plan migration.",
    },
    DetectionType.KEV_EXPOSURE: {
        "title": "Known-exploited vulnerability on OT-reachable asset",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "attck_ics_tactic": "Initial Access",
        "attck_ics_technique": "T0866",  # Exploitation of Remote Services
        "triage_steps": [
            "Identify the CVE and the affected asset/service.",
            "Confirm the asset is reachable from a less-trusted network.",
            "Check vendor advisories for patches or mitigations.",
            "Assess process/safety impact if exploited.",
        ],
        "safe_containment_steps": [
            "Prioritize remediation of the known-exploited vulnerability.",
            "If patching is infeasible, apply OT compensating controls (segmentation, access restriction, monitoring).",
            "Track remediation through the vulnerability-management process.",
        ],
        "ai_summary": "An OT-reachable asset is affected by a CISA KEV-listed vulnerability; prioritize remediation or compensating controls.",
    },
    DetectionType.UNKNOWN_ASSET: {
        "title": "Unknown asset discovered on the network",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "attck_ics_tactic": "Discovery",
        "attck_ics_technique": "T0846",  # Remote System Discovery
        "triage_steps": [
            "Identify the device by IP/MAC/hostname and where it was first seen.",
            "Determine whether it corresponds to an approved but un-inventoried asset.",
            "Classify the device type and function from its protocols.",
            "Confirm with site/operations whether it is expected.",
        ],
        "safe_containment_steps": [
            "Add the device to the inventory as 'unverified'.",
            "Increase passive monitoring of its communications.",
            "If unapproved, request a port/ACL review (change-managed).",
        ],
        "ai_summary": "A device not present in the inventory was observed; identify and verify it before trusting its communications.",
    },
    DetectionType.UNKNOWN_COMM_PATH: {
        "title": "Unknown communication path observed",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "attck_ics_tactic": "Lateral Movement",
        "attck_ics_technique": "T0867",  # Lateral Tool Transfer
        "triage_steps": [
            "Identify the source and destination assets and the protocol used.",
            "Determine whether this conduit is documented/expected between these zones.",
            "Review the volume and timing of the communication.",
            "Confirm intent with the asset owners.",
        ],
        "safe_containment_steps": [
            "Mark the path as unverified and increase passive monitoring.",
            "If unauthorized, request a segmentation/ACL review (change-managed).",
            "Preserve flow records as evidence.",
        ],
        "ai_summary": "A previously unseen communication path between assets was observed; verify whether the conduit is authorized.",
    },
    DetectionType.REMOTE_ACCESS: {
        "title": "Remote-access session to OT asset",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "attck_ics_tactic": "Initial Access",
        "attck_ics_technique": "T0822",  # External Remote Services
        "triage_steps": [
            "Identify the remote-access source, destination, and protocol.",
            "Verify the session used an approved gateway and account.",
            "Confirm the session is covered by an approved access request.",
            "Review session timing against expected maintenance windows.",
        ],
        "safe_containment_steps": [
            "Increase monitoring of remote-access sessions to the asset.",
            "If unapproved, request restriction of remote access to approved gateways (change-managed).",
            "Preserve authentication and session logs as evidence.",
        ],
        "ai_summary": "A remote-access session reached an OT asset; verify it used an approved gateway, account, and window.",
    },
    DetectionType.AUTORUN_PERSISTENCE: {
        "title": "Autorun / persistence mechanism detected",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "attck_ics_tactic": "Persistence",
        "attck_ics_technique": "T0889",  # Modify Program (host persistence analog)
        "triage_steps": [
            "Identify the host and the persistence mechanism (registry/run key/service/task).",
            "Determine the binary/script invoked and its provenance.",
            "Check whether the entry is part of a sanctioned application.",
            "Look for related endpoint detections.",
        ],
        "safe_containment_steps": [
            "Increase EDR monitoring of the host.",
            "Preserve the persistence artifact and related logs as evidence.",
            "If malicious, isolate via approved network controls and open an incident.",
        ],
        "ai_summary": "A persistence mechanism was detected on an OT host; validate provenance and check for related malicious activity.",
    },
    DetectionType.YARA_MATCH: {
        "title": "YARA rule match on OT endpoint",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "attck_ics_tactic": "Execution",
        "attck_ics_technique": "T0863",  # User Execution
        "triage_steps": [
            "Identify the host, matched YARA rule, and file path/hash.",
            "Determine whether the rule is high-fidelity or generic.",
            "Confirm whether the file executed or is dormant.",
            "Correlate with other endpoint detections.",
        ],
        "safe_containment_steps": [
            "Quarantine the matched file via the existing endpoint agent.",
            "Preserve the sample and host logs as evidence.",
            "If confirmed malicious, isolate the host via approved controls and open an incident.",
        ],
        "ai_summary": "A YARA rule matched content on an OT host; assess fidelity and confirm whether the file is malicious.",
    },
    DetectionType.SUSPICIOUS_PROCESS: {
        "title": "Suspicious process on OT endpoint",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "attck_ics_tactic": "Execution",
        "attck_ics_technique": "T0807",  # Command-Line Interface
        "triage_steps": [
            "Identify the host, process name, command line, and parent process.",
            "Determine whether the process is expected on this OT host.",
            "Check the signing status and origin of the executable.",
            "Review related network and file activity.",
        ],
        "safe_containment_steps": [
            "Increase EDR monitoring of the host.",
            "Preserve process and command-line telemetry as evidence.",
            "If malicious, isolate the host via approved controls and open an incident.",
        ],
        "ai_summary": "A suspicious process was observed on an OT host; validate whether it is expected and inspect related activity.",
    },
    DetectionType.ENDPOINT_PROTECTION_STATUS: {
        "title": "Endpoint protection unhealthy or missing",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
        "attck_ics_tactic": "Defense Evasion",
        "attck_ics_technique": "T0858",  # Change Operating Mode (defense impairment analog)
        "triage_steps": [
            "Identify the host and the protection-agent state (missing/disabled/outdated).",
            "Determine whether the host type is expected to run an agent.",
            "Check the last successful scan/definition-update time.",
            "Confirm whether maintenance explains the state.",
        ],
        "safe_containment_steps": [
            "Schedule re-enablement/repair of the endpoint agent with the asset owner.",
            "Increase network-based monitoring while the agent is degraded.",
            "Document the gap in the inventory.",
        ],
        "ai_summary": "An OT endpoint's protection agent is missing or unhealthy; restore coverage and monitor in the interim.",
    },
}

# Fallback template used when a DetectionType has no explicit entry.
_DEFAULT_TEMPLATE: dict = {
    "title": "Security detection",
    "severity": Severity.MEDIUM,
    "confidence": Confidence.MEDIUM,
    "attck_ics_tactic": None,
    "attck_ics_technique": None,
    "triage_steps": [
        "Review the detection details and affected asset.",
        "Validate whether the activity is expected/approved.",
        "Preserve relevant evidence.",
    ],
    "safe_containment_steps": [
        "Increase passive monitoring of the affected asset.",
        "Escalate to the OT security lead if the activity is unexpected.",
    ],
    "ai_summary": "A security detection was raised; review the affected asset and validate the activity.",
}


def template_for(detection_type: DetectionType) -> dict:
    """Return the rule template for a detection type (falling back to a generic one)."""
    return DETECTION_RULE_TEMPLATES.get(detection_type, _DEFAULT_TEMPLATE)


# --------------------------------------------------------------------------- #
# Detection factory
# --------------------------------------------------------------------------- #
def make_detection(
    detection_type: DetectionType,
    *,
    title: str | None = None,
    severity: Severity | None = None,
    confidence: Confidence | None = None,
    asset_id: uuid.UUID | None = None,
    site_id: uuid.UUID | None = None,
    description: str = "",
    source: SourceType = SourceType.SEED,
    is_demo: bool = True,
) -> Detection:
    """Build (but do not persist) a Detection from a rule template + overrides."""
    tpl = template_for(detection_type)
    return Detection(
        title=title or tpl["title"],
        detection_type=detection_type,
        severity=severity or tpl["severity"],
        confidence=confidence or tpl["confidence"],
        status=DetectionStatus.NEW,
        asset_id=asset_id,
        site_id=site_id,
        description=description,
        attck_ics_technique=tpl["attck_ics_technique"],
        attck_ics_tactic=tpl["attck_ics_tactic"],
        triage_steps=list(tpl["triage_steps"]),
        safe_containment_steps=list(tpl["safe_containment_steps"]),
        ai_summary=tpl["ai_summary"],
        source=source,
        detected_at=utcnow(),
        is_demo=is_demo,
    )


def create_from_template(
    session: Session,
    detection_type: DetectionType,
    asset: Asset | None,
    site_id: uuid.UUID | None,
    *,
    title: str | None = None,
    evidence: list[EvidenceCreate] | None = None,
    source: SourceType = SourceType.SEED,
) -> Detection:
    """Create and persist a Detection from a template, optionally with evidence.

    Reused by passive discovery handlers and by the seed routine.
    """
    asset_id = asset.id if asset is not None else None
    resolved_site = site_id if site_id is not None else (asset.site_id if asset is not None else None)
    detection = make_detection(
        detection_type,
        title=title,
        asset_id=asset_id,
        site_id=resolved_site,
        source=source,
    )
    session.add(detection)
    session.commit()
    session.refresh(detection)

    for ev in evidence or []:
        session.add(
            DetectionEvidence(
                detection_id=detection.id,
                kind=ev.kind,
                label=ev.label,
                data=ev.data,
                is_demo=True,
            )
        )
    if evidence:
        session.commit()
        session.refresh(detection)
    return detection


# --------------------------------------------------------------------------- #
# Queries / CRUD
# --------------------------------------------------------------------------- #
def list_detections(
    session: Session, *, filters: DetectionFilter, page: PaginationParams
) -> tuple[list[Detection], int]:
    stmt = select(Detection)
    count_stmt = select(func.count()).select_from(Detection)

    conditions = []
    if filters.status:
        conditions.append(Detection.status == filters.status)
    if filters.severity:
        conditions.append(Detection.severity == filters.severity)
    if filters.detection_type:
        conditions.append(Detection.detection_type == filters.detection_type)
    if filters.asset_id:
        conditions.append(Detection.asset_id == filters.asset_id)
    if filters.site_id:
        conditions.append(Detection.site_id == filters.site_id)
    if page.search:
        term = f"%{page.search}%"
        conditions.append(
            or_(
                Detection.title.ilike(term),  # type: ignore[attr-defined]
                Detection.description.ilike(term),  # type: ignore[attr-defined]
            )
        )
    for cond in conditions:
        stmt = stmt.where(cond)
        count_stmt = count_stmt.where(cond)

    total = session.exec(count_stmt).one()
    stmt = stmt.order_by(Detection.detected_at.desc()).offset(page.offset).limit(page.limit)  # type: ignore[attr-defined]
    items = session.exec(stmt).all()
    return list(items), int(total)


def get_detection(session: Session, detection_id: uuid.UUID) -> Detection:
    detection = session.get(Detection, detection_id)
    if detection is None:
        raise NotFoundError("Detection not found")
    return detection


def create_detection(
    session: Session, data: DetectionCreate, user: AuthenticatedUser | None = None
) -> Detection:
    asset = session.get(Asset, data.asset_id) if data.asset_id else None
    if data.asset_id and asset is None:
        raise NotFoundError("Asset not found")
    site_id = data.site_id if data.site_id else (asset.site_id if asset else None)
    detection = make_detection(
        data.detection_type,
        title=data.title,
        severity=data.severity,
        confidence=data.confidence,
        asset_id=data.asset_id,
        site_id=site_id,
        description=data.description,
        source=data.source,
    )
    session.add(detection)
    session.commit()
    session.refresh(detection)
    record_audit(
        session,
        action=AuditAction.DETECTION_STATUS_CHANGE,
        actor_user_id=user.id if user else None,
        actor_email=user.email if user else None,
        entity_type="detection",
        entity_id=detection.id,
        summary=f"Created detection '{detection.title}' ({detection.detection_type.value})",
    )
    if asset is not None:
        score_asset(session, asset, persist=True)
    return detection


def update_detection(
    session: Session, detection_id: uuid.UUID, data: DetectionUpdate, user: AuthenticatedUser | None
) -> Detection:
    detection = get_detection(session, detection_id)
    old_status = detection.status

    update_fields = data.model_dump(exclude_unset=True)
    new_status = update_fields.get("status")

    if "severity" in update_fields and update_fields["severity"] is not None:
        detection.severity = update_fields["severity"]
    if "confidence" in update_fields and update_fields["confidence"] is not None:
        detection.confidence = update_fields["confidence"]
    if "triage_steps" in update_fields and update_fields["triage_steps"] is not None:
        detection.triage_steps = update_fields["triage_steps"]
    if update_fields.get("triage_notes"):
        # Append triage notes to the description (audited free-form context).
        note = update_fields["triage_notes"]
        detection.description = (
            f"{detection.description}\n\n[Triage] {note}".strip()
            if detection.description
            else f"[Triage] {note}"
        )
    if new_status is not None:
        detection.status = new_status

    session.add(detection)
    session.commit()
    session.refresh(detection)

    status_changed = new_status is not None and new_status != old_status
    summary = (
        f"Detection '{detection.title}' status {old_status.value} -> {detection.status.value}"
        if status_changed
        else f"Triaged detection '{detection.title}'"
    )
    record_audit(
        session,
        action=AuditAction.DETECTION_STATUS_CHANGE,
        actor_user_id=user.id if user else None,
        actor_email=user.email if user else None,
        entity_type="detection",
        entity_id=detection.id,
        summary=summary,
    )

    # Resolving / confirming / dismissing changes the asset's open-detection picture,
    # so recompute the linked asset's risk.
    if (
        status_changed
        and detection.asset_id is not None
        and (new_status in RISK_AFFECTING_STATUSES or old_status in OPEN_DETECTION_STATUSES)
    ):
        asset = session.get(Asset, detection.asset_id)
        if asset is not None:
            score_asset(session, asset, persist=True)

    return detection


def add_evidence(
    session: Session,
    detection_id: uuid.UUID,
    data: EvidenceCreate,
    user: AuthenticatedUser | None,
) -> DetectionEvidence:
    detection = get_detection(session, detection_id)
    evidence = DetectionEvidence(
        detection_id=detection.id,
        kind=data.kind,
        label=data.label,
        data=data.data,
        is_demo=detection.is_demo,
    )
    session.add(evidence)
    session.commit()
    session.refresh(evidence)
    record_audit(
        session,
        action=AuditAction.DETECTION_STATUS_CHANGE,
        actor_user_id=user.id if user else None,
        actor_email=user.email if user else None,
        entity_type="detection",
        entity_id=detection.id,
        summary=f"Added {data.kind.value} evidence to detection '{detection.title}'",
    )
    return evidence


# --------------------------------------------------------------------------- #
# Detail / stats
# --------------------------------------------------------------------------- #
def detection_detail(session: Session, detection: Detection) -> dict:
    """Assemble detection detail: the detection, its evidence, and an asset summary."""
    assert detection.id is not None
    evidence = session.exec(
        select(DetectionEvidence).where(DetectionEvidence.detection_id == detection.id)
    ).all()
    asset_summary: dict | None = None
    if detection.asset_id is not None:
        asset = session.get(Asset, detection.asset_id)
        if asset is not None:
            asset_summary = {
                "id": str(asset.id),
                "asset_tag": asset.asset_tag,
                "asset_type": asset.asset_type.value,
                "risk_band": asset.risk_band.value,
                "risk_score": asset.risk_score,
            }
    return {
        "detection": detection.model_dump(),
        "evidence": [e.model_dump() for e in evidence],
        "asset": asset_summary,
    }


def detection_stats(session: Session) -> dict:
    """Counts of detections grouped by status, severity, and type."""

    def _counts(column) -> dict[str, int]:
        rows = session.exec(select(column, func.count()).group_by(column)).all()
        out: dict[str, int] = {}
        for key, count in rows:
            label = key.value if hasattr(key, "value") else str(key)
            out[label] = int(count)
        return out

    total = int(session.exec(select(func.count()).select_from(Detection)).one())
    open_count = int(
        session.exec(
            select(func.count())
            .select_from(Detection)
            .where(Detection.status.in_(tuple(OPEN_DETECTION_STATUSES)))  # type: ignore[attr-defined]
        ).one()
    )
    return {
        "total": total,
        "open": open_count,
        "by_status": _counts(Detection.status),
        "by_severity": _counts(Detection.severity),
        "by_type": _counts(Detection.detection_type),
    }
