"""Explainable OT risk scoring.

``compute_risk`` is a PURE, deterministic function of a flattened ``RiskInput`` so
it is fully unit-testable. ``build_risk_input`` assembles that input from the
database. The result carries the full ordered factor breakdown plus a single
recommended next action, all phrased for safe/passive OT operations.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from sqlmodel import Session, select

from app.core.enums import (
    GAP_CONTROL_STATUSES,
    Criticality,
    DetectionStatus,
    DetectionType,
    ImpactLevel,
    PatchStatus,
    PurdueLevel,
    RiskBand,
    Severity,
    SupportStatus,
    VulnRemediationStatus,
)
from app.models.asset import Asset
from app.models.compliance import ComplianceControl, ComplianceEvidence
from app.models.config_mgmt import ConfigChange
from app.models.detection import Detection
from app.models.vuln import AssetVulnerability, Vulnerability
from app.schemas.risk import RiskFactor, RiskResult

# Detection types that indicate active malicious/anomalous endpoint activity.
MALWARE_DETECTION_TYPES: frozenset[DetectionType] = frozenset(
    {
        DetectionType.MALWARE,
        DetectionType.QUARANTINED_FILE,
        DetectionType.YARA_MATCH,
        DetectionType.HASH_REPUTATION,
        DetectionType.SUSPICIOUS_PROCESS,
        DetectionType.AUTORUN_PERSISTENCE,
        DetectionType.UNSIGNED_BINARY,
        DetectionType.ENG_TOOL_ABUSE,
    }
)

OPEN_DETECTION_STATUSES: frozenset[DetectionStatus] = frozenset(
    {DetectionStatus.NEW, DetectionStatus.TRIAGING, DetectionStatus.CONFIRMED}
)

OPEN_VULN_STATUSES: frozenset[VulnRemediationStatus] = frozenset(
    {
        VulnRemediationStatus.OPEN,
        VulnRemediationStatus.PATCH_NOW,
        VulnRemediationStatus.MITIGATE,
        VulnRemediationStatus.MONITOR,
    }
)


@dataclass
class RiskInput:
    asset_id: uuid.UUID
    asset_tag: str
    criticality: Criticality
    safety_impact: ImpactLevel
    business_impact: ImpactLevel
    purdue_level: int
    internet_reachable: bool
    it_reachable: bool
    remote_access_enabled: bool
    support_status: SupportStatus
    patch_status: PatchStatus
    backup_available: bool
    has_owner: bool
    # Vulnerabilities
    has_kev_open: bool = False
    max_open_cvss: float = 0.0
    kev_refs: list[str] = field(default_factory=list)
    cvss_ref: str | None = None
    # Detections
    max_malware_severity: Severity | None = None
    malware_refs: list[str] = field(default_factory=list)
    # Config changes
    unauthorized_change_open: bool = False
    unauthorized_change_age_days: int = 0
    change_refs: list[str] = field(default_factory=list)
    # Compliance
    failed_controls_linked: int = 0
    control_refs: list[str] = field(default_factory=list)


_CRITICALITY_PTS = {
    Criticality.LOW: 2.0,
    Criticality.MEDIUM: 8.0,
    Criticality.HIGH: 14.0,
    Criticality.SAFETY_CRITICAL: 18.0,
}
_SAFETY_PTS = {
    ImpactLevel.NONE: 0.0,
    ImpactLevel.LOW: 5.0,
    ImpactLevel.MEDIUM: 10.0,
    ImpactLevel.HIGH: 16.0,
}
_BUSINESS_PTS = {
    ImpactLevel.NONE: 0.0,
    ImpactLevel.LOW: 2.0,
    ImpactLevel.MEDIUM: 5.0,
    ImpactLevel.HIGH: 8.0,
}
_MALWARE_PTS = {
    Severity.CRITICAL: 12.0,
    Severity.HIGH: 9.0,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.0,
    Severity.INFO: 1.0,
}


def _band(score: int) -> RiskBand:
    if score >= 80:
        return RiskBand.CRITICAL
    if score >= 60:
        return RiskBand.HIGH
    if score >= 35:
        return RiskBand.MEDIUM
    return RiskBand.LOW


def compute_risk(inp: RiskInput) -> RiskResult:
    asset_ref = f"asset:{inp.asset_id}"
    factors: list[RiskFactor] = []

    def add(key: str, label: str, points: float, max_points: float, detail: str, refs: list[str]):
        if points > 0:
            factors.append(
                RiskFactor(
                    key=key,
                    label=label,
                    points=round(points, 1),
                    max_points=max_points,
                    detail=detail,
                    record_refs=refs,
                )
            )

    # Criticality
    add(
        "criticality",
        "Asset criticality",
        _CRITICALITY_PTS[inp.criticality],
        18.0,
        f"Criticality is {inp.criticality.value}.",
        [asset_ref],
    )
    # Safety impact
    add(
        "safety_impact",
        "Safety impact",
        _SAFETY_PTS[inp.safety_impact],
        16.0,
        f"Safety impact rated {inp.safety_impact.value}.",
        [asset_ref],
    )
    # Business impact
    add(
        "business_impact",
        "Business impact",
        _BUSINESS_PTS[inp.business_impact],
        8.0,
        f"Business impact rated {inp.business_impact.value}.",
        [asset_ref],
    )
    # Known exploited vulnerability (KEV) / high CVSS
    if inp.has_kev_open:
        add(
            "known_exploited_vuln",
            "Known-exploited vulnerability",
            16.0,
            16.0,
            "At least one unmitigated CISA KEV-listed vulnerability affects this asset.",
            inp.kev_refs or [asset_ref],
        )
    elif inp.max_open_cvss >= 9.0:
        add(
            "known_exploited_vuln",
            "Critical-severity vulnerability",
            6.0,
            16.0,
            f"Unpatched vulnerability with CVSS {inp.max_open_cvss:.1f} present.",
            [inp.cvss_ref] if inp.cvss_ref else [asset_ref],
        )
    # CVSS exposure
    if inp.max_open_cvss > 0:
        add(
            "cvss_exposure",
            "Vulnerability severity exposure",
            min(10.0, inp.max_open_cvss),
            10.0,
            f"Highest open vulnerability CVSS is {inp.max_open_cvss:.1f}.",
            [inp.cvss_ref] if inp.cvss_ref else [asset_ref],
        )
    # Network exposure
    if inp.internet_reachable:
        add("network_exposure", "Network exposure", 12.0, 12.0,
            "Asset is reachable from the internet.", [asset_ref])
    elif inp.it_reachable:
        add("network_exposure", "Network exposure", 8.0, 12.0,
            "Asset is reachable from the IT network.", [asset_ref])
    elif inp.remote_access_enabled:
        add("network_exposure", "Network exposure", 6.0, 12.0,
            "Remote access is enabled to this asset.", [asset_ref])
    # Purdue inversion (low-level OT asset exposed upward)
    if inp.purdue_level <= PurdueLevel.L2:
        if inp.internet_reachable:
            add("purdue_inversion", "Purdue-level inversion", 6.0, 6.0,
                f"Level {inp.purdue_level} asset is internet-reachable.", [asset_ref])
        elif inp.it_reachable:
            add("purdue_inversion", "Purdue-level inversion", 3.0, 6.0,
                f"Level {inp.purdue_level} asset is IT-reachable.", [asset_ref])
    # Unsupported platform
    if inp.support_status == SupportStatus.UNSUPPORTED or inp.patch_status == PatchStatus.EOL:
        add("unsupported_platform", "Unsupported / end-of-life platform", 8.0, 8.0,
            "Platform is unsupported or end-of-life.", [asset_ref])
    elif inp.support_status == SupportStatus.EXTENDED or inp.patch_status == PatchStatus.OUTDATED:
        add("unsupported_platform", "Outdated platform", 4.0, 8.0,
            "Platform is on extended support or is outdated.", [asset_ref])
    # Unauthorized change
    if inp.unauthorized_change_open:
        pts = 8.0 if inp.unauthorized_change_age_days > 30 else 10.0
        add("unauthorized_change", "Unauthorized configuration change", pts, 10.0,
            "An unauthorized configuration change is open on this asset.", inp.change_refs or [asset_ref])
    # Malware / endpoint detection
    if inp.max_malware_severity is not None:
        add("malware_detection", "Active threat detection",
            _MALWARE_PTS.get(inp.max_malware_severity, 5.0), 12.0,
            f"Open endpoint/threat detection at {inp.max_malware_severity.value} severity.",
            inp.malware_refs or [asset_ref])
    # Missing backup
    if not inp.backup_available:
        add("missing_backup", "Missing backup/config", 4.0, 4.0,
            "No backup or saved configuration is recorded for this asset.", [asset_ref])
    # Missing owner (only matters for important assets)
    if not inp.has_owner and inp.criticality in (Criticality.HIGH, Criticality.SAFETY_CRITICAL):
        add("missing_owner", "Missing asset owner", 3.0, 3.0,
            "No owner is assigned to this high-criticality asset.", [asset_ref])
    # Compliance gaps
    if inp.failed_controls_linked > 0:
        add("compliance_gap", "Linked compliance gaps",
            min(5.0, inp.failed_controls_linked * 1.5), 5.0,
            f"{inp.failed_controls_linked} linked compliance control(s) are in a gap state.",
            inp.control_refs or [asset_ref])

    factors.sort(key=lambda f: f.points, reverse=True)
    raw = sum(f.points for f in factors)
    score = int(min(100.0, round(raw)))
    band = _band(score)
    top = [f.label for f in factors[:3]]
    action = _recommended_action(inp, factors)
    return RiskResult(
        score=score, band=band, factors=factors, top_factors=top, recommended_action=action
    )


def _recommended_action(inp: RiskInput, factors: list[RiskFactor]) -> str:
    keys = {f.key for f in factors}
    if "malware_detection" in keys:
        return (
            "Isolate the affected endpoint using existing, pre-approved network controls "
            "(do not alter PLC logic). Preserve forensic evidence and open an incident."
        )
    if "known_exploited_vuln" in keys and inp.has_kev_open:
        return (
            "Prioritize remediation of the known-exploited vulnerability. If patching is not "
            "feasible, apply OT compensating controls (segmentation, monitoring, access restriction)."
        )
    if "unauthorized_change" in keys:
        return (
            "Investigate the unauthorized configuration change. Compare against the approved "
            "baseline and confirm the associated change ticket before taking any action."
        )
    if "network_exposure" in keys and (inp.internet_reachable or inp.it_reachable):
        return (
            "Review network segmentation. Remove internet/IT reachability and restrict remote "
            "access to this OT asset via the firewall change process."
        )
    if "unsupported_platform" in keys:
        return (
            "Plan migration or apply compensating controls for the unsupported/EOL platform; "
            "increase monitoring in the interim."
        )
    if score_is_elevated(factors):
        return "Schedule a risk review, assign an owner, and ensure a current backup exists."
    return "Maintain passive monitoring; no elevated risk indicators."


def score_is_elevated(factors: list[RiskFactor]) -> bool:
    return sum(f.points for f in factors) >= 35


# --------------------------------------------------------------------------- #
# DB assembly
# --------------------------------------------------------------------------- #
def build_risk_input(session: Session, asset: Asset) -> RiskInput:
    assert asset.id is not None

    # Open vulnerabilities for this asset
    av_rows = session.exec(
        select(AssetVulnerability, Vulnerability)
        .where(AssetVulnerability.asset_id == asset.id)
        .where(AssetVulnerability.vuln_id == Vulnerability.id)
    ).all()
    has_kev = False
    max_cvss = 0.0
    kev_refs: list[str] = []
    cvss_ref: str | None = None
    for av, vuln in av_rows:
        if av.status not in OPEN_VULN_STATUSES:
            continue
        if vuln.known_exploited:
            has_kev = True
            kev_refs.append(f"vuln:{vuln.cve_id}")
        if vuln.cvss_base > max_cvss:
            max_cvss = vuln.cvss_base
            cvss_ref = f"vuln:{vuln.cve_id}"

    # Open malware/threat detections
    dets = session.exec(select(Detection).where(Detection.asset_id == asset.id)).all()
    max_sev: Severity | None = None
    malware_refs: list[str] = []
    sev_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    for d in dets:
        if d.status not in OPEN_DETECTION_STATUSES:
            continue
        if d.detection_type in MALWARE_DETECTION_TYPES:
            malware_refs.append(f"detection:{d.id}")
            if max_sev is None or sev_order.index(d.severity) > sev_order.index(max_sev):
                max_sev = d.severity

    # Unauthorized config changes
    from app.core.enums import ChangeDisposition
    from app.models.base import utcnow

    changes = session.exec(
        select(ConfigChange)
        .where(ConfigChange.asset_id == asset.id)
        .where(ConfigChange.disposition == ChangeDisposition.UNAUTHORIZED)
    ).all()
    unauth_open = len(changes) > 0
    age_days = 0
    change_refs: list[str] = []
    for c in changes:
        change_refs.append(f"config_change:{c.id}")
        ref_dt = c.detected_at or c.created_at
        if ref_dt is not None:
            age_days = max(age_days, (utcnow() - ref_dt).days)

    # Linked compliance gaps
    ev_rows = session.exec(
        select(ComplianceEvidence, ComplianceControl)
        .where(ComplianceEvidence.source_id == asset.id)
        .where(ComplianceEvidence.control_id == ComplianceControl.id)
    ).all()
    gap_control_ids: set[uuid.UUID] = set()
    control_refs: list[str] = []
    for _ev, ctrl in ev_rows:
        if ctrl.status in GAP_CONTROL_STATUSES and ctrl.id is not None:
            gap_control_ids.add(ctrl.id)
            control_refs.append(f"control:{ctrl.control_ref}")

    return RiskInput(
        asset_id=asset.id,
        asset_tag=asset.asset_tag,
        criticality=asset.criticality,
        safety_impact=asset.safety_impact,
        business_impact=asset.business_impact,
        purdue_level=int(asset.purdue_level),
        internet_reachable=asset.internet_reachable,
        it_reachable=asset.it_reachable,
        remote_access_enabled=asset.remote_access_enabled,
        support_status=asset.support_status,
        patch_status=asset.patch_status,
        backup_available=asset.backup_available,
        has_owner=bool(asset.owner),
        has_kev_open=has_kev,
        max_open_cvss=max_cvss,
        kev_refs=kev_refs,
        cvss_ref=cvss_ref,
        max_malware_severity=max_sev,
        malware_refs=malware_refs,
        unauthorized_change_open=unauth_open,
        unauthorized_change_age_days=age_days,
        change_refs=change_refs,
        failed_controls_linked=len(gap_control_ids),
        control_refs=sorted(set(control_refs)),
    )


def score_asset(session: Session, asset: Asset, *, persist: bool = True) -> RiskResult:
    """Compute risk for an asset and optionally persist the denormalized score."""
    result = compute_risk(build_risk_input(session, asset))
    if persist:
        asset.risk_score = result.score
        asset.risk_band = result.band
        session.add(asset)
        session.commit()
        session.refresh(asset)
    return result


def recompute_all(session: Session) -> int:
    assets = session.exec(select(Asset)).all()
    for asset in assets:
        score_asset(session, asset, persist=True)
    return len(assets)
