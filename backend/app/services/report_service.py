"""Report generation business logic.

One renderer per ``ReportType`` produces Markdown by querying the database
directly (this service does not depend on other domains' services). Markdown is
the source format; it is converted to HTML on demand with the ``markdown``
library. Every report carries a banner making clear it contains SIMULATED/DEMO
data. PDF rendering is opt-in (``settings.reports_pdf_enabled``) and only
available when WeasyPrint can be imported.
"""
from __future__ import annotations

import uuid
from collections import Counter
from collections.abc import Callable

import markdown
from sqlalchemy import func
from sqlmodel import Session, select

from app.ai.service import run_ai_query
from app.core.config import settings
from app.core.enums import (
    GAP_CONTROL_STATUSES,
    AIUseCase,
    AuditAction,
    ChangeDisposition,
    ControlStatus,
    DetectionStatus,
    FrameworkKey,
    IncidentStatus,
    ReportFormat,
    ReportType,
    VulnRemediationStatus,
)
from app.core.exceptions import NotFoundError, ValidationAppError
from app.core.security import AuthenticatedUser
from app.models.asset import Asset
from app.models.compliance import (
    ComplianceControl,
    ComplianceEvidence,
    ComplianceFramework,
)
from app.models.config_mgmt import ConfigChange
from app.models.detection import Detection
from app.models.incident import Incident, IncidentLink, IncidentTimelineEvent
from app.models.org import Site
from app.models.report import Report
from app.models.vuln import AssetVulnerability, Vulnerability
from app.schemas.common import PaginationParams
from app.schemas.report import GenerateReportRequest
from app.services.audit_service import record_audit

# Vulnerability workflow states still considered actively open.
_OPEN_VULN_STATUSES: frozenset[VulnRemediationStatus] = frozenset(
    {
        VulnRemediationStatus.OPEN,
        VulnRemediationStatus.PATCH_NOW,
        VulnRemediationStatus.MITIGATE,
        VulnRemediationStatus.MONITOR,
    }
)

_OPEN_INCIDENT_STATUSES: frozenset[IncidentStatus] = frozenset(
    {IncidentStatus.OPEN, IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED}
)

_DEMO_BANNER = (
    "> **SIMULATED / DEMO DATA.** This report was generated from the simulated "
    "ForgeShield OT evaluation dataset. It is advisory only and must not be used "
    "to operate production OT/ICS systems."
)


# --------------------------------------------------------------------------- #
# Report-type catalog
# --------------------------------------------------------------------------- #
_REPORT_CATALOG: dict[ReportType, tuple[str, str]] = {
    ReportType.EXEC_RISK_SUMMARY: (
        "Executive Risk Summary",
        "Portfolio-level OT risk posture: asset counts, risk bands, top risky "
        "assets, KEV exposure and open incidents/detections.",
    ),
    ReportType.ASSET_INVENTORY: (
        "Asset Inventory",
        "Full inventory of OT assets with type, site, Purdue level, criticality "
        "and risk.",
    ),
    ReportType.VULN_REMEDIATION_PLAN: (
        "Vulnerability Remediation Plan",
        "Open asset/vulnerability matches ranked by OT-aware priority with "
        "recommended SAFE/PASSIVE actions.",
    ),
    ReportType.UNAUTHORIZED_CHANGE: (
        "Unauthorized Change Report",
        "Configuration changes dispositioned as UNAUTHORIZED with affected "
        "assets and diff summaries.",
    ),
    ReportType.COMPLIANCE_GAP: (
        "Compliance Gap Report",
        "Per-framework readiness and the list of open gap controls "
        "(not-started / partial).",
    ),
    ReportType.IEC62443_EVIDENCE: (
        "IEC 62443 Evidence Pack",
        "IEC 62443 controls with their linked evidence.",
    ),
    ReportType.NERC_CIP_EVIDENCE: (
        "NERC CIP Evidence Pack",
        "NERC CIP controls with their linked evidence.",
    ),
    ReportType.NIS2_READINESS: (
        "NIS2 Readiness Summary",
        "NIS2 control readiness summary and gap list.",
    ),
    ReportType.OTCC_READINESS: (
        "NCA OTCC Readiness Summary",
        "NCA OTCC control readiness summary and gap list.",
    ),
    ReportType.INCIDENT_REPORT: (
        "Incident Report",
        "Single incident with timeline and linked entities. Requires "
        "params['incident_id'].",
    ),
    ReportType.AI_DAILY_BRIEF: (
        "AI Daily Brief",
        "AI-generated daily OT security brief (falls back to a deterministic "
        "brief if the AI provider is unavailable).",
    ),
}


def available_types() -> list[dict]:
    return [
        {
            "report_type": rt.value,
            "title": title,
            "description": description,
        }
        for rt, (title, description) in _REPORT_CATALOG.items()
    ]


# --------------------------------------------------------------------------- #
# Markdown helpers
# --------------------------------------------------------------------------- #
def _esc(value: object) -> str:
    """Escape pipe characters so free-form text never breaks a Markdown table."""
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ")


def _header(title: str, extra: list[str] | None = None) -> list[str]:
    lines = [f"# {title}", "", _DEMO_BANNER, ""]
    if extra:
        lines.extend(extra)
        lines.append("")
    return lines


def _band_distribution(assets: list[Asset]) -> Counter:
    return Counter(a.risk_band.value for a in assets)


# --------------------------------------------------------------------------- #
# Renderers (each returns (title, summary, markdown))
# --------------------------------------------------------------------------- #
def _render_exec_risk_summary(
    session: Session, req: GenerateReportRequest, user: AuthenticatedUser | None
) -> tuple[str, str, str]:
    assets = list(session.exec(select(Asset)).all())
    total_assets = len(assets)
    bands = _band_distribution(assets)
    crit_count = Counter(a.criticality.value for a in assets)

    top = sorted(assets, key=lambda a: a.risk_score, reverse=True)[:10]

    kev_exposure = int(
        session.exec(
            select(func.count())
            .select_from(AssetVulnerability)
            .where(AssetVulnerability.vuln_id == Vulnerability.id)
            .where(Vulnerability.known_exploited.is_(True))  # type: ignore[attr-defined]
            .where(AssetVulnerability.status.in_(_OPEN_VULN_STATUSES))  # type: ignore[attr-defined]
        ).one()
    )
    open_incidents = int(
        session.exec(
            select(func.count())
            .select_from(Incident)
            .where(Incident.status.in_(_OPEN_INCIDENT_STATUSES))  # type: ignore[attr-defined]
        ).one()
    )
    open_detections = int(
        session.exec(
            select(func.count())
            .select_from(Detection)
            .where(
                Detection.status.in_(  # type: ignore[attr-defined]
                    (DetectionStatus.NEW, DetectionStatus.TRIAGING, DetectionStatus.CONFIRMED)
                )
            )
        ).one()
    )

    title = "Executive Risk Summary"
    summary = (
        f"{total_assets} assets; {kev_exposure} open KEV exposures; "
        f"{open_incidents} open incidents; {open_detections} open detections."
    )

    lines = _header(title)
    lines.append("## Portfolio overview")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Total assets | {total_assets} |")
    lines.append(f"| Open KEV exposures | {kev_exposure} |")
    lines.append(f"| Open incidents | {open_incidents} |")
    lines.append(f"| Open detections | {open_detections} |")
    lines.append("")

    lines.append("## Risk band distribution")
    lines.append("")
    lines.append("| Risk band | Assets |")
    lines.append("| --- | --- |")
    for band in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        lines.append(f"| {band} | {bands.get(band, 0)} |")
    lines.append("")

    lines.append("## Criticality distribution")
    lines.append("")
    lines.append("| Criticality | Assets |")
    lines.append("| --- | --- |")
    for crit in ("SAFETY_CRITICAL", "HIGH", "MEDIUM", "LOW"):
        lines.append(f"| {crit} | {crit_count.get(crit, 0)} |")
    lines.append("")

    lines.append("## Top 10 risky assets")
    lines.append("")
    if top:
        lines.append("| Asset tag | Type | Criticality | Risk band | Risk score |")
        lines.append("| --- | --- | --- | --- | --- |")
        for a in top:
            lines.append(
                f"| {_esc(a.asset_tag)} | {a.asset_type.value} | "
                f"{a.criticality.value} | {a.risk_band.value} | {a.risk_score} |"
            )
    else:
        lines.append("_No assets in the inventory._")
    lines.append("")

    return title, summary, "\n".join(lines)


def _render_asset_inventory(
    session: Session, req: GenerateReportRequest, user: AuthenticatedUser | None
) -> tuple[str, str, str]:
    assets = list(
        session.exec(select(Asset).order_by(Asset.asset_tag)).all()  # type: ignore[arg-type]
    )
    sites = {s.id: s for s in session.exec(select(Site)).all()}

    title = "Asset Inventory"
    summary = f"{len(assets)} assets in the simulated inventory."

    lines = _header(title, [f"**Total assets:** {len(assets)}"])
    lines.append("| Asset tag | Type | Site | Purdue | Criticality | Risk band |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for a in assets:
        site = sites.get(a.site_id)
        site_label = site.code or site.name if site else str(a.site_id)
        lines.append(
            f"| {_esc(a.asset_tag)} | {a.asset_type.value} | {_esc(site_label)} | "
            f"L{int(a.purdue_level)} | {a.criticality.value} | {a.risk_band.value} |"
        )
    if not assets:
        lines.append("| _none_ | | | | | |")
    lines.append("")
    return title, summary, "\n".join(lines)


def _render_vuln_remediation_plan(
    session: Session, req: GenerateReportRequest, user: AuthenticatedUser | None
) -> tuple[str, str, str]:
    rows = list(
        session.exec(
            select(AssetVulnerability, Vulnerability, Asset)
            .where(AssetVulnerability.vuln_id == Vulnerability.id)
            .where(AssetVulnerability.asset_id == Asset.id)
            .where(AssetVulnerability.status.in_(_OPEN_VULN_STATUSES))  # type: ignore[attr-defined]
            .order_by(AssetVulnerability.priority_score.desc())  # type: ignore[attr-defined]
        ).all()
    )

    title = "Vulnerability Remediation Plan"
    summary = f"{len(rows)} open asset/vulnerability matches prioritized."

    lines = _header(
        title,
        [
            "> SAFE/PASSIVE plan. Prefer compensating controls and approved "
            "maintenance windows; never alter PLC logic or firmware outside an "
            "approved window.",
        ],
    )
    lines.append(
        "| Priority | CVE | CVSS | KEV | Asset | Status | Recommended action |"
    )
    lines.append("| --- | --- | --- | --- | --- | --- | --- |")
    for av, vuln, asset in rows:
        kev = "Yes" if vuln.known_exploited else "No"
        action = _recommended_vuln_action(av, vuln)
        lines.append(
            f"| {av.priority_score} | {_esc(vuln.cve_id)} | {vuln.cvss_base:.1f} | "
            f"{kev} | {_esc(asset.asset_tag)} | {av.status.value} | {_esc(action)} |"
        )
    if not rows:
        lines.append("| _none_ | | | | | | |")
    lines.append("")
    return title, summary, "\n".join(lines)


def _recommended_vuln_action(av: AssetVulnerability, vuln: Vulnerability) -> str:
    if vuln.ot_compensating_controls:
        base = "Apply OT compensating controls; " + vuln.ot_compensating_controls[0]
    elif vuln.patch_available:
        base = "Schedule patch in an approved maintenance window"
    else:
        base = "No patch available — maintain segmentation and monitor advisory"
    if vuln.known_exploited:
        base = "KEV-listed: prioritize. " + base
    return base


def _render_unauthorized_change(
    session: Session, req: GenerateReportRequest, user: AuthenticatedUser | None
) -> tuple[str, str, str]:
    rows = list(
        session.exec(
            select(ConfigChange, Asset)
            .where(ConfigChange.asset_id == Asset.id)
            .where(ConfigChange.disposition == ChangeDisposition.UNAUTHORIZED)
            .order_by(ConfigChange.detected_at.desc())  # type: ignore[attr-defined]
        ).all()
    )

    title = "Unauthorized Change Report"
    summary = f"{len(rows)} configuration changes dispositioned as UNAUTHORIZED."

    lines = _header(title, [f"**Unauthorized changes:** {len(rows)}"])
    lines.append("| Asset | Detected | Ticket | In window | Diff summary |")
    lines.append("| --- | --- | --- | --- | --- |")
    for change, asset in rows:
        detected = change.detected_at.isoformat() if change.detected_at else "unknown"
        diff_summary = change.summary or _summarize_diff(change.diff)
        ticket = change.change_ticket or "—"
        window = "Yes" if change.within_approved_window else "No"
        lines.append(
            f"| {_esc(asset.asset_tag)} | {_esc(detected)} | {_esc(ticket)} | "
            f"{window} | {_esc(diff_summary)} |"
        )
    if not rows:
        lines.append("| _none_ | | | | |")
    lines.append("")
    return title, summary, "\n".join(lines)


def _summarize_diff(diff: list[dict]) -> str:
    if not diff:
        return "No field-level diff recorded."
    fields = [str(d.get("field", "?")) for d in diff[:5]]
    suffix = "" if len(diff) <= 5 else f" (+{len(diff) - 5} more)"
    return "Changed: " + ", ".join(fields) + suffix


# --------------------------------------------------------------------------- #
# Compliance helpers + renderers
# --------------------------------------------------------------------------- #
def _framework_by_key(session: Session, key: FrameworkKey) -> ComplianceFramework | None:
    return session.exec(
        select(ComplianceFramework).where(ComplianceFramework.key == key)
    ).first()


def _controls_for_framework(
    session: Session, framework: ComplianceFramework
) -> list[ComplianceControl]:
    return list(
        session.exec(
            select(ComplianceControl)
            .where(ComplianceControl.framework_id == framework.id)
            .order_by(ComplianceControl.control_ref)  # type: ignore[arg-type]
        ).all()
    )


def _readiness_pct(controls: list[ComplianceControl]) -> float:
    """Readiness % excluding NOT_APPLICABLE controls; partial counts as half."""
    scored = [c for c in controls if c.status != ControlStatus.NOT_APPLICABLE]
    if not scored:
        return 0.0
    total = 0.0
    for c in scored:
        if c.status == ControlStatus.IMPLEMENTED:
            total += 1.0
        elif c.status == ControlStatus.PARTIAL:
            total += 0.5
    return round(100.0 * total / len(scored), 1)


def _render_compliance_gap(
    session: Session, req: GenerateReportRequest, user: AuthenticatedUser | None
) -> tuple[str, str, str]:
    frameworks = list(
        session.exec(select(ComplianceFramework).order_by(ComplianceFramework.key)).all()  # type: ignore[arg-type]
    )

    title = "Compliance Gap Report"
    total_gaps = 0
    lines = _header(title)
    lines.append("## Readiness by framework")
    lines.append("")
    lines.append("| Framework | Version | Readiness % | Gap controls |")
    lines.append("| --- | --- | --- | --- |")
    gap_sections: list[str] = []
    for fw in frameworks:
        controls = _controls_for_framework(session, fw)
        gaps = [c for c in controls if c.status in GAP_CONTROL_STATUSES]
        total_gaps += len(gaps)
        lines.append(
            f"| {_esc(fw.name or fw.key.value)} | {_esc(fw.version)} | "
            f"{_readiness_pct(controls)} | {len(gaps)} |"
        )
        if gaps:
            section = [f"### {_esc(fw.name or fw.key.value)} — open gaps", ""]
            section.append("| Control | Title | Status | Owner |")
            section.append("| --- | --- | --- | --- |")
            for c in gaps:
                section.append(
                    f"| {_esc(c.control_ref)} | {_esc(c.title)} | {c.status.value} | "
                    f"{_esc(c.owner or '—')} |"
                )
            section.append("")
            gap_sections.append("\n".join(section))
    lines.append("")
    lines.extend(["## Open gap controls", ""])
    if gap_sections:
        lines.append("\n".join(gap_sections))
    else:
        lines.append("_No open gap controls._")
        lines.append("")

    summary = f"{total_gaps} open gap controls across {len(frameworks)} frameworks."
    return title, summary, "\n".join(lines)


def _render_evidence_pack(
    session: Session, key: FrameworkKey, title: str
) -> tuple[str, str, str]:
    fw = _framework_by_key(session, key)
    lines = _header(title)
    if fw is None:
        lines.append(f"_Framework {key.value} not found in the dataset._")
        return title, f"Framework {key.value} not found.", "\n".join(lines)

    controls = _controls_for_framework(session, fw)
    evidence_count = 0
    lines.append(f"**Framework:** {_esc(fw.name or fw.key.value)} {_esc(fw.version)}")
    lines.append("")
    lines.append(f"**Readiness:** {_readiness_pct(controls)}%")
    lines.append("")
    for c in controls:
        evidence = list(
            session.exec(
                select(ComplianceEvidence).where(ComplianceEvidence.control_id == c.id)
            ).all()
        )
        evidence_count += len(evidence)
        lines.append(f"## {_esc(c.control_ref)} — {_esc(c.title)}")
        lines.append("")
        lines.append(f"- **Status:** {c.status.value}")
        if c.evidence_required:
            lines.append(f"- **Evidence required:** {_esc(c.evidence_required)}")
        lines.append("")
        if evidence:
            lines.append("| Source | Description | File | Auto-linked |")
            lines.append("| --- | --- | --- | --- |")
            for e in evidence:
                lines.append(
                    f"| {e.source_type.value} | {_esc(e.description)} | "
                    f"{_esc(e.file_name or '—')} | "
                    f"{'Yes' if e.auto_linked else 'No'} |"
                )
        else:
            lines.append("_No evidence linked yet._")
        lines.append("")

    summary = (
        f"{len(controls)} controls, {evidence_count} evidence items for "
        f"{fw.name or fw.key.value}."
    )
    return title, summary, "\n".join(lines)


def _render_readiness_summary(
    session: Session, key: FrameworkKey, title: str
) -> tuple[str, str, str]:
    fw = _framework_by_key(session, key)
    lines = _header(title)
    if fw is None:
        lines.append(f"_Framework {key.value} not found in the dataset._")
        return title, f"Framework {key.value} not found.", "\n".join(lines)

    controls = _controls_for_framework(session, fw)
    status_counts = Counter(c.status.value for c in controls)
    readiness = _readiness_pct(controls)

    lines.append(f"**Framework:** {_esc(fw.name or fw.key.value)} {_esc(fw.version)}")
    lines.append("")
    lines.append(f"**Overall readiness:** {readiness}%")
    lines.append("")
    lines.append("## Control status breakdown")
    lines.append("")
    lines.append("| Status | Controls |")
    lines.append("| --- | --- |")
    for status in (
        ControlStatus.IMPLEMENTED,
        ControlStatus.PARTIAL,
        ControlStatus.NOT_STARTED,
        ControlStatus.NOT_APPLICABLE,
    ):
        lines.append(f"| {status.value} | {status_counts.get(status.value, 0)} |")
    lines.append("")

    gaps = [c for c in controls if c.status in GAP_CONTROL_STATUSES]
    lines.append(f"## Open gap controls ({len(gaps)})")
    lines.append("")
    if gaps:
        lines.append("| Control | Title | Status | Owner |")
        lines.append("| --- | --- | --- | --- |")
        for c in gaps:
            lines.append(
                f"| {_esc(c.control_ref)} | {_esc(c.title)} | {c.status.value} | "
                f"{_esc(c.owner or '—')} |"
            )
    else:
        lines.append("_No open gap controls._")
    lines.append("")

    summary = f"{readiness}% readiness; {len(gaps)} open gap controls."
    return title, summary, "\n".join(lines)


# --------------------------------------------------------------------------- #
# Incident renderer
# --------------------------------------------------------------------------- #
def _render_incident_report(
    session: Session, req: GenerateReportRequest, user: AuthenticatedUser | None
) -> tuple[str, str, str]:
    raw_id = req.params.get("incident_id")
    if not raw_id:
        raise ValidationAppError("INCIDENT_REPORT requires params['incident_id']")
    try:
        incident_id = uuid.UUID(str(raw_id))
    except (ValueError, TypeError) as exc:
        raise ValidationAppError("params['incident_id'] is not a valid UUID") from exc

    incident = session.get(Incident, incident_id)
    if incident is None:
        raise NotFoundError("Incident not found")

    events = list(
        session.exec(
            select(IncidentTimelineEvent)
            .where(IncidentTimelineEvent.incident_id == incident.id)
            .order_by(IncidentTimelineEvent.occurred_at)  # type: ignore[arg-type]
        ).all()
    )
    links = list(
        session.exec(
            select(IncidentLink).where(IncidentLink.incident_id == incident.id)
        ).all()
    )

    title = f"Incident Report — {incident.reference}"
    summary = (
        f"{incident.reference}: {incident.title} "
        f"({incident.severity.value} / {incident.status.value})."
    )

    lines = _header(title)
    lines.append("## Overview")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Reference | {_esc(incident.reference)} |")
    lines.append(f"| Title | {_esc(incident.title)} |")
    lines.append(f"| Severity | {incident.severity.value} |")
    lines.append(f"| Status | {incident.status.value} |")
    lines.append(f"| Lead owner | {_esc(incident.lead_owner or '—')} |")
    opened = incident.opened_at.isoformat() if incident.opened_at else "—"
    closed = incident.closed_at.isoformat() if incident.closed_at else "—"
    lines.append(f"| Opened at | {_esc(opened)} |")
    lines.append(f"| Closed at | {_esc(closed)} |")
    if incident.attck_ics_technique:
        lines.append(f"| ATT&CK ICS | {_esc(incident.attck_ics_technique)} |")
    lines.append("")

    if incident.summary:
        lines.append("## Summary")
        lines.append("")
        lines.append(_esc(incident.summary))
        lines.append("")

    lines.append(f"## Timeline ({len(events)})")
    lines.append("")
    if events:
        lines.append("| When | Kind | Author | Description |")
        lines.append("| --- | --- | --- | --- |")
        for e in events:
            when = e.occurred_at.isoformat() if e.occurred_at else "—"
            lines.append(
                f"| {_esc(when)} | {e.kind.value} | {_esc(e.author or '—')} | "
                f"{_esc(e.description)} |"
            )
    else:
        lines.append("_No timeline events recorded._")
    lines.append("")

    lines.append(f"## Linked entities ({len(links)})")
    lines.append("")
    if links:
        lines.append("| Link type | Entity id |")
        lines.append("| --- | --- |")
        for link in links:
            lines.append(f"| {link.link_type.value} | {_esc(link.entity_id)} |")
    else:
        lines.append("_No linked entities._")
    lines.append("")

    if incident.containment_actions:
        lines.append("## Containment actions")
        lines.append("")
        for action in incident.containment_actions:
            lines.append(f"- {_esc(action)}")
        lines.append("")
    if incident.recovery_actions:
        lines.append("## Recovery actions")
        lines.append("")
        for action in incident.recovery_actions:
            lines.append(f"- {_esc(action)}")
        lines.append("")

    return title, summary, "\n".join(lines)


# --------------------------------------------------------------------------- #
# AI daily brief renderer (with deterministic fallback)
# --------------------------------------------------------------------------- #
def _render_ai_daily_brief(
    session: Session, req: GenerateReportRequest, user: AuthenticatedUser | None
) -> tuple[str, str, str]:
    title = "AI Daily Brief"
    try:
        answer = run_ai_query(
            session,
            user_id=user.id if user else None,
            actor_email=user.email if user else None,
            use_case=AIUseCase.DAILY_BRIEF,
            entity_id=None,
            question="Generate today's OT security daily brief",
            conversation_id=None,
        )
    except Exception:  # AI provider unavailable — never fail the report.
        return _render_ai_daily_brief_fallback(session)

    lines = _header(title)
    lines.append("## Summary")
    lines.append("")
    lines.append(_esc(answer.summary) or "_No summary produced._")
    lines.append("")
    if answer.findings:
        lines.append("## Key findings")
        lines.append("")
        for f in answer.findings:
            lines.append(f"- {_esc(f)}")
        lines.append("")
    if answer.safe_ot_actions:
        lines.append("## Safe OT actions")
        lines.append("")
        for a in answer.safe_ot_actions:
            lines.append(f"- {_esc(a)}")
        lines.append("")
    if answer.citations:
        lines.append("## Citations")
        lines.append("")
        for c in answer.citations:
            label = f" — {_esc(c.label)}" if c.label else ""
            lines.append(f"- `{_esc(c.ref)}`{label}")
        lines.append("")
    lines.append(f"_Provider: {_esc(answer.provider_name)} ({_esc(answer.model_name)})_")
    lines.append("")
    lines.append(f"> {_esc(answer.disclaimer)}")
    lines.append("")

    summary = (answer.summary or "AI daily brief")[:280]
    return title, summary, "\n".join(lines)


def _render_ai_daily_brief_fallback(session: Session) -> tuple[str, str, str]:
    """Deterministic brief from DB stats when the AI provider is unavailable."""
    title = "AI Daily Brief"
    total_assets = int(session.exec(select(func.count()).select_from(Asset)).one())
    open_detections = int(
        session.exec(
            select(func.count())
            .select_from(Detection)
            .where(
                Detection.status.in_(  # type: ignore[attr-defined]
                    (DetectionStatus.NEW, DetectionStatus.TRIAGING, DetectionStatus.CONFIRMED)
                )
            )
        ).one()
    )
    open_incidents = int(
        session.exec(
            select(func.count())
            .select_from(Incident)
            .where(Incident.status.in_(_OPEN_INCIDENT_STATUSES))  # type: ignore[attr-defined]
        ).one()
    )
    kev_exposure = int(
        session.exec(
            select(func.count())
            .select_from(AssetVulnerability)
            .where(AssetVulnerability.vuln_id == Vulnerability.id)
            .where(Vulnerability.known_exploited.is_(True))  # type: ignore[attr-defined]
            .where(AssetVulnerability.status.in_(_OPEN_VULN_STATUSES))  # type: ignore[attr-defined]
        ).one()
    )

    lines = _header(title)
    lines.append(
        "> The AI provider was unavailable; this is a deterministic fallback brief "
        "generated directly from the simulated dataset."
    )
    lines.append("")
    lines.append("## Today's posture")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Total assets | {total_assets} |")
    lines.append(f"| Open detections | {open_detections} |")
    lines.append(f"| Open incidents | {open_incidents} |")
    lines.append(f"| Open KEV exposures | {kev_exposure} |")
    lines.append("")
    lines.append("## Suggested safe OT actions")
    lines.append("")
    lines.append("- Triage any new detections starting with the highest severity.")
    lines.append("- Review open KEV exposures and verify compensating controls.")
    lines.append("- Confirm progress on open incidents with the assigned leads.")
    lines.append("- Maintain passive monitoring; do not alter PLC logic outside a window.")
    lines.append("")

    summary = (
        f"Fallback brief: {open_detections} open detections, "
        f"{open_incidents} open incidents, {kev_exposure} KEV exposures."
    )
    return title, summary, "\n".join(lines)


# --------------------------------------------------------------------------- #
# Dispatch table
# --------------------------------------------------------------------------- #
_Renderer = Callable[[Session, GenerateReportRequest, AuthenticatedUser | None], tuple[str, str, str]]

_RENDERERS: dict[ReportType, _Renderer] = {
    ReportType.EXEC_RISK_SUMMARY: _render_exec_risk_summary,
    ReportType.ASSET_INVENTORY: _render_asset_inventory,
    ReportType.VULN_REMEDIATION_PLAN: _render_vuln_remediation_plan,
    ReportType.UNAUTHORIZED_CHANGE: _render_unauthorized_change,
    ReportType.COMPLIANCE_GAP: _render_compliance_gap,
    ReportType.IEC62443_EVIDENCE: lambda s, r, u: _render_evidence_pack(
        s, FrameworkKey.IEC_62443, "IEC 62443 Evidence Pack"
    ),
    ReportType.NERC_CIP_EVIDENCE: lambda s, r, u: _render_evidence_pack(
        s, FrameworkKey.NERC_CIP, "NERC CIP Evidence Pack"
    ),
    ReportType.NIS2_READINESS: lambda s, r, u: _render_readiness_summary(
        s, FrameworkKey.NIS2, "NIS2 Readiness Summary"
    ),
    ReportType.OTCC_READINESS: lambda s, r, u: _render_readiness_summary(
        s, FrameworkKey.NCA_OTCC, "NCA OTCC Readiness Summary"
    ),
    ReportType.INCIDENT_REPORT: _render_incident_report,
    ReportType.AI_DAILY_BRIEF: _render_ai_daily_brief,
}


# --------------------------------------------------------------------------- #
# Format conversion
# --------------------------------------------------------------------------- #
def _markdown_to_html(md: str) -> str:
    body = markdown.markdown(md, extensions=["tables"])
    return (
        "<!doctype html>\n<html><head><meta charset=\"utf-8\">"
        "<title>ForgeShield OT Report</title></head><body>\n"
        f"{body}\n</body></html>"
    )


def _weasyprint_available() -> bool:
    try:
        import weasyprint  # noqa: F401
    except Exception:
        return False
    return True


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def generate(
    session: Session, req: GenerateReportRequest, user: AuthenticatedUser | None
) -> Report:
    """Render the report Markdown, convert per the requested format, persist a
    ``Report`` row and audit the generation."""
    renderer = _RENDERERS.get(req.report_type)
    if renderer is None:  # pragma: no cover - all ReportTypes are mapped
        raise ValidationAppError(f"Unsupported report type: {req.report_type}")

    title, summary, md = renderer(session, req, user)

    if req.fmt == ReportFormat.PDF:
        if not (settings.reports_pdf_enabled and _weasyprint_available()):
            raise ValidationAppError(
                "PDF report rendering is disabled in this environment. "
                "Use MARKDOWN or HTML instead."
            )
        html = _markdown_to_html(md)
        try:
            import weasyprint

            pdf_bytes = weasyprint.HTML(string=html).write_pdf()
        except Exception as exc:  # pragma: no cover - depends on optional dep
            raise ValidationAppError(f"PDF rendering failed: {exc}") from exc
        # Store as latin-1 string so the bytes round-trip through the text column.
        content = pdf_bytes.decode("latin-1")
    elif req.fmt == ReportFormat.HTML:
        content = _markdown_to_html(md)
    else:
        content = md

    report = Report(
        report_type=req.report_type,
        title=title,
        fmt=req.fmt,
        content=content,
        params=req.params,
        summary=summary,
        generated_by=user.id if user else None,
        is_demo=True,
    )
    session.add(report)
    session.commit()
    session.refresh(report)

    record_audit(
        session,
        action=AuditAction.REPORT_GENERATE,
        actor_user_id=user.id if user else None,
        actor_email=user.email if user else None,
        entity_type="report",
        entity_id=report.id,
        summary=f"Generated {req.report_type.value} report ({req.fmt.value})",
        meta={"report_type": req.report_type.value, "fmt": req.fmt.value},
    )
    return report


def list_reports(
    session: Session, *, page: PaginationParams
) -> tuple[list[Report], int]:
    total = int(session.exec(select(func.count()).select_from(Report)).one())
    items = list(
        session.exec(
            select(Report)
            .order_by(Report.created_at.desc())  # type: ignore[attr-defined]
            .offset(page.offset)
            .limit(page.limit)
        ).all()
    )
    return items, total


def get_report(session: Session, report_id: uuid.UUID) -> Report:
    report = session.get(Report, report_id)
    if report is None:
        raise NotFoundError("Report not found")
    return report
