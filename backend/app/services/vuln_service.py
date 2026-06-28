"""Vulnerability management business logic.

OT-aware: prioritization and remediation planning prefer SAFE/PASSIVE
compensating controls where patching is unsafe or requires an outage. All
mutations are audited and any change affecting an asset's risk recomputes it.
"""
from __future__ import annotations

import uuid

from sqlalchemy import func
from sqlmodel import Session, or_, select

from app.core.enums import (
    AuditAction,
    Criticality,
    ImpactLevel,
    MatchBasis,
    PatchRisk,
    VulnRemediationStatus,
)
from app.core.exceptions import ConflictError, NotFoundError
from app.core.security import AuthenticatedUser
from app.models.asset import Asset
from app.models.base import utcnow
from app.models.vuln import AssetVulnerability, Vulnerability
from app.schemas.common import PaginationParams
from app.schemas.vuln import (
    RiskAcceptanceRequest,
    VulnerabilityCreate,
    VulnerabilityUpdate,
    VulnFilter,
)
from app.services.audit_service import record_audit
from app.services.risk_engine import score_asset

# Vulnerability workflow states that still count as actively open.
_OPEN_STATUSES: frozenset[VulnRemediationStatus] = frozenset(
    {
        VulnRemediationStatus.OPEN,
        VulnRemediationStatus.PATCH_NOW,
        VulnRemediationStatus.MITIGATE,
        VulnRemediationStatus.MONITOR,
    }
)

# --------------------------------------------------------------------------- #
# Catalog CRUD
# --------------------------------------------------------------------------- #
def list_vulns(
    session: Session, *, filters: VulnFilter, page: PaginationParams
) -> tuple[list[Vulnerability], int]:
    stmt = select(Vulnerability)
    count_stmt = select(func.count()).select_from(Vulnerability)

    conditions = []
    if filters.vendor:
        conditions.append(Vulnerability.vendor.ilike(f"%{filters.vendor}%"))  # type: ignore[attr-defined]
    if filters.known_exploited is not None:
        conditions.append(Vulnerability.known_exploited == filters.known_exploited)
    if filters.min_cvss is not None:
        conditions.append(Vulnerability.cvss_base >= filters.min_cvss)
    search = filters.search or page.search
    if search:
        term = f"%{search}%"
        conditions.append(
            or_(
                Vulnerability.cve_id.ilike(term),  # type: ignore[attr-defined]
                Vulnerability.title.ilike(term),  # type: ignore[attr-defined]
                Vulnerability.vendor.ilike(term),  # type: ignore[attr-defined]
                Vulnerability.product.ilike(term),  # type: ignore[attr-defined]
            )
        )
    for cond in conditions:
        stmt = stmt.where(cond)
        count_stmt = count_stmt.where(cond)

    total = session.exec(count_stmt).one()
    stmt = (
        stmt.order_by(
            Vulnerability.known_exploited.desc(),  # type: ignore[attr-defined]
            Vulnerability.cvss_base.desc(),  # type: ignore[attr-defined]
        )
        .offset(page.offset)
        .limit(page.limit)
    )
    items = session.exec(stmt).all()
    return list(items), int(total)


def get_vuln(session: Session, vuln_id: uuid.UUID) -> Vulnerability:
    vuln = session.get(Vulnerability, vuln_id)
    if vuln is None:
        raise NotFoundError("Vulnerability not found")
    return vuln


def create_vuln(
    session: Session, data: VulnerabilityCreate, user: AuthenticatedUser | None
) -> Vulnerability:
    existing = session.exec(
        select(Vulnerability).where(Vulnerability.cve_id == data.cve_id)
    ).first()
    if existing:
        raise ConflictError(f"Vulnerability '{data.cve_id}' already exists")
    vuln = Vulnerability(**data.model_dump())
    session.add(vuln)
    session.commit()
    session.refresh(vuln)
    record_audit(
        session,
        action=AuditAction.VULN_STATUS_CHANGE,
        actor_user_id=user.id if user else None,
        actor_email=user.email if user else None,
        entity_type="vulnerability",
        entity_id=vuln.id,
        summary=f"Created vulnerability {vuln.cve_id}",
    )
    return vuln


def update_vuln(
    session: Session,
    vuln_id: uuid.UUID,
    data: VulnerabilityUpdate,
    user: AuthenticatedUser | None,
) -> Vulnerability:
    vuln = get_vuln(session, vuln_id)
    for key, value in data.model_dump(exclude_unset=True).items():
        setattr(vuln, key, value)
    session.add(vuln)
    session.commit()
    session.refresh(vuln)
    # CVSS / KEV changes feed asset risk; recompute affected assets.
    for av in session.exec(
        select(AssetVulnerability).where(AssetVulnerability.vuln_id == vuln.id)
    ).all():
        asset = session.get(Asset, av.asset_id)
        if asset is not None:
            av.priority_score = compute_priority(session, av, vuln, asset)
            session.add(av)
            score_asset(session, asset, persist=True)
    session.commit()
    record_audit(
        session,
        action=AuditAction.VULN_STATUS_CHANGE,
        actor_user_id=user.id if user else None,
        actor_email=user.email if user else None,
        entity_type="vulnerability",
        entity_id=vuln.id,
        summary=f"Updated vulnerability {vuln.cve_id}",
    )
    return vuln


# --------------------------------------------------------------------------- #
# Matching
# --------------------------------------------------------------------------- #
def _version_affected(vuln: Vulnerability, asset: Asset) -> bool:
    """Affected if the catalog lists no versions (all affected) or the asset's
    firmware/software version is in the affected list (case-insensitive)."""
    if not vuln.affected_versions:
        return True
    asset_versions = {
        (asset.firmware_version or "").strip().lower(),
        (asset.software_version or "").strip().lower(),
    }
    affected = {v.strip().lower() for v in vuln.affected_versions}
    return bool(asset_versions & affected) and asset_versions != {""}


def _product_matches(vuln: Vulnerability, asset: Asset) -> bool:
    product = (vuln.product or "").strip().lower()
    if not product:
        # No product constraint -> vendor match alone is enough.
        return True
    candidates = [
        (asset.model or "").strip().lower(),
        (asset.os_name or "").strip().lower(),
    ]
    if any(product == c for c in candidates if c):
        return True
    # Product token appears within the asset model string.
    model = (asset.model or "").strip().lower()
    if model and any(tok and tok in model for tok in product.split()):
        return True
    return False


def match_vuln_to_assets(session: Session, vuln: Vulnerability) -> int:
    """Find assets matching the vulnerability and create idempotent links.

    Match rule: vendor matches (case-insensitive) AND (product matches model/os
    OR product token appears in model) AND (asset version in affected_versions
    OR affected_versions empty). Recomputes risk for newly matched assets.
    Returns the number of links created.
    """
    if not vuln.vendor:
        return 0
    vendor = vuln.vendor.strip().lower()
    assets = session.exec(
        select(Asset).where(func.lower(Asset.vendor) == vendor)
    ).all()

    created = 0
    matched_assets: list[Asset] = []
    for asset in assets:
        if not _product_matches(vuln, asset):
            continue
        if not _version_affected(vuln, asset):
            continue
        existing = session.exec(
            select(AssetVulnerability)
            .where(AssetVulnerability.asset_id == asset.id)
            .where(AssetVulnerability.vuln_id == vuln.id)
        ).first()
        if existing is not None:
            continue
        av = AssetVulnerability(
            asset_id=asset.id,
            vuln_id=vuln.id,
            status=VulnRemediationStatus.OPEN,
            match_basis=MatchBasis.VENDOR_MODEL_VERSION,
            detected_at=utcnow(),
        )
        av.priority_score = compute_priority(session, av, vuln, asset)
        session.add(av)
        created += 1
        matched_assets.append(asset)

    if created:
        session.commit()
        for asset in matched_assets:
            score_asset(session, asset, persist=True)
    return created


# --------------------------------------------------------------------------- #
# Prioritization
# --------------------------------------------------------------------------- #
def compute_priority(
    session: Session,
    av: AssetVulnerability,
    vuln: Vulnerability,
    asset: Asset,
) -> int:
    """Deterministic 0-100 OT-aware priority score for an asset/vuln link."""
    score = 0.0

    # Known exploited (CISA KEV) dominates.
    if vuln.known_exploited:
        score += 40.0

    # CVSS base scaled to 30 points.
    score += min(10.0, max(0.0, vuln.cvss_base)) * 3.0

    # Asset criticality.
    if asset.criticality == Criticality.SAFETY_CRITICAL:
        score += 14.0
    elif asset.criticality == Criticality.HIGH:
        score += 10.0
    elif asset.criticality == Criticality.MEDIUM:
        score += 5.0

    # Safety impact of the vulnerability on this asset class.
    if asset.safety_impact == ImpactLevel.HIGH or vuln.safety_impact == ImpactLevel.HIGH:
        score += 8.0
    elif asset.safety_impact == ImpactLevel.MEDIUM or vuln.safety_impact == ImpactLevel.MEDIUM:
        score += 4.0

    # Network exposure.
    if asset.internet_reachable:
        score += 10.0
    elif asset.it_reachable:
        score += 6.0
    elif asset.remote_access_enabled:
        score += 3.0

    # Compensating controls / mitigation reduce urgency.
    if vuln.ot_compensating_controls:
        score -= 8.0
    if av.status in (VulnRemediationStatus.MITIGATE, VulnRemediationStatus.MONITOR):
        score -= 6.0
    if av.status in (VulnRemediationStatus.RISK_ACCEPTED, VulnRemediationStatus.REMEDIATED):
        score -= 30.0

    return int(min(100.0, max(0.0, round(score))))


def prioritize(session: Session) -> int:
    """Recompute priority for every asset/vuln link. Returns count updated."""
    rows = session.exec(
        select(AssetVulnerability, Vulnerability, Asset)
        .where(AssetVulnerability.vuln_id == Vulnerability.id)
        .where(AssetVulnerability.asset_id == Asset.id)
    ).all()
    for av, vuln, asset in rows:
        av.priority_score = compute_priority(session, av, vuln, asset)
        session.add(av)
    if rows:
        session.commit()
    return len(rows)


# --------------------------------------------------------------------------- #
# Status / risk acceptance
# --------------------------------------------------------------------------- #
def get_link(session: Session, av_id: uuid.UUID) -> AssetVulnerability:
    av = session.get(AssetVulnerability, av_id)
    if av is None:
        raise NotFoundError("Asset-vulnerability link not found")
    return av


def set_status(
    session: Session,
    av_id: uuid.UUID,
    status: VulnRemediationStatus,
    user: AuthenticatedUser | None,
    acceptance: RiskAcceptanceRequest | None = None,
) -> AssetVulnerability:
    av = get_link(session, av_id)
    vuln = session.get(Vulnerability, av.vuln_id)
    asset = session.get(Asset, av.asset_id)
    av.status = status

    if status == VulnRemediationStatus.RISK_ACCEPTED:
        if acceptance is None:
            from app.core.exceptions import ValidationAppError

            raise ValidationAppError("Risk acceptance requires a justification")
        av.risk_accepted_by = acceptance.accepted_by
        av.risk_acceptance_reason = acceptance.reason
        av.risk_accepted_until = acceptance.accepted_until
        audit_action = AuditAction.VULN_RISK_ACCEPTANCE
        summary = (
            f"Risk-accepted {vuln.cve_id if vuln else av.vuln_id} on "
            f"{asset.asset_tag if asset else av.asset_id}: {acceptance.reason}"
        )
    else:
        audit_action = AuditAction.VULN_STATUS_CHANGE
        summary = (
            f"Status of {vuln.cve_id if vuln else av.vuln_id} on "
            f"{asset.asset_tag if asset else av.asset_id} set to {status.value}"
        )

    if vuln is not None and asset is not None:
        av.priority_score = compute_priority(session, av, vuln, asset)
    session.add(av)
    session.commit()
    session.refresh(av)

    if asset is not None:
        score_asset(session, asset, persist=True)

    record_audit(
        session,
        action=audit_action,
        actor_user_id=user.id if user else None,
        actor_email=user.email if user else None,
        entity_type="asset_vulnerability",
        entity_id=av.id,
        summary=summary,
    )
    return av


# --------------------------------------------------------------------------- #
# Remediation planning (deterministic, SAFE/PASSIVE)
# --------------------------------------------------------------------------- #
def generate_remediation_plan(session: Session, vuln: Vulnerability) -> str:
    """Build a deterministic Markdown remediation plan and store it on every
    matched AssetVulnerability link. Prefers OT compensating controls when a
    patch is unsafe or requires an outage. SAFE/PASSIVE actions only."""
    links = session.exec(
        select(AssetVulnerability, Asset)
        .where(AssetVulnerability.vuln_id == vuln.id)
        .where(AssetVulnerability.asset_id == Asset.id)
    ).all()
    affected_assets = [asset for _av, asset in links]

    patch_unsafe = (
        not vuln.patch_available
        or vuln.patch_risk in (PatchRisk.HIGH, PatchRisk.REQUIRES_OUTAGE)
    )

    lines: list[str] = []
    lines.append(f"# Remediation Plan — {vuln.cve_id}")
    lines.append("")
    lines.append(f"**Title:** {vuln.title or 'N/A'}")
    lines.append(f"**CVSS base:** {vuln.cvss_base:.1f}")
    lines.append(f"**Known exploited (CISA KEV):** {'Yes' if vuln.known_exploited else 'No'}")
    lines.append(f"**Patch available:** {'Yes' if vuln.patch_available else 'No'}")
    lines.append(f"**Patch risk:** {vuln.patch_risk.value}")
    lines.append(f"**Safety impact:** {vuln.safety_impact.value}")
    lines.append("")
    lines.append(
        "> This is a SAFE/PASSIVE plan for a defensive OT/ICS environment. "
        "Do not alter PLC logic or apply firmware changes outside an approved "
        "maintenance window. All steps assume change-management approval."
    )
    lines.append("")
    lines.append(f"## Affected assets ({len(affected_assets)})")
    if affected_assets:
        for asset in affected_assets:
            lines.append(
                f"- `{asset.asset_tag}` — {asset.asset_type.value}, "
                f"criticality {asset.criticality.value}, "
                f"Purdue L{int(asset.purdue_level)}"
            )
    else:
        lines.append("- No assets currently matched. Run matching first.")
    lines.append("")

    # Stage 1
    lines.append("## Stage 1 — Triage & validation (immediate, passive)")
    lines.append("1. Confirm the match against the asset inventory (vendor, model, version).")
    lines.append("2. Verify exploitability in context: network reachability and exposed protocols.")
    lines.append("3. Ensure a current configuration backup exists before any change.")
    if vuln.known_exploited:
        lines.append(
            "4. KEV-listed: raise monitoring priority and notify the OT security lead."
        )
    lines.append("")

    # Stage 2 — preferred path
    lines.append("## Stage 2 — Containment (compensating controls first)")
    if patch_unsafe:
        lines.append(
            "Patching is unsafe or requires an outage; **prefer compensating controls**:"
        )
    else:
        lines.append(
            "A patch is available at acceptable risk, but apply compensating controls "
            "in the interim until the maintenance window:"
        )
    controls = vuln.ot_compensating_controls or [
        "Restrict network access to the affected asset via existing firewall rules.",
        "Enforce zone/conduit segmentation per the Purdue model.",
        "Disable or gate remote access until remediation is complete.",
        "Increase passive monitoring for anomalous traffic to/from the asset.",
    ]
    for i, control in enumerate(controls, start=1):
        lines.append(f"{i}. {control}")
    if vuln.workaround:
        lines.append(f"{len(controls) + 1}. Vendor workaround: {vuln.workaround}")
    lines.append("")

    # Stage 3 — patch path
    lines.append("## Stage 3 — Patch / firmware update (scheduled)")
    if vuln.patch_available:
        if vuln.remediation:
            lines.append(f"- Vendor remediation: {vuln.remediation}")
        downtime = vuln.required_downtime or "schedule per asset owner"
        lines.append(
            f"- Schedule the update during an **approved maintenance window** "
            f"(estimated downtime: {downtime})."
        )
        lines.append("- Validate process safety and have a rollback/backup ready before applying.")
        lines.append("- Re-baseline configuration after the change and verify operation.")
    else:
        lines.append(
            "- No vendor patch is available. Maintain compensating controls and "
            "monitor the vendor advisory for an update."
        )
        if vuln.advisory_url:
            lines.append(f"- Advisory: {vuln.advisory_url}")
    lines.append("")

    # Stage 4 — monitoring
    lines.append("## Stage 4 — Monitoring & verification")
    lines.append("- Keep the detection rules / passive monitoring active until remediated.")
    lines.append("- Re-run vulnerability matching after remediation to confirm closure.")
    lines.append("- Record the disposition and update the asset's risk score.")
    lines.append("")

    plan = "\n".join(lines)

    # Persist on each matched link.
    if links:
        for av, _asset in links:
            av.remediation_plan = plan
            session.add(av)
        session.commit()

    return plan


# --------------------------------------------------------------------------- #
# Read helpers
# --------------------------------------------------------------------------- #
def assets_for_vuln(session: Session, vuln: Vulnerability) -> list[dict]:
    rows = session.exec(
        select(AssetVulnerability, Asset)
        .where(AssetVulnerability.vuln_id == vuln.id)
        .where(AssetVulnerability.asset_id == Asset.id)
        .order_by(AssetVulnerability.priority_score.desc())  # type: ignore[attr-defined]
    ).all()
    return [{"link": av.model_dump(), "asset": asset.model_dump()} for av, asset in rows]


def stats(session: Session) -> dict:
    """Counts by CVSS severity band plus KEV count and totals."""
    vulns = session.exec(select(Vulnerability)).all()
    bands = {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0}
    kev = 0
    for v in vulns:
        if v.known_exploited:
            kev += 1
        c = v.cvss_base
        if c >= 9.0:
            bands["critical"] += 1
        elif c >= 7.0:
            bands["high"] += 1
        elif c >= 4.0:
            bands["medium"] += 1
        elif c > 0.0:
            bands["low"] += 1
        else:
            bands["none"] += 1

    open_links = session.exec(
        select(func.count())
        .select_from(AssetVulnerability)
        .where(AssetVulnerability.status.in_(_OPEN_STATUSES))  # type: ignore[attr-defined]
    ).one()
    total_links = session.exec(
        select(func.count()).select_from(AssetVulnerability)
    ).one()

    return {
        "total": len(vulns),
        "by_severity": bands,
        "known_exploited": kev,
        "open_asset_links": int(open_links),
        "total_asset_links": int(total_links),
    }
