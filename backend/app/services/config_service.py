"""Configuration & change management business logic.

Snapshots are content-hashed; changes are diffed against the asset's baseline.
Unauthorized changes on high-criticality assets raise a defensive, passive
out-of-window-change detection and trigger a risk recompute.
"""
from __future__ import annotations

import hashlib
import json
import uuid

from sqlalchemy import func
from sqlmodel import Session, select

from app.core.enums import (
    AuditAction,
    ChangeDisposition,
    Confidence,
    Criticality,
    DetectionStatus,
    DetectionType,
    Severity,
    SourceType,
)
from app.core.exceptions import NotFoundError, ValidationAppError
from app.core.security import AuthenticatedUser
from app.models.asset import Asset
from app.models.base import utcnow
from app.models.config_mgmt import ConfigChange, ConfigSnapshot
from app.models.detection import Detection
from app.schemas.common import PaginationParams
from app.schemas.config_mgmt import ChangeFilter, DispositionRequest, SnapshotCreate
from app.services.audit_service import record_audit
from app.services.risk_engine import score_asset

_HIGH_CRITICALITY: frozenset[Criticality] = frozenset(
    {Criticality.HIGH, Criticality.SAFETY_CRITICAL}
)


def _content_hash(content: dict) -> str:
    """Deterministic sha256 over canonical (sorted-key) JSON."""
    canonical = json.dumps(content or {}, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _require_asset(session: Session, asset_id: uuid.UUID) -> Asset:
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise NotFoundError("Asset not found")
    return asset


def _current_baseline(session: Session, asset_id: uuid.UUID) -> ConfigSnapshot | None:
    return session.exec(
        select(ConfigSnapshot)
        .where(ConfigSnapshot.asset_id == asset_id)
        .where(ConfigSnapshot.is_baseline == True)  # noqa: E712
    ).first()


# --------------------------------------------------------------------------- #
# Snapshots
# --------------------------------------------------------------------------- #
def list_snapshots(session: Session, asset_id: uuid.UUID | None = None) -> list[ConfigSnapshot]:
    stmt = select(ConfigSnapshot)
    if asset_id is not None:
        stmt = stmt.where(ConfigSnapshot.asset_id == asset_id)
    stmt = stmt.order_by(ConfigSnapshot.created_at.desc())  # type: ignore[attr-defined]
    return list(session.exec(stmt).all())


def get_snapshot(session: Session, snapshot_id: uuid.UUID) -> ConfigSnapshot:
    snap = session.get(ConfigSnapshot, snapshot_id)
    if snap is None:
        raise NotFoundError("Snapshot not found")
    return snap


def create_snapshot(
    session: Session, data: SnapshotCreate, user: AuthenticatedUser | None
) -> ConfigSnapshot:
    _require_asset(session, data.asset_id)
    # First snapshot for an asset becomes its baseline automatically.
    is_first = _current_baseline(session, data.asset_id) is None and not session.exec(
        select(ConfigSnapshot).where(ConfigSnapshot.asset_id == data.asset_id)
    ).first()
    snap = ConfigSnapshot(
        asset_id=data.asset_id,
        label=data.label,
        kind=data.kind,
        content=data.content,
        content_hash=_content_hash(data.content),
        captured_at=data.captured_at or utcnow(),
        is_baseline=is_first,
        source=SourceType.MANUAL,
    )
    session.add(snap)
    session.commit()
    session.refresh(snap)
    record_audit(
        session,
        action=AuditAction.CONFIG_SNAPSHOT,
        actor_user_id=user.id if user else None,
        actor_email=user.email if user else None,
        entity_type="config_snapshot",
        entity_id=snap.id,
        summary=f"Captured {snap.kind.value} snapshot for asset {snap.asset_id}",
    )
    return snap


def set_baseline(
    session: Session, snapshot_id: uuid.UUID, user: AuthenticatedUser | None
) -> ConfigSnapshot:
    snap = get_snapshot(session, snapshot_id)
    # Unset other baselines for this asset.
    others = session.exec(
        select(ConfigSnapshot)
        .where(ConfigSnapshot.asset_id == snap.asset_id)
        .where(ConfigSnapshot.is_baseline == True)  # noqa: E712
    ).all()
    for other in others:
        if other.id != snap.id:
            other.is_baseline = False
            session.add(other)
    snap.is_baseline = True
    session.add(snap)
    session.commit()
    session.refresh(snap)
    record_audit(
        session,
        action=AuditAction.CONFIG_BASELINE,
        actor_user_id=user.id if user else None,
        actor_email=user.email if user else None,
        entity_type="config_snapshot",
        entity_id=snap.id,
        summary=f"Set baseline snapshot for asset {snap.asset_id}",
    )
    return snap


# --------------------------------------------------------------------------- #
# Diffing
# --------------------------------------------------------------------------- #
def diff_content(before: dict, after: dict) -> list[dict]:
    """Key-by-key diff: added / removed / changed. Sorted for determinism."""
    before = before or {}
    after = after or {}
    diffs: list[dict] = []
    for key in sorted(set(before) | set(after)):
        b = before.get(key)
        a = after.get(key)
        if key not in before:
            diffs.append({"field": key, "before": None, "after": a})
        elif key not in after:
            diffs.append({"field": key, "before": b, "after": None})
        elif b != a:
            diffs.append({"field": key, "before": b, "after": a})
    return diffs


def diff_snapshots(
    session: Session, from_id: uuid.UUID, to_id: uuid.UUID
) -> list[dict]:
    from_snap = get_snapshot(session, from_id)
    to_snap = get_snapshot(session, to_id)
    return diff_content(from_snap.content, to_snap.content)


# --------------------------------------------------------------------------- #
# Import + compare -> ConfigChange
# --------------------------------------------------------------------------- #
def import_and_compare(
    session: Session, data: SnapshotCreate, user: AuthenticatedUser | None
) -> ConfigChange:
    """Create a snapshot, diff it against the current baseline, and record a
    ConfigChange (UNREVIEWED). Returns the change."""
    asset = _require_asset(session, data.asset_id)
    baseline = _current_baseline(session, data.asset_id)
    new_snap = create_snapshot(session, data, user)

    before = baseline.content if baseline else {}
    diff = diff_content(before, new_snap.content)

    if diff:
        summary = f"{len(diff)} configuration field(s) changed vs baseline on {asset.asset_tag}"
    else:
        summary = f"No configuration drift detected vs baseline on {asset.asset_tag}"

    change = ConfigChange(
        asset_id=data.asset_id,
        from_snapshot_id=baseline.id if baseline else None,
        to_snapshot_id=new_snap.id,
        summary=summary,
        diff=diff,
        disposition=ChangeDisposition.UNREVIEWED,
        within_approved_window=True,
        detected_at=utcnow(),
    )
    session.add(change)
    session.commit()
    session.refresh(change)
    record_audit(
        session,
        action=AuditAction.CONFIG_SNAPSHOT,
        actor_user_id=user.id if user else None,
        actor_email=user.email if user else None,
        entity_type="config_change",
        entity_id=change.id,
        summary=f"Imported snapshot and recorded change ({len(diff)} field diff)",
    )
    return change


# --------------------------------------------------------------------------- #
# Changes
# --------------------------------------------------------------------------- #
def list_changes(
    session: Session, *, filters: ChangeFilter, page: PaginationParams
) -> tuple[list[ConfigChange], int]:
    stmt = select(ConfigChange)
    count_stmt = select(func.count()).select_from(ConfigChange)
    conditions = []
    if filters.asset_id:
        conditions.append(ConfigChange.asset_id == filters.asset_id)
    if filters.disposition:
        conditions.append(ConfigChange.disposition == filters.disposition)
    if page.search:
        conditions.append(ConfigChange.summary.ilike(f"%{page.search}%"))  # type: ignore[attr-defined]
    for cond in conditions:
        stmt = stmt.where(cond)
        count_stmt = count_stmt.where(cond)
    total = session.exec(count_stmt).one()
    stmt = stmt.order_by(ConfigChange.created_at.desc()).offset(page.offset).limit(page.limit)  # type: ignore[attr-defined]
    items = session.exec(stmt).all()
    return list(items), int(total)


def get_change(session: Session, change_id: uuid.UUID) -> ConfigChange:
    change = session.get(ConfigChange, change_id)
    if change is None:
        raise NotFoundError("Configuration change not found")
    return change


def set_disposition(
    session: Session,
    change_id: uuid.UUID,
    req: DispositionRequest,
    user: AuthenticatedUser | None,
) -> ConfigChange:
    if req.disposition == ChangeDisposition.UNREVIEWED:
        raise ValidationAppError("Disposition must be AUTHORIZED or UNAUTHORIZED")
    change = get_change(session, change_id)
    change.disposition = req.disposition
    if req.change_ticket is not None:
        change.change_ticket = req.change_ticket
    if req.within_approved_window is not None:
        change.within_approved_window = req.within_approved_window
    change.reviewed_by = user.email if user else None
    session.add(change)
    session.commit()
    session.refresh(change)

    asset = session.get(Asset, change.asset_id)

    # Unauthorized change on a high-criticality asset -> raise a passive detection.
    if (
        req.disposition == ChangeDisposition.UNAUTHORIZED
        and asset is not None
        and asset.criticality in _HIGH_CRITICALITY
    ):
        _raise_unauthorized_change_detection(session, asset, change)

    if asset is not None:
        score_asset(session, asset, persist=True)

    record_audit(
        session,
        action=AuditAction.CHANGE_DISPOSITION,
        actor_user_id=user.id if user else None,
        actor_email=user.email if user else None,
        entity_type="config_change",
        entity_id=change.id,
        summary=(
            f"Change on {asset.asset_tag if asset else change.asset_id} "
            f"dispositioned {req.disposition.value}"
        ),
    )
    return change


def _raise_unauthorized_change_detection(
    session: Session, asset: Asset, change: ConfigChange
) -> Detection:
    """Build the out-of-window-change Detection directly to avoid a hard
    dependency on the detection service. Defensive/passive containment only."""
    detection = Detection(
        title=f"Unauthorized configuration change on {asset.asset_tag}",
        detection_type=DetectionType.OUT_OF_WINDOW_CHANGE,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        status=DetectionStatus.NEW,
        asset_id=asset.id,
        site_id=asset.site_id,
        description=(
            f"A configuration change dispositioned UNAUTHORIZED was detected on "
            f"high-criticality asset {asset.asset_tag}. {change.summary}"
        ),
        attck_ics_technique="T0843",
        attck_ics_tactic="Program Download",
        triage_steps=[
            "Compare the changed configuration against the approved baseline.",
            "Confirm whether an approved change ticket or maintenance window exists.",
            "Identify the source of the change (engineering workstation, remote access).",
            "Interview the asset owner and verify intent.",
        ],
        safe_containment_steps=[
            "Do NOT alter PLC logic; preserve current state for forensics.",
            "Restrict remote and engineering-workstation access via existing controls.",
            "Increase passive monitoring of the affected zone/conduit.",
            "Prepare to restore the approved baseline during a maintenance window if confirmed malicious.",
        ],
        source=SourceType.MANUAL,
        detected_at=utcnow(),
    )
    session.add(detection)
    session.commit()
    session.refresh(detection)
    return detection


def change_evidence_report(session: Session, change: ConfigChange) -> str:
    """Deterministic Markdown evidence report for a configuration change."""
    asset = session.get(Asset, change.asset_id)
    lines: list[str] = []
    lines.append("# Configuration Change Evidence Report")
    lines.append("")
    if asset is not None:
        lines.append(f"**Asset:** `{asset.asset_tag}` ({asset.asset_type.value})")
        lines.append(f"**Criticality:** {asset.criticality.value}")
    lines.append(f"**Change ID:** {change.id}")
    lines.append(f"**Disposition:** {change.disposition.value}")
    lines.append(f"**Within approved window:** {'Yes' if change.within_approved_window else 'No'}")
    lines.append(f"**Change ticket:** {change.change_ticket or 'N/A'}")
    lines.append(f"**Reviewed by:** {change.reviewed_by or 'N/A'}")
    detected = change.detected_at or change.created_at
    lines.append(f"**Detected at:** {detected.isoformat() if detected else 'N/A'}")
    lines.append("")
    lines.append("## Summary")
    lines.append(change.summary or "N/A")
    lines.append("")
    lines.append(f"## Field changes ({len(change.diff or [])})")
    if change.diff:
        lines.append("")
        lines.append("| Field | Before | After |")
        lines.append("| --- | --- | --- |")
        for d in change.diff:
            field = str(d.get("field", ""))
            before = str(d.get("before"))
            after = str(d.get("after"))
            lines.append(f"| {field} | {before} | {after} |")
    else:
        lines.append("No field-level differences recorded.")
    lines.append("")
    lines.append("> Simulated/demo evidence for evaluation purposes.")
    return "\n".join(lines)
