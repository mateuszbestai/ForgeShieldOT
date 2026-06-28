"""Asset inventory business logic."""
from __future__ import annotations

import uuid

from sqlalchemy import func
from sqlmodel import Session, or_, select

from app.core.enums import AuditAction, RiskBand
from app.core.exceptions import ConflictError, NotFoundError
from app.core.security import AuthenticatedUser
from app.models.asset import Asset, AssetRelationship, ProtocolObservation
from app.models.compliance import ComplianceControl, ComplianceEvidence
from app.models.config_mgmt import ConfigChange
from app.models.detection import Detection
from app.models.vuln import AssetVulnerability, Vulnerability
from app.schemas.asset import AssetCreate, AssetFilter, AssetUpdate
from app.schemas.common import PaginationParams
from app.services.audit_service import record_audit
from app.services.risk_engine import build_risk_input, compute_risk, score_asset


def list_assets(
    session: Session, *, filters: AssetFilter, page: PaginationParams
) -> tuple[list[Asset], int]:
    stmt = select(Asset)
    count_stmt = select(func.count()).select_from(Asset)

    conditions = []
    if filters.site_id:
        conditions.append(Asset.site_id == filters.site_id)
    if filters.zone_id:
        conditions.append(Asset.zone_id == filters.zone_id)
    if filters.asset_type:
        conditions.append(Asset.asset_type == filters.asset_type)
    if filters.criticality:
        conditions.append(Asset.criticality == filters.criticality)
    if filters.risk_band:
        try:
            conditions.append(Asset.risk_band == RiskBand(filters.risk_band.upper()))
        except ValueError:
            pass
    if filters.purdue_level is not None:
        conditions.append(Asset.purdue_level == filters.purdue_level)
    if page.search:
        term = f"%{page.search}%"
        conditions.append(
            or_(
                Asset.asset_tag.ilike(term),  # type: ignore[attr-defined]
                Asset.hostname.ilike(term),  # type: ignore[attr-defined]
                Asset.ip_address.ilike(term),  # type: ignore[attr-defined]
                Asset.vendor.ilike(term),  # type: ignore[attr-defined]
                Asset.model.ilike(term),  # type: ignore[attr-defined]
            )
        )
    for cond in conditions:
        stmt = stmt.where(cond)
        count_stmt = count_stmt.where(cond)

    total = session.exec(count_stmt).one()
    stmt = stmt.order_by(Asset.risk_score.desc()).offset(page.offset).limit(page.limit)  # type: ignore[attr-defined]
    items = session.exec(stmt).all()
    return list(items), int(total)


def get_asset(session: Session, asset_id: uuid.UUID) -> Asset:
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise NotFoundError("Asset not found")
    return asset


def create_asset(session: Session, data: AssetCreate, user: AuthenticatedUser | None) -> Asset:
    existing = session.exec(select(Asset).where(Asset.asset_tag == data.asset_tag)).first()
    if existing:
        raise ConflictError(f"Asset tag '{data.asset_tag}' already exists")
    asset = Asset(**data.model_dump())
    session.add(asset)
    session.commit()
    session.refresh(asset)
    score_asset(session, asset, persist=True)
    record_audit(
        session,
        action=AuditAction.ASSET_CREATE,
        actor_user_id=user.id if user else None,
        actor_email=user.email if user else None,
        entity_type="asset",
        entity_id=asset.id,
        summary=f"Created asset {asset.asset_tag}",
    )
    return asset


def update_asset(
    session: Session, asset_id: uuid.UUID, data: AssetUpdate, user: AuthenticatedUser | None
) -> Asset:
    asset = get_asset(session, asset_id)
    for key, value in data.model_dump(exclude_unset=True).items():
        setattr(asset, key, value)
    session.add(asset)
    session.commit()
    session.refresh(asset)
    score_asset(session, asset, persist=True)
    record_audit(
        session,
        action=AuditAction.ASSET_UPDATE,
        actor_user_id=user.id if user else None,
        actor_email=user.email if user else None,
        entity_type="asset",
        entity_id=asset.id,
        summary=f"Updated asset {asset.asset_tag}",
    )
    return asset


def delete_asset(session: Session, asset_id: uuid.UUID, user: AuthenticatedUser | None) -> None:
    asset = get_asset(session, asset_id)
    tag = asset.asset_tag
    session.delete(asset)
    session.commit()
    record_audit(
        session,
        action=AuditAction.ASSET_DELETE,
        actor_user_id=user.id if user else None,
        actor_email=user.email if user else None,
        entity_type="asset",
        entity_id=asset_id,
        summary=f"Deleted asset {tag}",
    )


def asset_detail(session: Session, asset: Asset) -> dict:
    """Assemble the full asset detail: protocols, vulns, detections, changes, compliance, risk."""
    assert asset.id is not None
    protocols = session.exec(
        select(ProtocolObservation).where(ProtocolObservation.asset_id == asset.id)
    ).all()
    av_rows = session.exec(
        select(AssetVulnerability, Vulnerability)
        .where(AssetVulnerability.asset_id == asset.id)
        .where(AssetVulnerability.vuln_id == Vulnerability.id)
    ).all()
    vulns = [
        {"link": av.model_dump(), "vulnerability": vuln.model_dump()} for av, vuln in av_rows
    ]
    detections = session.exec(select(Detection).where(Detection.asset_id == asset.id)).all()
    changes = session.exec(
        select(ConfigChange).where(ConfigChange.asset_id == asset.id)
    ).all()
    rels = session.exec(
        select(AssetRelationship).where(
            or_(
                AssetRelationship.src_asset_id == asset.id,
                AssetRelationship.dst_asset_id == asset.id,
            )
        )
    ).all()
    ev_rows = session.exec(
        select(ComplianceEvidence, ComplianceControl)
        .where(ComplianceEvidence.source_id == asset.id)
        .where(ComplianceEvidence.control_id == ComplianceControl.id)
    ).all()
    compliance_links = [
        {"evidence": ev.model_dump(), "control": ctrl.model_dump()} for ev, ctrl in ev_rows
    ]
    risk = compute_risk(build_risk_input(session, asset))
    return {
        "asset": asset.model_dump(),
        "protocols": [p.model_dump() for p in protocols],
        "vulnerabilities": vulns,
        "detections": [d.model_dump() for d in detections],
        "config_changes": [c.model_dump() for c in changes],
        "relationships": [r.model_dump() for r in rels],
        "compliance_links": compliance_links,
        "risk": risk.model_dump(),
    }


def distinct_filter_values(session: Session) -> dict:
    vendors = session.exec(select(Asset.vendor).distinct()).all()
    return {
        "vendors": sorted({v for v in vendors if v}),
    }
