"""Network map / Purdue model graph API."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlmodel import Session, select

from app.api.deps import AuthenticatedUser, get_current_user
from app.core.db import get_session
from app.models.asset import Asset, AssetRelationship
from app.models.org import Site, Zone

router = APIRouter(prefix="/network-map", tags=["network-map"])


@router.get("")
def network_map(
    site_id: uuid.UUID | None = Query(None),
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> dict:
    site_stmt = select(Site)
    if site_id:
        site_stmt = site_stmt.where(Site.id == site_id)
    sites = session.exec(site_stmt).all()
    site_ids = [s.id for s in sites]

    zones = session.exec(select(Zone).where(Zone.site_id.in_(site_ids))).all() if site_ids else []  # type: ignore[attr-defined]
    asset_stmt = select(Asset)
    if site_ids:
        asset_stmt = asset_stmt.where(Asset.site_id.in_(site_ids))  # type: ignore[attr-defined]
    assets = session.exec(asset_stmt).all()
    asset_ids = {a.id for a in assets}

    rels = session.exec(select(AssetRelationship)).all()
    # Only keep relationships whose endpoints are in scope.
    edges = []
    for r in rels:
        if r.src_asset_id in asset_ids and r.dst_asset_id in asset_ids:
            critical = r.is_internet_path or r.is_unknown or r.relationship_type.value in {
                "REMOTE_ACCESS",
                "EW_TO_PLC",
            }
            edges.append(
                {
                    "id": str(r.id),
                    "source": str(r.src_asset_id),
                    "target": str(r.dst_asset_id),
                    "protocol": r.protocol.value if r.protocol else None,
                    "relationship_type": r.relationship_type.value,
                    "is_unknown": r.is_unknown,
                    "is_internet_path": r.is_internet_path,
                    "critical": critical,
                }
            )

    nodes = [
        {
            "id": str(a.id),
            "label": a.asset_tag,
            "asset_type": a.asset_type.value,
            "purdue_level": int(a.purdue_level),
            "zone_id": str(a.zone_id) if a.zone_id else None,
            "site_id": str(a.site_id),
            "risk_band": a.risk_band.value,
            "risk_score": a.risk_score,
            "criticality": a.criticality.value,
            "internet_reachable": a.internet_reachable,
        }
        for a in assets
    ]

    return {
        "sites": [s.model_dump() for s in sites],
        "zones": [z.model_dump() for z in zones],
        "nodes": nodes,
        "edges": edges,
        "is_demo_environment": True,
    }
