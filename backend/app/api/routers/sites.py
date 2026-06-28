"""Sites and zones API."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlmodel import Session, select

from app.api.deps import AuthenticatedUser, get_current_user
from app.core.db import get_session
from app.models.org import Site, Zone

router = APIRouter(tags=["sites"])


@router.get("/sites")
def list_sites(
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> list[dict]:
    sites = session.exec(select(Site)).all()
    return [s.model_dump() for s in sites]


@router.get("/sites/{site_id}/zones")
def list_zones_for_site(
    site_id: uuid.UUID,
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> list[dict]:
    zones = session.exec(select(Zone).where(Zone.site_id == site_id)).all()
    return [z.model_dump() for z in zones]


@router.get("/zones")
def list_zones(
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> list[dict]:
    zones = session.exec(select(Zone)).all()
    return [z.model_dump() for z in zones]
