"""Celery tasks: scheduled AI daily brief and risk recomputation.

Both tasks open their own Session and are defensive: the daily brief relies on
``report_service.generate`` (which has an AI fallback), and neither task should
crash if the AI provider or other optional dependencies are unavailable.
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass

from sqlmodel import Session, select

from app.core.db import engine
from app.core.enums import ReportFormat, ReportType, RoleName
from app.models.user import User
from app.schemas.report import GenerateReportRequest
from app.services import report_service
from app.services.risk_engine import recompute_all
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _SystemUser:
    """Minimal stand-in for AuthenticatedUser when no real user is available.

    ``report_service.generate`` only reads ``.id`` and ``.email`` from the user.
    """

    id: uuid.UUID | None
    email: str
    role: RoleName = RoleName.ADMIN
    supabase_id: str = "system"
    full_name: str = "System"


def _system_user(session: Session) -> _SystemUser:
    """Use the seeded admin user when present; otherwise a lightweight system user."""
    admin = session.exec(
        select(User).where(User.role == RoleName.ADMIN)
    ).first()
    if admin is not None:
        return _SystemUser(id=admin.id, email=admin.email)
    return _SystemUser(id=None, email="system@forgeshield.local")


@celery_app.task(name="app.workers.tasks.generate_daily_brief")
def generate_daily_brief() -> dict:
    """Generate the AI daily-brief report. Resilient to AI-provider failures."""
    with Session(engine) as session:
        user = _system_user(session)
        req = GenerateReportRequest(
            report_type=ReportType.AI_DAILY_BRIEF,
            fmt=ReportFormat.MARKDOWN,
            params={"source": "scheduled"},
        )
        try:
            report = report_service.generate(session, req, user)  # type: ignore[arg-type]
        except Exception as exc:  # pragma: no cover - report_service has its own fallback
            logger.exception("Daily brief generation failed")
            return {"status": "error", "error": str(exc)}
        return {
            "status": "ok",
            "report_id": str(report.id),
            "title": report.title,
        }


@celery_app.task(name="app.workers.tasks.recompute_all_risk")
def recompute_all_risk() -> dict:
    """Recompute and persist risk scores/bands for every asset."""
    with Session(engine) as session:
        count = recompute_all(session)
    return {"status": "ok", "assets_recomputed": count}
