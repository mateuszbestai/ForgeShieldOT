"""The demo seed loader is idempotent."""
from __future__ import annotations

from sqlmodel import Session, func, select

from app.core.db import engine
from app.models.asset import Asset
from app.models.compliance import ComplianceControl, ComplianceFramework
from app.models.incident import Incident
from app.models.user import User
from app.models.vuln import AssetVulnerability, Vulnerability
from app.seed.loaders import seed_all

_TRACKED_MODELS = [
    User,
    Asset,
    Vulnerability,
    AssetVulnerability,
    ComplianceFramework,
    ComplianceControl,
    Incident,
]


def _counts(session: Session) -> dict[str, int]:
    return {
        m.__name__: int(session.exec(select(func.count()).select_from(m)).one())
        for m in _TRACKED_MODELS
    }


def test_seed_all_is_idempotent():
    # The session-scoped fixture has already seeded once; seeding again must not
    # change any row counts.
    with Session(engine) as session:
        before = _counts(session)
        seed_all(session)
        after = _counts(session)
    assert before == after


def test_second_seed_reports_no_new_core_rows():
    with Session(engine) as session:
        before = _counts(session)
        seed_all(session)
        seed_all(session)
        after = _counts(session)
    assert before == after
