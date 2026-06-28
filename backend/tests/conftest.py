"""Shared pytest fixtures for the ForgeShield OT backend test suite.

The environment is configured in ``tests/_env.py`` (imported first, before any
``app.`` import) so the DB engine binds to a throwaway temp-file SQLite database,
auth runs in dev-bypass mode and the AI provider is the deterministic mock.
"""
from __future__ import annotations

# Bootstrap the test environment BEFORE importing anything from ``app``.
from tests import _env  # noqa: F401  (import order matters)

import time

import pytest
from fastapi.testclient import TestClient
from jose import jwt
from sqlmodel import Session, SQLModel

# Importing app.models registers every table on SQLModel.metadata.
import app.models  # noqa: F401
from app.core.db import engine
from app.main import app
from app.seed.loaders import seed_all

_JWT_SECRET = "testsecret"

# supabase_id + email per role, mirroring the demo users created by the seed so
# that JIT user-provisioning resolves to the seeded local User rows.
_ROLE_IDENTITIES: dict[str, tuple[str, str]] = {
    "ADMIN": ("demo-admin", "admin@forgeshield.local"),
    "OT_SECURITY_ENGINEER": ("demo-engineer", "engineer@forgeshield.local"),
    "SOC_ANALYST": ("demo-analyst", "analyst@forgeshield.local"),
    "COMPLIANCE_OFFICER": ("demo-compliance", "compliance@forgeshield.local"),
    "VIEWER": ("demo-viewer", "viewer@forgeshield.local"),
}


@pytest.fixture(scope="session", autouse=True)
def _db() -> None:
    """Create the schema once and seed the demo dataset for the whole session."""
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        seed_all(session)
    yield
    SQLModel.metadata.drop_all(engine)


@pytest.fixture(scope="session")
def db_session():
    """A raw SQLModel session bound to the test engine (expire_on_commit=False)."""
    with Session(engine, expire_on_commit=False) as session:
        yield session


@pytest.fixture(scope="session")
def client() -> TestClient:
    """A FastAPI TestClient for the fully-wired application."""
    with TestClient(app) as c:
        yield c


def _mint_token(role: str) -> str:
    supabase_id, email = _ROLE_IDENTITIES.get(role, (f"demo-{role.lower()}", f"{role.lower()}@forgeshield.local"))
    return jwt.encode(
        {
            "sub": supabase_id,
            "email": email,
            "aud": "authenticated",
            "app_metadata": {"role": role},
            "exp": int(time.time()) + 3600,
        },
        _JWT_SECRET,
        algorithm="HS256",
    )


@pytest.fixture(scope="session")
def token():
    """Factory: ``token(role)`` -> a signed Supabase-style JWT string."""
    return _mint_token


@pytest.fixture(scope="session")
def auth(token):
    """Factory: ``auth(role)`` -> an Authorization header dict."""

    def _auth(role: str) -> dict:
        return {"Authorization": f"Bearer {token(role)}"}

    return _auth
