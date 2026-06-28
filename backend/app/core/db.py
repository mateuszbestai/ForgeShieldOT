"""Database engine and session management."""
from __future__ import annotations

from collections.abc import Generator

from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from app.core.config import settings

# psycopg3 driver. echo off; pre-ping keeps long-lived dev connections healthy.
_connect_args: dict = {}
_engine_kwargs: dict = {"pool_pre_ping": True}

engine = create_engine(settings.database_url, connect_args=_connect_args, **_engine_kwargs)


def init_db() -> None:
    """Create all tables (used as an Alembic fallback and by the test suite)."""
    # Importing models registers them on SQLModel.metadata.
    import app.models  # noqa: F401

    SQLModel.metadata.create_all(engine)


def get_session() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a session.

    ``expire_on_commit=False`` keeps ORM attributes populated after commit so that
    ``model_dump()`` on a just-committed object returns full data (otherwise commits
    triggered by e.g. audit logging would expire attributes to an empty dict).
    """
    with Session(engine, expire_on_commit=False) as session:
        yield session


def make_sqlite_engine(url: str = "sqlite://"):
    """In-memory SQLite engine for tests (shared connection across threads)."""
    return create_engine(
        url,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
