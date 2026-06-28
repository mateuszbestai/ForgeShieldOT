"""Test environment bootstrap.

Imported FIRST (before anything touches ``app.``) so the application settings,
DB engine, and auth verification all initialise in a deterministic, offline,
test-friendly configuration. In particular ``DATABASE_URL`` must be set before
``app.core.db`` is imported, because the SQLAlchemy engine is created at import
time from ``settings.database_url``.
"""
from __future__ import annotations

import os
import tempfile
import uuid

# A per-process temp-file SQLite DB. A file (not ``:memory:``) so that every
# connection the app opens shares the same data — an in-memory SQLite DB is
# private per connection unless a StaticPool is used.
_DB_PATH = os.path.join(tempfile.gettempdir(), f"fs_pytest_{uuid.uuid4().hex}.db")

# These MUST be forced (not ``setdefault``): when the suite runs inside the
# backend container, docker-compose has already injected the real ``.env`` values
# (e.g. the project ``SUPABASE_JWT_SECRET`` / ``SUPABASE_URL``) into the process
# environment. ``setdefault`` would then be a no-op and the app would verify
# tokens with the real secret while the test fixtures sign with ``testsecret`` —
# yielding spurious 401s. Forcing keeps the suite hermetic regardless of ambient
# environment. ``SUPABASE_URL`` is blanked so the asymmetric/JWKS path is never
# taken — tests exercise the HS256 path with the test secret.
_FORCED_ENV = {
    "DATABASE_URL": f"sqlite:///{_DB_PATH}",
    "SUPABASE_URL": "",
    "SUPABASE_JWT_SECRET": "testsecret",
    "AUTH_DEV_BYPASS": "true",
    "ENVIRONMENT": "development",
    "SUPABASE_JWT_AUD": "authenticated",
    "AI_PROVIDER": "mock",
    "SEED_ON_START": "false",
}
os.environ.update(_FORCED_ENV)

DB_PATH = _DB_PATH
