#!/usr/bin/env bash
# ForgeShield OT backend entrypoint.
# 1) Apply DB schema via Alembic (falls back to SQLModel create_all if no
#    migration revisions exist yet — keeps the demo runnable out of the box).
# 2) Optionally load idempotent demo data.
# 3) Launch the API server.
set -euo pipefail

echo "[entrypoint] Applying database schema..."
if ls /app/alembic/versions/*.py >/dev/null 2>&1; then
  alembic upgrade head
else
  echo "[entrypoint] No Alembic revisions found — bootstrapping schema with create_all()."
  python -c "from app.core.db import init_db; init_db()"
fi

if [ "${SEED_ON_START:-false}" = "true" ]; then
  echo "[entrypoint] Seeding demo data (idempotent)..."
  python -m app.seed.cli || echo "[entrypoint] Seed step reported a non-fatal error; continuing."
fi

echo "[entrypoint] Starting API on :8000"
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
