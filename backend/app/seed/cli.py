"""Runnable seed entrypoint: ``python -m app.seed.cli``.

Safe to run repeatedly (the loaders are idempotent). Each phase is isolated so a
Supabase provisioning failure does not prevent local DB seeding. Exits 0 on
success.
"""
from __future__ import annotations

import json
import logging
import sys

from sqlmodel import Session

from app.core.db import engine, init_db
from app.seed.loaders import seed_all
from app.seed.supabase_users import provision_demo_users

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("app.seed.cli")


def main() -> int:
    exit_code = 0

    # Phase 1 — local DB seeding (the important part; must not be blocked by Supabase).
    try:
        init_db()  # ensure tables exist (Alembic fallback / fresh DBs)
        with Session(engine) as session:
            summary = seed_all(session)
        print("=== ForgeShield OT demo seed summary ===")
        print(json.dumps(summary, indent=2, default=str))
    except Exception as exc:  # pragma: no cover - surfaced to operator
        logger.exception("Local demo seeding failed")
        print(f"ERROR: local seeding failed: {exc}", file=sys.stderr)
        exit_code = 1

    # Phase 2 — Supabase auth-user provisioning (self-guards on missing config).
    try:
        result = provision_demo_users()
        print("=== Supabase demo-user provisioning ===")
        print(json.dumps(result, indent=2, default=str))
    except Exception as exc:  # pragma: no cover - provision_demo_users already guards
        logger.exception("Supabase provisioning raised unexpectedly")
        print(f"WARNING: Supabase provisioning failed: {exc}", file=sys.stderr)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
