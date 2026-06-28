"""ForgeShield OT — FastAPI application factory."""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.core.config import settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging, get_logger
from app.core.redis import redis_healthy

log = get_logger("forgeshield")

DESCRIPTION = """
**ForgeShield OT** — a defensive OT/ICS cybersecurity console with an AI analyst layer.

⚠️ This environment uses **simulated / demo data**. All risky operations are mocked.
The platform is passive-first and read-only by default: it never writes to PLCs,
changes firewalls, or performs active scanning. The AI analyst is advisory-only.
"""


def create_app() -> FastAPI:
    configure_logging()
    app = FastAPI(
        title=settings.app_name,
        description=DESCRIPTION,
        version="0.1.0",
        docs_url="/docs",
        openapi_url="/openapi.json",
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    register_exception_handlers(app)
    app.include_router(api_router, prefix=settings.api_prefix)

    @app.get("/health", tags=["health"])
    def health() -> dict:
        return {
            "status": "ok",
            "app": settings.app_name,
            "environment": settings.environment,
            "redis": redis_healthy(),
            "ai_provider": settings.ai_provider.value,
            "demo_data": True,
        }

    @app.get("/", tags=["health"])
    def root() -> dict:
        return {
            "name": settings.app_name,
            "docs": "/docs",
            "notice": "Defensive OT security console. Simulated/demo data.",
        }

    return app


app = create_app()
