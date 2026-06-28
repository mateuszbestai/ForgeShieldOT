"""Provision the 5 demo auth users in Supabase (idempotently).

This module talks to the Supabase **Admin** API to create the real authentication
users that back the local mirror ``User`` rows seeded by ``loaders.py``. It is a
no-op (never raises) when ``supabase_url`` / ``supabase_service_key`` are not
configured, so local seeding works without a Supabase project.

No secrets are stored in code: the service key, URL and demo password all come
from settings (which load from the environment / ``.env``).
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from app.core.config import settings
from app.core.enums import RoleName

logger = logging.getLogger(__name__)

# email -> RBAC role placed into Supabase app_metadata.role.
_DEMO_AUTH_USERS: list[tuple[str, RoleName]] = [
    ("admin@forgeshield.local", RoleName.ADMIN),
    ("engineer@forgeshield.local", RoleName.OT_SECURITY_ENGINEER),
    ("analyst@forgeshield.local", RoleName.SOC_ANALYST),
    ("compliance@forgeshield.local", RoleName.COMPLIANCE_OFFICER),
    ("viewer@forgeshield.local", RoleName.VIEWER),
]

_TIMEOUT = 30.0


def _admin_headers() -> dict[str, str]:
    key = settings.supabase_service_key
    return {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }


def _existing_emails(client: httpx.Client, base: str) -> set[str]:
    """Return the set of existing user emails (best-effort, paginated)."""
    emails: set[str] = set()
    page = 1
    while True:
        resp = client.get(
            f"{base}/auth/v1/admin/users",
            headers=_admin_headers(),
            params={"page": page, "per_page": 200},
        )
        resp.raise_for_status()
        payload = resp.json()
        users = payload.get("users", payload) if isinstance(payload, dict) else payload
        if not users:
            break
        for u in users:
            email = (u or {}).get("email")
            if email:
                emails.add(email.lower())
        if len(users) < 200:
            break
        page += 1
    return emails


def provision_demo_users() -> dict[str, Any]:
    """Idempotently create the 5 demo Supabase auth users.

    Returns a summary dict ``{configured, created, existing, errors, message}``.
    Never raises: configuration gaps and HTTP errors are reported in the summary.
    """
    summary: dict[str, Any] = {
        "configured": False,
        "created": [],
        "existing": [],
        "errors": [],
        "message": "",
    }

    base = settings.supabase_url.rstrip("/")
    if not base or not settings.supabase_service_key:
        summary["message"] = (
            "Supabase URL/service key not configured; skipping auth-user provisioning "
            "(local mirror User rows were still seeded)."
        )
        logger.info(summary["message"])
        return summary

    summary["configured"] = True

    try:
        with httpx.Client(timeout=_TIMEOUT) as client:
            try:
                existing_emails = _existing_emails(client, base)
            except httpx.HTTPError as exc:
                # Listing failed; fall back to per-create idempotency handling.
                logger.warning("Could not list existing Supabase users: %s", exc)
                existing_emails = set()

            for email, role in _DEMO_AUTH_USERS:
                if email.lower() in existing_emails:
                    summary["existing"].append(email)
                    logger.info("Demo user already exists in Supabase: %s", email)
                    continue
                try:
                    resp = client.post(
                        f"{base}/auth/v1/admin/users",
                        headers=_admin_headers(),
                        json={
                            "email": email,
                            "password": settings.demo_user_password,
                            "email_confirm": True,
                            "app_metadata": {"role": role.value},
                        },
                    )
                    if resp.status_code in (200, 201):
                        summary["created"].append(email)
                        logger.info("Created demo Supabase user: %s (%s)", email, role.value)
                    elif resp.status_code in (409, 422):
                        # Already exists (race or pre-existing).
                        summary["existing"].append(email)
                        logger.info("Demo user already present (HTTP %s): %s", resp.status_code, email)
                    else:
                        msg = f"{email}: HTTP {resp.status_code} {resp.text[:200]}"
                        summary["errors"].append(msg)
                        logger.warning("Failed to create demo user %s", msg)
                except httpx.HTTPError as exc:
                    msg = f"{email}: {exc}"
                    summary["errors"].append(msg)
                    logger.warning("HTTP error creating demo user %s", msg)
    except Exception as exc:  # pragma: no cover - defensive, never crash the seed
        summary["errors"].append(str(exc))
        logger.exception("Unexpected error provisioning Supabase demo users")

    summary["message"] = (
        f"Supabase demo users: {len(summary['created'])} created, "
        f"{len(summary['existing'])} already existed, {len(summary['errors'])} errors."
    )
    logger.info(summary["message"])
    return summary
