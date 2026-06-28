"""Lightweight rate limiting as a FastAPI dependency.

Fixed-window counter in Redis (shared across replicas), with an in-memory fallback
when Redis is unavailable. Used to protect the AI chat endpoint. Implemented as a
dependency (not a decorator) so it composes cleanly with FastAPI's signature
introspection and request-body parsing.
"""
from __future__ import annotations

import threading
import time

from fastapi import Depends, Request

from app.core.config import settings
from app.core.exceptions import AppError
from app.core.redis import get_redis
from app.core.security import AuthenticatedUser, get_current_user

_UNITS = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}

# In-memory fallback store: key -> (window_start, count)
_local_lock = threading.Lock()
_local_store: dict[str, tuple[int, int]] = {}


class RateLimitExceeded(AppError):
    status_code = 429
    code = "rate_limited"


def parse_limit(spec: str) -> tuple[int, int]:
    """Parse a 'count/unit' spec like '20/minute' -> (count, window_seconds)."""
    try:
        count_str, unit = spec.split("/")
        count = int(count_str)
        unit_key = unit.strip().lower().rstrip("s")  # minute(s) -> minute
        return count, _UNITS.get(unit_key, 60)
    except (ValueError, KeyError):
        return 20, 60


def _check_local(key: str, limit: int, window: int) -> None:
    now = int(time.time())
    bucket = now // window
    composite = f"{key}:{bucket}"
    with _local_lock:
        start, count = _local_store.get(composite, (bucket, 0))
        count += 1
        _local_store[composite] = (bucket, count)
        # opportunistic cleanup of old buckets
        if len(_local_store) > 5000:
            _local_store.clear()
    if count > limit:
        raise RateLimitExceeded("Rate limit exceeded. Please slow down.")


def _check_redis(key: str, limit: int, window: int) -> None:
    r = get_redis()
    bucket = int(time.time()) // window
    composite = f"rl:{key}:{bucket}"
    count = r.incr(composite)
    if count == 1:
        r.expire(composite, window)
    if int(count) > limit:
        raise RateLimitExceeded("Rate limit exceeded. Please slow down.")


def _enforce(key: str, limit: int, window: int) -> None:
    try:
        _check_redis(key, limit, window)
    except RateLimitExceeded:
        raise
    except Exception:  # noqa: BLE001 - Redis unavailable -> in-memory fallback
        _check_local(key, limit, window)


_AI_LIMIT, _AI_WINDOW = parse_limit(settings.ai_rate_limit)


def ai_rate_limiter(
    request: Request,
    user: AuthenticatedUser = Depends(get_current_user),
) -> None:
    """Dependency: enforce the AI endpoint rate limit, keyed per user."""
    _enforce(f"user:{user.id}", _AI_LIMIT, _AI_WINDOW)
