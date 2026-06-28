"""Redis client factory (cache + rate-limit backend + Celery broker)."""
from __future__ import annotations

from functools import lru_cache

import redis

from app.core.config import settings


@lru_cache
def get_redis() -> redis.Redis:
    return redis.Redis.from_url(settings.redis_url, decode_responses=True)


def redis_healthy() -> bool:
    try:
        return bool(get_redis().ping())
    except Exception:  # noqa: BLE001 - health check must never raise
        return False
