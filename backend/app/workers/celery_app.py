"""Celery application for ForgeShield OT background work.

Construction never connects to the broker, so importing this module is safe even
when Redis is down. The beat schedule runs the daily AI brief once a day and a
risk recompute hourly.
"""
from __future__ import annotations

from celery import Celery
from celery.schedules import crontab

from app.core.config import settings

celery_app = Celery(
    "forgeshield",
    broker=settings.redis_url,
    backend=settings.redis_url,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    broker_connection_retry_on_startup=True,
)

celery_app.conf.beat_schedule = {
    "generate-daily-brief": {
        "task": "app.workers.tasks.generate_daily_brief",
        # 06:00 UTC every day.
        "schedule": crontab(hour=6, minute=0),
    },
    "recompute-all-risk-hourly": {
        "task": "app.workers.tasks.recompute_all_risk",
        # Top of every hour.
        "schedule": crontab(minute=0),
    },
}

# Discover @celery_app.task definitions in app.workers.tasks.
celery_app.autodiscover_tasks(["app.workers"])

# Import the tasks module so the tasks are registered even without autodiscovery
# (e.g. when a worker imports celery_app directly).
from app.workers import tasks  # noqa: E402,F401
