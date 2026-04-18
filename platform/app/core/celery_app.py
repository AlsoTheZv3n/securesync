"""Celery application factory.

Run a worker with:
    cd platform
    celery -A app.core.celery_app:celery_app worker --loglevel=info --concurrency=4

Run the beat scheduler with:
    celery -A app.core.celery_app:celery_app beat --loglevel=info
"""

from __future__ import annotations

from celery import Celery

from app.core.config import get_settings


def _build_celery() -> Celery:
    settings = get_settings()
    broker_url = str(settings.REDIS_URL)
    app = Celery(
        "securesync",
        broker=broker_url,
        backend=broker_url,
        include=["app.tasks.scan_tasks", "app.tasks.scheduler_tasks"],
    )
    app.conf.update(
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        timezone="UTC",
        enable_utc=True,
        # Per-task acks: fail fast, requeue only on explicit retry calls.
        task_acks_late=False,
        task_reject_on_worker_lost=True,
        worker_prefetch_multiplier=1,
        worker_max_tasks_per_child=200,
        # Long-running scans need generous time limits — but always cap.
        task_soft_time_limit=60 * 30,    # 30 minutes
        task_time_limit=60 * 35,         # hard kill at 35 minutes
        # Result expiry — we read results from the DB, not Celery's backend,
        # so prune the broker store quickly.
        result_expires=60 * 60 * 24,
        # Beat: poll the ScanSchedule table once a minute. Requires running
        # `celery -A app.core.celery_app:celery_app beat` alongside workers.
        beat_schedule={
            "scheduler-tick": {
                "task": "scheduler.tick",
                "schedule": 60.0,
            },
        },
    )
    return app


celery_app: Celery = _build_celery()
