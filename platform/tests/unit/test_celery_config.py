"""Smoke tests for Celery wiring — ensures the app loads and tasks register."""

from __future__ import annotations

from app.core.celery_app import celery_app


def test_celery_app_is_configured() -> None:
    assert celery_app.main == "securesync"
    assert celery_app.conf.task_serializer == "json"
    assert celery_app.conf.timezone == "UTC"
    # Sanity bounds for our hard cap.
    assert celery_app.conf.task_time_limit > celery_app.conf.task_soft_time_limit
    assert celery_app.conf.task_time_limit <= 60 * 60


def test_scan_task_registered() -> None:
    """Importing the tasks module registers the @celery_app.task decorator."""
    import app.tasks.scan_tasks  # noqa: F401  -- side-effect import

    assert "scan.nuclei" in celery_app.tasks


def test_broker_url_uses_settings() -> None:
    # Don't compare exact URL — just that it points at Redis from config.
    assert celery_app.conf.broker_url.startswith(("redis://", "rediss://"))
