"""Sentry initialization — error + performance tracking for API + Celery.

No-ops when `SENTRY_DSN_BACKEND` is unset (dev / tests). Called from two
entry points so both the FastAPI app and each Celery worker process get
instrumented:

  * `app/main.py`         — before FastAPI init
  * `app/tasks/*.py`      — inside the Celery process bootstrap

Tags every event with `environment` and the git commit SHA (if provided
via the `GIT_SHA` env var during image build).
"""

from __future__ import annotations

import os

import structlog

from app.core.config import get_settings

logger = structlog.get_logger()


# Sample rate for APM traces. Start conservative — 10% — and raise once
# volume is known. Errors are ALWAYS captured regardless.
_TRACES_SAMPLE_RATE = 0.1
# Sentry's profiler samples from within traced transactions.
_PROFILES_SAMPLE_RATE = 0.1

_initialised = False


def init_sentry() -> bool:
    """Configure Sentry based on `SENTRY_DSN_BACKEND`. Returns True iff a
    client was actually initialised (DSN present)."""
    global _initialised
    if _initialised:
        return True

    settings = get_settings()
    dsn = settings.SENTRY_DSN_BACKEND
    if not dsn:
        logger.info("sentry_disabled", reason="no_dsn")
        return False

    # Import deferred so environments without the sdk installed don't fail
    # on app import. The dep is pinned in pyproject.toml so this succeeds
    # in production + CI.
    import sentry_sdk
    from sentry_sdk.integrations.celery import CeleryIntegration
    from sentry_sdk.integrations.fastapi import FastApiIntegration
    from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration
    from sentry_sdk.integrations.starlette import StarletteIntegration

    sentry_sdk.init(
        dsn=dsn,
        environment=settings.ENVIRONMENT,
        release=os.getenv("GIT_SHA") or None,
        traces_sample_rate=_TRACES_SAMPLE_RATE,
        profiles_sample_rate=_PROFILES_SAMPLE_RATE,
        send_default_pii=False,          # don't ship IPs / request bodies by default
        integrations=[
            FastApiIntegration(),
            StarletteIntegration(),
            CeleryIntegration(),
            SqlalchemyIntegration(),
        ],
    )

    _initialised = True
    logger.info("sentry_initialised", environment=settings.ENVIRONMENT)
    return True


def _reset_for_tests() -> None:
    """Escape hatch for unit tests — drop the one-shot guard so a fresh
    `init_sentry()` call in a subsequent test re-runs the init logic."""
    global _initialised
    _initialised = False


__all__ = ["init_sentry"]
