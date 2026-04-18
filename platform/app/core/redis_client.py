"""Async Redis client + token blacklist helpers.

Used for:
  - JWT revocation (logout): store jti → "revoked" until original exp.
  - Refresh-token tracking: one active refresh jti per user; rotating invalidates old.
  - Cache (EPSS, NVD) — via the generic `get_redis()` dependency.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Any

from redis.asyncio import Redis, from_url

from app.core.config import get_settings

_redis: Redis | None = None


def get_redis_client() -> Redis:
    """Module-level singleton. Use `get_redis()` as a FastAPI dependency."""
    global _redis
    if _redis is None:
        settings = get_settings()
        _redis = from_url(
            str(settings.REDIS_URL),
            encoding="utf-8",
            decode_responses=True,
            health_check_interval=30,
        )
    return _redis


async def get_redis() -> AsyncGenerator[Redis, Any]:
    """FastAPI dependency."""
    yield get_redis_client()


# ── Token blacklist helpers ─────────────────────────────────
_BLACKLIST_PREFIX = "revoked_jti:"


async def blacklist_jti(jti: str, ttl_seconds: int) -> None:
    """Mark a token as revoked until its original expiry."""
    if ttl_seconds <= 0:
        return
    await get_redis_client().setex(f"{_BLACKLIST_PREFIX}{jti}", ttl_seconds, "1")


async def is_jti_blacklisted(jti: str) -> bool:
    return await get_redis_client().exists(f"{_BLACKLIST_PREFIX}{jti}") == 1
