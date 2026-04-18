"""Redis-backed fixed-window rate limiter.

Simple, predictable, and O(1) per check:
    key = "rate:<bucket>:<identifier>:<window_start_epoch>"
    INCR key
    if count == 1: EXPIRE key <window_seconds>
    allow iff count <= limit

Use `.as_dependency()` to plug into a FastAPI route. For login-style
endpoints where we don't yet have a user, key by IP. For authenticated
endpoints, key by user_id.

Tenant-level throttling (phases.md) composes from this primitive — build
a second limiter keyed by `tenant_id`, call both in the dependency.
"""

from __future__ import annotations

import time
from collections.abc import Callable

import structlog
from fastapi import Request

from app.core.exceptions import RateLimitError
from app.core.redis_client import get_redis_client

logger = structlog.get_logger()

_KEY_PREFIX = "rate:"


class RateLimiter:
    """Fixed-window limiter — simple and free of the GCRA-style traps."""

    def __init__(self, *, bucket: str, limit: int, window_seconds: int) -> None:
        if limit <= 0 or window_seconds <= 0:
            raise ValueError("limit and window_seconds must be positive")
        self.bucket = bucket
        self.limit = limit
        self.window_seconds = window_seconds

    def _redis_key(self, identifier: str, *, now_epoch: int) -> str:
        window_start = now_epoch - (now_epoch % self.window_seconds)
        return f"{_KEY_PREFIX}{self.bucket}:{identifier}:{window_start}"

    async def check(self, identifier: str) -> tuple[bool, int, int]:
        """Record a request. Returns `(allowed, current_count, retry_after_sec)`.

        `retry_after_sec` is the remaining time in the current window when
        the limit is hit (0 when allowed). Set on the Retry-After header.
        """
        now = int(time.time())
        key = self._redis_key(identifier, now_epoch=now)
        redis = get_redis_client()
        count = await redis.incr(key)
        if count == 1:
            # Only set TTL on the first hit — subsequent INCRs preserve it.
            await redis.expire(key, self.window_seconds)

        if count <= self.limit:
            return True, count, 0

        # Remaining seconds until this window closes.
        retry_after = self.window_seconds - (now % self.window_seconds)
        return False, count, max(retry_after, 1)

    def as_ip_dependency(self) -> Callable:
        """FastAPI dependency that throttles by client IP. Raises 429 when
        the limit is exceeded — the exception handler carries the bucket
        into the log entry so ops can tell buckets apart."""

        async def _dep(request: Request) -> None:
            ip = _client_ip(request) or "unknown"
            allowed, count, retry_after = await self.check(f"ip:{ip}")
            if not allowed:
                logger.warning(
                    "rate_limit_exceeded",
                    bucket=self.bucket,
                    ip=ip,
                    count=count,
                    limit=self.limit,
                    retry_after=retry_after,
                )
                # Stash retry_after on the error so middleware can echo
                # Retry-After. (SecureSyncError doesn't carry arbitrary data
                # yet — keep it simple: include in the message.)
                raise RateLimitError(
                    f"too many requests, retry in {retry_after}s"
                )

        return _dep


def _client_ip(request: Request) -> str | None:
    """Pull the real client IP from X-Forwarded-For when behind Nginx,
    otherwise fall back to the direct socket peer."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        # XFF is a comma-separated chain — first entry is the original client.
        return xff.split(",", 1)[0].strip()
    client = request.client
    return client.host if client else None


# Pre-built limiters for the endpoints that matter right now. Extend here
# as we lock down more surfaces.
LOGIN_LIMITER = RateLimiter(
    bucket="login",
    limit=5,           # 5 attempts
    window_seconds=60, # per 1 minute per IP
)


__all__ = ["LOGIN_LIMITER", "RateLimiter"]
