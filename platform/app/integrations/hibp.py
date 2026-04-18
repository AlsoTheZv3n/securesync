"""HaveIBeenPwned v3 client.

HIBP enforces a strict rate limit (1 request per 1500 ms on the cheapest
tier). We serialize all requests through a single asyncio lock + monotonic
clock so concurrent callers can't accidentally DoS ourselves into getting
banned.

Reference: https://haveibeenpwned.com/API/v3
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx
import structlog
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from app.core.config import get_settings
from app.core.exceptions import ExternalServiceError

logger = structlog.get_logger()


HIBP_BASE_URL = "https://haveibeenpwned.com/api/v3"
# Free tier = 1 req / 1500 ms. Paid "Pwned 1" = 1 req / 500 ms. We default to
# the conservative free-tier cadence; callers can override for paid keys.
DEFAULT_MIN_INTERVAL_SECONDS = 1.6
# User-Agent is MANDATORY for HIBP — requests without it get 403'd.
DEFAULT_USER_AGENT = "SecureSync-by-NEXO-AI"


@dataclass(frozen=True)
class Breach:
    """Subset of HIBP Breach fields we care about."""
    name: str
    title: str
    breach_date: str      # YYYY-MM-DD
    added_date: str       # ISO 8601
    description: str
    data_classes: list[str]
    is_verified: bool
    is_sensitive: bool


def _parse_breach(obj: dict[str, Any]) -> Breach:
    return Breach(
        name=str(obj.get("Name", "")),
        title=str(obj.get("Title", obj.get("Name", ""))),
        breach_date=str(obj.get("BreachDate", "")),
        added_date=str(obj.get("AddedDate", "")),
        description=str(obj.get("Description", "")),
        data_classes=list(obj.get("DataClasses") or []),
        is_verified=bool(obj.get("IsVerified", False)),
        is_sensitive=bool(obj.get("IsSensitive", False)),
    )


# Retry only on transport/timeouts. 404 (= no breaches found) is NOT a failure,
# we translate it at the method level.
_RETRYABLE = retry_if_exception_type((httpx.TransportError, httpx.TimeoutException))
_RETRY_POLICY = retry(
    reraise=True,
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=_RETRYABLE,
)


class HIBPClient:
    """Async HIBP v3 client with a per-instance rate limiter."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str = HIBP_BASE_URL,
        min_interval_seconds: float = DEFAULT_MIN_INTERVAL_SECONDS,
        user_agent: str = DEFAULT_USER_AGENT,
        timeout: float = 15.0,
    ) -> None:
        s = get_settings()
        self.api_key = api_key or s.HIBP_API_KEY

        if not self.api_key:
            raise ExternalServiceError("HIBP_API_KEY not configured")

        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=timeout,
            headers={
                "hibp-api-key": self.api_key,
                "User-Agent": user_agent,
                "Accept": "application/json",
            },
        )
        self._min_interval = min_interval_seconds
        self._lock = asyncio.Lock()
        self._last_request_at: float = 0.0

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "HIBPClient":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()

    # ── Rate-limited request helper ──
    async def _rate_limited_get(self, path: str, **kwargs: Any) -> httpx.Response:
        """Serialize + pace GETs to respect HIBP's rate limit."""
        async with self._lock:
            elapsed = time.monotonic() - self._last_request_at
            wait = self._min_interval - elapsed
            if wait > 0:
                await asyncio.sleep(wait)
            response = await self._client.get(path, **kwargs)
            self._last_request_at = time.monotonic()
        return response

    # ── Endpoints ──
    @_RETRY_POLICY
    async def breached_account(self, email: str) -> list[Breach]:
        """Return all breaches containing `email`. Empty list if none.

        404 from HIBP means "not found in any breach" — we translate that to
        [] rather than raising.
        """
        path = f"/breachedaccount/{quote(email, safe='@')}"
        resp = await self._rate_limited_get(path, params={"truncateResponse": "false"})
        if resp.status_code == 404:
            return []
        if resp.status_code == 429:
            raise ExternalServiceError("HIBP rate limit exceeded (429)")
        if not resp.is_success:
            logger.warning("hibp_error", status=resp.status_code, body=resp.text[:200])
            raise ExternalServiceError(
                f"HIBP error ({resp.status_code}): {resp.text[:200]}"
            )
        return [_parse_breach(row) for row in resp.json()]

    async def breached_accounts_bulk(self, emails: list[str]) -> dict[str, list[Breach]]:
        """Convenience: check many emails serially, respecting rate limit."""
        out: dict[str, list[Breach]] = {}
        for email in emails:
            try:
                out[email] = await self.breached_account(email)
            except ExternalServiceError as exc:
                logger.warning("hibp_lookup_failed", email=email, error=str(exc))
                out[email] = []
        return out


__all__ = ["Breach", "DEFAULT_MIN_INTERVAL_SECONDS", "HIBPClient", "HIBP_BASE_URL"]
