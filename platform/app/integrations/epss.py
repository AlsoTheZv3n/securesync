"""FIRST.org EPSS (Exploit Prediction Scoring System) client.

EPSS adds a "probability of exploitation in the next 30 days" to each CVE —
it's how we prioritise beyond raw CVSS.

Caching: each CVE's score is cached in Redis for 24h. EPSS data is refreshed
daily upstream, so a shorter TTL just burns API calls. Bulk mode caps at 100
CVEs per request (EPSS API limit).

Reference: https://www.first.org/epss/api
"""

from __future__ import annotations

import json
from decimal import Decimal, InvalidOperation
from typing import Any

import httpx
import structlog
from redis.asyncio import Redis
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from app.core.config import get_settings
from app.core.exceptions import ExternalServiceError
from app.core.redis_client import get_redis_client

logger = structlog.get_logger()


BATCH_SIZE = 100                      # EPSS API cap
CACHE_TTL_SECONDS = 60 * 60 * 24      # 24h
_CACHE_PREFIX = "epss:"


class EPSSScore:
    """Narrow container for an EPSS score pair. Stored as JSON in the cache."""

    __slots__ = ("epss", "percentile")

    def __init__(self, epss: Decimal, percentile: Decimal) -> None:
        self.epss = epss
        self.percentile = percentile

    def as_dict(self) -> dict[str, str]:
        return {"epss": str(self.epss), "percentile": str(self.percentile)}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EPSSScore | None":
        try:
            return cls(Decimal(str(data["epss"])), Decimal(str(data["percentile"])))
        except (KeyError, InvalidOperation, ValueError):
            return None


_RETRYABLE = retry_if_exception_type((httpx.TransportError, httpx.TimeoutException))
_RETRY_POLICY = retry(
    reraise=True,
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=_RETRYABLE,
)


class EPSSClient:
    """Async EPSS client with Redis-backed per-CVE cache."""

    def __init__(
        self,
        *,
        base_url: str | None = None,
        timeout: float = 30.0,
        redis: Redis | None = None,
    ) -> None:
        s = get_settings()
        self.base_url = (base_url or s.EPSS_API_URL).rstrip("/")
        self._client = httpx.AsyncClient(base_url=self.base_url, timeout=timeout)
        self._redis: Redis = redis or get_redis_client()

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "EPSSClient":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()

    # ── Cache helpers ──
    @staticmethod
    def _cache_key(cve: str) -> str:
        return f"{_CACHE_PREFIX}{cve}"

    async def _read_cache(self, cve_ids: list[str]) -> dict[str, EPSSScore]:
        if not cve_ids:
            return {}
        keys = [self._cache_key(c) for c in cve_ids]
        # mget returns a list parallel to keys, entries are either decoded
        # strings (decode_responses=True in our client) or None.
        raws = await self._redis.mget(*keys)
        out: dict[str, EPSSScore] = {}
        for cve, raw in zip(cve_ids, raws, strict=True):
            if raw is None:
                continue
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                continue
            score = EPSSScore.from_dict(payload)
            if score is not None:
                out[cve] = score
        return out

    async def _write_cache(self, scores: dict[str, EPSSScore]) -> None:
        if not scores:
            return
        pipe = self._redis.pipeline()
        for cve, score in scores.items():
            pipe.setex(
                self._cache_key(cve),
                CACHE_TTL_SECONDS,
                json.dumps(score.as_dict()),
            )
        await pipe.execute()

    # ── Upstream fetch ──
    @_RETRY_POLICY
    async def _fetch_batch(self, cve_ids: list[str]) -> dict[str, EPSSScore]:
        if not cve_ids:
            return {}
        resp = await self._client.get("/epss", params={"cve": ",".join(cve_ids)})
        if not resp.is_success:
            logger.warning(
                "epss_error", status=resp.status_code, body=resp.text[:400]
            )
            raise ExternalServiceError(
                f"EPSS API error ({resp.status_code}): {resp.text[:200]}"
            )
        data = resp.json().get("data") or []
        out: dict[str, EPSSScore] = {}
        for row in data:
            cve = row.get("cve")
            score = EPSSScore.from_dict(row)
            if cve and score is not None:
                out[cve] = score
        return out

    # ── Public API ──
    async def get_batch(self, cve_ids: list[str]) -> dict[str, EPSSScore]:
        """Return EPSS scores for every CVE that has one (cached or fresh).

        Unknown CVEs are simply absent from the result dict. Duplicates in
        the input are collapsed. Cache-hit CVEs don't hit the upstream.
        """
        # Walrus drops whitespace-only entries — an empty string in the
        # comma-joined URL param produced a `,CVE-...` that EPSS silently
        # rejects and broke dedup (CVE-2024-1 vs cve-2024-1 collapsed OK).
        unique = sorted({s for c in cve_ids if (s := c.strip().upper())})
        if not unique:
            return {}

        cached = await self._read_cache(unique)
        missing = [c for c in unique if c not in cached]

        fetched: dict[str, EPSSScore] = {}
        for start in range(0, len(missing), BATCH_SIZE):
            chunk = missing[start : start + BATCH_SIZE]
            try:
                batch = await self._fetch_batch(chunk)
            except (ExternalServiceError, httpx.TransportError, httpx.TimeoutException) as exc:
                # One bad batch shouldn't kill enrichment of the rest — log and
                # continue with whatever cache gave us. Transport/timeout errors
                # bubble up from tenacity's final retry.
                logger.warning("epss_batch_failed", cves=chunk, error=str(exc))
                continue
            fetched.update(batch)

        await self._write_cache(fetched)

        merged = dict(cached)
        merged.update(fetched)
        return merged


__all__ = ["BATCH_SIZE", "CACHE_TTL_SECONDS", "EPSSClient", "EPSSScore"]
