"""Tests for the EPSS client — cache-behaviour is the whole point.

Uses `respx` to mock the EPSS API and real Redis (docker-compose dev stack)
for the cache layer. Each test flushes the cache first so prior runs can't
leak state.
"""

from __future__ import annotations

from decimal import Decimal

import httpx
import pytest
import respx

from app.core.exceptions import ExternalServiceError
from app.integrations.epss import BATCH_SIZE, EPSSClient, EPSSScore
from app.core.redis_client import get_redis_client


@pytest.fixture(autouse=True)
async def _flush_cache() -> None:
    """Wipe every `epss:*` key before each test to avoid cross-run pollution."""
    redis = get_redis_client()
    try:
        keys = await redis.keys("epss:*")
        if keys:
            await redis.delete(*keys)
    except Exception:
        # Redis not reachable in this test run — skip cleanup; tests that
        # hit Redis will fail loudly anyway.
        pass


def _ok_response(rows: list[dict]) -> httpx.Response:
    return httpx.Response(200, json={"status": "OK", "data": rows})


@pytest.mark.asyncio
class TestEPSSBatch:
    async def test_empty_input_returns_empty(self) -> None:
        async with EPSSClient(base_url="https://epss.test") as client:
            out = await client.get_batch([])
        assert out == {}

    async def test_fetch_writes_cache(self) -> None:
        async with EPSSClient(base_url="https://epss.test") as client, \
                respx.mock(base_url="https://epss.test") as mock:
            route = mock.get("/epss").mock(
                return_value=_ok_response(
                    [{"cve": "CVE-2024-1", "epss": "0.12345", "percentile": "0.6789"}]
                )
            )
            out = await client.get_batch(["CVE-2024-1"])

            assert route.call_count == 1
            assert "CVE-2024-1" in out
            assert out["CVE-2024-1"].epss == Decimal("0.12345")
            assert out["CVE-2024-1"].percentile == Decimal("0.6789")

        # Second call should hit cache — NO more HTTP. `assert_all_called=False`
        # because we're testing that the route is NOT hit.
        async with EPSSClient(base_url="https://epss.test") as client, \
                respx.mock(base_url="https://epss.test", assert_all_called=False) as mock:
            route = mock.get("/epss").mock(return_value=_ok_response([]))
            out2 = await client.get_batch(["CVE-2024-1"])
            assert route.call_count == 0
            assert out2["CVE-2024-1"].epss == Decimal("0.12345")

    async def test_partial_cache_hit_fetches_only_missing(self) -> None:
        # Seed cache manually with one CVE.
        async with EPSSClient(base_url="https://epss.test") as client, \
                respx.mock(base_url="https://epss.test") as mock:
            mock.get("/epss").mock(
                return_value=_ok_response(
                    [{"cve": "CVE-2024-A", "epss": "0.1", "percentile": "0.2"}]
                )
            )
            await client.get_batch(["CVE-2024-A"])

        # Now ask for A + B; only B should hit upstream.
        async with EPSSClient(base_url="https://epss.test") as client, \
                respx.mock(base_url="https://epss.test") as mock:
            route = mock.get("/epss").mock(
                return_value=_ok_response(
                    [{"cve": "CVE-2024-B", "epss": "0.3", "percentile": "0.4"}]
                )
            )
            out = await client.get_batch(["CVE-2024-A", "CVE-2024-B"])

            assert route.call_count == 1
            sent = route.calls.last.request.url.params["cve"]
            assert sent == "CVE-2024-B"
            assert out["CVE-2024-A"].epss == Decimal("0.1")
            assert out["CVE-2024-B"].epss == Decimal("0.3")

    async def test_unknown_cve_absent_from_result(self) -> None:
        async with EPSSClient(base_url="https://epss.test") as client, \
                respx.mock(base_url="https://epss.test") as mock:
            mock.get("/epss").mock(return_value=_ok_response([]))
            out = await client.get_batch(["CVE-9999-9999"])
            assert out == {}

    async def test_duplicate_and_empty_inputs_collapsed(self) -> None:
        async with EPSSClient(base_url="https://epss.test") as client, \
                respx.mock(base_url="https://epss.test") as mock:
            route = mock.get("/epss").mock(
                return_value=_ok_response(
                    [{"cve": "CVE-2024-1", "epss": "0.5", "percentile": "0.9"}]
                )
            )
            await client.get_batch(["CVE-2024-1", "cve-2024-1", "", "  "])
            sent = route.calls.last.request.url.params["cve"]
            assert sent == "CVE-2024-1"

    async def test_batches_over_100(self) -> None:
        cves = [f"CVE-2024-{i:04d}" for i in range(BATCH_SIZE + 50)]

        async with EPSSClient(base_url="https://epss.test") as client, \
                respx.mock(base_url="https://epss.test") as mock:
            route = mock.get("/epss").mock(return_value=_ok_response([]))
            await client.get_batch(cves)
            # 100 + 50 → 2 requests.
            assert route.call_count == 2

    async def test_upstream_error_swallowed_for_partial_batch(self) -> None:
        """A batch returning 5xx must not kill already-cached results."""
        async with EPSSClient(base_url="https://epss.test") as client, \
                respx.mock(base_url="https://epss.test") as mock:
            mock.get("/epss").mock(return_value=httpx.Response(500, text="boom"))
            # Should not raise — returns whatever we had (empty cache).
            out = await client.get_batch(["CVE-2024-X"])
            assert out == {}


class TestEPSSScoreParsing:
    """Pure sync tests — no asyncio marker."""

    def test_valid_score(self) -> None:
        score = EPSSScore.from_dict({"epss": "0.12", "percentile": "0.8"})
        assert score is not None
        assert score.epss == Decimal("0.12")

    def test_missing_keys_return_none(self) -> None:
        assert EPSSScore.from_dict({}) is None
        assert EPSSScore.from_dict({"epss": "0.1"}) is None

    def test_invalid_numeric_returns_none(self) -> None:
        assert EPSSScore.from_dict({"epss": "nope", "percentile": "0.1"}) is None


@pytest.mark.asyncio
async def test_transport_error_swallowed_by_get_batch() -> None:
    """Tenacity retries TransportError 3×, then reraises. get_batch catches
    that so a flaky EPSS endpoint never fails the scan pipeline."""
    async with EPSSClient(base_url="https://epss.test") as client, \
            respx.mock(base_url="https://epss.test") as mock:
        mock.get("/epss").mock(side_effect=httpx.TransportError("network"))
        result = await client.get_batch(["CVE-2024-1"])
        assert result == {}
