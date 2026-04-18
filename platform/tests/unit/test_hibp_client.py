"""Tests for the HIBP client — rate limiting is the headline behaviour."""

from __future__ import annotations

import time

import httpx
import pytest
import respx

from app.core.exceptions import ExternalServiceError
from app.integrations.hibp import HIBPClient


@pytest.mark.asyncio
class TestBreachedAccount:
    async def test_parses_breach_list(self) -> None:
        async with HIBPClient(
            api_key="k",
            base_url="https://hibp.test/api/v3",
            min_interval_seconds=0.0,       # disable pacing for this assertion
        ) as hibp, respx.mock(base_url="https://hibp.test/api/v3") as mock:
            mock.get("/breachedaccount/alice%40example.com").mock(
                return_value=httpx.Response(
                    200,
                    json=[
                        {
                            "Name": "LinkedIn",
                            "Title": "LinkedIn",
                            "BreachDate": "2012-05-05",
                            "AddedDate": "2016-05-21T00:00:00Z",
                            "Description": "In May 2012...",
                            "DataClasses": ["Email addresses", "Passwords"],
                            "IsVerified": True,
                            "IsSensitive": False,
                        }
                    ],
                )
            )

            breaches = await hibp.breached_account("alice@example.com")
            assert len(breaches) == 1
            assert breaches[0].name == "LinkedIn"
            assert "Passwords" in breaches[0].data_classes

    async def test_404_means_no_breaches(self) -> None:
        async with HIBPClient(
            api_key="k",
            base_url="https://hibp.test/api/v3",
            min_interval_seconds=0.0,
        ) as hibp, respx.mock(base_url="https://hibp.test/api/v3") as mock:
            mock.get("/breachedaccount/clean%40example.com").mock(
                return_value=httpx.Response(404, text="")
            )
            breaches = await hibp.breached_account("clean@example.com")
            assert breaches == []

    async def test_429_raises(self) -> None:
        async with HIBPClient(
            api_key="k",
            base_url="https://hibp.test/api/v3",
            min_interval_seconds=0.0,
        ) as hibp, respx.mock(base_url="https://hibp.test/api/v3") as mock:
            mock.get("/breachedaccount/x%40example.com").mock(
                return_value=httpx.Response(429, text="rate limited")
            )
            with pytest.raises(ExternalServiceError):
                await hibp.breached_account("x@example.com")

    async def test_sends_required_headers(self) -> None:
        async with HIBPClient(
            api_key="secret-key",
            base_url="https://hibp.test/api/v3",
            min_interval_seconds=0.0,
        ) as hibp, respx.mock(base_url="https://hibp.test/api/v3") as mock:
            route = mock.get("/breachedaccount/a%40example.com").mock(
                return_value=httpx.Response(404)
            )
            await hibp.breached_account("a@example.com")

            headers = route.calls.last.request.headers
            assert headers["hibp-api-key"] == "secret-key"
            # HIBP requires a non-empty User-Agent.
            assert headers.get("User-Agent", "").strip() != ""


@pytest.mark.asyncio
class TestRateLimiter:
    async def test_second_call_waits_at_least_min_interval(self) -> None:
        """Back-to-back calls to breached_account must be paced."""
        interval = 0.3   # 300ms — fast enough for tests, long enough to measure

        async with HIBPClient(
            api_key="k",
            base_url="https://hibp.test/api/v3",
            min_interval_seconds=interval,
        ) as hibp, respx.mock(base_url="https://hibp.test/api/v3") as mock:
            mock.get("/breachedaccount/a%40example.com").mock(
                return_value=httpx.Response(404)
            )
            mock.get("/breachedaccount/b%40example.com").mock(
                return_value=httpx.Response(404)
            )

            start = time.monotonic()
            await hibp.breached_account("a@example.com")
            await hibp.breached_account("b@example.com")
            elapsed = time.monotonic() - start

            # Two sequential calls should take at least one interval.
            assert elapsed >= interval * 0.9, (
                f"rate limiter did not pace calls: elapsed={elapsed:.3f}s"
            )

    async def test_bulk_serializes_lookups(self) -> None:
        interval = 0.2

        async with HIBPClient(
            api_key="k",
            base_url="https://hibp.test/api/v3",
            min_interval_seconds=interval,
        ) as hibp, respx.mock(base_url="https://hibp.test/api/v3") as mock:
            # All three get a 404 → empty breach lists.
            for addr in ("a@example.com", "b@example.com", "c@example.com"):
                mock.get(f"/breachedaccount/{addr.replace('@', '%40')}").mock(
                    return_value=httpx.Response(404)
                )

            start = time.monotonic()
            result = await hibp.breached_accounts_bulk(
                ["a@example.com", "b@example.com", "c@example.com"]
            )
            elapsed = time.monotonic() - start

            assert result == {
                "a@example.com": [],
                "b@example.com": [],
                "c@example.com": [],
            }
            # 3 calls → at least 2 intervals of wait.
            assert elapsed >= interval * 1.9


@pytest.mark.asyncio
async def test_missing_api_key_raises() -> None:
    with pytest.raises(ExternalServiceError):
        HIBPClient(api_key="", base_url="https://hibp.test/api/v3")
