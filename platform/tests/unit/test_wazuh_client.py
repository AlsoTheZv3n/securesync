"""HTTP-level tests for the Wazuh REST client.

Traffic is intercepted by `respx`. No real Wazuh Manager needed.
See docs/mocks.md for swap instructions.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from app.core.exceptions import ExternalServiceError
from app.integrations.wazuh import WazuhClient


def _client() -> WazuhClient:
    return WazuhClient(
        base_url="https://wazuh.test:55000",
        username="wazuh-wui",
        password="s3cret",
        verify_ssl=False,
    )


@pytest.mark.asyncio
class TestWazuhAuth:
    async def test_token_is_fetched_on_first_call(self) -> None:
        async with _client() as w, respx.mock(base_url="https://wazuh.test:55000") as mock:
            auth_route = mock.post("/security/user/authenticate").mock(
                return_value=httpx.Response(200, json={"data": {"token": "jwt-AAA"}})
            )
            list_route = mock.get("/agents").mock(
                return_value=httpx.Response(200, json={"data": {"affected_items": []}})
            )

            await w.list_agents()

            assert auth_route.call_count == 1
            assert list_route.call_count == 1
            assert (
                list_route.calls.last.request.headers["Authorization"]
                == "Bearer jwt-AAA"
            )

    async def test_token_is_cached_across_calls(self) -> None:
        async with _client() as w, respx.mock(base_url="https://wazuh.test:55000") as mock:
            auth_route = mock.post("/security/user/authenticate").mock(
                return_value=httpx.Response(200, json={"data": {"token": "jwt-BBB"}})
            )
            mock.get("/agents").mock(
                return_value=httpx.Response(200, json={"data": {"affected_items": []}})
            )

            await w.list_agents()
            await w.list_agents()
            await w.list_agents()

            # Single auth round-trip; subsequent /agents calls reuse the token.
            assert auth_route.call_count == 1

    async def test_auth_failure_raises_external(self) -> None:
        async with _client() as w, respx.mock(base_url="https://wazuh.test:55000") as mock:
            mock.post("/security/user/authenticate").mock(
                return_value=httpx.Response(401, text="unauthorized")
            )
            with pytest.raises(ExternalServiceError):
                await w.list_agents()


@pytest.mark.asyncio
class TestAgentOperations:
    async def test_list_agents_passes_group_filter(self) -> None:
        async with _client() as w, respx.mock(base_url="https://wazuh.test:55000") as mock:
            mock.post("/security/user/authenticate").mock(
                return_value=httpx.Response(200, json={"data": {"token": "jwt"}})
            )
            route = mock.get("/agents").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "data": {
                            "affected_items": [
                                {"id": "001", "name": "host-1"},
                                {"id": "002", "name": "host-2"},
                            ]
                        }
                    },
                )
            )

            agents = await w.list_agents(group="ss-acme")

            assert len(agents) == 2
            params = dict(route.calls.last.request.url.params)
            assert params["group"] == "ss-acme"
            assert params["limit"] == "500"

    async def test_create_agent_group_posts_name(self) -> None:
        async with _client() as w, respx.mock(base_url="https://wazuh.test:55000") as mock:
            mock.post("/security/user/authenticate").mock(
                return_value=httpx.Response(200, json={"data": {"token": "jwt"}})
            )
            route = mock.post("/agents/groups").mock(
                return_value=httpx.Response(200, json={"message": "ok"})
            )

            await w.create_agent_group("ss-acme")

            assert route.called
            import json
            body = json.loads(route.calls.last.request.content.decode())
            assert body == {"group_id": "ss-acme"}

    async def test_create_agent_group_tolerates_already_exists(self) -> None:
        async with _client() as w, respx.mock(base_url="https://wazuh.test:55000") as mock:
            mock.post("/security/user/authenticate").mock(
                return_value=httpx.Response(200, json={"data": {"token": "jwt"}})
            )
            mock.post("/agents/groups").mock(
                return_value=httpx.Response(
                    400, json={"detail": "A group with this name already exists"}
                )
            )
            # Should NOT raise — idempotent semantics for onboarding retries.
            await w.create_agent_group("ss-acme")

    async def test_create_agent_group_rejects_bad_name(self) -> None:
        async with _client() as w:
            with pytest.raises(ValueError):
                await w.create_agent_group("has spaces")


@pytest.mark.asyncio
class TestVulnerabilityFetch:
    async def test_scan_pipes_through_parser(self) -> None:
        async with _client() as w, respx.mock(base_url="https://wazuh.test:55000") as mock:
            mock.post("/security/user/authenticate").mock(
                return_value=httpx.Response(200, json={"data": {"token": "jwt"}})
            )
            mock.get("/vulnerability/001").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "data": {
                            "affected_items": [
                                {
                                    "cve": "CVE-2024-1",
                                    "name": "p",
                                    "version": "1",
                                    "severity": "Medium",
                                    "cvss3_score": "5.5",
                                }
                            ]
                        }
                    },
                )
            )

            findings = await w.scan("001")

            assert len(findings) == 1
            assert findings[0].cve_id == "CVE-2024-1"

    async def test_missing_config_raises(self) -> None:
        with pytest.raises(ExternalServiceError):
            WazuhClient(base_url="", username="x", password="y")
        with pytest.raises(ExternalServiceError):
            WazuhClient(base_url="https://x", username="", password="y")
