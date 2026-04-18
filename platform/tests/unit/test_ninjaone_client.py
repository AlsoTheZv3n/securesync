"""HTTP-level tests for the NinjaOne RMM client."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from app.core.exceptions import ExternalServiceError
from app.integrations.ninjaone import (
    NinjaOneClient,
    severity_to_priority,
)
from app.models.enums import FindingSeverity


def _client() -> NinjaOneClient:
    return NinjaOneClient(
        base_url="https://ninja.test",
        client_id="cid",
        client_secret="csec",
    )


# ── Priority mapping ────────────────────────────────────────
class TestPriorityMapping:
    @pytest.mark.parametrize(
        "sev,expected",
        [
            (FindingSeverity.CRITICAL, "URGENT"),
            (FindingSeverity.HIGH, "HIGH"),
            (FindingSeverity.MEDIUM, "MEDIUM"),
            (FindingSeverity.LOW, "LOW"),
            (FindingSeverity.INFO, "NONE"),
        ],
    )
    def test_all_severities_mapped(
        self, sev: FindingSeverity, expected: str
    ) -> None:
        assert severity_to_priority(sev) == expected


# ── OAuth ───────────────────────────────────────────────────
@pytest.mark.asyncio
class TestOAuth:
    async def test_token_fetched_on_first_call(self) -> None:
        async with _client() as nj, respx.mock(base_url="https://ninja.test") as mock:
            oauth = mock.post("/ws/oauth/token").mock(
                return_value=httpx.Response(
                    200, json={"access_token": "tok-1", "expires_in": 3600}
                )
            )
            mock.get("/api/v2/devices").mock(
                return_value=httpx.Response(200, json=[])
            )
            await nj.list_devices()

            assert oauth.call_count == 1
            # client_credentials grant uses form-encoded body.
            body = oauth.calls.last.request.content.decode()
            assert "grant_type=client_credentials" in body
            assert "client_id=cid" in body
            assert "client_secret=csec" in body

    async def test_token_cached_across_calls(self) -> None:
        async with _client() as nj, respx.mock(base_url="https://ninja.test") as mock:
            oauth = mock.post("/ws/oauth/token").mock(
                return_value=httpx.Response(
                    200, json={"access_token": "tok-reuse", "expires_in": 3600}
                )
            )
            mock.get("/api/v2/devices").mock(
                return_value=httpx.Response(200, json=[])
            )

            await nj.list_devices()
            await nj.list_devices()
            await nj.list_devices()

            assert oauth.call_count == 1   # subsequent calls reuse the token

    async def test_auth_failure_raises(self) -> None:
        async with _client() as nj, respx.mock(base_url="https://ninja.test") as mock:
            mock.post("/ws/oauth/token").mock(
                return_value=httpx.Response(401, text="bad creds")
            )
            with pytest.raises(ExternalServiceError):
                await nj.list_devices()

    async def test_missing_credentials_raises(self) -> None:
        with pytest.raises(ExternalServiceError):
            NinjaOneClient(base_url="https://x", client_id="", client_secret="y")
        with pytest.raises(ExternalServiceError):
            NinjaOneClient(base_url="https://x", client_id="x", client_secret="")


# ── Devices ─────────────────────────────────────────────────
@pytest.mark.asyncio
class TestListDevices:
    async def test_bare_list_response(self) -> None:
        async with _client() as nj, respx.mock(base_url="https://ninja.test") as mock:
            mock.post("/ws/oauth/token").mock(
                return_value=httpx.Response(
                    200, json={"access_token": "t", "expires_in": 3600}
                )
            )
            mock.get("/api/v2/devices").mock(
                return_value=httpx.Response(
                    200, json=[{"id": 1, "systemName": "host-1"}, {"id": 2}]
                )
            )
            devices = await nj.list_devices()

            assert [d["id"] for d in devices] == [1, 2]

    async def test_wrapped_items_response(self) -> None:
        async with _client() as nj, respx.mock(base_url="https://ninja.test") as mock:
            mock.post("/ws/oauth/token").mock(
                return_value=httpx.Response(
                    200, json={"access_token": "t", "expires_in": 3600}
                )
            )
            mock.get("/api/v2/devices").mock(
                return_value=httpx.Response(200, json={"items": [{"id": 5}]})
            )
            devices = await nj.list_devices()
            assert devices == [{"id": 5}]


# ── Tickets ─────────────────────────────────────────────────
@pytest.mark.asyncio
class TestCreateTicket:
    async def test_happy_path_returns_ticket_id(self) -> None:
        async with _client() as nj, respx.mock(base_url="https://ninja.test") as mock:
            mock.post("/ws/oauth/token").mock(
                return_value=httpx.Response(
                    200, json={"access_token": "t", "expires_in": 3600}
                )
            )
            create = mock.post("/api/v2/ticketing/ticket").mock(
                return_value=httpx.Response(201, json={"id": 12345, "status": "NEW"})
            )
            ticket_id = await nj.create_ticket(
                subject="Critical finding", description="body", priority="URGENT"
            )

            assert ticket_id == "12345"
            body = json.loads(create.calls.last.request.content.decode())
            assert body["subject"] == "Critical finding"
            assert body["priority"] == "URGENT"
            assert "clientId" not in body   # optional
            assert "nodeId" not in body

    async def test_includes_client_and_node_when_provided(self) -> None:
        async with _client() as nj, respx.mock(base_url="https://ninja.test") as mock:
            mock.post("/ws/oauth/token").mock(
                return_value=httpx.Response(
                    200, json={"access_token": "t", "expires_in": 3600}
                )
            )
            create = mock.post("/api/v2/ticketing/ticket").mock(
                return_value=httpx.Response(201, json={"ticketId": "abc-999"})
            )
            await nj.create_ticket(
                subject="x",
                description="y",
                priority="HIGH",
                client_id=42,
                node_id=7,
            )
            body = json.loads(create.calls.last.request.content.decode())
            assert body["clientId"] == 42
            assert body["nodeId"] == 7

    async def test_missing_id_in_response_raises(self) -> None:
        async with _client() as nj, respx.mock(base_url="https://ninja.test") as mock:
            mock.post("/ws/oauth/token").mock(
                return_value=httpx.Response(
                    200, json={"access_token": "t", "expires_in": 3600}
                )
            )
            mock.post("/api/v2/ticketing/ticket").mock(
                return_value=httpx.Response(201, json={"status": "NEW"})
            )
            with pytest.raises(ExternalServiceError):
                await nj.create_ticket(subject="x", description="y", priority="HIGH")

    async def test_subject_truncated_to_200_chars(self) -> None:
        async with _client() as nj, respx.mock(base_url="https://ninja.test") as mock:
            mock.post("/ws/oauth/token").mock(
                return_value=httpx.Response(
                    200, json={"access_token": "t", "expires_in": 3600}
                )
            )
            create = mock.post("/api/v2/ticketing/ticket").mock(
                return_value=httpx.Response(201, json={"id": 1})
            )
            long_subject = "X" * 500
            await nj.create_ticket(
                subject=long_subject, description="y", priority="HIGH"
            )
            body = json.loads(create.calls.last.request.content.decode())
            assert len(body["subject"]) == 200
