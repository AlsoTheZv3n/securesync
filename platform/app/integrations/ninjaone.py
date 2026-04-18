"""NinjaOne RMM integration.

We push one ticket per Critical/High finding into the MSP's NinjaOne tenant
so their technicians get the alert in their existing queue. OAuth 2.0
client-credentials, token cached in-process with refresh-before-expiry —
same pattern as `WazuhClient`.

Reference:
  - API reference: https://app.ninjarmm.com/apidocs/
  - OAuth flow:    https://ninjarmm.zendesk.com/hc/en-us/articles/12973871685517
"""

from __future__ import annotations

import time
from typing import Any

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
from app.models.enums import FindingSeverity

logger = structlog.get_logger()


# Our severity → NinjaOne priority (features.md §8.1).
_PRIORITY_MAP: dict[FindingSeverity, str] = {
    FindingSeverity.CRITICAL: "URGENT",
    FindingSeverity.HIGH: "HIGH",
    FindingSeverity.MEDIUM: "MEDIUM",
    FindingSeverity.LOW: "LOW",
    FindingSeverity.INFO: "NONE",
}

# Default OAuth scopes — read devices + open tickets.
DEFAULT_SCOPES = "monitoring management"


def severity_to_priority(severity: FindingSeverity) -> str:
    return _PRIORITY_MAP[severity]


_RETRYABLE = retry_if_exception_type((httpx.TransportError, httpx.TimeoutException))
_RETRY_POLICY = retry(
    reraise=True,
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=_RETRYABLE,
)


class NinjaOneClient:
    """Async NinjaOne API client with cached OAuth bearer token."""

    _TOKEN_REFRESH_MARGIN = 30.0  # refresh this many seconds before expiry

    def __init__(
        self,
        *,
        base_url: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        scopes: str = DEFAULT_SCOPES,
        timeout: float = 30.0,
    ) -> None:
        s = get_settings()
        self.base_url = (base_url or s.NINJAONE_API_URL).rstrip("/")
        self.client_id = client_id or s.NINJAONE_CLIENT_ID
        self.client_secret = client_secret or s.NINJAONE_CLIENT_SECRET
        self.scopes = scopes

        if not (self.client_id and self.client_secret):
            raise ExternalServiceError("NinjaOne OAuth credentials not configured")

        self._client = httpx.AsyncClient(base_url=self.base_url, timeout=timeout)
        self._token: str | None = None
        self._token_expires_at: float = 0.0

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "NinjaOneClient":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()

    # ── OAuth token ─────────────────────────────────────────
    async def _fetch_token(self) -> tuple[str, float]:
        resp = await self._client.post(
            "/ws/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": self.scopes,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if not resp.is_success:
            logger.warning(
                "ninjaone_oauth_failed",
                status=resp.status_code,
                body=resp.text[:400],
            )
            raise ExternalServiceError(
                f"NinjaOne OAuth failed ({resp.status_code}): {resp.text[:200]}"
            )
        body = resp.json()
        token = body.get("access_token")
        # NinjaOne's expires_in is seconds; default to 1h if missing.
        expires_in = int(body.get("expires_in", 3600))
        if not token:
            raise ExternalServiceError("NinjaOne OAuth returned no access_token")
        return token, expires_in

    async def _ensure_token(self) -> str:
        now = time.monotonic()
        if self._token and now < (self._token_expires_at - self._TOKEN_REFRESH_MARGIN):
            return self._token

        token, expires_in = await self._fetch_token()
        self._token = token
        self._token_expires_at = now + expires_in
        return token

    async def _request(
        self, method: str, path: str, **kwargs: Any
    ) -> httpx.Response:
        token = await self._ensure_token()
        headers = dict(kwargs.pop("headers", {}) or {})
        headers["Authorization"] = f"Bearer {token}"
        headers.setdefault("Accept", "application/json")
        return await self._client.request(method, path, headers=headers, **kwargs)

    @staticmethod
    def _check(response: httpx.Response, action: str) -> None:
        if response.is_success:
            return
        logger.warning(
            "ninjaone_error",
            action=action,
            status=response.status_code,
            body=response.text[:400],
        )
        raise ExternalServiceError(
            f"NinjaOne {action} failed ({response.status_code}): {response.text[:200]}"
        )

    # ── Devices ─────────────────────────────────────────────
    @_RETRY_POLICY
    async def list_devices(self) -> list[dict[str, Any]]:
        resp = await self._request("GET", "/api/v2/devices")
        self._check(resp, "list_devices")
        data = resp.json()
        # Some versions return a bare list, others wrap in {"items": [...]}.
        if isinstance(data, list):
            return data
        return list(data.get("items") or [])

    # ── Tickets ─────────────────────────────────────────────
    @_RETRY_POLICY
    async def create_ticket(
        self,
        *,
        subject: str,
        description: str,
        priority: str,
        client_id: int | None = None,
        node_id: int | None = None,
    ) -> str:
        """Create a NinjaOne ticket and return its id as a string.

        `client_id` is the NinjaOne organization id (their "customer"). If
        the SecureSync tenant hasn't been mapped to one yet, we create a
        standalone ticket — still visible to the MSP technician.
        """
        payload: dict[str, Any] = {
            "subject": subject[:200],
            "description": description,
            "priority": priority,
        }
        if client_id is not None:
            payload["clientId"] = client_id
        if node_id is not None:
            payload["nodeId"] = node_id

        resp = await self._request(
            "POST",
            "/api/v2/ticketing/ticket",
            json=payload,
            headers={"Content-Type": "application/json"},
        )
        self._check(resp, "create_ticket")
        data = resp.json()
        # Different API versions use different field names.
        ticket_id = data.get("id") or data.get("ticketId")
        if ticket_id is None:
            raise ExternalServiceError(
                "NinjaOne created ticket but returned no id in the response"
            )
        return str(ticket_id)


__all__ = ["NinjaOneClient", "severity_to_priority"]
