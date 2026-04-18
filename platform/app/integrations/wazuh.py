"""Wazuh Manager REST API integration.

Agents report software inventory + vulnerabilities continuously to the Wazuh
Manager; we poll the Manager's REST API (port 55000) rather than talking to
agents directly.

Auth pattern: HTTP Basic → JWT token (15 min default TTL) → Bearer header for
all subsequent calls. We cache the token in-process and refresh when it's
within 30s of expiring.

Reference:
  - API reference: https://documentation.wazuh.com/current/user-manual/api/reference.html
  - Vuln detection: https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/
"""

from __future__ import annotations

import re
import time
from decimal import Decimal, InvalidOperation
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
from app.models.enums import FindingSeverity, FindingSource
from app.services.normalizer import NormalizedFinding

logger = structlog.get_logger()


# Wazuh severity strings → our enum.
_SEVERITY_MAP: dict[str, FindingSeverity] = {
    "critical": FindingSeverity.CRITICAL,
    "high": FindingSeverity.HIGH,
    "medium": FindingSeverity.MEDIUM,
    "low": FindingSeverity.LOW,
    "none": FindingSeverity.INFO,
    "untriaged": FindingSeverity.INFO,
}

# Group names must be filesystem-safe on the Wazuh Manager host.
_GROUP_NAME_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,126}[a-z0-9])?$")


def tenant_group_name(tenant_slug: str) -> str:
    """Derive the Wazuh agent group name from a tenant slug."""
    name = f"ss-{tenant_slug}"
    if not _GROUP_NAME_PATTERN.match(name):
        raise ValueError(f"invalid derived Wazuh group name: {name!r}")
    return name


def _decimal_or_none(raw: Any) -> Decimal | None:
    if raw is None:
        return None
    text = str(raw).strip()
    if not text or text.lower() in {"none", "null", "nan"}:
        return None
    try:
        return Decimal(text)
    except (InvalidOperation, ValueError):
        return None


def _vuln_to_finding(
    vuln: dict[str, Any], *, agent_id: str, asset_value: str
) -> NormalizedFinding | None:
    """Map one Wazuh vulnerability row to a NormalizedFinding."""
    cve = vuln.get("cve")
    pkg_name = vuln.get("name") or "unknown-package"
    pkg_version = vuln.get("version") or "?"
    title = vuln.get("title") or f"{pkg_name} {pkg_version} vulnerable ({cve or 'no CVE'})"

    severity_raw = str(vuln.get("severity", "none")).lower().strip()
    severity = _SEVERITY_MAP.get(severity_raw, FindingSeverity.INFO)

    # Wazuh exposes cvss3_score primarily; fall back to cvss2_score.
    cvss = _decimal_or_none(vuln.get("cvss3_score")) or _decimal_or_none(vuln.get("cvss2_score"))

    description = vuln.get("condition") or vuln.get("title")
    references = vuln.get("external_references")
    if isinstance(references, list) and references:
        description = (description or "") + "\n\nReferences:\n" + "\n".join(str(r) for r in references)

    evidence = (
        f"Package: {pkg_name} {pkg_version}\n"
        f"Agent: {agent_id}\n"
        f"Detection: {vuln.get('detection_time', 'unknown')}\n"
        f"Status: {vuln.get('status', 'unknown')}"
    )

    try:
        return NormalizedFinding(
            title=title[:512],
            severity=severity,
            source=FindingSource.WAZUH,
            asset_value=asset_value[:255],
            cve_id=cve,
            description=description,
            evidence=evidence,
            cvss_score=cvss,
            raw_data=vuln,
        )
    except ValueError as exc:
        logger.warning("wazuh_vuln_skipped", cve=cve, reason=str(exc))
        return None


def parse_vulnerabilities(
    response_body: dict[str, Any], *, agent_id: str, asset_value: str | None = None
) -> list[NormalizedFinding]:
    """Pure function: Wazuh vulnerability endpoint JSON → NormalizedFindings."""
    data = response_body.get("data") or {}
    items = data.get("affected_items") or []
    out: list[NormalizedFinding] = []
    for vuln in items:
        finding = _vuln_to_finding(
            vuln, agent_id=agent_id, asset_value=asset_value or agent_id
        )
        if finding is not None:
            out.append(finding)
    return out


_RETRYABLE = retry_if_exception_type((httpx.TransportError, httpx.TimeoutException))
_RETRY_POLICY = retry(
    reraise=True,
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=_RETRYABLE,
)


class WazuhClient:
    """Async Wazuh Manager REST client.

    Not thread-safe: the token cache is per-instance. Create a fresh client
    per async context to avoid stale-token issues across processes.
    """

    # Refresh token this many seconds before its declared expiry.
    _TOKEN_REFRESH_MARGIN = 30.0

    def __init__(
        self,
        *,
        base_url: str | None = None,
        username: str | None = None,
        password: str | None = None,
        verify_ssl: bool | None = None,
        timeout: float = 30.0,
        token_ttl_seconds: int = 900,
    ) -> None:
        s = get_settings()
        self.base_url = (base_url or s.WAZUH_API_URL or "").rstrip("/")
        self.username = username or s.WAZUH_USERNAME
        self.password = password or s.WAZUH_PASSWORD
        verify = s.WAZUH_VERIFY_SSL if verify_ssl is None else verify_ssl

        if not self.base_url:
            raise ExternalServiceError("WAZUH_API_URL not configured")
        if not (self.username and self.password):
            raise ExternalServiceError("Wazuh credentials not configured")

        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=timeout,
            verify=verify,
        )
        self._token: str | None = None
        self._token_expires_at: float = 0.0
        self._token_ttl = token_ttl_seconds

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "WazuhClient":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()

    # ── Auth ──
    async def _ensure_token(self) -> str:
        now = time.monotonic()
        if self._token and now < (self._token_expires_at - self._TOKEN_REFRESH_MARGIN):
            return self._token

        resp = await self._client.post(
            "/security/user/authenticate",
            auth=(self.username or "", self.password or ""),
        )
        if not resp.is_success:
            raise ExternalServiceError(
                f"Wazuh auth failed ({resp.status_code}): {resp.text[:200]}"
            )
        token = (resp.json().get("data") or {}).get("token")
        if not token:
            raise ExternalServiceError("Wazuh auth returned no token")

        self._token = token
        self._token_expires_at = now + self._token_ttl
        return token

    async def _request(
        self, method: str, path: str, **kwargs: Any
    ) -> httpx.Response:
        token = await self._ensure_token()
        headers = dict(kwargs.pop("headers", {}) or {})
        headers["Authorization"] = f"Bearer {token}"
        return await self._client.request(method, path, headers=headers, **kwargs)

    @staticmethod
    def _check(response: httpx.Response, action: str) -> None:
        if response.is_success:
            return
        logger.warning(
            "wazuh_error",
            action=action,
            status=response.status_code,
            body=response.text[:400],
        )
        raise ExternalServiceError(
            f"Wazuh {action} failed ({response.status_code}): {response.text[:200]}"
        )

    # ── Agents & groups ──
    @_RETRY_POLICY
    async def list_agents(self, *, group: str | None = None) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"limit": 500}
        if group:
            params["group"] = group
        resp = await self._request("GET", "/agents", params=params)
        self._check(resp, "list_agents")
        data = resp.json().get("data") or {}
        return list(data.get("affected_items") or [])

    @_RETRY_POLICY
    async def create_agent_group(self, group_name: str) -> None:
        """Idempotent: returns silently if the group already exists."""
        if not _GROUP_NAME_PATTERN.match(group_name):
            raise ValueError(f"invalid Wazuh group name: {group_name!r}")
        resp = await self._request(
            "POST", "/agents/groups", json={"group_id": group_name}
        )
        # Wazuh returns 200 on success OR when the group already exists
        # (response body reports "already exists"); we accept both silently.
        if resp.status_code == 400 and "already exists" in resp.text.lower():
            return
        self._check(resp, "create_agent_group")

    # ── Vulnerabilities ──
    @_RETRY_POLICY
    async def get_vulnerabilities(self, agent_id: str) -> dict[str, Any]:
        resp = await self._request("GET", f"/vulnerability/{agent_id}")
        self._check(resp, "get_vulnerabilities")
        return resp.json()

    # ── Public async API (scanner protocol) ──
    async def scan(self, target: str) -> list[NormalizedFinding]:
        """Fetch vulnerabilities for the given agent id and return normalized findings.

        `target` is the Wazuh agent id (stored on Asset.value for INTERNAL_ENDPOINT
        or on Asset.wazuh_agent_id). Short alphanumeric, validated by the schema.
        """
        agent_id = target.strip()
        if not agent_id:
            raise ExternalServiceError("Wazuh scan requires an agent id")

        logger.info("wazuh_scan_start", agent_id=agent_id)
        body = await self.get_vulnerabilities(agent_id)
        findings = parse_vulnerabilities(body, agent_id=agent_id, asset_value=agent_id)
        logger.info("wazuh_scan_done", agent_id=agent_id, count=len(findings))
        return findings


__all__ = [
    "WazuhClient",
    "parse_vulnerabilities",
    "tenant_group_name",
]
