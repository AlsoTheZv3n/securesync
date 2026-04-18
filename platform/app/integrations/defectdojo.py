"""DefectDojo integration — aggregator + dedup engine.

DefectDojo holds the canonical deduplicated finding set across all scanners
for a given product (= tenant). Our flow:

    Tenant created  → DefectDojo product created
    Scan completes  → DefectDojo engagement created
                    → findings uploaded via "Generic Findings Import"
                    → ScanJob.defectdojo_engagement_id stored

We ship NormalizedFindings — converted to DefectDojo's Generic Findings JSON
schema — rather than raw scanner output. This keeps one upload path across
all scanners instead of scanner-specific XML/JSON handling.

Reference:
  - API:           https://demo.defectdojo.org/api/v2/doc/
  - Generic JSON:  https://docs.defectdojo.com/integrations/parsers/file/generic/
"""

from __future__ import annotations

import json
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
from app.services.normalizer import NormalizedFinding

logger = structlog.get_logger()


# DefectDojo's severity strings for Generic Findings Import.
_SEVERITY_TO_DEFECTDOJO: dict[FindingSeverity, str] = {
    FindingSeverity.CRITICAL: "Critical",
    FindingSeverity.HIGH: "High",
    FindingSeverity.MEDIUM: "Medium",
    FindingSeverity.LOW: "Low",
    FindingSeverity.INFO: "Info",
}

GENERIC_FINDINGS_IMPORT = "Generic Findings Import"


def build_generic_findings_payload(findings: list[NormalizedFinding]) -> dict[str, Any]:
    """Convert NormalizedFindings to DefectDojo Generic Findings Import JSON."""
    return {
        "findings": [
            {
                "title": f.title,
                "description": f.description or "",
                "severity": _SEVERITY_TO_DEFECTDOJO[f.severity],
                "mitigation": f.remediation or "",
                "references": "",
                "impact": f.evidence or "",
                "date": None,
                "cve": f.cve_id,
                "cvssv3_score": float(f.cvss_score) if f.cvss_score is not None else None,
                "url": f.asset_value,
                # Marking all findings active + not dup — DefectDojo itself
                # performs dedup once imported into the engagement.
                "active": True,
                "verified": False,
                "duplicate": False,
            }
            for f in findings
        ]
    }


_RETRYABLE = retry_if_exception_type((httpx.TransportError, httpx.TimeoutException))
_RETRY_POLICY = retry(
    reraise=True,
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=_RETRYABLE,
)


class DefectDojoClient:
    """Async DefectDojo v2 REST client — just the endpoints we need."""

    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        s = get_settings()
        self.base_url = (base_url or s.DEFECTDOJO_URL or "").rstrip("/")
        self.api_key = api_key or s.DEFECTDOJO_API_KEY

        if not self.base_url:
            raise ExternalServiceError("DEFECTDOJO_URL not configured")
        if not self.api_key:
            raise ExternalServiceError("DEFECTDOJO_API_KEY not configured")

        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={
                "Authorization": f"Token {self.api_key}",
                "Accept": "application/json",
            },
            timeout=timeout,
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "DefectDojoClient":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()

    # ── Error translation ──
    @staticmethod
    def _check(response: httpx.Response, action: str) -> None:
        if response.is_success:
            return
        logger.warning(
            "defectdojo_error",
            action=action,
            status=response.status_code,
            body=response.text[:400],
        )
        raise ExternalServiceError(
            f"DefectDojo {action} failed ({response.status_code}): {response.text[:200]}"
        )

    # ── Products ──
    @_RETRY_POLICY
    async def create_product(
        self, *, name: str, description: str = "", prod_type_id: int = 1
    ) -> int:
        """Create a DefectDojo product and return its id.

        `prod_type_id` defaults to 1, which is the stock "Research and
        Development" type. In production, create tenant-specific prod types
        first and pass their id in.
        """
        resp = await self._client.post(
            "/api/v2/products/",
            json={"name": name, "description": description or name, "prod_type": prod_type_id},
        )
        self._check(resp, "create_product")
        return int(resp.json()["id"])

    @_RETRY_POLICY
    async def get_product(self, product_id: int) -> dict[str, Any]:
        resp = await self._client.get(f"/api/v2/products/{product_id}/")
        self._check(resp, "get_product")
        return resp.json()

    # ── Engagements ──
    @_RETRY_POLICY
    async def create_engagement(
        self,
        *,
        product_id: int,
        name: str,
        target_start: str,
        target_end: str,
        status: str = "In Progress",
    ) -> int:
        """Create an engagement under a product — one per scan run."""
        resp = await self._client.post(
            "/api/v2/engagements/",
            json={
                "name": name,
                "product": product_id,
                "target_start": target_start,
                "target_end": target_end,
                "status": status,
                "engagement_type": "CI/CD",
            },
        )
        self._check(resp, "create_engagement")
        return int(resp.json()["id"])

    # ── Scan import ──
    @_RETRY_POLICY
    async def import_findings(
        self,
        *,
        engagement_id: int,
        findings: list[NormalizedFinding],
        scan_date: str,
        active: bool = True,
        verified: bool = False,
    ) -> dict[str, Any]:
        """Upload NormalizedFindings to an engagement as Generic Findings Import.

        Returns the decoded DefectDojo response body, which includes
        `scan_type`, `test_id`, and import counts.
        """
        payload = build_generic_findings_payload(findings)
        payload_bytes = json.dumps(payload).encode("utf-8")

        # import-scan is multipart: file + several form fields.
        resp = await self._client.post(
            "/api/v2/import-scan/",
            data={
                "scan_type": GENERIC_FINDINGS_IMPORT,
                "engagement": str(engagement_id),
                "active": "true" if active else "false",
                "verified": "true" if verified else "false",
                "scan_date": scan_date,
                "minimum_severity": "Info",
                "close_old_findings": "false",
            },
            files={"file": ("generic.json", payload_bytes, "application/json")},
        )
        self._check(resp, "import_findings")
        return resp.json()

    # ── Findings ──
    @_RETRY_POLICY
    async def list_findings(
        self,
        *,
        product_id: int | None = None,
        engagement_id: int | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"limit": limit}
        if product_id is not None:
            params["product"] = product_id
        if engagement_id is not None:
            params["engagement"] = engagement_id
        resp = await self._client.get("/api/v2/findings/", params=params)
        self._check(resp, "list_findings")
        return list(resp.json().get("results", []))


__all__ = [
    "DefectDojoClient",
    "GENERIC_FINDINGS_IMPORT",
    "build_generic_findings_payload",
]
