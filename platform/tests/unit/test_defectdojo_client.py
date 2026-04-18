"""Tests for the DefectDojo REST client.

HTTP traffic is intercepted by respx — tests never reach a real DefectDojo
instance. See docs/mocks.md.
"""

from __future__ import annotations

import json
from decimal import Decimal

import httpx
import pytest
import respx

from app.core.exceptions import ExternalServiceError
from app.integrations.defectdojo import (
    GENERIC_FINDINGS_IMPORT,
    DefectDojoClient,
    build_generic_findings_payload,
)
from app.models.enums import FindingSeverity, FindingSource
from app.services.normalizer import NormalizedFinding


def _client() -> DefectDojoClient:
    # Explicit kwargs so we don't rely on env vars for unit tests.
    return DefectDojoClient(base_url="https://dd.test", api_key="token-xyz")


# ── Generic Findings payload ────────────────────────────────
class TestBuildGenericFindingsPayload:
    def test_severity_mapped_to_defectdojo_label(self) -> None:
        findings = [
            NormalizedFinding(
                title="X",
                severity=FindingSeverity.CRITICAL,
                source=FindingSource.NUCLEI,
                asset_value="https://x.example.com",
            )
        ]
        payload = build_generic_findings_payload(findings)
        assert payload["findings"][0]["severity"] == "Critical"

    def test_all_severities_covered(self) -> None:
        findings = [
            NormalizedFinding(
                title=f"F{s.value}",
                severity=s,
                source=FindingSource.NUCLEI,
                asset_value="https://x.example.com",
            )
            for s in FindingSeverity
        ]
        out = build_generic_findings_payload(findings)
        labels = {f["severity"] for f in out["findings"]}
        assert labels == {"Critical", "High", "Medium", "Low", "Info"}

    def test_cve_and_cvss_carried_through(self) -> None:
        findings = [
            NormalizedFinding(
                title="CVE check",
                severity=FindingSeverity.HIGH,
                source=FindingSource.OPENVAS,
                asset_value="192.168.1.10:22/tcp",
                cve_id="CVE-2024-1234",
                cvss_score=Decimal("7.5"),
            )
        ]
        payload = build_generic_findings_payload(findings)
        row = payload["findings"][0]
        assert row["cve"] == "CVE-2024-1234"
        assert row["cvssv3_score"] == 7.5

    def test_empty_inputs_stringified(self) -> None:
        findings = [
            NormalizedFinding(
                title="X",
                severity=FindingSeverity.LOW,
                source=FindingSource.NUCLEI,
                asset_value="https://x.example.com",
            )
        ]
        row = build_generic_findings_payload(findings)["findings"][0]
        # Empty but present — DefectDojo parser rejects missing keys.
        assert row["description"] == ""
        assert row["mitigation"] == ""
        assert row["cvssv3_score"] is None


# ── Client HTTP interactions ────────────────────────────────
@pytest.mark.asyncio
class TestDefectDojoClient:
    async def test_create_product_posts_json(self) -> None:
        async with _client() as dd, respx.mock(base_url="https://dd.test") as mock:
            route = mock.post("/api/v2/products/").mock(
                return_value=httpx.Response(201, json={"id": 42, "name": "acme"})
            )
            pid = await dd.create_product(name="acme", description="Acme Corp")

            assert pid == 42
            call = route.calls.last
            sent = json.loads(call.request.content.decode())
            assert sent["name"] == "acme"
            assert sent["description"] == "Acme Corp"
            assert sent["prod_type"] == 1
            assert call.request.headers["Authorization"] == "Token token-xyz"

    async def test_create_product_raises_on_http_error(self) -> None:
        async with _client() as dd, respx.mock(base_url="https://dd.test") as mock:
            mock.post("/api/v2/products/").mock(
                return_value=httpx.Response(400, json={"detail": "bad"})
            )
            with pytest.raises(ExternalServiceError):
                await dd.create_product(name="x")

    async def test_create_engagement_payload(self) -> None:
        async with _client() as dd, respx.mock(base_url="https://dd.test") as mock:
            route = mock.post("/api/v2/engagements/").mock(
                return_value=httpx.Response(201, json={"id": 99})
            )
            eid = await dd.create_engagement(
                product_id=42,
                name="scan-abc",
                target_start="2026-04-18",
                target_end="2026-04-18",
            )

            assert eid == 99
            body = json.loads(route.calls.last.request.content.decode())
            assert body["product"] == 42
            assert body["name"] == "scan-abc"
            assert body["engagement_type"] == "CI/CD"
            assert body["status"] == "In Progress"

    async def test_import_findings_uses_multipart(self) -> None:
        async with _client() as dd, respx.mock(base_url="https://dd.test") as mock:
            route = mock.post("/api/v2/import-scan/").mock(
                return_value=httpx.Response(
                    201, json={"test_id": 5, "scan_type": GENERIC_FINDINGS_IMPORT}
                )
            )
            findings = [
                NormalizedFinding(
                    title="Open Redirect",
                    severity=FindingSeverity.MEDIUM,
                    source=FindingSource.ZAP,
                    asset_value="https://x.example.com",
                )
            ]
            result = await dd.import_findings(
                engagement_id=99, findings=findings, scan_date="2026-04-18"
            )

            assert result["test_id"] == 5
            request = route.calls.last.request
            # Multipart bodies contain both the form fields and the JSON file chunk.
            body = request.content.decode(errors="ignore")
            assert "Generic Findings Import" in body
            assert "Open Redirect" in body        # from the JSON payload
            assert "generic.json" in body         # filename from the files= tuple

    async def test_list_findings_filters_by_engagement(self) -> None:
        async with _client() as dd, respx.mock(base_url="https://dd.test") as mock:
            route = mock.get("/api/v2/findings/").mock(
                return_value=httpx.Response(
                    200, json={"results": [{"id": 1}, {"id": 2}]}
                )
            )
            rows = await dd.list_findings(product_id=42, engagement_id=99, limit=200)

            assert [r["id"] for r in rows] == [1, 2]
            params = dict(route.calls.last.request.url.params)
            assert params["product"] == "42"
            assert params["engagement"] == "99"
            assert params["limit"] == "200"

    async def test_missing_config_raises(self) -> None:
        with pytest.raises(ExternalServiceError):
            DefectDojoClient(base_url="", api_key="x")
        with pytest.raises(ExternalServiceError):
            DefectDojoClient(base_url="https://dd", api_key="")

    async def test_retry_on_transport_error(self) -> None:
        """tenacity should retry once on a transport error, then succeed."""
        async with _client() as dd, respx.mock(base_url="https://dd.test") as mock:
            route = mock.post("/api/v2/products/")
            route.side_effect = [
                httpx.TransportError("boom"),
                httpx.Response(201, json={"id": 7}),
            ]
            pid = await dd.create_product(name="retry")

        assert pid == 7
        assert route.call_count == 2
