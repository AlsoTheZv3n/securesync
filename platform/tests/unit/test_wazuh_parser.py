"""Tests for the Wazuh vulnerability JSON parser.

Pure-function — no Wazuh Manager needed. HTTP-level behaviour of WazuhClient
lives in `tests/unit/test_wazuh_client.py`.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from app.integrations.wazuh import (
    parse_vulnerabilities,
    tenant_group_name,
)
from app.models.enums import FindingSeverity, FindingSource

SAMPLE_BODY = {
    "data": {
        "total_affected_items": 3,
        "affected_items": [
            {
                "cve": "CVE-2024-1234",
                "name": "openssh",
                "version": "8.9p1",
                "severity": "High",
                "cvss3_score": "7.5",
                "cvss2_score": "7.5",
                "title": "Vulnerability in openssh before 9.0",
                "condition": "Package less than 9.0",
                "detection_time": "2026-04-18T09:00:00Z",
                "status": "VALID",
                "type": "PACKAGE",
                "external_references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
            },
            {
                "cve": "CVE-2024-9999",
                "name": "glibc",
                "version": "2.31",
                "severity": "Critical",
                "cvss3_score": "9.8",
                "detection_time": "2026-04-18T09:00:00Z",
                "status": "VALID",
            },
            {
                "cve": None,
                "name": "dpkg",
                "version": "1.20",
                "severity": "Low",
                "cvss3_score": "0.0",
            },
        ],
    }
}

EMPTY_BODY = {"data": {"affected_items": []}}
MISSING_DATA_BODY: dict = {}  # type: ignore[var-annotated]


# ── Group name derivation ──────────────────────────────────
class TestTenantGroupName:
    def test_simple_slug(self) -> None:
        assert tenant_group_name("acme") == "ss-acme"

    def test_slug_with_hyphens(self) -> None:
        assert tenant_group_name("acme-corp-ch") == "ss-acme-corp-ch"

    def test_rejects_invalid_slug(self) -> None:
        # Slug validation in TenantCreate should prevent these upstream,
        # but the derivation must fail hard if somehow bypassed.
        with pytest.raises(ValueError):
            tenant_group_name("has spaces")


# ── Vulnerability parser ───────────────────────────────────
class TestParseVulnerabilities:
    def test_parses_three_items(self) -> None:
        findings = parse_vulnerabilities(SAMPLE_BODY, agent_id="001")
        assert len(findings) == 3

    def test_source_is_always_wazuh(self) -> None:
        findings = parse_vulnerabilities(SAMPLE_BODY, agent_id="001")
        assert all(f.source is FindingSource.WAZUH for f in findings)

    def test_severity_mapping(self) -> None:
        findings = parse_vulnerabilities(SAMPLE_BODY, agent_id="001")
        sevs = [f.severity for f in findings]
        assert sevs == [FindingSeverity.HIGH, FindingSeverity.CRITICAL, FindingSeverity.LOW]

    def test_cve_extracted(self) -> None:
        findings = parse_vulnerabilities(SAMPLE_BODY, agent_id="001")
        assert findings[0].cve_id == "CVE-2024-1234"
        assert findings[1].cve_id == "CVE-2024-9999"
        assert findings[2].cve_id is None

    def test_cvss_uses_v3_when_available(self) -> None:
        findings = parse_vulnerabilities(SAMPLE_BODY, agent_id="001")
        assert findings[0].cvss_score == Decimal("7.5")
        assert findings[1].cvss_score == Decimal("9.8")

    def test_external_references_appended_to_description(self) -> None:
        findings = parse_vulnerabilities(SAMPLE_BODY, agent_id="001")
        assert findings[0].description is not None
        assert "nvd.nist.gov" in findings[0].description

    def test_evidence_includes_agent_and_package(self) -> None:
        findings = parse_vulnerabilities(SAMPLE_BODY, agent_id="001")
        assert "openssh 8.9p1" in findings[0].evidence  # type: ignore[operator]
        assert "Agent: 001" in findings[0].evidence     # type: ignore[operator]

    def test_asset_value_defaults_to_agent_id(self) -> None:
        findings = parse_vulnerabilities(SAMPLE_BODY, agent_id="abc-123")
        assert findings[0].asset_value == "abc-123"

    def test_asset_value_override(self) -> None:
        findings = parse_vulnerabilities(
            SAMPLE_BODY, agent_id="001", asset_value="linux-01.corp.local"
        )
        assert findings[0].asset_value == "linux-01.corp.local"

    def test_unknown_severity_falls_back_to_info(self) -> None:
        body = {"data": {"affected_items": [{"cve": "CVE-X", "name": "p", "version": "1", "severity": "Frobnicated"}]}}
        findings = parse_vulnerabilities(body, agent_id="1")
        assert findings[0].severity is FindingSeverity.INFO

    def test_empty_response_yields_no_findings(self) -> None:
        assert parse_vulnerabilities(EMPTY_BODY, agent_id="1") == []

    def test_missing_data_key_is_safe(self) -> None:
        assert parse_vulnerabilities(MISSING_DATA_BODY, agent_id="1") == []

    def test_raw_data_preserved(self) -> None:
        findings = parse_vulnerabilities(SAMPLE_BODY, agent_id="001")
        assert findings[0].raw_data["name"] == "openssh"
        assert findings[0].raw_data["type"] == "PACKAGE"
