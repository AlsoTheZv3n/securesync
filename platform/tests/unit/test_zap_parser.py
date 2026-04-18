"""Tests for the OWASP ZAP alert parser + risk mapping.

Pure-function tests — no ZAP daemon, no network. End-to-end coverage of
the spider+ascan workflow happens in integration tests with the ZAP API
mocked.
"""

from __future__ import annotations

import pytest

from app.integrations.zap import (
    _normalize_target_url,
    parse_zap_alerts,
)
from app.models.enums import FindingSeverity, FindingSource

# Sample ZAP alert dicts — shape mirrors `zap.alert.alerts(baseurl=...)` output.
SAMPLE_ALERTS = [
    {
        "alert": "Cross Site Scripting (Reflected)",
        "name": "Cross Site Scripting (Reflected)",
        "risk": "High",
        "confidence": "Medium",
        "description": "Cross-site Scripting (XSS) is an attack technique...",
        "solution": "Phase: Architecture and Design — Use a vetted library...",
        "reference": "https://owasp.org/www-community/attacks/xss/",
        "cweid": "79",
        "wascid": "8",
        "pluginid": "40012",
        "url": "https://target.example.com/search?q=test",
        "param": "q",
        "attack": "<script>alert(1)</script>",
        "evidence": "<script>alert(1)</script>",
    },
    {
        "alert": "X-Frame-Options Header Not Set",
        "name": "X-Frame-Options Header Not Set",
        "risk": "Medium",
        "confidence": "Medium",
        "description": "X-Frame-Options header is not included...",
        "solution": "Most modern Web browsers support the X-Frame-Options HTTP header...",
        "reference": "https://owasp.org/www-community/attacks/Clickjacking",
        "cweid": "1021",
        "pluginid": "10020",
        "url": "https://target.example.com/",
    },
    {
        "alert": "Strict-Transport-Security Header Not Set",
        "name": "Strict-Transport-Security Header Not Set",
        "risk": "Low",
        "confidence": "High",
        "description": "HTTP Strict Transport Security (HSTS) is a web security policy...",
        "url": "https://target.example.com/",
        "cweid": "319",
        "pluginid": "10035",
    },
    {
        "alert": "Modern Web Application",
        "name": "Modern Web Application",
        "risk": "Informational",
        "confidence": "Medium",
        "description": "The application appears to be a modern web app...",
        "url": "https://target.example.com/",
        "pluginid": "10109",
    },
]

# Alert with a CVE reference — exercises best-effort CVE extraction from text.
ALERT_WITH_CVE_REF = {
    "alert": "Apache Struts RCE",
    "name": "Apache Struts RCE",
    "risk": "High",
    "description": "Server may be vulnerable to remote code execution",
    "reference": "https://nvd.nist.gov/vuln/detail/CVE-2017-5638",
    "url": "https://target.example.com/struts2-showcase/",
    "cweid": "20",
}


# ── URL normalisation ───────────────────────────────────────
class TestNormalizeTargetUrl:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("example.com", "https://example.com"),
            ("https://example.com", "https://example.com"),
            ("http://example.com", "http://example.com"),
            ("  example.com  ", "https://example.com"),
            ("example.com:8080/path", "https://example.com:8080/path"),
        ],
    )
    def test_adds_scheme_when_missing(self, raw: str, expected: str) -> None:
        assert _normalize_target_url(raw) == expected


# ── Alert parsing ───────────────────────────────────────────
class TestParseZapAlerts:
    def test_parses_four_alerts(self) -> None:
        findings = parse_zap_alerts(SAMPLE_ALERTS)
        assert len(findings) == 4

    def test_risk_mapping(self) -> None:
        findings = parse_zap_alerts(SAMPLE_ALERTS)
        assert [f.severity for f in findings] == [
            FindingSeverity.HIGH,
            FindingSeverity.MEDIUM,
            FindingSeverity.LOW,
            FindingSeverity.INFO,
        ]

    def test_unknown_risk_falls_back_to_info(self) -> None:
        findings = parse_zap_alerts([{"name": "Weird", "risk": "Frobnicated", "url": "https://x.example.com"}])
        assert findings[0].severity is FindingSeverity.INFO

    def test_titles_extracted_from_name(self) -> None:
        findings = parse_zap_alerts(SAMPLE_ALERTS)
        titles = [f.title for f in findings]
        assert "Cross Site Scripting (Reflected)" in titles

    def test_asset_value_is_alert_url(self) -> None:
        findings = parse_zap_alerts(SAMPLE_ALERTS)
        # XSS alert was on the search endpoint.
        xss = next(f for f in findings if "XSS" in f.title.upper() or "Cross" in f.title)
        assert xss.asset_value == "https://target.example.com/search?q=test"

    def test_remediation_from_solution_field(self) -> None:
        findings = parse_zap_alerts(SAMPLE_ALERTS)
        xss = next(f for f in findings if "Cross" in f.title)
        assert xss.remediation is not None
        assert "vetted library" in xss.remediation

    def test_evidence_combines_param_attack_evidence(self) -> None:
        findings = parse_zap_alerts(SAMPLE_ALERTS)
        xss = next(f for f in findings if "Cross" in f.title)
        assert xss.evidence is not None
        assert "param: q" in xss.evidence
        assert "attack: <script>alert(1)</script>" in xss.evidence
        assert "evidence: <script>alert(1)</script>" in xss.evidence

    def test_no_cve_when_alert_lacks_one(self) -> None:
        findings = parse_zap_alerts(SAMPLE_ALERTS)
        assert all(f.cve_id is None for f in findings)

    def test_cve_extracted_from_reference_text(self) -> None:
        findings = parse_zap_alerts([ALERT_WITH_CVE_REF])
        assert findings[0].cve_id == "CVE-2017-5638"

    def test_cve_field_takes_precedence(self) -> None:
        alert = {
            "name": "Some CVE",
            "risk": "High",
            "url": "https://x.example.com",
            "cve": "cve-2024-0001",                                 # lowercase input
            "reference": "https://nvd.nist.gov/CVE-2999-9999",      # noise
        }
        findings = parse_zap_alerts([alert])
        assert findings[0].cve_id == "CVE-2024-0001"

    def test_source_is_always_zap(self) -> None:
        findings = parse_zap_alerts(SAMPLE_ALERTS)
        assert all(f.source is FindingSource.ZAP for f in findings)

    def test_raw_data_preserved(self) -> None:
        findings = parse_zap_alerts(SAMPLE_ALERTS)
        assert findings[0].raw_data["pluginid"] == "40012"
        assert findings[0].raw_data["cweid"] == "79"

    def test_empty_input_returns_empty(self) -> None:
        assert parse_zap_alerts([]) == []
