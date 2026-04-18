"""Tests for the Greenbone GMP XML parser + severity mapping.

The parser is a pure function over scanner output — these tests never
spawn the gvmd container or hit a Greenbone manager. End-to-end coverage
of the GMP workflow lives in `tests/integration/test_scans_api.py` (with
the GMP client mocked).
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from app.core.exceptions import ExternalServiceError
from app.integrations.openvas import (
    _severity_for_score,
    parse_report_xml,
)
from app.models.enums import FindingSeverity, FindingSource

# Sample GMP report XML — shape mirrors real `gmp.get_report(...)` output.
# Keep this fixture stable: if it changes, real-world parsing regressions
# will sneak in unnoticed.
SAMPLE_REPORT_XML = """\
<get_reports_response status="200">
  <report>
    <report id="abc-123">
      <results count="3">
        <result id="r1">
          <name>SSH Weak Encryption Algorithms Supported</name>
          <host>192.168.1.10</host>
          <port>22/tcp</port>
          <nvt oid="1.3.6.1.4.1.25623.1.0.103674">
            <name>SSH Weak Encryption Algorithms Supported</name>
            <cvss_base>4.3</cvss_base>
            <refs>
              <ref id="CVE-2008-5161" type="cve"/>
              <ref id="MSKB:1234" type="other"/>
            </refs>
          </nvt>
          <threat>Medium</threat>
          <severity>4.3</severity>
          <description>Weak ciphers offered by the SSH server.</description>
        </result>

        <result id="r2">
          <name>SSH Server Banner</name>
          <host>192.168.1.10</host>
          <port>22/tcp</port>
          <threat>Log</threat>
          <severity>0.0</severity>
          <description>Informational banner.</description>
        </result>

        <result id="r3">
          <name>BlueKeep RDP RCE</name>
          <host>192.168.1.20</host>
          <port>3389/tcp</port>
          <nvt>
            <refs>
              <ref id="CVE-2019-0708" type="cve"/>
            </refs>
          </nvt>
          <threat>Critical</threat>
          <severity>9.8</severity>
          <description>Remote code execution via RDP.</description>
        </result>
      </results>
    </report>
  </report>
</get_reports_response>
"""

# Same shape but no <threat> element → tests the CVSS-fallback path.
NO_THREAT_REPORT_XML = """\
<get_reports_response>
  <report>
    <report>
      <results>
        <result>
          <name>High by score alone</name>
          <host>10.0.0.1</host>
          <port>443/tcp</port>
          <severity>7.5</severity>
        </result>
        <result>
          <name>Low by score alone</name>
          <host>10.0.0.1</host>
          <port>80/tcp</port>
          <severity>2.0</severity>
        </result>
      </results>
    </report>
  </report>
</get_reports_response>
"""

EMPTY_REPORT_XML = """\
<get_reports_response>
  <report>
    <report>
      <results count="0"/>
    </report>
  </report>
</get_reports_response>
"""


class TestParseReportXml:
    def test_parses_three_results(self) -> None:
        findings = parse_report_xml(SAMPLE_REPORT_XML)
        assert len(findings) == 3

    def test_titles_extracted(self) -> None:
        findings = parse_report_xml(SAMPLE_REPORT_XML)
        titles = [f.title for f in findings]
        assert titles == [
            "SSH Weak Encryption Algorithms Supported",
            "SSH Server Banner",
            "BlueKeep RDP RCE",
        ]

    def test_severity_mapping_from_threat(self) -> None:
        findings = parse_report_xml(SAMPLE_REPORT_XML)
        severities = [f.severity for f in findings]
        assert severities == [
            FindingSeverity.MEDIUM,
            FindingSeverity.INFO,         # "Log" → INFO
            FindingSeverity.CRITICAL,
        ]

    def test_severity_fallback_when_no_threat(self) -> None:
        findings = parse_report_xml(NO_THREAT_REPORT_XML)
        # 7.5 → HIGH, 2.0 → LOW
        assert [f.severity for f in findings] == [FindingSeverity.HIGH, FindingSeverity.LOW]

    def test_cve_extracted_from_nvt_refs(self) -> None:
        findings = parse_report_xml(SAMPLE_REPORT_XML)
        cves = [f.cve_id for f in findings]
        assert cves == ["CVE-2008-5161", None, "CVE-2019-0708"]

    def test_asset_value_includes_port(self) -> None:
        findings = parse_report_xml(SAMPLE_REPORT_XML)
        assert findings[0].asset_value == "192.168.1.10:22/tcp"
        assert findings[2].asset_value == "192.168.1.20:3389/tcp"

    def test_cvss_score_decimal_precision(self) -> None:
        findings = parse_report_xml(SAMPLE_REPORT_XML)
        assert findings[0].cvss_score == Decimal("4.3")
        assert findings[2].cvss_score == Decimal("9.8")
        # Severity 0.0 should still parse as Decimal('0.0').
        assert findings[1].cvss_score == Decimal("0.0")

    def test_source_is_always_openvas(self) -> None:
        findings = parse_report_xml(SAMPLE_REPORT_XML)
        assert all(f.source is FindingSource.OPENVAS for f in findings)

    def test_descriptions_preserved(self) -> None:
        findings = parse_report_xml(SAMPLE_REPORT_XML)
        assert findings[0].description == "Weak ciphers offered by the SSH server."

    def test_empty_report_yields_no_findings(self) -> None:
        assert parse_report_xml(EMPTY_REPORT_XML) == []

    def test_invalid_xml_raises_external_error(self) -> None:
        with pytest.raises(ExternalServiceError):
            parse_report_xml("<not> valid xml without closing")

    def test_raw_data_includes_source_xml(self) -> None:
        findings = parse_report_xml(SAMPLE_REPORT_XML)
        assert "_source_xml" in findings[0].raw_data
        assert "<host>192.168.1.10</host>" in findings[0].raw_data["_source_xml"]


class TestSeverityForScore:
    @pytest.mark.parametrize(
        "score,expected",
        [
            (Decimal("9.0"), FindingSeverity.CRITICAL),
            (Decimal("9.9"), FindingSeverity.CRITICAL),
            (Decimal("10.0"), FindingSeverity.CRITICAL),
            (Decimal("8.9"), FindingSeverity.HIGH),
            (Decimal("7.0"), FindingSeverity.HIGH),
            (Decimal("6.9"), FindingSeverity.MEDIUM),
            (Decimal("4.0"), FindingSeverity.MEDIUM),
            (Decimal("3.9"), FindingSeverity.LOW),
            (Decimal("0.1"), FindingSeverity.LOW),
            (Decimal("0.0"), FindingSeverity.INFO),
            (None, FindingSeverity.INFO),
        ],
    )
    def test_buckets(self, score: Decimal | None, expected: FindingSeverity) -> None:
        assert _severity_for_score(score) is expected
