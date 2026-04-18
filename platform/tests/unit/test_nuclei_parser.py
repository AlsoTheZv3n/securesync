"""Tests for the Nuclei JSONL parser + target validation.

We never invoke the actual nuclei binary in these tests — the parser is a
pure function over scanner stdout, and that's what matters.
"""

from __future__ import annotations

import json
from decimal import Decimal

import pytest

from app.integrations.nuclei import (
    _validate_target,
    parse_nuclei_jsonl,
)
from app.models.enums import FindingSeverity, FindingSource


# ── Sample fixtures ────────────────────────────────────────
# Shape mirrors real nuclei -jsonl output. Don't add fields the parser
# doesn't read — we want to catch regressions when the parser stops looking
# at something it should.
_SAMPLE_GIT_CONFIG = {
    "template-id": "git-config",
    "info": {
        "name": "Git Configuration Files",
        "severity": "medium",
        "description": "Git config exposed",
        "remediation": "block /.git/",
        "classification": {"cve-id": ["CVE-2024-99999"], "cvss-score": 5.3},
    },
    "host": "https://example.com",
    "matched-at": "https://example.com/.git/config",
    "extracted-results": ["[core]\nrepositoryformatversion = 0"],
}

_SAMPLE_TECH_DETECT = {
    "template-id": "tech-detect:nginx",
    "info": {"name": "nginx detected", "severity": "info"},
    "host": "https://example.com",
}

_SAMPLE_HIGH_NO_CVE = {
    "template-id": "exposed-panels:grafana",
    "info": {"name": "Grafana panel exposed", "severity": "high"},
    "host": "https://example.com",
    "matched-at": "https://example.com/grafana/login",
}


def _to_jsonl(*events: dict) -> str:
    return "\n".join(json.dumps(e) for e in events) + "\n"


# ── Target validation ──────────────────────────────────────
class TestTargetValidation:
    @pytest.mark.parametrize(
        "target",
        [
            "example.com",
            "https://example.com",
            "http://example.com:8080/path",
            "192.168.1.1",
            "192.168.1.1:8080",
            "[2001:db8::1]:443",
            "sub.domain.example.co.uk",
        ],
    )
    def test_accepts_safe_targets(self, target: str) -> None:
        assert _validate_target(target) == target

    @pytest.mark.parametrize(
        "target",
        [
            "",
            "; rm -rf /",
            "example.com; ls",
            "$(whoami).example.com",
            "example.com `id`",
            "x" * 256,
            "javascript:alert(1)",
        ],
    )
    def test_rejects_dangerous_targets(self, target: str) -> None:
        with pytest.raises(ValueError):
            _validate_target(target)


# ── JSONL parsing ──────────────────────────────────────────
class TestParseJsonl:
    def test_parses_three_events(self) -> None:
        out = _to_jsonl(_SAMPLE_GIT_CONFIG, _SAMPLE_TECH_DETECT, _SAMPLE_HIGH_NO_CVE)
        findings = parse_nuclei_jsonl(out)
        assert len(findings) == 3

    def test_empty_input_returns_empty(self) -> None:
        assert parse_nuclei_jsonl("") == []
        assert parse_nuclei_jsonl("\n\n\n") == []

    def test_severity_mapping(self) -> None:
        out = _to_jsonl(_SAMPLE_GIT_CONFIG, _SAMPLE_TECH_DETECT, _SAMPLE_HIGH_NO_CVE)
        sevs = [f.severity for f in parse_nuclei_jsonl(out)]
        assert sevs == [FindingSeverity.MEDIUM, FindingSeverity.INFO, FindingSeverity.HIGH]

    def test_unknown_severity_falls_back_to_info(self) -> None:
        event = {**_SAMPLE_TECH_DETECT, "info": {"name": "x", "severity": "frobnicated"}}
        f = parse_nuclei_jsonl(_to_jsonl(event))[0]
        assert f.severity is FindingSeverity.INFO

    def test_cve_extracted_from_classification(self) -> None:
        f = parse_nuclei_jsonl(_to_jsonl(_SAMPLE_GIT_CONFIG))[0]
        assert f.cve_id == "CVE-2024-99999"

    def test_no_cve_when_classification_missing(self) -> None:
        f = parse_nuclei_jsonl(_to_jsonl(_SAMPLE_HIGH_NO_CVE))[0]
        assert f.cve_id is None

    def test_cvss_extracted(self) -> None:
        f = parse_nuclei_jsonl(_to_jsonl(_SAMPLE_GIT_CONFIG))[0]
        assert f.cvss_score == Decimal("5.3")

    def test_evidence_built_from_extracted_results(self) -> None:
        f = parse_nuclei_jsonl(_to_jsonl(_SAMPLE_GIT_CONFIG))[0]
        assert f.evidence is not None
        assert "repositoryformatversion" in f.evidence

    def test_asset_value_prefers_matched_at(self) -> None:
        f = parse_nuclei_jsonl(_to_jsonl(_SAMPLE_GIT_CONFIG))[0]
        assert f.asset_value == "https://example.com/.git/config"

    def test_asset_value_falls_back_to_host(self) -> None:
        f = parse_nuclei_jsonl(_to_jsonl(_SAMPLE_TECH_DETECT))[0]
        assert f.asset_value == "https://example.com"

    def test_source_is_always_nuclei(self) -> None:
        out = _to_jsonl(_SAMPLE_GIT_CONFIG, _SAMPLE_HIGH_NO_CVE)
        assert all(f.source is FindingSource.NUCLEI for f in parse_nuclei_jsonl(out))

    def test_invalid_json_lines_skipped(self) -> None:
        out = _to_jsonl(_SAMPLE_GIT_CONFIG) + "not json at all\n" + _to_jsonl(_SAMPLE_TECH_DETECT)
        findings = parse_nuclei_jsonl(out)
        assert len(findings) == 2

    def test_raw_data_preserved(self) -> None:
        f = parse_nuclei_jsonl(_to_jsonl(_SAMPLE_GIT_CONFIG))[0]
        assert f.raw_data["template-id"] == "git-config"
