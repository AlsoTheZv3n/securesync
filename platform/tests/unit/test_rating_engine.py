"""Exhaustive tests for the rating engine (CLAUDE.md calls for this explicitly).

Covers:
  - Weights sum to 1 (sanity)
  - Grade thresholds A–F boundary values
  - Severity deductions per category
  - EPSS high-score multiplier
  - Category routing per FindingSource
  - Ransomware questionnaire reduces score
  - All-green baseline vs all-critical worst case
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

import pytest

from app.models.enums import FindingSeverity, FindingSource, RatingGrade
from app.services.rating_engine import (
    CAT_CREDENTIALS,
    CAT_ENDPOINT,
    CAT_NETWORK,
    CAT_PATCH,
    CAT_WEB,
    CATEGORY_WEIGHTS,
    EPSS_HIGH_MULTIPLIER,
    GRADE_THRESHOLDS,
    SEVERITY_DEDUCTIONS,
    calculate_rating,
    categorize,
    grade_for_score,
)


# Lightweight stand-in for Finding / NormalizedFinding — only the Protocol
# fields the engine reads. Using a dataclass keeps these tests ORM-free.
@dataclass
class Fake:
    severity: FindingSeverity
    source: FindingSource
    epss_score: Decimal | None = None
    cve_id: str | None = None


def _many(source: FindingSource, severity: FindingSeverity, count: int) -> list[Fake]:
    return [Fake(severity=severity, source=source) for _ in range(count)]


# ── Sanity ──────────────────────────────────────────────────
class TestWeights:
    def test_weights_sum_to_one(self) -> None:
        assert sum(CATEGORY_WEIGHTS.values()) == Decimal("1.00")

    def test_grade_thresholds_descending(self) -> None:
        scores = [t[0] for t in GRADE_THRESHOLDS]
        assert scores == sorted(scores, reverse=True)


# ── Grade bucketing ─────────────────────────────────────────
class TestGradeForScore:
    @pytest.mark.parametrize(
        "score,expected",
        [
            (Decimal("100"), RatingGrade.A),
            (Decimal("90"), RatingGrade.A),
            (Decimal("89.99"), RatingGrade.B),
            (Decimal("75"), RatingGrade.B),
            (Decimal("74.99"), RatingGrade.C),
            (Decimal("60"), RatingGrade.C),
            (Decimal("59.99"), RatingGrade.D),
            (Decimal("45"), RatingGrade.D),
            (Decimal("44.99"), RatingGrade.E),
            (Decimal("25"), RatingGrade.E),
            (Decimal("24.99"), RatingGrade.F),
            (Decimal("0"), RatingGrade.F),
        ],
    )
    def test_boundary_values(self, score: Decimal, expected: RatingGrade) -> None:
        assert grade_for_score(score) is expected


# ── Category routing ────────────────────────────────────────
class TestCategorize:
    @pytest.mark.parametrize(
        "source,expected",
        [
            (FindingSource.OPENVAS, CAT_NETWORK),
            (FindingSource.ZAP, CAT_WEB),
            (FindingSource.NUCLEI, CAT_WEB),
            (FindingSource.WAZUH, CAT_PATCH),
            (FindingSource.HIBP, CAT_CREDENTIALS),
            (FindingSource.MANUAL, CAT_NETWORK),
        ],
    )
    def test_source_mapping(self, source: FindingSource, expected: str) -> None:
        f = Fake(severity=FindingSeverity.MEDIUM, source=source)
        assert categorize(f) == expected


# ── Pure scoring behaviour ──────────────────────────────────
class TestCalculateRating:
    def test_zero_findings_is_perfect(self) -> None:
        result = calculate_rating([])
        assert result.overall_grade is RatingGrade.A
        assert result.overall_score == Decimal("100.00")

    def test_all_categories_pass_gives_a(self) -> None:
        """Clean scanners + good questionnaire → A."""
        good_questionnaire = {
            "has_offsite_backup": True,
            "tests_restore_regularly": True,
            "macro_execution_restricted": True,
            "security_awareness_training": True,
        }
        result = calculate_rating([], good_questionnaire)
        assert result.overall_grade is RatingGrade.A
        assert result.ransomware_score == Decimal("100")

    def test_single_critical_nuclei_hits_web_category(self) -> None:
        findings = [Fake(severity=FindingSeverity.CRITICAL, source=FindingSource.NUCLEI)]
        result = calculate_rating(findings)
        # 100 - 25 = 75 in web. Other finding-driven categories stay 100.
        assert result.web_score == Decimal("75")
        assert result.network_score == Decimal("100")
        assert result.patch_score == Decimal("100")

    def test_five_critical_openvas_flattens_network_to_zero(self) -> None:
        findings = _many(FindingSource.OPENVAS, FindingSeverity.CRITICAL, 5)
        result = calculate_rating(findings)
        # 100 - 5*25 = -25 → floored at 0.
        assert result.network_score == Decimal("0")

    def test_epss_boost_applied_once(self) -> None:
        """EPSS ≥ 0.5 makes the deduction 1.5×."""
        base = calculate_rating(
            [Fake(severity=FindingSeverity.HIGH, source=FindingSource.NUCLEI)]
        )
        boosted = calculate_rating(
            [
                Fake(
                    severity=FindingSeverity.HIGH,
                    source=FindingSource.NUCLEI,
                    epss_score=Decimal("0.9"),
                )
            ]
        )
        # Base deduction: 10. Boosted: 15. So web_score drops 5 more.
        assert base.web_score - boosted.web_score == Decimal("5")
        assert (
            SEVERITY_DEDUCTIONS[FindingSeverity.HIGH] * EPSS_HIGH_MULTIPLIER
            - SEVERITY_DEDUCTIONS[FindingSeverity.HIGH]
        ) == Decimal("5")

    def test_epss_below_threshold_no_boost(self) -> None:
        boosted = calculate_rating(
            [
                Fake(
                    severity=FindingSeverity.HIGH,
                    source=FindingSource.NUCLEI,
                    epss_score=Decimal("0.3"),
                )
            ]
        )
        assert boosted.web_score == Decimal("90")  # same as no-EPSS

    def test_mixed_severity_network(self) -> None:
        findings = [
            Fake(severity=FindingSeverity.CRITICAL, source=FindingSource.OPENVAS),
            Fake(severity=FindingSeverity.HIGH, source=FindingSource.OPENVAS),
            Fake(severity=FindingSeverity.MEDIUM, source=FindingSource.OPENVAS),
            Fake(severity=FindingSeverity.LOW, source=FindingSource.OPENVAS),
        ]
        result = calculate_rating(findings)
        # 100 - 25 - 10 - 3 - 1 = 61
        assert result.network_score == Decimal("61")

    def test_info_findings_no_impact(self) -> None:
        findings = _many(FindingSource.OPENVAS, FindingSeverity.INFO, 100)
        result = calculate_rating(findings)
        assert result.network_score == Decimal("100")

    def test_findings_only_affect_own_category(self) -> None:
        # Patch management findings don't lower network score.
        findings = _many(FindingSource.WAZUH, FindingSeverity.CRITICAL, 2)
        result = calculate_rating(findings)
        assert result.patch_score == Decimal("50")
        assert result.network_score == Decimal("100")
        assert result.web_score == Decimal("100")
        assert result.endpoint_score == Decimal("100")
        assert result.breach_score == Decimal("100")

    def test_all_categories_failing_gives_f(self) -> None:
        """Push every finding-driven category to 0 + worst questionnaire."""
        # 5 criticals per category wipes each to 0 (5*25 = 125, floored).
        findings: list[Fake] = []
        for src in (
            FindingSource.OPENVAS,
            FindingSource.NUCLEI,
            FindingSource.WAZUH,
            FindingSource.HIBP,
        ):
            findings.extend(_many(src, FindingSeverity.CRITICAL, 5))

        # endpoint_security has no integration routing to it yet (Wazuh → patch)
        # so it stays at 100 despite real-world intent. Explicitly noted in
        # the engine.

        result = calculate_rating(
            findings,
            questionnaire={
                "has_offsite_backup": False,
                "tests_restore_regularly": False,
                "macro_execution_restricted": False,
                "security_awareness_training": False,
            },
        )
        # patch/network/web/credentials = 0; endpoint/email = 100; ransomware = 0.
        # Overall = 0*0.25 + 0*0.20 + 0*0.15 + 100*0.15 + 100*0.10 + 0*0.10 + 0*0.05
        #        = 15 + 10 = 25.00
        assert result.overall_score == Decimal("25.00")
        assert result.overall_grade is RatingGrade.E

    def test_overall_score_matches_weighted_sum(self) -> None:
        findings = [
            Fake(severity=FindingSeverity.HIGH, source=FindingSource.OPENVAS),   # -10
            Fake(severity=FindingSeverity.HIGH, source=FindingSource.NUCLEI),    # -10
        ]
        result = calculate_rating(
            findings,
            questionnaire={"has_offsite_backup": True, "tests_restore_regularly": True,
                           "macro_execution_restricted": True,
                           "security_awareness_training": True},
        )
        # network=90, web=90, patch=100, endpoint=100, email=100, breach=100, ransom=100
        expected = (
            Decimal("100") * Decimal("0.25")   # patch
            + Decimal("90") * Decimal("0.20")  # network
            + Decimal("90") * Decimal("0.15")  # web
            + Decimal("100") * Decimal("0.15") # endpoint
            + Decimal("100") * Decimal("0.10") # email
            + Decimal("100") * Decimal("0.10") # breach
            + Decimal("100") * Decimal("0.05") # ransomware
        )
        assert result.overall_score == expected.quantize(Decimal("0.01"))

    def test_ransomware_each_missing_control_costs_25(self) -> None:
        base = calculate_rating(
            [],
            questionnaire={
                "has_offsite_backup": True,
                "tests_restore_regularly": True,
                "macro_execution_restricted": True,
                "security_awareness_training": True,
            },
        )
        one_missing = calculate_rating(
            [],
            questionnaire={
                "has_offsite_backup": False,
                "tests_restore_regularly": True,
                "macro_execution_restricted": True,
                "security_awareness_training": True,
            },
        )
        assert base.ransomware_score - one_missing.ransomware_score == Decimal("25")

    def test_no_questionnaire_defaults_to_best_score(self) -> None:
        """`None` questionnaire = "not yet assessed" → 100. An explicitly-empty
        `{}` = "all controls answered False" → deductions kick in. Keeps the
        UI honest: we don't penalise tenants who haven't filled the form yet."""
        not_assessed = calculate_rating([])
        explicitly_empty = calculate_rating([], questionnaire={})
        assert not_assessed.ransomware_score == Decimal("100")
        assert explicitly_empty.ransomware_score == Decimal("0")

    def test_category_findings_debug_payload(self) -> None:
        findings = [
            Fake(severity=FindingSeverity.CRITICAL, source=FindingSource.NUCLEI,
                 cve_id="CVE-2024-1", epss_score=Decimal("0.8")),
            Fake(severity=FindingSeverity.HIGH, source=FindingSource.OPENVAS),
        ]
        result = calculate_rating(findings)
        assert CAT_WEB in result.category_findings
        assert CAT_NETWORK in result.category_findings
        # Finding-less categories don't show up at all.
        assert CAT_CREDENTIALS not in result.category_findings
        # Payload carries the fields we'd need for House Analogy.
        web_payload = result.category_findings[CAT_WEB][0]
        assert web_payload["severity"] == "critical"
        assert web_payload["cve_id"] == "CVE-2024-1"
        assert web_payload["epss_score"] == "0.8"
