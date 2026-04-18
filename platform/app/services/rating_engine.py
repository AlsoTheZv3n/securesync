"""A–F security rating calculation — the platform's core business logic.

Per CLAUDE.md contract:
  Input:  findings (list, must expose `severity`, `source`, optional `epss_score`)
          + optional questionnaire responses (not wired in Phase 3.1 yet)
  Output: RatingResult with overall_grade (A–F) and per-category scores (0–100)

The engine is intentionally pure: no DB, no IO, no mutation. Persistence
lives in `app/services/rating_service.py`. Test it exhaustively — every
public method is deterministic.

Category weights (CLAUDE.md — must stay in sync):
    patch_management     0.25
    network_exposure     0.20
    web_security         0.15
    endpoint_security    0.15
    email_security       0.10
    credential_exposure  0.10
    ransomware_readiness 0.05
                         ────
                         1.00
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Protocol

from app.models.enums import FindingSeverity, FindingSource, RatingGrade


# ── Category identifiers ────────────────────────────────────
CAT_PATCH = "patch_management"
CAT_NETWORK = "network_exposure"
CAT_WEB = "web_security"
CAT_ENDPOINT = "endpoint_security"
CAT_EMAIL = "email_security"
CAT_CREDENTIALS = "credential_exposure"
CAT_RANSOMWARE = "ransomware_readiness"

CATEGORY_WEIGHTS: dict[str, Decimal] = {
    CAT_PATCH: Decimal("0.25"),
    CAT_NETWORK: Decimal("0.20"),
    CAT_WEB: Decimal("0.15"),
    CAT_ENDPOINT: Decimal("0.15"),
    CAT_EMAIL: Decimal("0.10"),
    CAT_CREDENTIALS: Decimal("0.10"),
    CAT_RANSOMWARE: Decimal("0.05"),
}

# Sanity: weights must sum to exactly 1. Any drift breaks the grade math.
assert sum(CATEGORY_WEIGHTS.values()) == Decimal("1.00"), "rating weights drift"


# ── Severity deductions (points per finding) ────────────────
# Tuned so that one Critical drops a category by a full grade band (~25),
# and 3 Highs do roughly the same.
SEVERITY_DEDUCTIONS: dict[FindingSeverity, Decimal] = {
    FindingSeverity.CRITICAL: Decimal("25"),
    FindingSeverity.HIGH: Decimal("10"),
    FindingSeverity.MEDIUM: Decimal("3"),
    FindingSeverity.LOW: Decimal("1"),
    FindingSeverity.INFO: Decimal("0"),
}

# Multiplier applied when a finding has a high EPSS score — actively exploited
# CVEs hurt more than theoretically-exploitable ones.
EPSS_HIGH_THRESHOLD = Decimal("0.5")
EPSS_HIGH_MULTIPLIER = Decimal("1.5")

# Grade thresholds (CLAUDE.md — A ≥ 90, ..., F < 25).
GRADE_THRESHOLDS: list[tuple[Decimal, RatingGrade]] = [
    (Decimal("90"), RatingGrade.A),
    (Decimal("75"), RatingGrade.B),
    (Decimal("60"), RatingGrade.C),
    (Decimal("45"), RatingGrade.D),
    (Decimal("25"), RatingGrade.E),
    (Decimal("0"), RatingGrade.F),
]

# Categories without an integrated data source yet — phases.md §2.5/3 will
# land these. Default to 100 (best) rather than 0, matching the "assume
# good until proven otherwise" UX principle.
UNIMPLEMENTED_CATEGORY_DEFAULT = Decimal("100")


class _FindingLike(Protocol):
    """Both NormalizedFinding and the Finding ORM row satisfy this."""
    severity: FindingSeverity
    source: FindingSource
    epss_score: Decimal | None


@dataclass(frozen=True)
class RatingResult:
    """Engine output — mirrors the Rating ORM columns 1:1."""
    overall_grade: RatingGrade
    overall_score: Decimal
    patch_score: Decimal
    network_score: Decimal
    web_score: Decimal
    endpoint_score: Decimal
    email_score: Decimal
    breach_score: Decimal           # == credential_exposure
    ransomware_score: Decimal

    # Category → list of finding-level debug info (useful for the House
    # Analogy visualisation). Not persisted; computed on demand.
    category_findings: dict[str, list[dict[str, Any]]] = field(default_factory=dict)


def categorize(finding: _FindingLike) -> str:
    """Route a finding to its rating category based on scanner source.

    This mapping is intentionally coarse — a single source maps to a single
    category. If we ever split Wazuh vulns vs SCA results into two flows,
    update here (and add tests).
    """
    match finding.source:
        case FindingSource.OPENVAS:
            return CAT_NETWORK
        case FindingSource.ZAP | FindingSource.NUCLEI:
            return CAT_WEB
        case FindingSource.WAZUH:
            # Wazuh's primary output for us is CVE/patch detection.
            # Secondary outputs (SCA, FIM) will also end up here for MVP.
            return CAT_PATCH
        case FindingSource.HIBP:
            return CAT_CREDENTIALS
        case FindingSource.MANUAL:
            # Manual findings default to network_exposure (most common use case:
            # pen-testers logging things network scanners missed).
            return CAT_NETWORK
    # mypy-complete match, but fall back to web if enum grows.
    return CAT_WEB  # pragma: no cover


def _score_category(findings: list[_FindingLike]) -> Decimal:
    """Reduce a category's findings to a 0-100 score."""
    score = Decimal("100")
    for f in findings:
        deduction = SEVERITY_DEDUCTIONS[f.severity]
        if f.epss_score is not None and f.epss_score >= EPSS_HIGH_THRESHOLD:
            deduction = deduction * EPSS_HIGH_MULTIPLIER
        score = score - deduction
    return max(score, Decimal("0"))


def grade_for_score(score: Decimal) -> RatingGrade:
    """Bucket a 0-100 score into an A–F grade."""
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return RatingGrade.F  # pragma: no cover — GRADE_THRESHOLDS ends at 0


def _finding_debug(f: _FindingLike) -> dict[str, Any]:
    """Serialisable summary of a finding for the debug payload."""
    return {
        "severity": f.severity.value,
        "source": f.source.value,
        "cve_id": getattr(f, "cve_id", None),
        "epss_score": str(f.epss_score) if f.epss_score is not None else None,
    }


def calculate_rating(
    findings: list[_FindingLike],
    questionnaire: dict[str, Any] | None = None,
) -> RatingResult:
    """Compute the A–F rating + per-category breakdown.

    `questionnaire` currently only influences `ransomware_readiness`. Keys
    consumed when present:
      - has_offsite_backup: bool
      - tests_restore_regularly: bool
      - macro_execution_restricted: bool
      - security_awareness_training: bool
    Each missing/false key deducts 25 points from the ransomware score.
    """
    by_cat: dict[str, list[_FindingLike]] = defaultdict(list)
    for f in findings:
        by_cat[categorize(f)].append(f)

    # Finding-driven category scores.
    category_scores: dict[str, Decimal] = {}
    for cat in (CAT_PATCH, CAT_NETWORK, CAT_WEB, CAT_ENDPOINT, CAT_CREDENTIALS):
        category_scores[cat] = _score_category(by_cat[cat])

    # Categories without an integrated scanner yet.
    category_scores[CAT_EMAIL] = UNIMPLEMENTED_CATEGORY_DEFAULT
    # A missing questionnaire ≠ "customer failed every control". Without data
    # we assume the best, flag the gap in the UI, and let the MSP collect the
    # answers. Only an explicitly-provided questionnaire triggers deductions.
    if questionnaire is None:
        category_scores[CAT_RANSOMWARE] = UNIMPLEMENTED_CATEGORY_DEFAULT
    else:
        category_scores[CAT_RANSOMWARE] = _ransomware_score(questionnaire)

    overall = sum(
        (score * CATEGORY_WEIGHTS[cat] for cat, score in category_scores.items()),
        start=Decimal("0"),
    )
    overall = overall.quantize(Decimal("0.01"))

    grade = grade_for_score(overall)

    debug = {
        cat: [_finding_debug(f) for f in fs[:20]]  # cap per category for payload size
        for cat, fs in by_cat.items()
        if fs
    }

    return RatingResult(
        overall_grade=grade,
        overall_score=overall,
        patch_score=category_scores[CAT_PATCH],
        network_score=category_scores[CAT_NETWORK],
        web_score=category_scores[CAT_WEB],
        endpoint_score=category_scores[CAT_ENDPOINT],
        email_score=category_scores[CAT_EMAIL],
        breach_score=category_scores[CAT_CREDENTIALS],
        ransomware_score=category_scores[CAT_RANSOMWARE],
        category_findings=debug,
    )


def _ransomware_score(q: dict[str, Any]) -> Decimal:
    """Simple checklist: 4 controls, -25 points per missing one."""
    controls = (
        "has_offsite_backup",
        "tests_restore_regularly",
        "macro_execution_restricted",
        "security_awareness_training",
    )
    score = Decimal("100")
    for key in controls:
        if not q.get(key):
            score -= Decimal("25")
    return max(score, Decimal("0"))


__all__ = [
    "CAT_CREDENTIALS",
    "CAT_EMAIL",
    "CAT_ENDPOINT",
    "CAT_NETWORK",
    "CAT_PATCH",
    "CAT_RANSOMWARE",
    "CAT_WEB",
    "CATEGORY_WEIGHTS",
    "EPSS_HIGH_MULTIPLIER",
    "EPSS_HIGH_THRESHOLD",
    "GRADE_THRESHOLDS",
    "RatingResult",
    "SEVERITY_DEDUCTIONS",
    "calculate_rating",
    "categorize",
    "grade_for_score",
]
