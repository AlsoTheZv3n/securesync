"""Generate executive + technical PDF reports via Jinja2 + WeasyPrint.

Pipeline:
    1. `build_context()`      — pure function: DB rows → dict of template vars
    2. `render_html()`        — pure function: context → rendered HTML string
    3. `render_pdf()`         — impure: HTML → PDF bytes (WeasyPrint)

Splitting HTML from PDF lets us unit-test template rendering without
depending on WeasyPrint's native libs (Cairo / Pango / gdk-pixbuf), which
are painful on Windows.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import structlog
from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import (
    FindingSeverity,
    FindingStatus,
    RatingGrade,
    ReportType,
)
from app.models.finding import Finding
from app.models.rating import Rating
from app.models.scan_job import ScanJob
from app.models.tenant import Tenant

logger = structlog.get_logger()

_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"

# Preconfigured once — the env is thread-safe for rendering.
_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATES_DIR)),
    autoescape=select_autoescape(default_for_string=True, default=True),
    trim_blocks=True,
    lstrip_blocks=True,
)

# Grade → badge colour (matches design.md).
_GRADE_COLORS: dict[RatingGrade, str] = {
    RatingGrade.A: "#10B981",
    RatingGrade.B: "#84CC16",
    RatingGrade.C: "#F59E0B",
    RatingGrade.D: "#F97316",
    RatingGrade.E: "#EF4444",
    RatingGrade.F: "#7F1D1D",
}

# Severity rank for sort-by-worst-first.
_SEVERITY_RANK: dict[FindingSeverity, int] = {
    FindingSeverity.CRITICAL: 5,
    FindingSeverity.HIGH: 4,
    FindingSeverity.MEDIUM: 3,
    FindingSeverity.LOW: 2,
    FindingSeverity.INFO: 1,
}

TOP_FINDINGS_LIMIT = 10


# ── Data assembly ───────────────────────────────────────────
async def _load_inputs(
    session: AsyncSession, *, tenant_id, scan_job_id
) -> tuple[Tenant, ScanJob, Rating, Rating | None, list[Finding]]:
    tenant = (
        await session.execute(select(Tenant).where(Tenant.id == tenant_id))
    ).scalar_one()
    scan_job = (
        await session.execute(select(ScanJob).where(ScanJob.id == scan_job_id))
    ).scalar_one()

    rating = (
        await session.execute(
            select(Rating).where(Rating.scan_job_id == scan_job_id)
        )
    ).scalar_one_or_none()
    if rating is None:
        raise ValueError("cannot generate report: scan has no rating")

    # Previous rating for trend delta: latest rating for this tenant before
    # the current one.
    previous = (
        await session.execute(
            select(Rating)
            .where(
                Rating.tenant_id == tenant_id,
                Rating.calculated_at < rating.calculated_at,
            )
            .order_by(Rating.calculated_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    # All currently-open findings for the tenant (same input the rating used).
    findings = list(
        (
            await session.execute(
                select(Finding).where(
                    Finding.tenant_id == tenant_id,
                    Finding.status == FindingStatus.OPEN,
                )
            )
        )
        .scalars()
        .all()
    )

    return tenant, scan_job, rating, previous, findings


def _asset_display(f: Finding) -> str:
    """Fall back on raw_data hints when Finding.asset_value isn't loaded."""
    asset_val = f.raw_data.get("asset_value") if f.raw_data else None
    return asset_val or f.raw_data.get("url") or f.raw_data.get("host") or str(f.asset_id)


def _sort_findings_worst_first(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (
            -_SEVERITY_RANK[f.severity],
            -(float(f.epss_score) if f.epss_score is not None else 0.0),
            -(float(f.cvss_score) if f.cvss_score is not None else 0.0),
        ),
    )


def _build_recommendations(rating: Rating, findings: list[Finding]) -> list[str]:
    """Plain-language action items for the Executive report.

    Stays deterministic: no templating of finding titles into advice, just
    category- and severity-based hints. UI can prettify later.
    """
    recs: list[str] = []

    # Category-score based prompts (lowest score → most urgent).
    category_hints = [
        (rating.patch_score, "Prioritise patch management — several unpatched CVEs "
         "are dragging down this customer's score."),
        (rating.network_score, "Review network exposure and close unneeded ports; "
         "consider a firewall ruleset audit."),
        (rating.web_score, "Web-application findings indicate missing headers or "
         "known CMS vulnerabilities — harden public-facing services."),
        (rating.breach_score, "Credentials for this tenant appear in known "
         "breaches — rotate affected passwords and enforce MFA."),
    ]
    for score, hint in sorted(category_hints, key=lambda x: x[0]):
        if score < Decimal("75"):
            recs.append(hint)
        if len(recs) >= 3:
            break

    # If there's a single Critical finding, call it out explicitly.
    criticals = [f for f in findings if f.severity is FindingSeverity.CRITICAL]
    if criticals:
        recs.insert(
            0,
            f"{len(criticals)} critical finding"
            f"{'s' if len(criticals) != 1 else ''} require immediate remediation.",
        )

    return recs[:5]


def _category_rows(rating: Rating) -> list[dict[str, Any]]:
    """Flat rows for the rating-breakdown table."""
    return [
        {"label": "Patch management", "score": int(rating.patch_score)},
        {"label": "Network exposure", "score": int(rating.network_score)},
        {"label": "Web security", "score": int(rating.web_score)},
        {"label": "Endpoint security", "score": int(rating.endpoint_score)},
        {"label": "Email security", "score": int(rating.email_score)},
        {"label": "Credential exposure", "score": int(rating.breach_score)},
        {"label": "Ransomware readiness", "score": int(rating.ransomware_score)},
    ]


def build_context(
    *,
    tenant: Tenant,
    scan_job: ScanJob,
    rating: Rating,
    previous_rating: Rating | None,
    findings: list[Finding],
    report_type: ReportType,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Build the Jinja context — kept pure for easy unit testing."""
    generated_at = generated_at or datetime.utcnow()

    ordered = _sort_findings_worst_first(findings)

    # Translate asset_id to something human-readable using raw_data hints.
    # We can't eager-load Asset here without an N+1 problem, so fall back
    # to what's in raw_data (already the scanner's asset_value).
    for f in ordered:
        f.asset_display = _asset_display(f)  # type: ignore[attr-defined]

    rating_delta_str = ""
    if previous_rating is not None:
        delta = rating.overall_score - previous_rating.overall_score
        sign = "+" if delta >= 0 else ""
        rating_delta_str = f"{sign}{delta} points"

    scan_period_str = (
        scan_job.completed_at.strftime("%Y-%m-%d")
        if scan_job.completed_at
        else "ongoing"
    )

    ctx: dict[str, Any] = {
        "title": (
            f"{tenant.name} — "
            f"{'Executive Security Report' if report_type is ReportType.EXECUTIVE else 'Technical Security Report'}"
        ),
        "footer": f"Confidential · {tenant.name}",
        "tenant": tenant,
        "branding": {
            "logo_url": tenant.logo_url,
            "primary_color": tenant.primary_color or "#3B82F6",
            "msp_name": None,   # wired up in Phase 4 when MSP profiles land
        },
        "rating": rating,
        "previous_rating": previous_rating,
        "rating_delta_str": rating_delta_str,
        "grade_color": _GRADE_COLORS[rating.overall_grade],
        "categories": _category_rows(rating),
        "findings": ordered,
        "top_findings": ordered[:TOP_FINDINGS_LIMIT],
        "recommendations": _build_recommendations(rating, ordered),
        "generated_at_str": generated_at.strftime("%Y-%m-%d %H:%M UTC"),
        "scan_period_str": scan_period_str,
    }
    return ctx


# ── Rendering ───────────────────────────────────────────────
def render_html(*, context: dict[str, Any], report_type: ReportType) -> str:
    template_name = (
        "report_executive.html"
        if report_type is ReportType.EXECUTIVE
        else "report_technical.html"
    )
    return _env.get_template(template_name).render(**context)


def render_pdf(html: str) -> bytes:
    """HTML → PDF bytes via WeasyPrint.

    Imported lazily so that importing this module doesn't fail on systems
    without the native libs (Cairo/Pango). Tests that don't hit render_pdf
    keep working.
    """
    from weasyprint import HTML  # type: ignore[import-not-found]

    return HTML(string=html).write_pdf() or b""


# ── Public API ──────────────────────────────────────────────
async def generate_report_pdf(
    session: AsyncSession,
    *,
    tenant_id,
    scan_job_id,
    report_type: ReportType,
) -> tuple[bytes, str]:
    """Produce the PDF bytes + a human-readable title. Raises ValueError on
    missing rating / scan job."""
    tenant, scan_job, rating, previous, findings = await _load_inputs(
        session, tenant_id=tenant_id, scan_job_id=scan_job_id
    )
    context = build_context(
        tenant=tenant,
        scan_job=scan_job,
        rating=rating,
        previous_rating=previous,
        findings=findings,
        report_type=report_type,
    )
    html = render_html(context=context, report_type=report_type)
    pdf_bytes = render_pdf(html)

    logger.info(
        "report_generated",
        tenant_id=str(tenant_id),
        scan_job_id=str(scan_job_id),
        type=report_type.value,
        size=len(pdf_bytes),
    )
    return pdf_bytes, context["title"]


__all__ = [
    "TOP_FINDINGS_LIMIT",
    "build_context",
    "generate_report_pdf",
    "render_html",
    "render_pdf",
]
