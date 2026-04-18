"""Template-rendering tests — Jinja only, no WeasyPrint.

The generator splits pure (`build_context` / `render_html`) from impure
(`render_pdf`). These tests exercise the pure half exhaustively so
regressions in the template layout surface as fast failures.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

import pytest

from app.models.asset import Asset
from app.models.enums import (
    AssetType,
    FindingSeverity,
    FindingSource,
    FindingStatus,
    RatingGrade,
    ReportType,
    ScanStatus,
    ScanType,
)
from app.models.finding import Finding
from app.models.rating import Rating
from app.models.scan_job import ScanJob
from app.models.tenant import Tenant
from app.services.report_generator import (
    TOP_FINDINGS_LIMIT,
    build_context,
    render_html,
)


def _make_tenant(**overrides) -> Tenant:
    defaults: dict = dict(
        id=uuid4(),
        name="Acme Corp",
        slug="acme",
        primary_color="#3B82F6",
        logo_url=None,
        custom_domain=None,
    )
    defaults.update(overrides)
    return Tenant(**defaults)


def _make_scan_job(tenant_id, **overrides) -> ScanJob:
    defaults: dict = dict(
        id=uuid4(),
        tenant_id=tenant_id,
        asset_id=uuid4(),
        scan_type=ScanType.FAST,
        status=ScanStatus.COMPLETED,
        completed_at=datetime(2026, 4, 18, 12, 0, tzinfo=UTC),
    )
    defaults.update(overrides)
    return ScanJob(**defaults)


def _make_rating(tenant_id, scan_job_id, **overrides) -> Rating:
    # Default scores are all >= 75 so baseline tests produce zero
    # recommendations. Individual tests lower specific scores to exercise
    # the recommendation builder.
    defaults: dict = dict(
        id=uuid4(),
        tenant_id=tenant_id,
        scan_job_id=scan_job_id,
        overall_grade=RatingGrade.B,
        overall_score=Decimal("85.00"),
        patch_score=Decimal("85"),
        network_score=Decimal("85"),
        web_score=Decimal("85"),
        endpoint_score=Decimal("90"),
        email_score=Decimal("100"),
        breach_score=Decimal("90"),
        ransomware_score=Decimal("80"),
    )
    defaults.update(overrides)
    return Rating(**defaults)


def _make_finding(tenant_id, scan_job_id, asset_id, **overrides) -> Finding:
    defaults: dict = dict(
        id=uuid4(),
        tenant_id=tenant_id,
        scan_job_id=scan_job_id,
        asset_id=asset_id,
        title="Example finding",
        severity=FindingSeverity.MEDIUM,
        status=FindingStatus.OPEN,
        source=FindingSource.NUCLEI,
        raw_data={"asset_value": "https://target.example.com"},
    )
    defaults.update(overrides)
    return Finding(**defaults)


class TestBuildContext:
    def test_basic_shape(self) -> None:
        tenant = _make_tenant()
        job = _make_scan_job(tenant.id)
        rating = _make_rating(tenant.id, job.id)

        ctx = build_context(
            tenant=tenant,
            scan_job=job,
            rating=rating,
            previous_rating=None,
            findings=[],
            report_type=ReportType.EXECUTIVE,
        )
        assert ctx["tenant"] is tenant
        assert ctx["rating"] is rating
        assert ctx["top_findings"] == []
        assert ctx["recommendations"] == []
        assert ctx["branding"]["primary_color"] == "#3B82F6"
        assert ctx["grade_color"] == "#84CC16"   # Grade B → lime

    def test_delta_string_positive_sign(self) -> None:
        tenant = _make_tenant()
        job = _make_scan_job(tenant.id)
        prev = _make_rating(
            tenant.id, uuid4(),
            overall_score=Decimal("75"), overall_grade=RatingGrade.B,
        )
        rating = _make_rating(tenant.id, job.id, overall_score=Decimal("85"))

        ctx = build_context(
            tenant=tenant,
            scan_job=job,
            rating=rating,
            previous_rating=prev,
            findings=[],
            report_type=ReportType.EXECUTIVE,
        )
        assert ctx["rating_delta_str"] == "+10 points"

    def test_findings_sorted_worst_first(self) -> None:
        tenant = _make_tenant()
        job = _make_scan_job(tenant.id)
        rating = _make_rating(tenant.id, job.id)

        f_low = _make_finding(
            tenant.id, job.id, uuid4(),
            title="low", severity=FindingSeverity.LOW,
        )
        f_crit = _make_finding(
            tenant.id, job.id, uuid4(),
            title="critical", severity=FindingSeverity.CRITICAL,
        )
        f_high = _make_finding(
            tenant.id, job.id, uuid4(),
            title="high", severity=FindingSeverity.HIGH,
        )

        ctx = build_context(
            tenant=tenant,
            scan_job=job,
            rating=rating,
            previous_rating=None,
            findings=[f_low, f_crit, f_high],
            report_type=ReportType.TECHNICAL,
        )
        titles = [f.title for f in ctx["findings"]]
        assert titles == ["critical", "high", "low"]

    def test_top_findings_capped(self) -> None:
        tenant = _make_tenant()
        job = _make_scan_job(tenant.id)
        rating = _make_rating(tenant.id, job.id)
        asset_id = uuid4()
        fs = [
            _make_finding(tenant.id, job.id, asset_id, title=f"f{i}")
            for i in range(TOP_FINDINGS_LIMIT + 5)
        ]
        ctx = build_context(
            tenant=tenant,
            scan_job=job,
            rating=rating,
            previous_rating=None,
            findings=fs,
            report_type=ReportType.EXECUTIVE,
        )
        assert len(ctx["top_findings"]) == TOP_FINDINGS_LIMIT
        assert len(ctx["findings"]) == TOP_FINDINGS_LIMIT + 5

    def test_recommendations_flag_criticals(self) -> None:
        tenant = _make_tenant()
        job = _make_scan_job(tenant.id)
        # Low patch score → one category hint; plus a Critical → first line
        rating = _make_rating(
            tenant.id, job.id,
            patch_score=Decimal("40"),
        )
        asset_id = uuid4()
        findings = [
            _make_finding(
                tenant.id, job.id, asset_id,
                severity=FindingSeverity.CRITICAL,
            )
        ]
        ctx = build_context(
            tenant=tenant,
            scan_job=job,
            rating=rating,
            previous_rating=None,
            findings=findings,
            report_type=ReportType.EXECUTIVE,
        )
        recs = ctx["recommendations"]
        assert any("1 critical finding" in r for r in recs)
        assert any("patch management" in r.lower() for r in recs)

    def test_no_recommendations_when_all_scores_good(self) -> None:
        tenant = _make_tenant()
        job = _make_scan_job(tenant.id)
        rating = _make_rating(
            tenant.id, job.id,
            patch_score=Decimal("95"),
            network_score=Decimal("95"),
            web_score=Decimal("95"),
            breach_score=Decimal("95"),
        )
        ctx = build_context(
            tenant=tenant,
            scan_job=job,
            rating=rating,
            previous_rating=None,
            findings=[],
            report_type=ReportType.EXECUTIVE,
        )
        assert ctx["recommendations"] == []


class TestRenderHtml:
    def test_executive_contains_rating_and_tenant_name(self) -> None:
        import re

        tenant = _make_tenant(name="Acme Corp")
        job = _make_scan_job(tenant.id)
        rating = _make_rating(tenant.id, job.id, overall_grade=RatingGrade.B)

        ctx = build_context(
            tenant=tenant,
            scan_job=job,
            rating=rating,
            previous_rating=None,
            findings=[],
            report_type=ReportType.EXECUTIVE,
        )
        html = render_html(context=ctx, report_type=ReportType.EXECUTIVE)

        assert "Acme Corp" in html
        assert "Executive" in ctx["title"]
        # Rating-badge div wraps the grade letter (whitespace-tolerant).
        assert re.search(r'class="rating-badge"[^>]*>\s*B\s*<', html) is not None
        assert "Category Breakdown" in html
        assert "Patch management" in html

    def test_technical_contains_all_findings_and_cvss(self) -> None:
        tenant = _make_tenant()
        job = _make_scan_job(tenant.id)
        rating = _make_rating(tenant.id, job.id)
        asset_id = uuid4()
        findings = [
            _make_finding(
                tenant.id, job.id, asset_id,
                title="Nginx version leak",
                severity=FindingSeverity.LOW,
                cve_id="CVE-2024-1234",
                cvss_score=Decimal("3.1"),
                description="The server banner exposes nginx/1.18.",
                remediation="Set `server_tokens off`.",
            )
        ]
        ctx = build_context(
            tenant=tenant,
            scan_job=job,
            rating=rating,
            previous_rating=None,
            findings=findings,
            report_type=ReportType.TECHNICAL,
        )
        html = render_html(context=ctx, report_type=ReportType.TECHNICAL)

        assert "Nginx version leak" in html
        assert "CVE-2024-1234" in html
        assert "3.1" in html
        assert "server_tokens off" in html
        assert "nginx/1.18" in html

    def test_logo_rendered_when_tenant_has_url(self) -> None:
        tenant = _make_tenant(logo_url="https://cdn.example.com/logo.png")
        job = _make_scan_job(tenant.id)
        rating = _make_rating(tenant.id, job.id)

        ctx = build_context(
            tenant=tenant,
            scan_job=job,
            rating=rating,
            previous_rating=None,
            findings=[],
            report_type=ReportType.EXECUTIVE,
        )
        html = render_html(context=ctx, report_type=ReportType.EXECUTIVE)
        assert 'src="https://cdn.example.com/logo.png"' in html

    def test_primary_color_injected(self) -> None:
        tenant = _make_tenant(primary_color="#c0ffee")
        job = _make_scan_job(tenant.id)
        rating = _make_rating(tenant.id, job.id)

        ctx = build_context(
            tenant=tenant,
            scan_job=job,
            rating=rating,
            previous_rating=None,
            findings=[],
            report_type=ReportType.EXECUTIVE,
        )
        html = render_html(context=ctx, report_type=ReportType.EXECUTIVE)
        assert "#c0ffee" in html

    def test_escaping_prevents_template_injection(self) -> None:
        """A finding title with angle brackets must not break the HTML."""
        tenant = _make_tenant()
        job = _make_scan_job(tenant.id)
        rating = _make_rating(tenant.id, job.id)
        f = _make_finding(
            tenant.id, job.id, uuid4(),
            title="<script>alert(1)</script>",
        )
        ctx = build_context(
            tenant=tenant,
            scan_job=job,
            rating=rating,
            previous_rating=None,
            findings=[f],
            report_type=ReportType.TECHNICAL,
        )
        html = render_html(context=ctx, report_type=ReportType.TECHNICAL)
        # Raw tag must be escaped.
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
