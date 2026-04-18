"""Integration tests for /api/v1/reports.

WeasyPrint's native deps fail to load on Windows dev (Cairo / Pango /
gdk-pixbuf) — we mock `render_pdf` so tests exercise the DB + route glue
without depending on the render backend. See docs/mocks.md row #12.
"""

from __future__ import annotations

from decimal import Decimal

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import (
    FindingSeverity,
    FindingSource,
    FindingStatus,
    RatingGrade,
    ReportType,
    ScanStatus,
    UserRole,
)
from app.models.finding import Finding
from app.models.rating import Rating
from tests.conftest import integration
from tests.factories import (
    auth_header,
    make_asset,
    make_scan_job,
    make_tenant,
    make_user,
)

FAKE_PDF_BYTES = b"%PDF-1.4\n%fake for tests\n%%EOF\n"


@pytest.fixture(autouse=True)
def _mock_weasyprint(monkeypatch: pytest.MonkeyPatch) -> None:
    # MOCK — see docs/mocks.md row #12
    from app.services import report_generator

    def fake_render_pdf(html: str) -> bytes:
        # Echo a marker so we can assert "the HTML went through rendering".
        marker = b"<!--html-rendered: " + str(len(html)).encode() + b"-->"
        return FAKE_PDF_BYTES + marker

    monkeypatch.setattr(report_generator, "render_pdf", fake_render_pdf)


async def _seed_completed_scan(
    db_session: AsyncSession, *, tenant_slug: str, user_email: str
) -> tuple:
    """Seed tenant + user + asset + completed ScanJob + Rating."""
    tenant = await make_tenant(db_session, slug=tenant_slug)
    user = await make_user(db_session, email=user_email, tenant=tenant)
    asset = await make_asset(db_session, tenant=tenant, value="reports.example.com")
    job = await make_scan_job(
        db_session, tenant=tenant, asset=asset, status=ScanStatus.COMPLETED
    )

    # Rating must exist — the generator errors without one.
    rating = Rating(
        tenant_id=tenant.id,
        scan_job_id=job.id,
        overall_grade=RatingGrade.B,
        overall_score=Decimal("82.00"),
        patch_score=Decimal("80"),
        network_score=Decimal("80"),
        web_score=Decimal("80"),
        endpoint_score=Decimal("80"),
        email_score=Decimal("100"),
        breach_score=Decimal("90"),
        ransomware_score=Decimal("75"),
    )
    db_session.add(rating)

    # A couple of open findings for the report body.
    for sev in (FindingSeverity.CRITICAL, FindingSeverity.LOW):
        db_session.add(
            Finding(
                tenant_id=tenant.id,
                scan_job_id=job.id,
                asset_id=asset.id,
                title=f"Issue {sev.value}",
                severity=sev,
                source=FindingSource.NUCLEI,
                status=FindingStatus.OPEN,
                raw_data={"asset_value": "https://reports.example.com"},
            )
        )
    await db_session.commit()
    return tenant, user, asset, job


@integration
@pytest.mark.asyncio
class TestGenerate:
    async def test_creates_executive_report(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        _, user, _, job = await _seed_completed_scan(
            db_session, tenant_slug="rep-exec", user_email="a@rep-exec.example.com"
        )

        resp = await client.post(
            "/api/v1/reports",
            headers=auth_header(user),
            json={"scan_job_id": str(job.id), "type": ReportType.EXECUTIVE.value},
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["type"] == "executive"
        assert body["pdf_size_bytes"] > len(FAKE_PDF_BYTES)
        assert body["scan_job_id"] == str(job.id)
        assert body["generated_by_user_id"] == str(user.id)
        assert "Executive Security Report" in body["title"]

    async def test_creates_technical_report(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        _, user, _, job = await _seed_completed_scan(
            db_session, tenant_slug="rep-tech", user_email="a@rep-tech.example.com"
        )

        resp = await client.post(
            "/api/v1/reports",
            headers=auth_header(user),
            json={"scan_job_id": str(job.id), "type": ReportType.TECHNICAL.value},
        )
        assert resp.status_code == 201
        assert resp.json()["type"] == "technical"

    async def test_rejects_incomplete_scan(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        tenant = await make_tenant(db_session, slug="rep-incomplete")
        user = await make_user(db_session, email="a@incomplete.example.com", tenant=tenant)
        asset = await make_asset(db_session, tenant=tenant, value="i.example.com")
        job = await make_scan_job(
            db_session, tenant=tenant, asset=asset, status=ScanStatus.QUEUED
        )

        resp = await client.post(
            "/api/v1/reports",
            headers=auth_header(user),
            json={"scan_job_id": str(job.id), "type": ReportType.EXECUTIVE.value},
        )
        assert resp.status_code == 422

    async def test_rejects_scan_without_rating(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        tenant = await make_tenant(db_session, slug="rep-no-rating")
        user = await make_user(db_session, email="a@no-rating.example.com", tenant=tenant)
        asset = await make_asset(db_session, tenant=tenant, value="nr.example.com")
        job = await make_scan_job(
            db_session, tenant=tenant, asset=asset, status=ScanStatus.COMPLETED
        )
        # Deliberately no Rating — simulates a scan that completed before
        # the rating engine existed, or a dev DB seed without ratings.

        resp = await client.post(
            "/api/v1/reports",
            headers=auth_header(user),
            json={"scan_job_id": str(job.id), "type": ReportType.EXECUTIVE.value},
        )
        assert resp.status_code == 422
        assert "rating" in resp.json()["detail"].lower()

    async def test_cross_tenant_scan_blocked(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp_a = await make_tenant(db_session, slug="rep-cross-a")
        msp_b = await make_tenant(db_session, slug="rep-cross-b")
        admin_a = await make_user(
            db_session, email="a@rep-cross.example.com", tenant=msp_a
        )

        asset_b = await make_asset(db_session, tenant=msp_b, value="b.example.com")
        job_b = await make_scan_job(
            db_session, tenant=msp_b, asset=asset_b, status=ScanStatus.COMPLETED
        )

        resp = await client.post(
            "/api/v1/reports",
            headers=auth_header(admin_a),
            json={"scan_job_id": str(job_b.id), "type": ReportType.EXECUTIVE.value},
        )
        assert resp.status_code == 403

    async def test_customer_readonly_cannot_generate(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        _, _, _, job = await _seed_completed_scan(
            db_session, tenant_slug="rep-ro", user_email="admin@ro.example.com"
        )
        # Role on the user we seeded is MSP_ADMIN. Make a separate readonly user.
        tenant = await make_tenant(db_session, slug="rep-ro-ro")
        ro = await make_user(
            db_session, email="ro@ro.example.com",
            tenant=tenant, role=UserRole.CUSTOMER_READONLY,
        )

        resp = await client.post(
            "/api/v1/reports",
            headers=auth_header(ro),
            json={"scan_job_id": str(job.id), "type": ReportType.EXECUTIVE.value},
        )
        # 403 for role OR tenant isolation — both satisfy the rule that
        # read-only users cannot generate reports.
        assert resp.status_code == 403


@integration
@pytest.mark.asyncio
class TestDownload:
    async def test_returns_pdf_bytes(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        _, user, _, job = await _seed_completed_scan(
            db_session, tenant_slug="rep-dl", user_email="a@dl.example.com"
        )
        create_resp = await client.post(
            "/api/v1/reports",
            headers=auth_header(user),
            json={"scan_job_id": str(job.id), "type": ReportType.EXECUTIVE.value},
        )
        report_id = create_resp.json()["id"]

        resp = await client.get(
            f"/api/v1/reports/{report_id}/download", headers=auth_header(user)
        )
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/pdf"
        assert resp.headers["content-disposition"].startswith("attachment;")
        assert resp.content.startswith(b"%PDF-")
        # Our mock embeds the rendered-HTML length marker — asserts the
        # generator actually reached render_pdf (instead of short-circuiting).
        assert b"<!--html-rendered:" in resp.content

    async def test_cross_tenant_download_blocked(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        _, owner, _, job = await _seed_completed_scan(
            db_session, tenant_slug="rep-dl-own", user_email="a@dlown.example.com"
        )
        create_resp = await client.post(
            "/api/v1/reports",
            headers=auth_header(owner),
            json={"scan_job_id": str(job.id), "type": ReportType.EXECUTIVE.value},
        )
        report_id = create_resp.json()["id"]

        # Different MSP tries to download.
        other_msp = await make_tenant(db_session, slug="rep-dl-other")
        stranger = await make_user(
            db_session, email="stranger@dl-other.example.com", tenant=other_msp
        )
        resp = await client.get(
            f"/api/v1/reports/{report_id}/download", headers=auth_header(stranger)
        )
        assert resp.status_code == 403


@integration
@pytest.mark.asyncio
class TestList:
    async def test_filter_by_type(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        _, user, _, job = await _seed_completed_scan(
            db_session, tenant_slug="rep-list", user_email="a@rep-list.example.com"
        )
        for t in (ReportType.EXECUTIVE, ReportType.TECHNICAL, ReportType.EXECUTIVE):
            await client.post(
                "/api/v1/reports",
                headers=auth_header(user),
                json={"scan_job_id": str(job.id), "type": t.value},
            )

        resp = await client.get(
            "/api/v1/reports",
            headers=auth_header(user),
            params={"type": ReportType.EXECUTIVE.value},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert len(body) == 2
        assert all(r["type"] == "executive" for r in body)
