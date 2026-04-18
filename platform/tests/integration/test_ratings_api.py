"""Rating API + end-to-end rating creation via the scan pipeline."""

from __future__ import annotations

from decimal import Decimal

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import (
    FindingSeverity,
    FindingSource,
    RatingGrade,
    ScanStatus,
    UserRole,
)
from app.models.rating import Rating
from app.services.normalizer import NormalizedFinding
from tests.conftest import integration
from tests.factories import (
    auth_header,
    make_asset,
    make_scan_job,
    make_tenant,
    make_user,
)


async def _seed_rating(
    db: AsyncSession,
    *,
    tenant_id,
    scan_job_id,
    grade: RatingGrade = RatingGrade.B,
    score: Decimal = Decimal("80.00"),
) -> Rating:
    r = Rating(
        tenant_id=tenant_id,
        scan_job_id=scan_job_id,
        overall_grade=grade,
        overall_score=score,
        patch_score=score,
        network_score=score,
        web_score=score,
        endpoint_score=score,
        email_score=score,
        breach_score=score,
        ransomware_score=score,
    )
    db.add(r)
    await db.commit()
    await db.refresh(r)
    return r


@integration
@pytest.mark.asyncio
class TestCurrentRating:
    async def test_returns_own_latest(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="rate-own-msp")
        admin = await make_user(db_session, email="a@rate.example.com", tenant=msp)
        asset = await make_asset(db_session, tenant=msp, value="rate.example.com")
        job = await make_scan_job(db_session, tenant=msp, asset=asset)
        await _seed_rating(db_session, tenant_id=msp.id, scan_job_id=job.id)

        resp = await client.get("/api/v1/ratings/current", headers=auth_header(admin))
        assert resp.status_code == 200
        body = resp.json()
        assert body["tenant_id"] == str(msp.id)
        assert body["overall_grade"] == "B"

    async def test_404_when_no_rating_yet(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="rate-empty-msp")
        admin = await make_user(db_session, email="a@empty.example.com", tenant=msp)

        resp = await client.get("/api/v1/ratings/current", headers=auth_header(admin))
        assert resp.status_code == 404

    async def test_tenant_scoped_access(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp_a = await make_tenant(db_session, slug="rate-cross-a")
        msp_b = await make_tenant(db_session, slug="rate-cross-b")
        admin_a = await make_user(db_session, email="a@cross-rate.example.com", tenant=msp_a)

        asset_b = await make_asset(db_session, tenant=msp_b, value="cross-b.example.com")
        job_b = await make_scan_job(db_session, tenant=msp_b, asset=asset_b)
        await _seed_rating(db_session, tenant_id=msp_b.id, scan_job_id=job_b.id)

        resp = await client.get(
            f"/api/v1/ratings/current/{msp_b.id}", headers=auth_header(admin_a)
        )
        assert resp.status_code == 403


@integration
@pytest.mark.asyncio
class TestRatingHistory:
    async def test_returns_recent_first(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="hist-msp")
        admin = await make_user(db_session, email="a@hist.example.com", tenant=msp)
        asset = await make_asset(db_session, tenant=msp, value="hist.example.com")

        # Three scans, three ratings with decreasing grades over time.
        grades = [RatingGrade.D, RatingGrade.C, RatingGrade.B]
        for g in grades:
            job = await make_scan_job(db_session, tenant=msp, asset=asset)
            await _seed_rating(db_session, tenant_id=msp.id, scan_job_id=job.id, grade=g)

        resp = await client.get(
            f"/api/v1/ratings/history/{msp.id}", headers=auth_header(admin)
        )
        assert resp.status_code == 200
        grades_returned = [r["overall_grade"] for r in resp.json()]
        # Recent-first means the last-inserted grade comes first.
        assert grades_returned == ["B", "C", "D"]

    async def test_limit_honored(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="hist-limit-msp")
        admin = await make_user(db_session, email="a@hist-l.example.com", tenant=msp)
        asset = await make_asset(db_session, tenant=msp, value="hist-l.example.com")

        for _ in range(5):
            job = await make_scan_job(db_session, tenant=msp, asset=asset)
            await _seed_rating(db_session, tenant_id=msp.id, scan_job_id=job.id)

        resp = await client.get(
            f"/api/v1/ratings/history/{msp.id}",
            headers=auth_header(admin),
            params={"limit": 2},
        )
        assert len(resp.json()) == 2


@integration
@pytest.mark.asyncio
async def test_scan_completion_creates_rating(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End-to-end: running a scan produces a Rating row tied to the scan."""
    from sqlalchemy import select

    from app.integrations.nuclei import NucleiClient
    from app.tasks.scan_tasks import _run_nuclei_scan_async

    msp = await make_tenant(db_session, slug="e2e-rate-msp")
    asset = await make_asset(db_session, tenant=msp, value="e2e.example.com")
    job = await make_scan_job(db_session, tenant=msp, asset=asset)
    job_id = job.id

    # MOCK — see docs/mocks.md row #1.
    async def stub_scan(self, target: str, **_: object) -> list[NormalizedFinding]:
        return [
            NormalizedFinding(
                title="One High",
                severity=FindingSeverity.HIGH,
                source=FindingSource.NUCLEI,
                asset_value=target,
                cve_id="CVE-2024-RATE",
            )
        ]

    monkeypatch.setattr(NucleiClient, "scan", stub_scan)

    result = await _run_nuclei_scan_async(job_id)
    assert result["status"] == "completed"

    await db_session.refresh(job)
    assert job.status is ScanStatus.COMPLETED

    rating = (
        await db_session.execute(select(Rating).where(Rating.scan_job_id == job_id))
    ).scalar_one_or_none()

    assert rating is not None
    assert rating.tenant_id == msp.id
    # One HIGH Nuclei finding → -10 in web_score → 90 there; other finding
    # categories still 100. Ransomware starts at 0 (no questionnaire). Overall
    # should be solidly below 100 but still in A/B territory.
    assert rating.web_score == Decimal("90")
    assert rating.network_score == Decimal("100")
    assert rating.patch_score == Decimal("100")
    assert rating.overall_grade in {RatingGrade.A, RatingGrade.B}
