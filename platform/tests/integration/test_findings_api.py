"""Tests for /api/v1/findings — list/filter, get, status update."""

from __future__ import annotations

from decimal import Decimal

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import (
    FindingSeverity,
    FindingSource,
    FindingStatus,
    UserRole,
)
from app.models.finding import Finding
from tests.conftest import integration
from tests.factories import (
    auth_header,
    make_asset,
    make_scan_job,
    make_tenant,
    make_user,
)


async def _seed_finding(
    db: AsyncSession,
    *,
    tenant_id,
    scan_job_id,
    asset_id,
    title: str = "F",
    severity: FindingSeverity = FindingSeverity.MEDIUM,
    source: FindingSource = FindingSource.NUCLEI,
    status: FindingStatus = FindingStatus.OPEN,
    cve_id: str | None = None,
) -> Finding:
    f = Finding(
        tenant_id=tenant_id,
        scan_job_id=scan_job_id,
        asset_id=asset_id,
        title=title,
        severity=severity,
        source=source,
        status=status,
        cve_id=cve_id,
        cvss_score=Decimal("5.0") if cve_id else None,
    )
    db.add(f)
    await db.commit()
    await db.refresh(f)
    return f


@integration
@pytest.mark.asyncio
class TestListFindings:
    async def test_returns_only_own_tenant(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="find-list-msp")
        admin = await make_user(db_session, email="a@find-list.example.com", tenant=msp)
        asset = await make_asset(db_session, tenant=msp, value="x.example.com")
        job = await make_scan_job(db_session, tenant=msp, asset=asset)
        await _seed_finding(
            db_session, tenant_id=msp.id, scan_job_id=job.id, asset_id=asset.id, title="A"
        )

        # Foreign tenant — must not appear.
        other = await make_tenant(db_session, slug="find-list-other")
        other_asset = await make_asset(db_session, tenant=other, value="y.example.com")
        other_job = await make_scan_job(db_session, tenant=other, asset=other_asset)
        await _seed_finding(
            db_session,
            tenant_id=other.id,
            scan_job_id=other_job.id,
            asset_id=other_asset.id,
            title="OTHER",
        )

        resp = await client.get("/api/v1/findings", headers=auth_header(admin))
        assert resp.status_code == 200
        titles = [f["title"] for f in resp.json()]
        assert titles == ["A"]

    async def test_filter_by_severity(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="find-sev-msp")
        admin = await make_user(db_session, email="a@find-sev.example.com", tenant=msp)
        asset = await make_asset(db_session, tenant=msp, value="sev.example.com")
        job = await make_scan_job(db_session, tenant=msp, asset=asset)
        await _seed_finding(
            db_session, tenant_id=msp.id, scan_job_id=job.id, asset_id=asset.id,
            title="crit", severity=FindingSeverity.CRITICAL,
        )
        await _seed_finding(
            db_session, tenant_id=msp.id, scan_job_id=job.id, asset_id=asset.id,
            title="low", severity=FindingSeverity.LOW,
        )

        resp = await client.get(
            "/api/v1/findings",
            headers=auth_header(admin),
            params={"severity": FindingSeverity.CRITICAL.value},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert len(body) == 1
        assert body[0]["title"] == "crit"

    async def test_filter_by_cve(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="find-cve-msp")
        admin = await make_user(db_session, email="a@find-cve.example.com", tenant=msp)
        asset = await make_asset(db_session, tenant=msp, value="cve.example.com")
        job = await make_scan_job(db_session, tenant=msp, asset=asset)
        await _seed_finding(
            db_session, tenant_id=msp.id, scan_job_id=job.id, asset_id=asset.id,
            title="match", cve_id="CVE-2024-1234",
        )
        await _seed_finding(
            db_session, tenant_id=msp.id, scan_job_id=job.id, asset_id=asset.id,
            title="other", cve_id="CVE-2024-9999",
        )

        # Test case-insensitive match too.
        resp = await client.get(
            "/api/v1/findings",
            headers=auth_header(admin),
            params={"cve_id": "cve-2024-1234"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert len(body) == 1
        assert body[0]["title"] == "match"


@integration
@pytest.mark.asyncio
class TestUpdateFinding:
    async def test_set_resolved_succeeds(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="upd-find-msp")
        admin = await make_user(db_session, email="a@upd-find.example.com", tenant=msp)
        asset = await make_asset(db_session, tenant=msp, value="upd.example.com")
        job = await make_scan_job(db_session, tenant=msp, asset=asset)
        f = await _seed_finding(
            db_session, tenant_id=msp.id, scan_job_id=job.id, asset_id=asset.id
        )

        resp = await client.patch(
            f"/api/v1/findings/{f.id}",
            headers=auth_header(admin),
            json={"status": FindingStatus.RESOLVED.value},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == FindingStatus.RESOLVED.value

    async def test_false_positive_requires_notes(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="fp-msp")
        admin = await make_user(db_session, email="a@fp.example.com", tenant=msp)
        asset = await make_asset(db_session, tenant=msp, value="fp.example.com")
        job = await make_scan_job(db_session, tenant=msp, asset=asset)
        f = await _seed_finding(
            db_session, tenant_id=msp.id, scan_job_id=job.id, asset_id=asset.id
        )

        # Missing notes → 422.
        bad = await client.patch(
            f"/api/v1/findings/{f.id}",
            headers=auth_header(admin),
            json={"status": FindingStatus.FALSE_POSITIVE.value},
        )
        assert bad.status_code == 422

        # With notes → 200.
        good = await client.patch(
            f"/api/v1/findings/{f.id}",
            headers=auth_header(admin),
            json={
                "status": FindingStatus.FALSE_POSITIVE.value,
                "resolution_notes": "Tested manually, not exploitable on our nginx config",
            },
        )
        assert good.status_code == 200
        assert good.json()["status"] == FindingStatus.FALSE_POSITIVE.value

    async def test_customer_readonly_cannot_patch(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="ro-find-msp")
        cust = await make_tenant(db_session, slug="ro-find-cust", msp_id=msp.id)
        ro = await make_user(
            db_session, email="ro@find.example.com", tenant=cust, role=UserRole.CUSTOMER_READONLY
        )
        asset = await make_asset(db_session, tenant=cust, value="ro-find.example.com")
        job = await make_scan_job(db_session, tenant=cust, asset=asset)
        f = await _seed_finding(
            db_session, tenant_id=cust.id, scan_job_id=job.id, asset_id=asset.id
        )

        resp = await client.patch(
            f"/api/v1/findings/{f.id}",
            headers=auth_header(ro),
            json={"status": FindingStatus.RESOLVED.value},
        )
        assert resp.status_code == 403


@integration
@pytest.mark.asyncio
async def test_cross_tenant_finding_access_blocked(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    msp_a = await make_tenant(db_session, slug="x-find-a")
    msp_b = await make_tenant(db_session, slug="x-find-b")
    admin_a = await make_user(db_session, email="a@x-find.example.com", tenant=msp_a)

    asset_b = await make_asset(db_session, tenant=msp_b, value="x-other.example.com")
    job_b = await make_scan_job(db_session, tenant=msp_b, asset=asset_b)
    f_b = await _seed_finding(
        db_session, tenant_id=msp_b.id, scan_job_id=job_b.id, asset_id=asset_b.id
    )

    resp = await client.get(f"/api/v1/findings/{f_b.id}", headers=auth_header(admin_a))
    assert resp.status_code == 403
