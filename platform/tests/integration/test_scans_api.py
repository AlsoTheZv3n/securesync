"""Tests for /api/v1/scans — focused on the API contract.

The Celery dispatch is mocked here (see docs/mocks.md row #2). Worker-side
behaviour — what happens after `.delay()` returns — is covered by
test_scan_task.py with a different fixture set.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import AssetType, ScanStatus, ScanType
from tests.conftest import integration
from tests.factories import auth_header, make_asset, make_scan_job, make_tenant, make_user


# ── MOCK — see docs/mocks.md row #2 ─────────────────────────
# We intercept the .delay() of every scanner Celery task so:
#   - tests don't depend on a running Redis broker / Celery worker, AND
#   - we can assert which task was enqueued with which scan_job_id.
# Production swap: drop this fixture once a worker runs alongside CI.
class _FakeAsyncResult:
    def __init__(self, task_id: str) -> None:
        self.id = task_id


@pytest.fixture
def dispatch_calls(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    """Captures each (task_name, scan_job_id) the API tried to enqueue."""
    from app.api.v1 import scans as scans_module

    captured: list[tuple[str, str]] = []

    def make_fake(task_name: str):
        def fake_delay(scan_job_id: str) -> _FakeAsyncResult:
            captured.append((task_name, scan_job_id))
            return _FakeAsyncResult(task_id=f"fake-task-{uuid.uuid4().hex[:8]}")
        return fake_delay

    # MOCK — see docs/mocks.md row #2
    monkeypatch.setattr(scans_module.run_nuclei_scan, "delay", make_fake("nuclei"))
    monkeypatch.setattr(scans_module.run_openvas_scan, "delay", make_fake("openvas"))
    monkeypatch.setattr(scans_module.run_zap_scan, "delay", make_fake("zap"))
    monkeypatch.setattr(scans_module.run_wazuh_scan, "delay", make_fake("wazuh"))
    return captured


# ── Tests ───────────────────────────────────────────────────
@integration
@pytest.mark.asyncio
class TestCreateScan:
    async def test_enqueues_nuclei_for_fast_type(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        dispatch_calls: list[tuple[str, str]],
    ) -> None:
        msp = await make_tenant(db_session, slug="scan-msp")
        admin = await make_user(db_session, email="a@scan.example.com", tenant=msp)
        asset = await make_asset(db_session, tenant=msp, value="enqueue.example.com")

        resp = await client.post(
            "/api/v1/scans",
            headers=auth_header(admin),
            json={"asset_id": str(asset.id), "scan_type": ScanType.FAST.value},
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["scan_type"] == ScanType.FAST.value
        assert body["status"] == ScanStatus.QUEUED.value
        assert body["asset_id"] == str(asset.id)
        assert body["celery_task_id"] is not None

        assert dispatch_calls == [("nuclei", body["id"])]

    async def test_enqueues_openvas_for_external_full_type(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        dispatch_calls: list[tuple[str, str]],
    ) -> None:
        msp = await make_tenant(db_session, slug="ov-scan-msp")
        admin = await make_user(db_session, email="a@ov-scan.example.com", tenant=msp)
        asset = await make_asset(db_session, tenant=msp, value="openvas-target.example.com")

        resp = await client.post(
            "/api/v1/scans",
            headers=auth_header(admin),
            json={"asset_id": str(asset.id), "scan_type": ScanType.EXTERNAL_FULL.value},
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["scan_type"] == ScanType.EXTERNAL_FULL.value
        assert body["status"] == ScanStatus.QUEUED.value
        assert body["celery_task_id"] is not None

        assert dispatch_calls == [("openvas", body["id"])]

    async def test_enqueues_zap_for_web_app_type(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        dispatch_calls: list[tuple[str, str]],
    ) -> None:
        msp = await make_tenant(db_session, slug="zap-scan-msp")
        admin = await make_user(db_session, email="a@zap-scan.example.com", tenant=msp)
        asset = await make_asset(db_session, tenant=msp, value="webapp.example.com")

        resp = await client.post(
            "/api/v1/scans",
            headers=auth_header(admin),
            json={"asset_id": str(asset.id), "scan_type": ScanType.WEB_APP.value},
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["scan_type"] == ScanType.WEB_APP.value
        assert body["status"] == ScanStatus.QUEUED.value
        assert body["celery_task_id"] is not None

        assert dispatch_calls == [("zap", body["id"])]

    async def test_enqueues_wazuh_for_internal_type(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        dispatch_calls: list[tuple[str, str]],
    ) -> None:
        msp = await make_tenant(db_session, slug="wazuh-scan-msp")
        admin = await make_user(db_session, email="a@wazuh-scan.example.com", tenant=msp)
        asset = await make_asset(
            db_session, tenant=msp, value="agent-001", type=AssetType.INTERNAL_ENDPOINT,
        )

        resp = await client.post(
            "/api/v1/scans",
            headers=auth_header(admin),
            json={"asset_id": str(asset.id), "scan_type": ScanType.INTERNAL.value},
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["scan_type"] == ScanType.INTERNAL.value
        assert body["status"] == ScanStatus.QUEUED.value
        assert body["celery_task_id"] is not None
        assert dispatch_calls == [("wazuh", body["id"])]

    async def test_cross_tenant_asset_blocked(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        dispatch_calls: list[tuple[str, str]],
    ) -> None:
        msp_a = await make_tenant(db_session, slug="scan-cross-a")
        msp_b = await make_tenant(db_session, slug="scan-cross-b")
        cust_b = await make_tenant(db_session, slug="scan-cross-cust", msp_id=msp_b.id)
        asset_b = await make_asset(db_session, tenant=cust_b, value="b-only.example.com")
        admin_a = await make_user(db_session, email="a@cross-scan.example.com", tenant=msp_a)

        resp = await client.post(
            "/api/v1/scans",
            headers=auth_header(admin_a),
            json={"asset_id": str(asset_b.id), "scan_type": ScanType.FAST.value},
        )
        assert resp.status_code == 403
        assert dispatch_calls == []

    async def test_customer_readonly_cannot_scan(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        dispatch_calls: list[tuple[str, str]],
    ) -> None:
        from app.models.enums import UserRole

        msp = await make_tenant(db_session, slug="ro-scan-msp")
        cust = await make_tenant(db_session, slug="ro-scan-cust", msp_id=msp.id)
        ro = await make_user(
            db_session,
            email="ro@scan.example.com",
            tenant=cust,
            role=UserRole.CUSTOMER_READONLY,
        )
        asset = await make_asset(db_session, tenant=cust, value="ro.example.com")

        resp = await client.post(
            "/api/v1/scans",
            headers=auth_header(ro),
            json={"asset_id": str(asset.id), "scan_type": ScanType.FAST.value},
        )
        assert resp.status_code == 403
        assert dispatch_calls == []


@integration
@pytest.mark.asyncio
class TestListAndGetScan:
    async def test_list_scoped_to_tenant(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="list-scan-msp")
        admin = await make_user(db_session, email="a@list-scan.example.com", tenant=msp)
        asset = await make_asset(db_session, tenant=msp, value="list.example.com")
        await make_scan_job(db_session, tenant=msp, asset=asset)
        await make_scan_job(db_session, tenant=msp, asset=asset)

        # Foreign tenant — must not appear.
        other = await make_tenant(db_session, slug="list-scan-other")
        other_asset = await make_asset(db_session, tenant=other, value="other.example.com")
        await make_scan_job(db_session, tenant=other, asset=other_asset)

        resp = await client.get("/api/v1/scans", headers=auth_header(admin))
        assert resp.status_code == 200
        body = resp.json()
        assert len(body) == 2
        assert all(j["tenant_id"] == str(msp.id) for j in body)

    async def test_get_scan_includes_findings_count(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        from app.models.enums import FindingSeverity, FindingSource
        from app.models.finding import Finding

        msp = await make_tenant(db_session, slug="get-scan-msp")
        admin = await make_user(db_session, email="a@get-scan.example.com", tenant=msp)
        asset = await make_asset(db_session, tenant=msp, value="get.example.com")
        job = await make_scan_job(db_session, tenant=msp, asset=asset)

        # Three findings under this scan.
        for i in range(3):
            db_session.add(
                Finding(
                    tenant_id=msp.id,
                    scan_job_id=job.id,
                    asset_id=asset.id,
                    title=f"Finding {i}",
                    severity=FindingSeverity.LOW,
                    source=FindingSource.NUCLEI,
                )
            )
        await db_session.commit()

        resp = await client.get(f"/api/v1/scans/{job.id}", headers=auth_header(admin))
        assert resp.status_code == 200
        body = resp.json()
        assert body["findings_count"] == 3

    async def test_filter_by_status(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="filter-scan-msp")
        admin = await make_user(db_session, email="a@filter-scan.example.com", tenant=msp)
        asset = await make_asset(db_session, tenant=msp, value="filter.example.com")
        await make_scan_job(db_session, tenant=msp, asset=asset, status=ScanStatus.QUEUED)
        await make_scan_job(
            db_session, tenant=msp, asset=asset, status=ScanStatus.COMPLETED
        )

        resp = await client.get(
            "/api/v1/scans",
            headers=auth_header(admin),
            params={"status": ScanStatus.QUEUED.value},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert len(body) == 1
        assert body[0]["status"] == ScanStatus.QUEUED.value
