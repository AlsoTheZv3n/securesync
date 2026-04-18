"""ScanSchedule CRUD + scheduler-tick end-to-end."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, time, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import ScanStatus, ScanType, UserRole
from app.models.scan_job import ScanJob
from app.models.scan_schedule import ScanSchedule
from tests.conftest import integration
from tests.factories import (
    auth_header,
    make_asset,
    make_tenant,
    make_user,
)


# ── CRUD + validation ───────────────────────────────────────
@integration
@pytest.mark.asyncio
class TestScheduleCRUD:
    async def test_create_schedule_sets_next_run(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="sch-create")
        admin = await make_user(
            db_session, email="a@sch-create.example.com", tenant=msp
        )
        asset = await make_asset(db_session, tenant=msp, value="sched.example.com")

        resp = await client.post(
            "/api/v1/scan-schedules",
            headers=auth_header(admin),
            json={
                "asset_id": str(asset.id),
                "scan_type": ScanType.FAST.value,
                "cron_expression": "0 3 * * *",
                "timezone": "Europe/Zurich",
                "is_active": True,
            },
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["cron_expression"] == "0 3 * * *"
        assert body["timezone"] == "Europe/Zurich"
        assert body["is_active"] is True
        assert body["next_run_at"]     # set by the engine

    async def test_create_rejects_invalid_cron(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="sch-bad-cron")
        admin = await make_user(
            db_session, email="a@sch-bad.example.com", tenant=msp
        )
        asset = await make_asset(db_session, tenant=msp, value="bad.example.com")

        resp = await client.post(
            "/api/v1/scan-schedules",
            headers=auth_header(admin),
            json={
                "asset_id": str(asset.id),
                "scan_type": ScanType.FAST.value,
                "cron_expression": "not a cron",
                "timezone": "UTC",
            },
        )
        assert resp.status_code == 422

    async def test_create_rejects_bad_timezone(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="sch-bad-tz")
        admin = await make_user(
            db_session, email="a@sch-bad-tz.example.com", tenant=msp
        )
        asset = await make_asset(db_session, tenant=msp, value="badtz.example.com")

        resp = await client.post(
            "/api/v1/scan-schedules",
            headers=auth_header(admin),
            json={
                "asset_id": str(asset.id),
                "scan_type": ScanType.FAST.value,
                "cron_expression": "0 3 * * *",
                "timezone": "Not/A/Zone",
            },
        )
        assert resp.status_code == 422

    async def test_create_rejects_half_blackout(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="sch-half-blk")
        admin = await make_user(
            db_session, email="a@half-blk.example.com", tenant=msp
        )
        asset = await make_asset(db_session, tenant=msp, value="half.example.com")

        resp = await client.post(
            "/api/v1/scan-schedules",
            headers=auth_header(admin),
            json={
                "asset_id": str(asset.id),
                "scan_type": ScanType.FAST.value,
                "cron_expression": "0 * * * *",
                "timezone": "UTC",
                "blackout_start": "09:00:00",
                # no end
            },
        )
        assert resp.status_code == 422

    async def test_list_scoped_to_tenant(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp_a = await make_tenant(db_session, slug="sch-list-a")
        msp_b = await make_tenant(db_session, slug="sch-list-b")
        admin_a = await make_user(
            db_session, email="a@sch-list.example.com", tenant=msp_a
        )

        asset_a = await make_asset(db_session, tenant=msp_a, value="a.example.com")
        asset_b = await make_asset(db_session, tenant=msp_b, value="b.example.com")

        # Seed schedules directly (avoids going through the API for setup).
        db_session.add_all([
            ScanSchedule(
                tenant_id=msp_a.id, asset_id=asset_a.id,
                scan_type=ScanType.FAST, cron_expression="0 * * * *",
                timezone="UTC", is_active=True,
                next_run_at=datetime.now(UTC) + timedelta(minutes=5),
            ),
            ScanSchedule(
                tenant_id=msp_b.id, asset_id=asset_b.id,
                scan_type=ScanType.FAST, cron_expression="0 * * * *",
                timezone="UTC", is_active=True,
                next_run_at=datetime.now(UTC) + timedelta(minutes=5),
            ),
        ])
        await db_session.commit()

        resp = await client.get(
            "/api/v1/scan-schedules", headers=auth_header(admin_a)
        )
        assert resp.status_code == 200
        tenant_ids = {s["tenant_id"] for s in resp.json()}
        assert tenant_ids == {str(msp_a.id)}

    async def test_patch_cron_recomputes_next_run(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="sch-patch")
        admin = await make_user(db_session, email="a@patch.example.com", tenant=msp)
        asset = await make_asset(db_session, tenant=msp, value="patch.example.com")

        create = await client.post(
            "/api/v1/scan-schedules",
            headers=auth_header(admin),
            json={
                "asset_id": str(asset.id),
                "scan_type": ScanType.FAST.value,
                "cron_expression": "0 3 * * *",
                "timezone": "UTC",
            },
        )
        schedule_id = create.json()["id"]
        original_next_run = create.json()["next_run_at"]

        # Change cron to a different time of day.
        patch = await client.patch(
            f"/api/v1/scan-schedules/{schedule_id}",
            headers=auth_header(admin),
            json={"cron_expression": "0 15 * * *"},
        )
        assert patch.status_code == 200
        new_next_run = patch.json()["next_run_at"]
        assert new_next_run != original_next_run

    async def test_customer_readonly_cannot_create(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="sch-ro-msp")
        cust = await make_tenant(db_session, slug="sch-ro-cust", msp_id=msp.id)
        ro = await make_user(
            db_session, email="ro@sch.example.com", tenant=cust,
            role=UserRole.CUSTOMER_READONLY,
        )
        asset = await make_asset(db_session, tenant=cust, value="ro.example.com")

        resp = await client.post(
            "/api/v1/scan-schedules",
            headers=auth_header(ro),
            json={
                "asset_id": str(asset.id),
                "scan_type": ScanType.FAST.value,
                "cron_expression": "0 * * * *",
                "timezone": "UTC",
            },
        )
        assert resp.status_code == 403


# ── Scheduler tick ──────────────────────────────────────────
@integration
@pytest.mark.asyncio
class TestSchedulerTick:
    async def test_due_schedule_dispatches_scan(
        self,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from app.tasks import scheduler_tasks

        msp = await make_tenant(db_session, slug="tick-dispatch")
        asset = await make_asset(
            db_session, tenant=msp, value="tick.example.com"
        )

        # Schedule is already past due: next_run_at is 1 min ago.
        past = datetime.now(UTC) - timedelta(minutes=1)
        schedule = ScanSchedule(
            tenant_id=msp.id,
            asset_id=asset.id,
            scan_type=ScanType.FAST,
            cron_expression="*/5 * * * *",
            timezone="UTC",
            is_active=True,
            next_run_at=past,
        )
        db_session.add(schedule)
        await db_session.commit()
        await db_session.refresh(schedule)

        # MOCK — see docs/mocks.md row #2 (Celery dispatch).
        dispatched: list[str] = []

        class _Fake:
            def __init__(self, i: str) -> None:
                self.id = i

        def fake_delay(scan_job_id: str) -> _Fake:
            dispatched.append(scan_job_id)
            return _Fake(f"fake-{uuid.uuid4().hex[:6]}")

        monkeypatch.setattr(scheduler_tasks.run_nuclei_scan, "delay", fake_delay)

        outcome = await scheduler_tasks.process_one_for_test(
            db_session, schedule.id, datetime.now(UTC)
        )

        assert outcome == "dispatched"
        # A ScanJob exists for this schedule's tenant/asset.
        jobs = (
            await db_session.execute(
                select(ScanJob).where(ScanJob.asset_id == asset.id)
            )
        ).scalars().all()
        assert len(jobs) == 1
        assert jobs[0].status is ScanStatus.QUEUED
        assert dispatched == [str(jobs[0].id)]

        # Schedule bookkeeping updated.
        await db_session.refresh(schedule)
        assert schedule.last_run_at is not None
        assert schedule.next_run_at > past

    async def test_blackout_skips_dispatch(
        self,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from app.tasks import scheduler_tasks

        msp = await make_tenant(db_session, slug="tick-blackout")
        asset = await make_asset(
            db_session, tenant=msp, value="blk.example.com"
        )

        # Force "now" to sit inside a 09:00–17:00 UTC blackout.
        frozen_now = datetime(2026, 4, 18, 10, 0, tzinfo=UTC)
        past = frozen_now - timedelta(minutes=1)

        schedule = ScanSchedule(
            tenant_id=msp.id,
            asset_id=asset.id,
            scan_type=ScanType.FAST,
            cron_expression="*/5 * * * *",
            timezone="UTC",
            is_active=True,
            blackout_start=time(9, 0),
            blackout_end=time(17, 0),
            next_run_at=past,
        )
        db_session.add(schedule)
        await db_session.commit()
        await db_session.refresh(schedule)

        dispatched: list[str] = []

        def fake_delay(scan_job_id: str):
            dispatched.append(scan_job_id)
            class _F: id = "x"
            return _F

        monkeypatch.setattr(scheduler_tasks.run_nuclei_scan, "delay", fake_delay)

        outcome = await scheduler_tasks.process_one_for_test(
            db_session, schedule.id, frozen_now
        )

        assert outcome == "blackout"
        # No scan job was created.
        jobs = (
            await db_session.execute(
                select(ScanJob).where(ScanJob.asset_id == asset.id)
            )
        ).scalars().all()
        assert jobs == []
        assert dispatched == []

        # next_run_at got bumped past the blackout end.
        await db_session.refresh(schedule)
        assert schedule.next_run_at.astimezone(UTC).hour >= 17
