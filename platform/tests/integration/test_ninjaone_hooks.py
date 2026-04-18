"""NinjaOne sync wiring: after a scan, only Critical+High findings get tickets."""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import FindingSeverity, FindingSource, ScanStatus
from app.models.finding import Finding
from app.services.normalizer import NormalizedFinding
from tests.conftest import integration
from tests.factories import make_asset, make_scan_job, make_tenant


@integration
@pytest.mark.asyncio
async def test_only_critical_and_high_findings_get_tickets(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.integrations.nuclei import NucleiClient
    from app.tasks.scan_tasks import _run_nuclei_scan_async

    msp = await make_tenant(db_session, slug="nj-hook-msp")
    asset = await make_asset(db_session, tenant=msp, value="nj.example.com")
    job = await make_scan_job(db_session, tenant=msp, asset=asset)
    job_id = job.id

    # MOCK — see docs/mocks.md row #1.
    async def stub_scan(self, target: str, **_: object) -> list[NormalizedFinding]:
        return [
            NormalizedFinding(
                title="Crit",
                severity=FindingSeverity.CRITICAL,
                source=FindingSource.NUCLEI,
                asset_value=target,
                cve_id="CVE-2024-CRIT",
            ),
            NormalizedFinding(
                title="Hi",
                severity=FindingSeverity.HIGH,
                source=FindingSource.NUCLEI,
                asset_value=target,
            ),
            NormalizedFinding(
                title="Med",
                severity=FindingSeverity.MEDIUM,
                source=FindingSource.NUCLEI,
                asset_value=target,
            ),
            NormalizedFinding(
                title="Inf",
                severity=FindingSeverity.INFO,
                source=FindingSource.NUCLEI,
                asset_value=target,
            ),
        ]

    monkeypatch.setattr(NucleiClient, "scan", stub_scan)

    # MOCK — see docs/mocks.md row #13 (NinjaOne auto-ticket hook).
    calls: list[tuple[str, FindingSeverity]] = []

    async def fake_push(session, *, tenant, findings) -> int:
        n = 0
        for f in findings:
            if f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH):
                f.ninjaone_ticket_id = f"NJ-{len(calls):04d}"
                calls.append((f.title, f.severity))
                n += 1
        if n:
            await session.commit()
        return n

    monkeypatch.setattr("app.tasks.scan_tasks.push_findings_to_ninjaone", fake_push)

    result = await _run_nuclei_scan_async(job_id)
    assert result["status"] == "completed"

    # Two tickets: one for Critical, one for High.
    assert [sev for _, sev in calls] == [
        FindingSeverity.CRITICAL,
        FindingSeverity.HIGH,
    ]

    rows = (
        await db_session.execute(select(Finding).where(Finding.scan_job_id == job_id))
    ).scalars().all()
    by_title = {f.title: f for f in rows}
    assert by_title["Crit"].ninjaone_ticket_id is not None
    assert by_title["Hi"].ninjaone_ticket_id is not None
    assert by_title["Med"].ninjaone_ticket_id is None
    assert by_title["Inf"].ninjaone_ticket_id is None

    await db_session.refresh(job)
    assert job.status is ScanStatus.COMPLETED


@integration
@pytest.mark.asyncio
async def test_scan_completes_when_ninjaone_unconfigured(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With NinjaOne creds unset (default in tests), the real service
    short-circuits via `_ninjaone_configured()` → scan still completes."""
    from app.integrations.nuclei import NucleiClient
    from app.tasks.scan_tasks import _run_nuclei_scan_async

    msp = await make_tenant(db_session, slug="nj-off-msp")
    asset = await make_asset(db_session, tenant=msp, value="nj-off.example.com")
    job = await make_scan_job(db_session, tenant=msp, asset=asset)
    job_id = job.id

    async def stub_scan(self, target: str, **_: object) -> list[NormalizedFinding]:
        return [
            NormalizedFinding(
                title="Crit",
                severity=FindingSeverity.CRITICAL,
                source=FindingSource.NUCLEI,
                asset_value=target,
            )
        ]

    monkeypatch.setattr(NucleiClient, "scan", stub_scan)

    # NO ninjaone monkeypatch — exercise the real service, which returns 0
    # silently because `NINJAONE_CLIENT_ID` is unset in the test env.
    result = await _run_nuclei_scan_async(job_id)
    assert result["status"] == "completed"

    rows = (
        await db_session.execute(select(Finding).where(Finding.scan_job_id == job_id))
    ).scalars().all()
    assert len(rows) == 1
    # No ticket was issued because NinjaOne is unconfigured.
    assert rows[0].ninjaone_ticket_id is None
