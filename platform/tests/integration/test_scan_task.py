"""End-to-end test of `_run_nuclei_scan_async` with the Nuclei subprocess mocked.

What this verifies:
  - The async task transitions the ScanJob through QUEUED → RUNNING → COMPLETED.
  - Returned NormalizedFindings get persisted as Finding rows.
  - On ExternalServiceError the job is marked FAILED with the error message.

What this does NOT verify:
  - That the real `nuclei` binary works (covered by Phase 2 staging tests with
    a real binary on the worker host).
  - That Celery dispatches correctly via Redis (covered by `test_scans_api.py`
    which asserts `.delay()` was called with the right args).

See docs/mocks.md row #1 for the rationale + production-swap recipe.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ExternalServiceError
from app.models.enums import FindingSeverity, FindingSource, ScanStatus
from app.models.finding import Finding
from app.services.normalizer import NormalizedFinding
from app.tasks.scan_tasks import _run_nuclei_scan_async
from tests.conftest import integration
from tests.factories import make_asset, make_scan_job, make_tenant


# ── MOCK — see docs/mocks.md row #1 ─────────────────────────
# The real NucleiClient.scan() spawns the Go binary as a subprocess and
# requires it on PATH plus network egress. We replace it with a deterministic
# async function so this test exercises only OUR persistence + state-machine
# logic. To swap to production behaviour: install nuclei, drop the
# `monkeypatch.setattr(NucleiClient, "scan", ...)` line.
async def _stub_nuclei_findings(_self, _target: str, **_kwargs) -> list[NormalizedFinding]:
    return [
        NormalizedFinding(
            title="Exposed git config",
            severity=FindingSeverity.MEDIUM,
            source=FindingSource.NUCLEI,
            asset_value="https://target.test/.git/config",
            cve_id="CVE-2024-99999",
        ),
        NormalizedFinding(
            title="nginx version disclosure",
            severity=FindingSeverity.INFO,
            source=FindingSource.NUCLEI,
            asset_value="https://target.example.com",
        ),
    ]


async def _stub_nuclei_failure(_self, _target: str, **_kwargs) -> list[NormalizedFinding]:
    raise ExternalServiceError("nuclei binary not found on PATH: nuclei")


@integration
@pytest.mark.asyncio
async def test_async_task_persists_findings(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    msp = await make_tenant(db_session, slug="task-success-msp")
    asset = await make_asset(db_session, tenant=msp, value="success.example.com")
    job = await make_scan_job(db_session, tenant=msp, asset=asset)
    job_id = job.id

    # MOCK — see docs/mocks.md row #1
    from app.integrations.nuclei import NucleiClient

    monkeypatch.setattr(NucleiClient, "scan", _stub_nuclei_findings)

    result = await _run_nuclei_scan_async(job_id)

    assert result == {"scan_job_id": str(job_id), "findings": 2, "status": "completed"}

    # Worker committed via its own session — refresh ours to see the changes.
    await db_session.refresh(job)
    assert job.status is ScanStatus.COMPLETED
    assert job.started_at is not None
    assert job.completed_at is not None
    assert job.error_message is None

    findings = (
        await db_session.execute(select(Finding).where(Finding.scan_job_id == job_id))
    ).scalars().all()
    assert len(findings) == 2
    titles = {f.title for f in findings}
    assert titles == {"Exposed git config", "nginx version disclosure"}
    # CVE got attached to the right finding.
    cve_finding = next(f for f in findings if f.title == "Exposed git config")
    assert cve_finding.cve_id == "CVE-2024-99999"


@integration
@pytest.mark.asyncio
async def test_async_task_marks_failed_on_external_error(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    msp = await make_tenant(db_session, slug="task-fail-msp")
    asset = await make_asset(db_session, tenant=msp, value="fail.example.com")
    job = await make_scan_job(db_session, tenant=msp, asset=asset)
    job_id = job.id

    # MOCK — see docs/mocks.md row #1
    from app.integrations.nuclei import NucleiClient

    monkeypatch.setattr(NucleiClient, "scan", _stub_nuclei_failure)

    with pytest.raises(ExternalServiceError):
        await _run_nuclei_scan_async(job_id)

    await db_session.refresh(job)
    assert job.status is ScanStatus.FAILED
    assert job.completed_at is not None
    assert job.error_message is not None
    assert "nuclei" in job.error_message

    # No findings should have been persisted on failure.
    count = (
        await db_session.execute(select(Finding).where(Finding.scan_job_id == job_id))
    ).scalars().all()
    assert count == []
