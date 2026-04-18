"""Integration test for the post-scan EPSS enrichment hook.

Verifies that after a scan completes, Finding rows with CVEs get their
`epss_score` / `epss_percentile` columns populated via the EPSS HTTP call
(mocked with respx). Enrichment runs inside the async scan task, so we
invoke `_run_scan_async` directly and check the DB rows afterward.
"""

from __future__ import annotations

from decimal import Decimal

import httpx
import pytest
import respx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.redis_client import get_redis_client
from app.models.enums import FindingSeverity, FindingSource, ScanStatus
from app.models.finding import Finding
from app.services.normalizer import NormalizedFinding
from tests.conftest import integration
from tests.factories import make_asset, make_scan_job, make_tenant


@pytest.fixture(autouse=True)
async def _flush_epss_cache() -> None:
    redis = get_redis_client()
    try:
        keys = await redis.keys("epss:*")
        if keys:
            await redis.delete(*keys)
    except Exception:
        pass


def _epss_ok(rows: list[dict]) -> httpx.Response:
    return httpx.Response(200, json={"status": "OK", "data": rows})


@integration
@pytest.mark.asyncio
async def test_epss_scores_populated_on_findings(
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.config import get_settings
    from app.integrations.nuclei import NucleiClient
    from app.tasks.scan_tasks import _run_nuclei_scan_async

    msp = await make_tenant(db_session, slug="epss-msp")
    asset = await make_asset(db_session, tenant=msp, value="epss.example.com")
    job = await make_scan_job(db_session, tenant=msp, asset=asset)
    job_id = job.id

    # MOCK — see docs/mocks.md row #1 (Nuclei subprocess).
    async def fake_scan(self, target: str, **_: object) -> list[NormalizedFinding]:
        return [
            NormalizedFinding(
                title="Critical CVE",
                severity=FindingSeverity.CRITICAL,
                source=FindingSource.NUCLEI,
                asset_value=target,
                cve_id="CVE-2024-0001",
            ),
            NormalizedFinding(
                title="Second CVE",
                severity=FindingSeverity.HIGH,
                source=FindingSource.NUCLEI,
                asset_value=target,
                cve_id="CVE-2024-0002",
            ),
            NormalizedFinding(
                title="Non-CVE info",
                severity=FindingSeverity.INFO,
                source=FindingSource.NUCLEI,
                asset_value=target,
            ),
        ]

    monkeypatch.setattr(NucleiClient, "scan", fake_scan)

    # MOCK — see docs/mocks.md row #10 (EPSS HTTP).
    epss_base = get_settings().EPSS_API_URL.rstrip("/")
    with respx.mock(base_url=epss_base) as mock:
        mock.get("/epss").mock(
            return_value=_epss_ok(
                [
                    {"cve": "CVE-2024-0001", "epss": "0.95", "percentile": "0.99"},
                    {"cve": "CVE-2024-0002", "epss": "0.10", "percentile": "0.50"},
                ]
            )
        )

        result = await _run_nuclei_scan_async(job_id)
        assert result["status"] == "completed"

    await db_session.refresh(job)
    assert job.status is ScanStatus.COMPLETED

    rows = (
        await db_session.execute(select(Finding).where(Finding.scan_job_id == job_id))
    ).scalars().all()
    assert len(rows) == 3

    by_cve = {f.cve_id: f for f in rows if f.cve_id}
    # CVE-tied findings got their EPSS columns set.
    assert by_cve["CVE-2024-0001"].epss_score == Decimal("0.95")
    assert by_cve["CVE-2024-0001"].epss_percentile == Decimal("0.99")
    assert by_cve["CVE-2024-0002"].epss_score == Decimal("0.10")

    # The non-CVE row stays unenriched.
    non_cve = next(f for f in rows if f.cve_id is None)
    assert non_cve.epss_score is None
    assert non_cve.epss_percentile is None


@integration
@pytest.mark.asyncio
async def test_epss_outage_does_not_fail_scan(
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If EPSS is down, the scan still succeeds — findings just lack scores."""
    from app.core.config import get_settings
    from app.integrations.nuclei import NucleiClient
    from app.tasks.scan_tasks import _run_nuclei_scan_async

    msp = await make_tenant(db_session, slug="epss-down-msp")
    asset = await make_asset(db_session, tenant=msp, value="epss-down.example.com")
    job = await make_scan_job(db_session, tenant=msp, asset=asset)
    job_id = job.id

    async def fake_scan(self, target: str, **_: object) -> list[NormalizedFinding]:
        return [
            NormalizedFinding(
                title="CVE thing",
                severity=FindingSeverity.HIGH,
                source=FindingSource.NUCLEI,
                asset_value=target,
                cve_id="CVE-2024-DOWN",
            )
        ]

    monkeypatch.setattr(NucleiClient, "scan", fake_scan)

    epss_base = get_settings().EPSS_API_URL.rstrip("/")
    with respx.mock(base_url=epss_base) as mock:
        mock.get("/epss").mock(return_value=httpx.Response(503, text="down"))
        result = await _run_nuclei_scan_async(job_id)

    assert result["status"] == "completed"
    await db_session.refresh(job)
    assert job.status is ScanStatus.COMPLETED

    rows = (
        await db_session.execute(select(Finding).where(Finding.scan_job_id == job_id))
    ).scalars().all()
    assert len(rows) == 1
    assert rows[0].epss_score is None
