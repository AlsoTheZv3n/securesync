"""Celery tasks that execute scanner integrations and persist findings.

Pattern: each task is a thin sync shim that runs an `async def` worker via
`asyncio.run`. The async worker owns its own DB session — Celery workers
don't share state with the FastAPI process.

Status state machine for ScanJob:
    QUEUED → RUNNING → (COMPLETED | FAILED)

Adding a new scanner means:
  1. Implement an integration class with `async scan(target) -> list[NormalizedFinding]`
  2. Define a sync Celery task wrapping `_run_scan_async(...)` with that class
  3. Register the task in `app/api/v1/scans.py:_TASK_DISPATCH`
  4. Whitelist the scan_type in `app/schemas/scan.py:IMPLEMENTED_SCAN_TYPES`
"""

from __future__ import annotations

import asyncio
import sys
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.celery_app import celery_app
from app.core.config import get_settings
from app.core.exceptions import ExternalServiceError
from app.integrations.nuclei import NucleiClient
from app.integrations.openvas import GreenBoneClient
from app.integrations.wazuh import WazuhClient
from app.integrations.zap import ZAPClient
from app.models.asset import Asset
from app.models.enums import ScanStatus
from app.models.finding import Finding
from app.models.scan_job import ScanJob
from app.models.tenant import Tenant
from app.services.defectdojo_sync import push_scan_to_defectdojo
from app.services.enrichment import enrich_findings_with_epss
from app.services.ninjaone_sync import push_findings_to_ninjaone
from app.services.normalizer import NormalizedFinding, to_orm
from app.services.rating_service import compute_and_store_rating

logger = structlog.get_logger()

# psycopg async refuses Windows' default ProactorEventLoop. Worker processes
# get a fresh loop per task, so set the policy here too (mirrors main.py).
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


class _ScannerProtocol(Protocol):
    """Every integration plugged into _run_scan_async must satisfy this."""

    async def scan(self, target: str) -> list[NormalizedFinding]: ...


ScannerFactory = Callable[[], _ScannerProtocol]


# ── Per-process async engine ────────────────────────────────
# Celery workers spawn their own processes; reusing the FastAPI app's engine
# would leak connections from a different event loop. We build a worker-local
# engine on first task execution and cache it.
_worker_engine = None
_worker_session_factory: async_sessionmaker[AsyncSession] | None = None


def _get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _worker_engine, _worker_session_factory
    if _worker_session_factory is None:
        _worker_engine = create_async_engine(
            str(get_settings().DATABASE_URL),
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=10,
        )
        _worker_session_factory = async_sessionmaker(
            _worker_engine, expire_on_commit=False, autoflush=False
        )
    return _worker_session_factory


async def _load_scan_context(
    session: AsyncSession, scan_job_id: UUID
) -> tuple[ScanJob, Asset, Tenant]:
    job = (
        await session.execute(select(ScanJob).where(ScanJob.id == scan_job_id))
    ).scalar_one_or_none()
    if job is None:
        raise LookupError(f"ScanJob {scan_job_id} not found")
    asset = (
        await session.execute(select(Asset).where(Asset.id == job.asset_id))
    ).scalar_one_or_none()
    if asset is None:
        raise LookupError(f"Asset {job.asset_id} not found for ScanJob {scan_job_id}")
    tenant = (
        await session.execute(select(Tenant).where(Tenant.id == job.tenant_id))
    ).scalar_one_or_none()
    if tenant is None:
        raise LookupError(f"Tenant {job.tenant_id} not found for ScanJob {scan_job_id}")
    return job, asset, tenant


async def _persist_findings(
    session: AsyncSession,
    findings: list[NormalizedFinding],
    *,
    tenant_id: UUID,
    scan_job_id: UUID,
    asset_id: UUID,
) -> list[Finding]:
    if not findings:
        return []
    rows = [
        to_orm(f, tenant_id=tenant_id, scan_job_id=scan_job_id, asset_id=asset_id)
        for f in findings
    ]
    session.add_all(rows)
    await session.flush()
    return rows


async def _run_scan_async(
    scan_job_id: UUID,
    scanner_factory: ScannerFactory,
    *,
    scanner_name: str,
) -> dict[str, int | str]:
    """Generic scan runner — load job, run scanner, persist findings, mark done."""
    factory = _get_session_factory()
    async with factory() as session:
        job, asset, tenant = await _load_scan_context(session, scan_job_id)

        job.status = ScanStatus.RUNNING
        job.started_at = datetime.now(UTC)
        await session.commit()

        client = scanner_factory()
        try:
            scan_coro: Awaitable[list[NormalizedFinding]] = client.scan(asset.value)
            findings = await scan_coro
        except ExternalServiceError as exc:
            job.status = ScanStatus.FAILED
            job.error_message = str(exc)
            job.completed_at = datetime.now(UTC)
            await session.commit()
            logger.error(
                "scan_failed", scan_job_id=str(scan_job_id), scanner=scanner_name, error=str(exc)
            )
            raise

        rows = await _persist_findings(
            session,
            findings,
            tenant_id=job.tenant_id,
            scan_job_id=job.id,
            asset_id=asset.id,
        )

        job.status = ScanStatus.COMPLETED
        job.completed_at = datetime.now(UTC)
        await session.commit()

        # Best-effort: enrich with EPSS scores BEFORE downstream syncs so any
        # future DefectDojo fields could carry them. Today DefectDojo's
        # Generic JSON has no EPSS field, so this is purely for our own DB.
        await enrich_findings_with_epss(session, rows)

        # Core business logic: recompute the tenant rating based on ALL
        # currently-open findings (not just this scan's). Failures here
        # surface — rating is not a side-channel.
        await compute_and_store_rating(
            session, tenant_id=job.tenant_id, scan_job_id=job.id
        )

        # Best-effort: push into DefectDojo for cross-scanner dedup.
        await push_scan_to_defectdojo(session, job, tenant, findings)

        # Best-effort: auto-ticket Critical/High findings in NinjaOne so the
        # MSP sees them in their existing workflow. Skips Medium+Low.
        await push_findings_to_ninjaone(session, tenant=tenant, findings=rows)

        logger.info(
            "scan_completed",
            scan_job_id=str(scan_job_id),
            scanner=scanner_name,
            findings=len(rows),
        )
        return {
            "scan_job_id": str(scan_job_id),
            "findings": len(rows),
            "status": "completed",
        }


# Backwards-compatible alias used by existing tests.
async def _run_nuclei_scan_async(scan_job_id: UUID) -> dict[str, int | str]:
    return await _run_scan_async(scan_job_id, NucleiClient, scanner_name="nuclei")


# ── Celery tasks ────────────────────────────────────────────
@celery_app.task(name="scan.nuclei", bind=True, max_retries=2)
def run_nuclei_scan(self, scan_job_id: str) -> dict[str, int | str]:
    try:
        return asyncio.run(_run_scan_async(UUID(scan_job_id), NucleiClient, scanner_name="nuclei"))
    except ExternalServiceError as exc:
        raise self.retry(exc=exc, countdown=2 ** self.request.retries * 30) from exc


@celery_app.task(
    name="scan.openvas",
    bind=True,
    max_retries=1,            # OpenVAS scans are expensive — retry once at most
    time_limit=60 * 60 * 3,   # 3h hard kill (full network sweeps can be long)
    soft_time_limit=60 * 60 * 2 + 60 * 30,  # 2h30 graceful
)
def run_openvas_scan(self, scan_job_id: str) -> dict[str, int | str]:
    try:
        return asyncio.run(
            _run_scan_async(UUID(scan_job_id), GreenBoneClient, scanner_name="openvas")
        )
    except ExternalServiceError as exc:
        raise self.retry(exc=exc, countdown=300) from exc


@celery_app.task(
    name="scan.zap",
    bind=True,
    max_retries=1,
    time_limit=60 * 60 * 4,        # 4h hard kill (deep web crawl + ascan)
    soft_time_limit=60 * 60 * 3 + 60 * 30,  # 3h30 graceful
)
def run_zap_scan(self, scan_job_id: str) -> dict[str, int | str]:
    try:
        return asyncio.run(_run_scan_async(UUID(scan_job_id), ZAPClient, scanner_name="zap"))
    except ExternalServiceError as exc:
        raise self.retry(exc=exc, countdown=300) from exc


@celery_app.task(name="scan.wazuh", bind=True, max_retries=2)
def run_wazuh_scan(self, scan_job_id: str) -> dict[str, int | str]:
    """Pull the current vulnerability state for an enrolled Wazuh agent.

    Wazuh agents report continuously, so this is cheap compared to network
    scans: fast default retry cadence, low time limit.
    """
    try:
        return asyncio.run(_run_scan_async(UUID(scan_job_id), WazuhClient, scanner_name="wazuh"))
    except ExternalServiceError as exc:
        raise self.retry(exc=exc, countdown=2 ** self.request.retries * 30) from exc
