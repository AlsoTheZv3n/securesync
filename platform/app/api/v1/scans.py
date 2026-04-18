"""Scan job endpoints: enqueue + poll status.

POST /scans creates a ScanJob row in `queued` state and dispatches the
matching Celery task. The worker transitions it to `running` → `completed`
or `failed`, then the client polls GET /scans/{id} for status.

Phase 1.5: only scan_type=fast (Nuclei) is wired up. Other scan types are
rejected with 422 until their integrations land in Phase 2.
"""

from __future__ import annotations

from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import (
    assert_tenant_access,
    get_current_user,
    require_role,
)
from app.core.exceptions import ResourceNotFoundError, ValidationError
from app.models.asset import Asset
from app.models.enums import ScanStatus, ScanType, UserRole
from app.models.finding import Finding
from app.models.scan_job import ScanJob
from app.models.user import User
from app.schemas.scan import (
    IMPLEMENTED_SCAN_TYPES,
    ScanCreate,
    ScanRead,
    ScanReadWithCounts,
)
from app.tasks.scan_tasks import (
    run_nuclei_scan,
    run_openvas_scan,
    run_wazuh_scan,
    run_zap_scan,
)

router = APIRouter(prefix="/scans", tags=["scans"])
logger = structlog.get_logger()


# Maps an implemented scan_type to its Celery task. Add new scanners here
# as their integrations land — and update IMPLEMENTED_SCAN_TYPES in the
# schema module.
_TASK_DISPATCH = {
    ScanType.FAST: run_nuclei_scan,
    ScanType.EXTERNAL_FULL: run_openvas_scan,
    ScanType.WEB_APP: run_zap_scan,
    ScanType.INTERNAL: run_wazuh_scan,
}


@router.post(
    "",
    response_model=ScanRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(
            require_role(
                UserRole.PLATFORM_ADMIN, UserRole.MSP_ADMIN, UserRole.MSP_TECHNICIAN
            )
        )
    ],
)
async def create_scan(
    payload: ScanCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanJob:
    """Create + enqueue a scan job for the given asset."""
    if payload.scan_type not in IMPLEMENTED_SCAN_TYPES:
        raise ValidationError(
            f"scan_type {payload.scan_type.value!r} is not yet implemented "
            f"(supported: {sorted(t.value for t in IMPLEMENTED_SCAN_TYPES)})"
        )

    asset = (
        await db.execute(select(Asset).where(Asset.id == payload.asset_id))
    ).scalar_one_or_none()
    if asset is None:
        raise ResourceNotFoundError("asset not found")
    await assert_tenant_access(asset.tenant_id, user, db)

    job = ScanJob(
        tenant_id=asset.tenant_id,
        asset_id=asset.id,
        scan_type=payload.scan_type,
        status=ScanStatus.QUEUED,
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    # Dispatch the matching Celery task. The task ID is stored back on the row
    # so the UI can correlate with worker logs / Flower.
    task = _TASK_DISPATCH[payload.scan_type].delay(str(job.id))
    job.celery_task_id = task.id
    await db.commit()
    await db.refresh(job)

    logger.info(
        "scan_enqueued",
        scan_job_id=str(job.id),
        asset_id=str(asset.id),
        scan_type=payload.scan_type.value,
        task_id=task.id,
        by=str(user.id),
    )
    return job


@router.get("", response_model=list[ScanRead])
async def list_scans(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    tenant_id: UUID | None = Query(default=None, description="Defaults to caller's tenant"),
    asset_id: UUID | None = Query(default=None),
    scan_status: ScanStatus | None = Query(default=None, alias="status"),
    scan_type: ScanType | None = Query(default=None),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
) -> list[ScanJob]:
    target_tenant_id = tenant_id or user.tenant_id
    await assert_tenant_access(target_tenant_id, user, db)

    stmt = select(ScanJob).where(ScanJob.tenant_id == target_tenant_id)
    if asset_id is not None:
        stmt = stmt.where(ScanJob.asset_id == asset_id)
    if scan_status is not None:
        stmt = stmt.where(ScanJob.status == scan_status)
    if scan_type is not None:
        stmt = stmt.where(ScanJob.scan_type == scan_type)
    stmt = stmt.order_by(ScanJob.created_at.desc()).offset(skip).limit(limit)

    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.get("/{scan_id}", response_model=ScanReadWithCounts)
async def get_scan(
    scan_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanReadWithCounts:
    job = (
        await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
    ).scalar_one_or_none()
    if job is None:
        raise ResourceNotFoundError("scan job not found")
    await assert_tenant_access(job.tenant_id, user, db)

    count = (
        await db.execute(
            select(func.count(Finding.id)).where(Finding.scan_job_id == scan_id)
        )
    ).scalar_one()

    base = ScanRead.model_validate(job)
    return ScanReadWithCounts(**base.model_dump(), findings_count=count)
