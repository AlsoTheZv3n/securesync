"""ScanSchedule CRUD endpoints — recurring scans per tenant/asset."""

from __future__ import annotations

from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import (
    assert_tenant_access,
    get_current_user,
    require_role,
)
from app.core.exceptions import ResourceNotFoundError, ValidationError
from app.models.asset import Asset
from app.models.enums import ScanType, UserRole
from app.models.scan_schedule import ScanSchedule
from app.models.user import User
from app.schemas.scan_schedule import (
    ScanScheduleCreate,
    ScanScheduleRead,
    ScanScheduleUpdate,
)
from app.schemas.scan import IMPLEMENTED_SCAN_TYPES
from app.services.scheduler import (
    InvalidCronError,
    next_run_skipping_blackout,
)

router = APIRouter(prefix="/scan-schedules", tags=["scan-schedules"])
logger = structlog.get_logger()


@router.post(
    "",
    response_model=ScanScheduleRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(
            require_role(
                UserRole.PLATFORM_ADMIN, UserRole.MSP_ADMIN, UserRole.MSP_TECHNICIAN
            )
        )
    ],
)
async def create_schedule(
    payload: ScanScheduleCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanSchedule:
    if payload.scan_type not in IMPLEMENTED_SCAN_TYPES:
        raise ValidationError(
            f"scan_type {payload.scan_type.value!r} is not implemented"
        )

    # Asset must exist + caller must have access to its tenant.
    asset = (
        await db.execute(select(Asset).where(Asset.id == payload.asset_id))
    ).scalar_one_or_none()
    if asset is None:
        raise ResourceNotFoundError("asset not found")
    await assert_tenant_access(asset.tenant_id, user, db)

    try:
        next_run_at = next_run_skipping_blackout(
            payload.cron_expression,
            payload.timezone,
            blackout_start=payload.blackout_start,
            blackout_end=payload.blackout_end,
        )
    except InvalidCronError as exc:
        raise ValidationError(str(exc)) from exc

    schedule = ScanSchedule(
        tenant_id=asset.tenant_id,
        asset_id=asset.id,
        scan_type=payload.scan_type,
        cron_expression=payload.cron_expression,
        timezone=payload.timezone,
        is_active=payload.is_active,
        blackout_start=payload.blackout_start,
        blackout_end=payload.blackout_end,
        next_run_at=next_run_at,
    )
    db.add(schedule)
    await db.commit()
    await db.refresh(schedule)

    logger.info(
        "scan_schedule_created",
        schedule_id=str(schedule.id),
        tenant_id=str(asset.tenant_id),
        asset_id=str(asset.id),
        cron=schedule.cron_expression,
        by=str(user.id),
    )
    return schedule


@router.get("", response_model=list[ScanScheduleRead])
async def list_schedules(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    tenant_id: UUID | None = Query(default=None),
    asset_id: UUID | None = Query(default=None),
    scan_type: ScanType | None = Query(default=None),
    is_active: bool | None = Query(default=None),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
) -> list[ScanSchedule]:
    target_tenant_id = tenant_id or user.tenant_id
    await assert_tenant_access(target_tenant_id, user, db)

    stmt = select(ScanSchedule).where(ScanSchedule.tenant_id == target_tenant_id)
    if asset_id is not None:
        stmt = stmt.where(ScanSchedule.asset_id == asset_id)
    if scan_type is not None:
        stmt = stmt.where(ScanSchedule.scan_type == scan_type)
    if is_active is not None:
        stmt = stmt.where(ScanSchedule.is_active.is_(is_active))
    stmt = stmt.order_by(ScanSchedule.next_run_at.asc()).offset(skip).limit(limit)

    return list((await db.execute(stmt)).scalars().all())


@router.get("/{schedule_id}", response_model=ScanScheduleRead)
async def get_schedule(
    schedule_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanSchedule:
    schedule = (
        await db.execute(
            select(ScanSchedule).where(ScanSchedule.id == schedule_id)
        )
    ).scalar_one_or_none()
    if schedule is None:
        raise ResourceNotFoundError("schedule not found")
    await assert_tenant_access(schedule.tenant_id, user, db)
    return schedule


@router.patch(
    "/{schedule_id}",
    response_model=ScanScheduleRead,
    dependencies=[
        Depends(
            require_role(
                UserRole.PLATFORM_ADMIN, UserRole.MSP_ADMIN, UserRole.MSP_TECHNICIAN
            )
        )
    ],
)
async def update_schedule(
    schedule_id: UUID,
    payload: ScanScheduleUpdate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanSchedule:
    schedule = (
        await db.execute(
            select(ScanSchedule).where(ScanSchedule.id == schedule_id)
        )
    ).scalar_one_or_none()
    if schedule is None:
        raise ResourceNotFoundError("schedule not found")
    await assert_tenant_access(schedule.tenant_id, user, db)

    update_data = payload.model_dump(exclude_unset=True)
    if "scan_type" in update_data and update_data["scan_type"] not in IMPLEMENTED_SCAN_TYPES:
        raise ValidationError(
            f"scan_type {update_data['scan_type'].value!r} is not implemented"
        )

    for field, value in update_data.items():
        setattr(schedule, field, value)

    # Recompute next_run_at if anything that affects it changed.
    if any(
        k in update_data
        for k in ("cron_expression", "timezone", "blackout_start", "blackout_end")
    ):
        try:
            schedule.next_run_at = next_run_skipping_blackout(
                schedule.cron_expression,
                schedule.timezone,
                blackout_start=schedule.blackout_start,
                blackout_end=schedule.blackout_end,
            )
        except InvalidCronError as exc:
            raise ValidationError(str(exc)) from exc

    await db.commit()
    await db.refresh(schedule)
    logger.info(
        "scan_schedule_updated",
        schedule_id=str(schedule.id),
        by=str(user.id),
    )
    return schedule


@router.delete(
    "/{schedule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[
        Depends(
            require_role(
                UserRole.PLATFORM_ADMIN, UserRole.MSP_ADMIN, UserRole.MSP_TECHNICIAN
            )
        )
    ],
)
async def delete_schedule(
    schedule_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    schedule = (
        await db.execute(
            select(ScanSchedule).where(ScanSchedule.id == schedule_id)
        )
    ).scalar_one_or_none()
    if schedule is None:
        raise ResourceNotFoundError("schedule not found")
    await assert_tenant_access(schedule.tenant_id, user, db)

    await db.delete(schedule)
    await db.commit()
    logger.info("scan_schedule_deleted", schedule_id=str(schedule_id), by=str(user.id))
    return None
