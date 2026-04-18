"""Asset CRUD endpoints — scan targets per tenant."""

from __future__ import annotations

from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import (
    assert_tenant_access,
    get_current_user,
    require_role,
)
from app.core.exceptions import ResourceNotFoundError, ValidationError
from app.models.asset import Asset
from app.models.enums import AssetType, UserRole
from app.models.user import User
from app.schemas.asset import AssetCreate, AssetRead, AssetUpdate

router = APIRouter(prefix="/assets", tags=["assets"])
logger = structlog.get_logger()


@router.get("", response_model=list[AssetRead])
async def list_assets(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    tenant_id: UUID | None = Query(default=None, description="Defaults to caller's tenant"),
    type: AssetType | None = Query(default=None),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
) -> list[Asset]:
    """List assets for a tenant. The caller must have access to that tenant."""
    target_tenant_id = tenant_id or user.tenant_id
    await assert_tenant_access(target_tenant_id, user, db)

    stmt = select(Asset).where(Asset.tenant_id == target_tenant_id)
    if type is not None:
        stmt = stmt.where(Asset.type == type)
    stmt = stmt.order_by(Asset.created_at.desc()).offset(skip).limit(limit)

    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.post(
    "",
    response_model=AssetRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(
            require_role(
                UserRole.PLATFORM_ADMIN, UserRole.MSP_ADMIN, UserRole.MSP_TECHNICIAN
            )
        )
    ],
)
async def create_asset(
    payload: AssetCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Asset:
    await assert_tenant_access(payload.tenant_id, user, db)

    asset = Asset(
        tenant_id=payload.tenant_id,
        type=payload.type,
        value=payload.value,
        tags=payload.tags,
    )
    db.add(asset)
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise ValidationError("an asset with that value already exists for this tenant") from exc

    await db.refresh(asset)
    logger.info(
        "asset_created",
        asset_id=str(asset.id),
        tenant_id=str(asset.tenant_id),
        type=asset.type.value,
        by=str(user.id),
    )
    return asset


@router.get("/{asset_id}", response_model=AssetRead)
async def get_asset(
    asset_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Asset:
    asset = (await db.execute(select(Asset).where(Asset.id == asset_id))).scalar_one_or_none()
    if asset is None:
        raise ResourceNotFoundError("asset not found")
    # Order matters: fetch first, then check access — but never reveal which.
    # Both code paths above raise the same 404/403 distinction; tenant check below
    # gates on access.
    await assert_tenant_access(asset.tenant_id, user, db)
    return asset


@router.patch(
    "/{asset_id}",
    response_model=AssetRead,
    dependencies=[
        Depends(
            require_role(
                UserRole.PLATFORM_ADMIN, UserRole.MSP_ADMIN, UserRole.MSP_TECHNICIAN
            )
        )
    ],
)
async def update_asset(
    asset_id: UUID,
    payload: AssetUpdate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Asset:
    asset = (await db.execute(select(Asset).where(Asset.id == asset_id))).scalar_one_or_none()
    if asset is None:
        raise ResourceNotFoundError("asset not found")
    await assert_tenant_access(asset.tenant_id, user, db)

    update_data = payload.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(asset, field, value)

    await db.commit()
    await db.refresh(asset)
    logger.info("asset_updated", asset_id=str(asset.id), by=str(user.id))
    return asset


@router.delete(
    "/{asset_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[
        Depends(require_role(UserRole.PLATFORM_ADMIN, UserRole.MSP_ADMIN))
    ],
)
async def delete_asset(
    asset_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    asset = (await db.execute(select(Asset).where(Asset.id == asset_id))).scalar_one_or_none()
    if asset is None:
        raise ResourceNotFoundError("asset not found")
    await assert_tenant_access(asset.tenant_id, user, db)

    await db.delete(asset)
    await db.commit()
    logger.info("asset_deleted", asset_id=str(asset_id), by=str(user.id))
    return None
