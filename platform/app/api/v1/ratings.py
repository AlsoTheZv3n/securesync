"""Rating endpoints — latest + history per tenant."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import assert_tenant_access, get_current_user
from app.core.exceptions import ResourceNotFoundError
from app.models.rating import Rating
from app.models.user import User
from app.schemas.rating import RatingRead

router = APIRouter(prefix="/ratings", tags=["ratings"])


async def _latest_for_tenant(
    db: AsyncSession, tenant_id: UUID
) -> Rating | None:
    stmt = (
        select(Rating)
        .where(Rating.tenant_id == tenant_id)
        .order_by(Rating.calculated_at.desc())
        .limit(1)
    )
    return (await db.execute(stmt)).scalar_one_or_none()


@router.get("/current", response_model=RatingRead)
async def get_current_rating(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Rating:
    """Latest rating for the caller's own tenant."""
    rating = await _latest_for_tenant(db, user.tenant_id)
    if rating is None:
        raise ResourceNotFoundError("no rating yet — run a scan first")
    return rating


@router.get("/current/{tenant_id}", response_model=RatingRead)
async def get_current_rating_for_tenant(
    tenant_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Rating:
    """Latest rating for any tenant the caller has access to."""
    await assert_tenant_access(tenant_id, user, db)
    rating = await _latest_for_tenant(db, tenant_id)
    if rating is None:
        raise ResourceNotFoundError("no rating yet — run a scan first")
    return rating


@router.get("/history/{tenant_id}", response_model=list[RatingRead])
async def get_rating_history(
    tenant_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=12, ge=1, le=100),
) -> list[Rating]:
    """Recent ratings for a tenant — recent-first, capped at `limit`.

    Default 12 matches the Trend Graph spec (12 most recent scans).
    """
    await assert_tenant_access(tenant_id, user, db)
    stmt = (
        select(Rating)
        .where(Rating.tenant_id == tenant_id)
        .order_by(Rating.calculated_at.desc())
        .limit(limit)
    )
    return list((await db.execute(stmt)).scalars().all())
