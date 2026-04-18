"""Test factories — small helpers for building DB rows + auth tokens.

Kept intentionally simple (no factory_boy) so the helpers stay easy to read.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.asset import Asset
from app.models.enums import AssetType, ScanStatus, ScanType, UserRole
from app.models.scan_job import ScanJob
from app.models.tenant import Tenant
from app.models.user import User


async def make_tenant(
    db: AsyncSession,
    *,
    slug: str,
    name: str | None = None,
    msp_id=None,
) -> Tenant:
    tenant = Tenant(name=name or slug.replace("-", " ").title(), slug=slug, msp_id=msp_id)
    db.add(tenant)
    await db.commit()
    await db.refresh(tenant)
    return tenant


async def make_user(
    db: AsyncSession,
    *,
    email: str,
    tenant: Tenant,
    role: UserRole = UserRole.MSP_ADMIN,
    password: str = "DefaultTestPass!23",
) -> User:
    user = User(
        email=email.lower(),
        hashed_password=hash_password(password),
        role=role,
        tenant_id=tenant.id,
        is_active=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


def auth_header(user: User) -> dict[str, str]:
    """Build an Authorization header for `user` without going through /login."""
    token, _ = create_access_token(
        subject=user.id, tenant_id=user.tenant_id, role=user.role.value
    )
    return {"Authorization": f"Bearer {token}"}


async def make_asset(
    db: AsyncSession,
    *,
    tenant: Tenant,
    value: str = "example.com",
    type: AssetType = AssetType.EXTERNAL_DOMAIN,
) -> Asset:
    asset = Asset(tenant_id=tenant.id, type=type, value=value, tags={})
    db.add(asset)
    await db.commit()
    await db.refresh(asset)
    return asset


async def make_scan_job(
    db: AsyncSession,
    *,
    tenant: Tenant,
    asset: Asset,
    scan_type: ScanType = ScanType.FAST,
    status: ScanStatus = ScanStatus.QUEUED,
) -> ScanJob:
    job = ScanJob(
        tenant_id=tenant.id, asset_id=asset.id, scan_type=scan_type, status=status
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)
    return job
