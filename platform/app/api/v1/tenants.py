"""Tenant CRUD endpoints.

Hierarchy rules:
  - platform_admin can do anything.
  - msp_admin/msp_technician can manage their own MSP tenant and its customers.
  - customer_readonly can only GET their own tenant.

Soft delete only — `deleted_at` is set, the row stays.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import (
    assert_tenant_access,
    get_current_user,
    require_role,
)
from app.core.exceptions import (
    PermissionDeniedError,
    ResourceNotFoundError,
    ValidationError,
)
from app.models.enums import UserRole
from app.models.tenant import Tenant
from app.models.user import User
from app.schemas.tenant import (
    DomainVerificationChallenge,
    DomainVerificationResult,
    TenantCreate,
    TenantRead,
    TenantUpdate,
)
from app.services.defectdojo_sync import provision_product_for_tenant
from app.services.domain_verification import (
    build_expected_txt_value,
    build_verification_dns_name,
    generate_verification_token,
    verify_domain_txt,
)
from app.services.wazuh_sync import provision_agent_group_for_tenant

router = APIRouter(prefix="/tenants", tags=["tenants"])
logger = structlog.get_logger()


def _is_msp_role(role: UserRole) -> bool:
    return role in {UserRole.MSP_ADMIN, UserRole.MSP_TECHNICIAN}


@router.get("", response_model=list[TenantRead])
async def list_tenants(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
) -> list[Tenant]:
    """Returns tenants visible to the caller, scoped by role."""
    stmt = select(Tenant).where(Tenant.deleted_at.is_(None))

    if user.role is UserRole.PLATFORM_ADMIN:
        pass  # all tenants
    elif _is_msp_role(user.role):
        # Own MSP tenant + all of its customer tenants.
        stmt = stmt.where(or_(Tenant.id == user.tenant_id, Tenant.msp_id == user.tenant_id))
    else:
        # customer_readonly → only their own tenant.
        stmt = stmt.where(Tenant.id == user.tenant_id)

    stmt = stmt.order_by(Tenant.created_at.desc()).offset(skip).limit(limit)
    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.post(
    "",
    response_model=TenantRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_role(UserRole.PLATFORM_ADMIN, UserRole.MSP_ADMIN))],
)
async def create_tenant(
    payload: TenantCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Tenant:
    """Create a customer tenant under an MSP.

    For MSP admins: msp_id is forced to the caller's tenant. Platform admins
    may set any (or none, to create another MSP).
    """
    if user.role is UserRole.MSP_ADMIN:
        if payload.msp_id is not None and payload.msp_id != user.tenant_id:
            raise PermissionDeniedError("MSP admins may only create customers under their own MSP")
        msp_id: UUID | None = user.tenant_id
    else:
        msp_id = payload.msp_id

    tenant = Tenant(
        name=payload.name,
        slug=payload.slug,
        primary_color=payload.primary_color,
        custom_domain=payload.custom_domain,
        logo_url=payload.logo_url,
        msp_id=msp_id,
    )
    db.add(tenant)
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise ValidationError("slug or custom_domain already in use") from exc

    await db.refresh(tenant)
    logger.info("tenant_created", tenant_id=str(tenant.id), slug=tenant.slug, by=str(user.id))

    # Best-effort: create the matching DefectDojo product and Wazuh agent
    # group. If either system is offline or unconfigured, the tenant stays
    # valid without those side-channel resources.
    await provision_product_for_tenant(db, tenant)
    await provision_agent_group_for_tenant(tenant)

    return tenant


@router.get("/{tenant_id}", response_model=TenantRead)
async def get_tenant(
    tenant_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Tenant:
    await assert_tenant_access(tenant_id, user, db)

    stmt = select(Tenant).where(Tenant.id == tenant_id, Tenant.deleted_at.is_(None))
    tenant = (await db.execute(stmt)).scalar_one_or_none()
    if tenant is None:
        raise ResourceNotFoundError("tenant not found")
    return tenant


@router.patch(
    "/{tenant_id}",
    response_model=TenantRead,
    dependencies=[Depends(require_role(UserRole.PLATFORM_ADMIN, UserRole.MSP_ADMIN))],
)
async def update_tenant(
    tenant_id: UUID,
    payload: TenantUpdate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Tenant:
    await assert_tenant_access(tenant_id, user, db)

    stmt = select(Tenant).where(Tenant.id == tenant_id, Tenant.deleted_at.is_(None))
    tenant = (await db.execute(stmt)).scalar_one_or_none()
    if tenant is None:
        raise ResourceNotFoundError("tenant not found")

    update_data = payload.model_dump(exclude_unset=True)

    # Changing custom_domain invalidates the old verification — the TXT
    # record from the previous domain obviously doesn't apply. Reset both
    # flag + token so the tenant has to re-run the challenge.
    if (
        "custom_domain" in update_data
        and update_data["custom_domain"] != tenant.custom_domain
    ):
        update_data["custom_domain_verified"] = False
        update_data["custom_domain_verification_token"] = None

    for field, value in update_data.items():
        setattr(tenant, field, value)

    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise ValidationError("custom_domain already in use") from exc

    await db.refresh(tenant)
    logger.info("tenant_updated", tenant_id=str(tenant.id), by=str(user.id))
    return tenant


@router.delete(
    "/{tenant_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_role(UserRole.PLATFORM_ADMIN, UserRole.MSP_ADMIN))],
)
async def delete_tenant(
    tenant_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await assert_tenant_access(tenant_id, user, db)

    # MSP admins cannot delete their own MSP tenant — only customers.
    if user.role is UserRole.MSP_ADMIN and tenant_id == user.tenant_id:
        raise PermissionDeniedError("Cannot delete your own MSP tenant")

    stmt = select(Tenant).where(Tenant.id == tenant_id, Tenant.deleted_at.is_(None))
    tenant = (await db.execute(stmt)).scalar_one_or_none()
    if tenant is None:
        raise ResourceNotFoundError("tenant not found")

    tenant.deleted_at = datetime.now(UTC)
    await db.commit()
    logger.info("tenant_soft_deleted", tenant_id=str(tenant_id), by=str(user.id))
    return None


# ── Custom-domain verification ──────────────────────────────
_CHALLENGE_TTL_HOURS = 24


@router.post(
    "/{tenant_id}/verify-domain",
    response_model=DomainVerificationChallenge,
    dependencies=[Depends(require_role(UserRole.PLATFORM_ADMIN, UserRole.MSP_ADMIN))],
)
async def start_domain_verification(
    tenant_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> DomainVerificationChallenge:
    """Issue a fresh DNS challenge. Overwrites any prior in-flight token."""
    await assert_tenant_access(tenant_id, user, db)

    tenant = (
        await db.execute(
            select(Tenant).where(Tenant.id == tenant_id, Tenant.deleted_at.is_(None))
        )
    ).scalar_one_or_none()
    if tenant is None:
        raise ResourceNotFoundError("tenant not found")
    if not tenant.custom_domain:
        raise ValidationError(
            "tenant has no custom_domain set — update the tenant first"
        )

    token = generate_verification_token()
    tenant.custom_domain_verification_token = token
    tenant.custom_domain_verified = False
    await db.commit()
    await db.refresh(tenant)

    expires_at = datetime.now(UTC) + timedelta(hours=_CHALLENGE_TTL_HOURS)
    logger.info(
        "domain_verification_challenge_issued",
        tenant_id=str(tenant.id),
        domain=tenant.custom_domain,
        by=str(user.id),
    )
    return DomainVerificationChallenge(
        custom_domain=tenant.custom_domain,
        dns_name=build_verification_dns_name(tenant.custom_domain),
        txt_record_value=build_expected_txt_value(token),
        expires_at=expires_at,
    )


@router.post(
    "/{tenant_id}/verify-domain/confirm",
    response_model=DomainVerificationResult,
    dependencies=[Depends(require_role(UserRole.PLATFORM_ADMIN, UserRole.MSP_ADMIN))],
)
async def confirm_domain_verification(
    tenant_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> DomainVerificationResult:
    """Look up the TXT record and confirm the challenge."""
    await assert_tenant_access(tenant_id, user, db)

    tenant = (
        await db.execute(
            select(Tenant).where(Tenant.id == tenant_id, Tenant.deleted_at.is_(None))
        )
    ).scalar_one_or_none()
    if tenant is None:
        raise ResourceNotFoundError("tenant not found")
    if not tenant.custom_domain:
        raise ValidationError("tenant has no custom_domain set")
    if not tenant.custom_domain_verification_token:
        raise ValidationError(
            "no verification in progress — call /verify-domain first"
        )

    matched = await verify_domain_txt(
        tenant.custom_domain,
        expected_token=tenant.custom_domain_verification_token,
    )

    if matched:
        tenant.custom_domain_verified = True
        tenant.custom_domain_verification_token = None
        await db.commit()
        logger.info(
            "domain_verification_confirmed",
            tenant_id=str(tenant.id),
            domain=tenant.custom_domain,
            by=str(user.id),
        )
    else:
        logger.info(
            "domain_verification_failed",
            tenant_id=str(tenant.id),
            domain=tenant.custom_domain,
            by=str(user.id),
        )

    return DomainVerificationResult(
        verified=matched,
        custom_domain=tenant.custom_domain,
    )
