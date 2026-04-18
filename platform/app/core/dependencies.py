"""FastAPI dependencies: current user resolution + role guards.

Every protected endpoint should depend on `get_current_user`. Endpoints
that touch a specific tenant must additionally pass that tenant_id through
`assert_tenant_access` so an MSP technician cannot reach into customers
that don't belong to their MSP.
"""

from __future__ import annotations

from collections.abc import Callable
from uuid import UUID

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.core.exceptions import (
    AuthenticationError,
    PermissionDeniedError,
    TenantIsolationError,
)
from app.core.redis_client import is_jti_blacklisted
from app.core.security import decode_token
from app.models.enums import UserRole
from app.models.tenant import Tenant
from app.models.user import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


async def get_current_user(
    token: str | None = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Validate access token, ensure not blacklisted, return active User row."""
    if not token:
        raise AuthenticationError("Missing bearer token")

    payload = decode_token(token, expected_type="access")

    if await is_jti_blacklisted(payload["jti"]):
        raise AuthenticationError("Token has been revoked")

    user_id = UUID(payload["sub"])
    stmt = (
        select(User)
        .where(User.id == user_id)
        .options(selectinload(User.tenant))
    )
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise AuthenticationError("User no longer active")

    # Defence in depth: token tenant_id must still match the DB row.
    if str(user.tenant_id) != payload["tenant_id"]:
        raise AuthenticationError("Token/tenant mismatch")

    return user


def require_role(*allowed_roles: UserRole) -> Callable[[User], User]:
    """Factory for role-gated endpoints. Usage: `Depends(require_role(UserRole.MSP_ADMIN))`."""

    async def _checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed_roles:
            raise PermissionDeniedError(
                f"Role {user.role.value} not allowed (need one of: "
                f"{', '.join(r.value for r in allowed_roles)})"
            )
        return user

    return _checker


async def assert_tenant_access(
    target_tenant_id: UUID,
    user: User,
    db: AsyncSession,
) -> None:
    """Enforce multi-tenant isolation.

    Rules:
      - platform_admin: unrestricted.
      - msp_admin / msp_technician: own MSP tenant + any customer of that MSP.
      - customer_readonly: own tenant only.

    Always raises `TenantIsolationError` (403) on violation — never reveals
    whether the resource exists.
    """
    if user.role is UserRole.PLATFORM_ADMIN:
        return

    if user.tenant_id == target_tenant_id:
        return

    if user.role in {UserRole.MSP_ADMIN, UserRole.MSP_TECHNICIAN}:
        # Allow access when target is a customer of the user's MSP tenant.
        # The user's tenant is the MSP itself (msp_id IS NULL on it).
        stmt = select(Tenant.id).where(
            Tenant.id == target_tenant_id,
            Tenant.msp_id == user.tenant_id,
            Tenant.deleted_at.is_(None),
        )
        result = await db.execute(stmt)
        if result.scalar_one_or_none() is not None:
            return

    raise TenantIsolationError()
