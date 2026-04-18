"""Read-only audit log endpoint.

Platform admins can query the full stream across all tenants. MSP admins
can only see entries that touched their own MSP / its customers. No other
roles can read it.

Intentionally no DELETE / PATCH — the `audit_logs` table is append-only.
Retention policies live in ops (DB job) rather than the app.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import (
    assert_tenant_access,
    get_current_user,
    require_role,
)
from app.models.audit_log import AuditLog
from app.models.enums import UserRole
from app.models.tenant import Tenant
from app.models.user import User
from app.schemas.audit_log import AuditLogRead

router = APIRouter(prefix="/audit-logs", tags=["audit-logs"])


@router.get(
    "",
    response_model=list[AuditLogRead],
    dependencies=[
        Depends(require_role(UserRole.PLATFORM_ADMIN, UserRole.MSP_ADMIN))
    ],
)
async def list_audit_logs(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    tenant_id: UUID | None = Query(default=None),
    action: str | None = Query(default=None, max_length=64),
    user_id: UUID | None = Query(default=None),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
) -> list[AuditLog]:
    """Filter-rich read of the audit stream. Recent-first."""

    if tenant_id is not None:
        await assert_tenant_access(tenant_id, user, db)
        stmt = select(AuditLog).where(AuditLog.tenant_id == tenant_id)
    elif user.role is UserRole.PLATFORM_ADMIN:
        stmt = select(AuditLog)
    else:
        # MSP admin with no tenant_id filter → see own MSP + its customer
        # tenants only. Build the allowed tenant-id set inline.
        own_and_children = select(Tenant.id).where(
            or_(Tenant.id == user.tenant_id, Tenant.msp_id == user.tenant_id)
        )
        stmt = select(AuditLog).where(AuditLog.tenant_id.in_(own_and_children))

    if action is not None:
        stmt = stmt.where(AuditLog.action == action)
    if user_id is not None:
        stmt = stmt.where(AuditLog.user_id == user_id)
    if since is not None:
        stmt = stmt.where(AuditLog.created_at >= since)
    if until is not None:
        stmt = stmt.where(AuditLog.created_at <= until)

    stmt = stmt.order_by(AuditLog.created_at.desc()).offset(skip).limit(limit)
    return list((await db.execute(stmt)).scalars().all())
