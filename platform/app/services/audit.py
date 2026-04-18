"""Audit-log helper — call `record_audit(...)` from mutating endpoints.

Usage (inside an endpoint body):

    await record_audit(
        db,
        action="tenant.create",
        user=caller,
        request=request,
        resource_type="tenant",
        resource_id=tenant.id,
        tenant_id=tenant.id,
        details={"slug": tenant.slug},
    )

Keep `details` small — don't dump full request bodies. Prefer listing
the fields the user tried to change.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

import structlog
from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.models.user import User

logger = structlog.get_logger()


def _client_ip(request: Request | None) -> str | None:
    if request is None:
        return None
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",", 1)[0].strip()
    return request.client.host if request.client else None


async def record_audit(
    session: AsyncSession,
    *,
    action: str,
    user: User | None = None,
    request: Request | None = None,
    resource_type: str | None = None,
    resource_id: UUID | None = None,
    tenant_id: UUID | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Append an AuditLog row. Never raises — audit failures must not fail
    the caller's business flow."""
    # Derive tenant_id from the acting user when the caller didn't pass one.
    if tenant_id is None and user is not None:
        tenant_id = user.tenant_id

    entry = AuditLog(
        tenant_id=tenant_id,
        user_id=user.id if user else None,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=_client_ip(request),
        user_agent=(request.headers.get("user-agent")[:512] if request else None),
        details=details or {},
    )
    session.add(entry)
    try:
        await session.flush()       # append-only, commit driven by caller
    except Exception as exc:
        logger.warning("audit_record_failed", action=action, error=str(exc))


__all__ = ["record_audit"]
