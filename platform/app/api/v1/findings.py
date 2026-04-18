"""Finding read + status-update endpoints."""

from __future__ import annotations

from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import (
    assert_tenant_access,
    get_current_user,
    require_role,
)
from app.core.exceptions import (
    ResourceNotFoundError,
    ValidationError,
)
from app.models.enums import FindingSeverity, FindingSource, FindingStatus, UserRole
from app.models.finding import Finding
from app.models.user import User
from app.schemas.finding import FindingRead, FindingUpdate
from app.services.audit import record_audit

router = APIRouter(prefix="/findings", tags=["findings"])
logger = structlog.get_logger()


@router.get("", response_model=list[FindingRead])
async def list_findings(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    tenant_id: UUID | None = Query(default=None, description="Defaults to caller's tenant"),
    asset_id: UUID | None = Query(default=None),
    scan_job_id: UUID | None = Query(default=None),
    severity: FindingSeverity | None = Query(default=None),
    finding_status: FindingStatus | None = Query(default=None, alias="status"),
    source: FindingSource | None = Query(default=None),
    cve_id: str | None = Query(default=None, max_length=20),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
) -> list[Finding]:
    target_tenant_id = tenant_id or user.tenant_id
    await assert_tenant_access(target_tenant_id, user, db)

    stmt = select(Finding).where(Finding.tenant_id == target_tenant_id)
    if asset_id is not None:
        stmt = stmt.where(Finding.asset_id == asset_id)
    if scan_job_id is not None:
        stmt = stmt.where(Finding.scan_job_id == scan_job_id)
    if severity is not None:
        stmt = stmt.where(Finding.severity == severity)
    if finding_status is not None:
        stmt = stmt.where(Finding.status == finding_status)
    if source is not None:
        stmt = stmt.where(Finding.source == source)
    if cve_id is not None:
        stmt = stmt.where(Finding.cve_id == cve_id.upper().strip())

    # Severity desc → critical first; tie-break by recency.
    stmt = stmt.order_by(Finding.severity.desc(), Finding.created_at.desc()).offset(skip).limit(limit)
    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.get("/{finding_id}", response_model=FindingRead)
async def get_finding(
    finding_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Finding:
    finding = (
        await db.execute(select(Finding).where(Finding.id == finding_id))
    ).scalar_one_or_none()
    if finding is None:
        raise ResourceNotFoundError("finding not found")
    await assert_tenant_access(finding.tenant_id, user, db)
    return finding


@router.patch(
    "/{finding_id}",
    response_model=FindingRead,
    dependencies=[
        Depends(
            require_role(
                UserRole.PLATFORM_ADMIN, UserRole.MSP_ADMIN, UserRole.MSP_TECHNICIAN
            )
        )
    ],
)
async def update_finding(
    finding_id: UUID,
    payload: FindingUpdate,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Finding:
    finding = (
        await db.execute(select(Finding).where(Finding.id == finding_id))
    ).scalar_one_or_none()
    if finding is None:
        raise ResourceNotFoundError("finding not found")
    await assert_tenant_access(finding.tenant_id, user, db)

    update_data = payload.model_dump(exclude_unset=True)
    new_status = update_data.get("status")

    # Marking as false_positive or accepted_risk requires a justification —
    # both for audit reasons and to prevent click-through suppression.
    if new_status in {FindingStatus.FALSE_POSITIVE, FindingStatus.ACCEPTED}:
        notes = update_data.get("resolution_notes") or ""
        if len(notes.strip()) < 5:
            raise ValidationError(
                f"resolution_notes (>=5 chars) required when setting status to {new_status.value}"
            )

    previous_status = finding.status
    if new_status is not None:
        finding.status = new_status

    # Audit BEFORE commit so one transaction persists both rows.
    if new_status is not None and new_status is not previous_status:
        await record_audit(
            db,
            action=f"finding.status.{new_status.value}",
            user=user,
            request=request,
            resource_type="finding",
            resource_id=finding.id,
            tenant_id=finding.tenant_id,
            details={
                "previous_status": previous_status.value,
                "new_status": new_status.value,
                "resolution_notes": update_data.get("resolution_notes"),
            },
        )

    await db.commit()
    await db.refresh(finding)

    # Phase 4 will replace this with a proper audit-log table — for now,
    # structured logs serve as the trail.
    logger.info(
        "finding_updated",
        finding_id=str(finding.id),
        tenant_id=str(finding.tenant_id),
        previous_status=previous_status.value,
        new_status=finding.status.value,
        resolution_notes=update_data.get("resolution_notes"),
        by=str(user.id),
    )
    return finding
