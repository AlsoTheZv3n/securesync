"""Report endpoints — generate, list, download.

Generation is synchronous for MVP. Most reports render in under a second
and we already block for the same amount of time on DefectDojo/EPSS.
Move to a Celery task if Phase 4 shows user-visible slowdowns.
"""

from __future__ import annotations

from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, Query, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import (
    assert_tenant_access,
    get_current_user,
    require_role,
)
from app.core.exceptions import ResourceNotFoundError, ValidationError
from app.models.enums import ReportType, ScanStatus, UserRole
from app.models.report import Report
from app.models.scan_job import ScanJob
from app.models.user import User
from app.schemas.report import ReportCreate, ReportRead
from app.services.audit import record_audit
from app.services.report_generator import generate_report_pdf

router = APIRouter(prefix="/reports", tags=["reports"])
logger = structlog.get_logger()


@router.post(
    "",
    response_model=ReportRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(
            require_role(
                UserRole.PLATFORM_ADMIN, UserRole.MSP_ADMIN, UserRole.MSP_TECHNICIAN
            )
        )
    ],
)
async def generate_report(
    payload: ReportCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Report:
    """Render and persist a PDF report for a completed scan."""
    scan_job = (
        await db.execute(select(ScanJob).where(ScanJob.id == payload.scan_job_id))
    ).scalar_one_or_none()
    if scan_job is None:
        raise ResourceNotFoundError("scan job not found")
    await assert_tenant_access(scan_job.tenant_id, user, db)

    if scan_job.status is not ScanStatus.COMPLETED:
        raise ValidationError(
            f"scan is {scan_job.status.value} — only completed scans can be reported on"
        )

    try:
        pdf_bytes, title = await generate_report_pdf(
            db,
            tenant_id=scan_job.tenant_id,
            scan_job_id=scan_job.id,
            report_type=payload.type,
        )
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc

    report = Report(
        tenant_id=scan_job.tenant_id,
        scan_job_id=scan_job.id,
        type=payload.type,
        pdf_data=pdf_bytes,
        pdf_size_bytes=len(pdf_bytes),
        title=title,
        generated_by_user_id=user.id,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    logger.info(
        "report_persisted",
        report_id=str(report.id),
        tenant_id=str(report.tenant_id),
        type=report.type.value,
        size=report.pdf_size_bytes,
        by=str(user.id),
    )
    return report


@router.get("", response_model=list[ReportRead])
async def list_reports(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    tenant_id: UUID | None = Query(default=None),
    report_type: ReportType | None = Query(default=None, alias="type"),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
) -> list[Report]:
    target_tenant_id = tenant_id or user.tenant_id
    await assert_tenant_access(target_tenant_id, user, db)

    stmt = select(Report).where(Report.tenant_id == target_tenant_id)
    if report_type is not None:
        stmt = stmt.where(Report.type == report_type)
    stmt = stmt.order_by(Report.created_at.desc()).offset(skip).limit(limit)

    return list((await db.execute(stmt)).scalars().all())


@router.get("/{report_id}", response_model=ReportRead)
async def get_report(
    report_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Report:
    report = (
        await db.execute(select(Report).where(Report.id == report_id))
    ).scalar_one_or_none()
    if report is None:
        raise ResourceNotFoundError("report not found")
    await assert_tenant_access(report.tenant_id, user, db)
    return report


@router.get("/{report_id}/download")
async def download_report(
    report_id: UUID,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    report = (
        await db.execute(select(Report).where(Report.id == report_id))
    ).scalar_one_or_none()
    if report is None:
        raise ResourceNotFoundError("report not found")
    await assert_tenant_access(report.tenant_id, user, db)

    # Audit the download — reports contain CVE detail and customer PII,
    # tracking every access is a Phase-4 compliance baseline.
    await record_audit(
        db,
        action="report.download",
        user=user,
        request=request,
        resource_type="report",
        resource_id=report.id,
        tenant_id=report.tenant_id,
        details={"type": report.type.value, "size": report.pdf_size_bytes},
    )
    await db.commit()

    filename = f"{report.type.value}-report-{report.id}.pdf"
    return Response(
        content=report.pdf_data,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
