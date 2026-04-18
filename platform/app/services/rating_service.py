"""Rating persistence — bridges the pure rating engine and the Rating ORM.

Design: the rating reflects ALL currently-open findings for the tenant,
not just findings from the triggering scan. So a scan that finds 0 new
issues can still produce a great rating if old ones are still open.
"""

from __future__ import annotations

from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import FindingStatus
from app.models.finding import Finding
from app.models.rating import Rating
from app.services.rating_engine import RatingResult, calculate_rating

logger = structlog.get_logger()


async def compute_and_store_rating(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    scan_job_id: UUID,
) -> Rating:
    """Recompute the tenant's rating and persist it linked to this scan job.

    Raises nothing — rating failure must not bring down the scan pipeline.
    Actually, scratch that — rating is core business logic, not a
    side-channel. Failures here SHOULD surface.
    """
    stmt = select(Finding).where(
        Finding.tenant_id == tenant_id,
        Finding.status == FindingStatus.OPEN,
    )
    findings = list((await session.execute(stmt)).scalars().all())

    result: RatingResult = calculate_rating(findings)

    rating = Rating(
        tenant_id=tenant_id,
        scan_job_id=scan_job_id,
        overall_grade=result.overall_grade,
        overall_score=result.overall_score,
        patch_score=result.patch_score,
        network_score=result.network_score,
        web_score=result.web_score,
        endpoint_score=result.endpoint_score,
        email_score=result.email_score,
        breach_score=result.breach_score,
        ransomware_score=result.ransomware_score,
    )
    session.add(rating)
    await session.commit()
    await session.refresh(rating)

    logger.info(
        "rating_computed",
        tenant_id=str(tenant_id),
        scan_job_id=str(scan_job_id),
        grade=result.overall_grade.value,
        score=str(result.overall_score),
        open_findings=len(findings),
    )
    return rating


__all__ = ["compute_and_store_rating"]
