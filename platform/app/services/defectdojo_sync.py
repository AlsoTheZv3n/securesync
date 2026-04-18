"""Best-effort DefectDojo sync hooks.

Every function here is **non-blocking**: if DefectDojo is unreachable, returns
an error, or isn't configured at all, we log a warning and move on. The core
tenant/scan flows must never fail because of a DefectDojo outage.
"""

from __future__ import annotations

from datetime import date

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.exceptions import ExternalServiceError
from app.integrations.defectdojo import DefectDojoClient
from app.models.scan_job import ScanJob
from app.models.tenant import Tenant
from app.services.normalizer import NormalizedFinding

logger = structlog.get_logger()


def _defectdojo_configured() -> bool:
    s = get_settings()
    return bool(s.DEFECTDOJO_URL and s.DEFECTDOJO_API_KEY)


async def provision_product_for_tenant(session: AsyncSession, tenant: Tenant) -> None:
    """Create a DefectDojo product for this tenant if configured.

    Stores the returned id on `tenant.defectdojo_product_id` and commits.
    Silently skips if DefectDojo is unconfigured, the tenant already has a
    product, or the call fails.
    """
    if not _defectdojo_configured():
        return
    if tenant.defectdojo_product_id is not None:
        return

    try:
        async with DefectDojoClient() as dd:
            product_id = await dd.create_product(
                name=tenant.slug,
                description=f"SecureSync tenant: {tenant.name}",
            )
    except ExternalServiceError as exc:
        logger.warning(
            "defectdojo_product_create_failed",
            tenant_id=str(tenant.id),
            error=str(exc),
        )
        return

    tenant.defectdojo_product_id = product_id
    await session.commit()
    logger.info(
        "defectdojo_product_created",
        tenant_id=str(tenant.id),
        product_id=product_id,
    )


async def push_scan_to_defectdojo(
    session: AsyncSession,
    scan_job: ScanJob,
    tenant: Tenant,
    findings: list[NormalizedFinding],
) -> None:
    """Push a completed scan's findings into DefectDojo.

    Creates a fresh engagement under the tenant's product, uploads findings
    as Generic Findings Import (dedup happens inside DefectDojo), and stores
    the engagement id on the ScanJob. Swallows errors.
    """
    if not _defectdojo_configured():
        return
    if tenant.defectdojo_product_id is None:
        logger.info(
            "defectdojo_push_skipped_no_product",
            tenant_id=str(tenant.id),
            scan_job_id=str(scan_job.id),
        )
        return
    if not findings:
        return

    scan_date = date.today().isoformat()
    engagement_name = f"{scan_job.scan_type.value}-{scan_job.id}"

    try:
        async with DefectDojoClient() as dd:
            engagement_id = await dd.create_engagement(
                product_id=tenant.defectdojo_product_id,
                name=engagement_name,
                target_start=scan_date,
                target_end=scan_date,
            )
            await dd.import_findings(
                engagement_id=engagement_id,
                findings=findings,
                scan_date=scan_date,
            )
    except ExternalServiceError as exc:
        logger.warning(
            "defectdojo_push_failed",
            scan_job_id=str(scan_job.id),
            error=str(exc),
        )
        return

    scan_job.defectdojo_engagement_id = engagement_id
    await session.commit()
    logger.info(
        "defectdojo_push_ok",
        scan_job_id=str(scan_job.id),
        engagement_id=engagement_id,
        findings=len(findings),
    )


