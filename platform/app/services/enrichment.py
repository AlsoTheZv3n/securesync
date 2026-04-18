"""Post-scan enrichment hooks.

Enrichment runs on the already-persisted Finding rows so it survives even
when the scanner tasks restart. Best-effort: a missing API key or an EPSS
outage logs a warning but does NOT fail the surrounding scan flow.
"""

from __future__ import annotations

from collections.abc import Sequence

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ExternalServiceError
from app.integrations.epss import EPSSClient
from app.models.finding import Finding

logger = structlog.get_logger()


async def enrich_findings_with_epss(
    session: AsyncSession, findings: Sequence[Finding]
) -> int:
    """Fill in `epss_score` / `epss_percentile` on every finding with a CVE.

    Returns the number of rows that were actually updated (excludes CVEs EPSS
    didn't know about).
    """
    cve_ids = sorted({f.cve_id for f in findings if f.cve_id})
    if not cve_ids:
        return 0

    try:
        async with EPSSClient() as epss:
            scores = await epss.get_batch(cve_ids)
    except ExternalServiceError as exc:
        logger.warning("epss_enrichment_failed", count=len(cve_ids), error=str(exc))
        return 0

    updated = 0
    for finding in findings:
        if not finding.cve_id:
            continue
        score = scores.get(finding.cve_id)
        if score is None:
            continue
        finding.epss_score = score.epss
        finding.epss_percentile = score.percentile
        updated += 1

    if updated:
        await session.commit()
        logger.info(
            "epss_enriched",
            matched=updated,
            total_with_cve=len([f for f in findings if f.cve_id]),
        )
    return updated
