"""Best-effort NinjaOne ticket push for high-severity findings.

Policy (features.md §8.1):
  * One ticket per Critical or High finding (never auto-tickets Medium / Low).
  * Priority mapping: CRITICAL → URGENT, HIGH → HIGH.
  * Skipped when a finding already has a `ninjaone_ticket_id` (idempotent
    across rescans).
  * Failures are logged but never raised — same contract as the DefectDojo
    sync hook.
"""

from __future__ import annotations

from collections.abc import Sequence

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.exceptions import ExternalServiceError
from app.integrations.ninjaone import NinjaOneClient, severity_to_priority
from app.models.enums import FindingSeverity
from app.models.finding import Finding
from app.models.tenant import Tenant

logger = structlog.get_logger()

_AUTO_TICKET_SEVERITIES = (FindingSeverity.CRITICAL, FindingSeverity.HIGH)


def _ninjaone_configured() -> bool:
    s = get_settings()
    return bool(s.NINJAONE_CLIENT_ID and s.NINJAONE_CLIENT_SECRET)


def _build_ticket_body(finding: Finding, tenant: Tenant) -> tuple[str, str]:
    subject = f"[SecureSync/{finding.severity.value.upper()}] {finding.title}"
    body_parts = [
        f"Tenant: {tenant.name} ({tenant.slug})",
        f"Severity: {finding.severity.value}",
        f"Source: {finding.source.value}",
    ]
    if finding.cve_id:
        body_parts.append(f"CVE: {finding.cve_id}")
    if finding.cvss_score is not None:
        body_parts.append(f"CVSS: {finding.cvss_score}")
    if finding.epss_score is not None:
        body_parts.append(f"EPSS: {finding.epss_score} (percentile {finding.epss_percentile})")
    if finding.description:
        body_parts.append("")
        body_parts.append(f"Description:\n{finding.description}")
    if finding.remediation:
        body_parts.append("")
        body_parts.append(f"Remediation:\n{finding.remediation}")
    body_parts.append("")
    body_parts.append(f"Finding id (SecureSync): {finding.id}")
    return subject, "\n".join(body_parts)


async def push_findings_to_ninjaone(
    session: AsyncSession,
    *,
    tenant: Tenant,
    findings: Sequence[Finding],
) -> int:
    """Create NinjaOne tickets for every Critical/High finding that doesn't
    have one yet. Returns the count of successfully-ticketed findings.
    """
    if not _ninjaone_configured():
        return 0

    targets = [
        f
        for f in findings
        if f.severity in _AUTO_TICKET_SEVERITIES and f.ninjaone_ticket_id is None
    ]
    if not targets:
        return 0

    created = 0
    try:
        async with NinjaOneClient() as nj:
            for finding in targets:
                subject, body = _build_ticket_body(finding, tenant)
                try:
                    ticket_id = await nj.create_ticket(
                        subject=subject,
                        description=body,
                        priority=severity_to_priority(finding.severity),
                    )
                except ExternalServiceError as exc:
                    logger.warning(
                        "ninjaone_ticket_failed",
                        finding_id=str(finding.id),
                        error=str(exc),
                    )
                    continue
                finding.ninjaone_ticket_id = ticket_id
                created += 1
    except ExternalServiceError as exc:
        # Connection / auth errors — bail the whole batch, already-created
        # tickets above keep their ids.
        logger.warning("ninjaone_batch_failed", error=str(exc))

    if created:
        await session.commit()
        logger.info(
            "ninjaone_tickets_created",
            tenant_id=str(tenant.id),
            count=created,
        )
    return created


__all__ = ["push_findings_to_ninjaone"]
