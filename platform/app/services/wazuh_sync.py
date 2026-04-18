"""Best-effort Wazuh sync hooks.

Same contract as defectdojo_sync.py: calls never raise into the main flow,
they only emit warning-level logs and move on.
"""

from __future__ import annotations

import structlog

from app.core.config import get_settings
from app.core.exceptions import ExternalServiceError
from app.integrations.wazuh import WazuhClient, tenant_group_name
from app.models.tenant import Tenant

logger = structlog.get_logger()


def _wazuh_configured() -> bool:
    s = get_settings()
    return bool(s.WAZUH_API_URL and s.WAZUH_USERNAME and s.WAZUH_PASSWORD)


async def provision_agent_group_for_tenant(tenant: Tenant) -> None:
    """Create a Wazuh agent group for this tenant, idempotent.

    The group name is derived from `tenant.slug` (no DB column needed — the
    mapping is deterministic). If Wazuh is offline or rejects the call, we
    just log it and move on.
    """
    if not _wazuh_configured():
        return

    try:
        group = tenant_group_name(tenant.slug)
    except ValueError as exc:
        logger.warning("wazuh_group_name_invalid", tenant_id=str(tenant.id), error=str(exc))
        return

    try:
        async with WazuhClient() as w:
            await w.create_agent_group(group)
    except ExternalServiceError as exc:
        logger.warning(
            "wazuh_group_create_failed",
            tenant_id=str(tenant.id),
            group=group,
            error=str(exc),
        )
        return

    logger.info("wazuh_group_created", tenant_id=str(tenant.id), group=group)
