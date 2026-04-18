"""Pydantic schemas for ScanJob CRUD."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import ScanStatus, ScanType

# Scan types whose integration + Celery task are wired up. The API rejects
# other types with 422 even though the enum knows about them — this protects
# us from queueing work no worker can handle.
#   Phase 1.5: FAST (Nuclei)
#   Phase 2.1: + EXTERNAL_FULL (OpenVAS / Greenbone)
#   Phase 2.2: + WEB_APP (OWASP ZAP)
#   Phase 2.4: + INTERNAL (Wazuh Manager poll)
IMPLEMENTED_SCAN_TYPES: frozenset[ScanType] = frozenset(
    {ScanType.FAST, ScanType.EXTERNAL_FULL, ScanType.WEB_APP, ScanType.INTERNAL}
)


class ScanCreate(BaseModel):
    asset_id: UUID
    scan_type: ScanType


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    asset_id: UUID
    scan_type: ScanType
    status: ScanStatus
    started_at: datetime | None
    completed_at: datetime | None
    celery_task_id: str | None
    error_message: str | None
    created_at: datetime


class ScanReadWithCounts(ScanRead):
    """Detail view — includes findings_count for the dashboard."""
    findings_count: int = Field(default=0, ge=0)
