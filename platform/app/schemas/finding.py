"""Pydantic schemas for Finding read/update."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import FindingSeverity, FindingSource, FindingStatus


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    scan_job_id: UUID
    asset_id: UUID
    cve_id: str | None
    title: str
    description: str | None
    remediation: str | None
    evidence: str | None
    severity: FindingSeverity
    status: FindingStatus
    source: FindingSource
    cvss_score: Decimal | None
    epss_score: Decimal | None
    epss_percentile: Decimal | None
    raw_data: dict[str, Any] = Field(default_factory=dict)
    defectdojo_id: int | None
    created_at: datetime
    updated_at: datetime


class FindingUpdate(BaseModel):
    """Mutable fields on a finding. Severity / source / scanner data is immutable."""

    status: FindingStatus | None = None
    # Free-text justification — required by UI when marking false_positive,
    # validated at the API layer (not here, so single-field updates still work).
    resolution_notes: str | None = Field(default=None, max_length=2000)
