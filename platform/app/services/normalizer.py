"""Unified finding schema across all scanners.

Every scanner integration (`app.integrations.*`) returns a list of
`NormalizedFinding`. The `to_orm` helper converts them to `Finding` rows once
the scan owner (tenant + scan_job + asset) is known.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.enums import FindingSeverity, FindingSource
from app.models.finding import Finding


class NormalizedFinding(BaseModel):
    """Vendor-neutral finding shape produced by every scanner integration."""

    model_config = ConfigDict(frozen=True)

    title: str = Field(min_length=1, max_length=512)
    severity: FindingSeverity
    source: FindingSource

    # Target as the scanner saw it (URL / hostname / IP / agent id).
    # Resolved to an asset_id by the calling Celery task.
    asset_value: str = Field(min_length=1, max_length=255)

    cve_id: str | None = Field(default=None, max_length=20)
    description: str | None = None
    remediation: str | None = None
    evidence: str | None = None
    cvss_score: Decimal | None = None
    epss_score: Decimal | None = None
    epss_percentile: Decimal | None = None

    # Original scanner payload — kept for re-parsing without rescanning.
    raw_data: dict[str, Any] = Field(default_factory=dict)

    @field_validator("cve_id")
    @classmethod
    def _normalise_cve(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip().upper()
        if not v.startswith("CVE-"):
            raise ValueError(f"cve_id must start with 'CVE-', got {v!r}")
        return v

    @field_validator("cvss_score")
    @classmethod
    def _check_cvss_range(cls, v: Decimal | None) -> Decimal | None:
        if v is None:
            return None
        if not (Decimal("0.0") <= v <= Decimal("10.0")):
            raise ValueError("cvss_score must be in [0.0, 10.0]")
        return v


def to_orm(
    finding: NormalizedFinding,
    *,
    tenant_id: UUID,
    scan_job_id: UUID,
    asset_id: UUID,
) -> Finding:
    """Build (un-persisted) ORM row from a NormalizedFinding + scan ownership."""
    return Finding(
        tenant_id=tenant_id,
        scan_job_id=scan_job_id,
        asset_id=asset_id,
        cve_id=finding.cve_id,
        title=finding.title[:512],
        description=finding.description,
        remediation=finding.remediation,
        evidence=finding.evidence,
        severity=finding.severity,
        source=finding.source,
        cvss_score=finding.cvss_score,
        epss_score=finding.epss_score,
        epss_percentile=finding.epss_percentile,
        raw_data=finding.raw_data,
    )
