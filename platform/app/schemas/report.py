"""Pydantic schemas for Report generation + read endpoints."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.models.enums import ReportType


class ReportCreate(BaseModel):
    scan_job_id: UUID
    type: ReportType


class ReportRead(BaseModel):
    """Metadata only — use GET /reports/{id}/download for the PDF bytes."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    scan_job_id: UUID | None
    type: ReportType
    title: str
    pdf_size_bytes: int
    generated_by_user_id: UUID | None
    created_at: datetime
