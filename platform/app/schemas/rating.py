"""Pydantic schemas for Rating read endpoints."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.models.enums import RatingGrade


class RatingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    scan_job_id: UUID
    overall_grade: RatingGrade
    overall_score: Decimal
    patch_score: Decimal
    network_score: Decimal
    web_score: Decimal
    endpoint_score: Decimal
    email_score: Decimal
    breach_score: Decimal
    ransomware_score: Decimal
    calculated_at: datetime
