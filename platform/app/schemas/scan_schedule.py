"""Pydantic schemas for ScanSchedule CRUD."""

from __future__ import annotations

from datetime import datetime, time
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.enums import ScanType
from app.services.scheduler import (
    InvalidCronError,
    InvalidTimezoneError,
    resolve_timezone,
    validate_cron,
)


class ScanScheduleBase(BaseModel):
    cron_expression: str = Field(min_length=9, max_length=128)
    timezone: str = Field(default="UTC", max_length=64)
    is_active: bool = True
    blackout_start: time | None = None
    blackout_end: time | None = None

    @field_validator("cron_expression")
    @classmethod
    def _check_cron(cls, v: str) -> str:
        try:
            validate_cron(v)
        except InvalidCronError as exc:
            raise ValueError(str(exc)) from exc
        return v

    @field_validator("timezone")
    @classmethod
    def _check_timezone(cls, v: str) -> str:
        try:
            resolve_timezone(v)
        except InvalidTimezoneError as exc:
            raise ValueError(str(exc)) from exc
        return v

    @model_validator(mode="after")
    def _check_blackout_pair(self) -> "ScanScheduleBase":
        # Both-or-neither on the blackout pair.
        if (self.blackout_start is None) != (self.blackout_end is None):
            raise ValueError(
                "blackout_start and blackout_end must both be set or both omitted"
            )
        return self


class ScanScheduleCreate(ScanScheduleBase):
    asset_id: UUID
    scan_type: ScanType


class ScanScheduleUpdate(BaseModel):
    cron_expression: str | None = Field(default=None, min_length=9, max_length=128)
    timezone: str | None = Field(default=None, max_length=64)
    is_active: bool | None = None
    blackout_start: time | None = None
    blackout_end: time | None = None
    scan_type: ScanType | None = None

    @field_validator("cron_expression")
    @classmethod
    def _check_cron(cls, v: str | None) -> str | None:
        if v is None:
            return v
        try:
            validate_cron(v)
        except InvalidCronError as exc:
            raise ValueError(str(exc)) from exc
        return v

    @field_validator("timezone")
    @classmethod
    def _check_timezone(cls, v: str | None) -> str | None:
        if v is None:
            return v
        try:
            resolve_timezone(v)
        except InvalidTimezoneError as exc:
            raise ValueError(str(exc)) from exc
        return v


class ScanScheduleRead(ScanScheduleBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    asset_id: UUID
    scan_type: ScanType
    next_run_at: datetime
    last_run_at: datetime | None
    created_at: datetime
    updated_at: datetime
