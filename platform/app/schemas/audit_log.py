"""Read-only schema for audit log entries."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class AuditLogRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID | None
    user_id: UUID | None
    action: str
    resource_type: str | None
    resource_id: UUID | None
    ip_address: str | None
    user_agent: str | None
    details: dict[str, Any]
    created_at: datetime
