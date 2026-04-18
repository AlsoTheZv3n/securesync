"""Pydantic schemas for Asset CRUD."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.enums import AssetType

# Hostname per RFC 1123, lenient — full DNS label validation done elsewhere.
_HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.)*"
    r"[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?$"
)


def _looks_like_ip_or_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return True


class AssetBase(BaseModel):
    type: AssetType
    value: str = Field(min_length=1, max_length=255)
    tags: dict[str, Any] = Field(default_factory=dict)

    @field_validator("value")
    @classmethod
    def _strip_value(cls, v: str) -> str:
        return v.strip()

    @model_validator(mode="after")
    def _validate_value_for_type(self) -> "AssetBase":
        match self.type:
            case AssetType.EXTERNAL_DOMAIN:
                # The hostname regex would also accept "192.168.1.1" because
                # IP-like strings are valid DNS labels. Reject IPs explicitly
                # so users use the EXTERNAL_IP type instead.
                if _looks_like_ip_or_cidr(self.value):
                    raise ValueError(
                        "value looks like an IP/CIDR — use type=external_ip instead"
                    )
                if not _HOSTNAME_PATTERN.match(self.value):
                    raise ValueError("value must be a valid hostname for external_domain")
            case AssetType.EXTERNAL_IP:
                if not _looks_like_ip_or_cidr(self.value):
                    raise ValueError("value must be an IP address or CIDR for external_ip")
            case AssetType.INTERNAL_ENDPOINT:
                # Wazuh agent identifiers are short alphanumerics — keep loose for now.
                if len(self.value) > 64:
                    raise ValueError("agent identifier too long")
        return self


class AssetCreate(AssetBase):
    tenant_id: UUID


class AssetUpdate(BaseModel):
    """Only mutable fields. Type and value are immutable after creation."""
    tags: dict[str, Any] | None = None
    wazuh_agent_id: str | None = Field(default=None, max_length=64)


class AssetRead(AssetBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    wazuh_agent_id: str | None
    created_at: datetime
    updated_at: datetime
