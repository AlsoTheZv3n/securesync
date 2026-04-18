"""Pydantic schemas for Tenant CRUD."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

# DNS label rules: lowercase, alphanumeric + hyphen, 3–63 chars,
# no leading/trailing hyphen. Used for white-label subdomains.
_SLUG_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?$")
_HEX_COLOR_PATTERN = re.compile(r"^#[0-9a-fA-F]{6}$")
# Lenient FQDN check — full punycode validation lives elsewhere if needed.
_DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

Slug = Annotated[str, Field(min_length=3, max_length=63)]
HexColor = Annotated[str, Field(min_length=7, max_length=7)]


class TenantBase(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    slug: Slug
    primary_color: HexColor | None = None
    custom_domain: str | None = Field(default=None, max_length=255)
    logo_url: str | None = Field(default=None, max_length=2048)

    @field_validator("slug")
    @classmethod
    def _validate_slug(cls, v: str) -> str:
        v = v.lower()
        if not _SLUG_PATTERN.match(v):
            raise ValueError(
                "slug must be 3–63 chars, lowercase alphanumeric or hyphen, "
                "no leading/trailing hyphen"
            )
        return v

    @field_validator("primary_color")
    @classmethod
    def _validate_color(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if not _HEX_COLOR_PATTERN.match(v):
            raise ValueError("primary_color must be a hex string like '#3B82F6'")
        return v.lower()

    @field_validator("custom_domain")
    @classmethod
    def _validate_domain(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        v = v.lower().strip(".")
        if not _DOMAIN_PATTERN.match(v):
            raise ValueError("custom_domain must be a valid FQDN")
        return v


class TenantCreate(TenantBase):
    """If `msp_id` is omitted, the API sets it from the calling user's tenant."""
    msp_id: UUID | None = None


class TenantUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    primary_color: HexColor | None = None
    custom_domain: str | None = Field(default=None, max_length=255)
    logo_url: str | None = Field(default=None, max_length=2048)

    @field_validator("primary_color")
    @classmethod
    def _validate_color(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if not _HEX_COLOR_PATTERN.match(v):
            raise ValueError("primary_color must be a hex string like '#3B82F6'")
        return v.lower()

    @field_validator("custom_domain")
    @classmethod
    def _validate_domain(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        v = v.lower().strip(".")
        if not _DOMAIN_PATTERN.match(v):
            raise ValueError("custom_domain must be a valid FQDN")
        return v


class TenantRead(TenantBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    msp_id: UUID | None
    custom_domain_verified: bool = False
    created_at: datetime
    updated_at: datetime


class DomainVerificationChallenge(BaseModel):
    """Returned by POST /tenants/{id}/verify-domain — tells the caller what
    TXT record to add at their DNS provider."""

    custom_domain: str
    dns_name: str            # e.g. "_securesync.customer.example.com"
    txt_record_value: str    # e.g. "securesync-verify=abc123..."
    expires_at: datetime


class DomainVerificationResult(BaseModel):
    """Returned by POST /tenants/{id}/verify-domain/confirm."""

    verified: bool
    custom_domain: str
