"""Pydantic schemas for User read/write."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.models.enums import UserRole


class UserBase(BaseModel):
    email: EmailStr
    role: UserRole


class UserCreate(UserBase):
    password: str = Field(min_length=12, max_length=256)
    tenant_id: UUID


class UserRead(UserBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    is_active: bool
    mfa_enabled: bool
    created_at: datetime


# ── Invitation flow ─────────────────────────────────────────
class UserInvite(BaseModel):
    """Payload an admin sends to invite a new user into a tenant."""

    email: EmailStr
    role: UserRole
    tenant_id: UUID


class UserInviteResponse(BaseModel):
    """Response to a successful invite. The frontend is responsible for
    building the accept-link using the returned token — keeps the API
    transport-agnostic (mail / Slack / chat / printed page)."""

    user_id: UUID
    email: EmailStr
    role: UserRole
    tenant_id: UUID
    invitation_token: str
    invitation_expires_at: datetime


class UserAcceptInvitation(BaseModel):
    """Payload the invitee sends to activate the account."""

    token: str = Field(min_length=16, max_length=128)
    password: str = Field(min_length=12, max_length=256)
