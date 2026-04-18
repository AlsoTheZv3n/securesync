"""Tenant model — MSP partners and their customer tenants.

Self-referential: a customer tenant has `msp_id` pointing to its parent MSP
tenant. MSP tenants themselves have `msp_id IS NULL`.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.asset import Asset
    from app.models.user import User


class Tenant(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "tenants"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(63), nullable=False, unique=True, index=True)

    # White-label branding
    logo_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    primary_color: Mapped[str | None] = mapped_column(String(7), nullable=True)  # hex #RRGGBB
    custom_domain: Mapped[str | None] = mapped_column(
        String(255), nullable=True, unique=True, index=True
    )

    # Self-referential MSP → Customer relationship.
    # NULL = top-level MSP partner; non-null = customer of that MSP.
    msp_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )

    # Soft-delete: tombstone instead of CASCADE so audit trail is preserved.
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # DefectDojo product id. Populated best-effort after tenant creation —
    # nullable so a DefectDojo outage doesn't block tenant onboarding.
    defectdojo_product_id: Mapped[int | None] = mapped_column(
        Integer, nullable=True, index=True
    )

    # Custom-domain DNS ownership verification. The flow sets
    # `custom_domain_verification_token` to a one-time value, user adds a
    # TXT record, we look it up, if it matches we set `custom_domain_verified`.
    # Only verified domains get vhosts + Let's Encrypt certs provisioned.
    custom_domain_verified: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    custom_domain_verification_token: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )

    # ── Relationships ──
    msp: Mapped["Tenant | None"] = relationship(
        "Tenant",
        remote_side="Tenant.id",
        back_populates="customers",
    )
    customers: Mapped[list["Tenant"]] = relationship(
        "Tenant",
        back_populates="msp",
        cascade="save-update",
    )
    users: Mapped[list["User"]] = relationship(
        "User",
        back_populates="tenant",
        cascade="all, delete-orphan",
    )
    assets: Mapped[list["Asset"]] = relationship(
        "Asset",
        back_populates="tenant",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Tenant id={self.id} slug={self.slug!r} msp_id={self.msp_id}>"
