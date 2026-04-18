"""Asset model — scan targets (external domains/IPs and internal endpoints)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, pg_enum
from app.models.enums import AssetType

if TYPE_CHECKING:
    from app.models.finding import Finding
    from app.models.scan_job import ScanJob
    from app.models.tenant import Tenant


class Asset(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("tenant_id", "value", name="uq_assets_tenant_id_value"),
    )

    tenant_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    type: Mapped[AssetType] = mapped_column(
        pg_enum(AssetType, name="asset_type"),
        nullable=False,
    )

    # Hostname / IP / CIDR for external; agent_id for internal.
    value: Mapped[str] = mapped_column(String(255), nullable=False)

    # Free-form labels: ["managed", "critical", "dmz", "production"], etc.
    tags: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )

    # Set when type=internal_endpoint and Wazuh registration succeeds.
    wazuh_agent_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # ── Relationships ──
    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="assets")
    scan_jobs: Mapped[list["ScanJob"]] = relationship(
        "ScanJob",
        back_populates="asset",
        cascade="all, delete-orphan",
    )
    findings: Mapped[list["Finding"]] = relationship(
        "Finding",
        back_populates="asset",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Asset id={self.id} type={self.type.value} value={self.value!r}>"
