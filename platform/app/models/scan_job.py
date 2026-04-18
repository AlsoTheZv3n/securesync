"""ScanJob model — one row per scan run, owns its findings and rating."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, pg_enum
from app.models.enums import ScanStatus, ScanType

if TYPE_CHECKING:
    from app.models.asset import Asset
    from app.models.finding import Finding
    from app.models.rating import Rating


class ScanJob(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "scan_jobs"

    tenant_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asset_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    scan_type: Mapped[ScanType] = mapped_column(
        pg_enum(ScanType, name="scan_type"),
        nullable=False,
    )
    status: Mapped[ScanStatus] = mapped_column(
        pg_enum(ScanStatus, name="scan_status"),
        nullable=False,
        default=ScanStatus.QUEUED,
        server_default=ScanStatus.QUEUED.value,
        index=True,
    )

    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    celery_task_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # DefectDojo engagement id — set after findings are successfully pushed.
    # Nullable: a DefectDojo outage doesn't fail the scan itself.
    defectdojo_engagement_id: Mapped[int | None] = mapped_column(
        Integer, nullable=True, index=True
    )

    # ── Relationships ──
    asset: Mapped["Asset"] = relationship("Asset", back_populates="scan_jobs")
    findings: Mapped[list["Finding"]] = relationship(
        "Finding",
        back_populates="scan_job",
        cascade="all, delete-orphan",
    )
    rating: Mapped["Rating | None"] = relationship(
        "Rating",
        back_populates="scan_job",
        uselist=False,
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return (
            f"<ScanJob id={self.id} type={self.scan_type.value} "
            f"status={self.status.value}>"
        )
