"""Rating model — per-scan A–F security score with category breakdown."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, Numeric, func
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, pg_enum
from app.models.enums import RatingGrade

if TYPE_CHECKING:
    from app.models.scan_job import ScanJob


class Rating(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "ratings"

    tenant_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # One rating per completed scan — enforced at app layer via uselist=False.
    scan_job_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("scan_jobs.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )

    overall_grade: Mapped[RatingGrade] = mapped_column(
        pg_enum(RatingGrade, name="rating_grade"),
        nullable=False,
        index=True,
    )
    overall_score: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)

    # Per-category sub-scores (0–100).
    # Weights defined in app/services/rating_engine.py (see CLAUDE.md contract).
    patch_score: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)
    network_score: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)
    web_score: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)
    endpoint_score: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)
    email_score: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)
    breach_score: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)
    ransomware_score: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)

    calculated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # ── Relationships ──
    scan_job: Mapped["ScanJob"] = relationship("ScanJob", back_populates="rating")

    def __repr__(self) -> str:
        return (
            f"<Rating id={self.id} grade={self.overall_grade.value} "
            f"score={self.overall_score}>"
        )
