"""Report model — generated PDFs (executive + technical) per scan."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import ForeignKey, LargeBinary, String
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, pg_enum
from app.models.enums import ReportType

if TYPE_CHECKING:
    from app.models.scan_job import ScanJob


class Report(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "reports"

    tenant_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Nullable: some reports (e.g. cross-asset rollups) may not tie to one scan.
    scan_job_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("scan_jobs.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    type: Mapped[ReportType] = mapped_column(
        pg_enum(ReportType, name="report_type"),
        nullable=False,
        index=True,
    )

    # PDF bytes stored inline for Phase 3. Migrate to S3 once volumes grow —
    # 1000 tenants × 12 monthly reports × 2 MB ≈ 24 GB per year is the
    # rough trip-point.
    pdf_data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    pdf_size_bytes: Mapped[int] = mapped_column(nullable=False)

    # Rough content description for the list view.
    title: Mapped[str] = mapped_column(String(255), nullable=False)

    # Who triggered generation. Nullable because scheduled jobs may have
    # no user attached (Phase 4 scheduler).
    generated_by_user_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # ── Relationships ──
    scan_job: Mapped["ScanJob | None"] = relationship("ScanJob")

    def __repr__(self) -> str:
        return (
            f"<Report id={self.id} type={self.type.value} "
            f"size={self.pdf_size_bytes}b>"
        )
