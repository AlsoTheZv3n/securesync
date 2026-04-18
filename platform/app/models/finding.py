"""Finding model — normalized vulnerability across all scanners."""

from __future__ import annotations

from decimal import Decimal
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import ForeignKey, Index, Numeric, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, pg_enum
from app.models.enums import FindingSeverity, FindingSource, FindingStatus

if TYPE_CHECKING:
    from app.models.asset import Asset
    from app.models.scan_job import ScanJob


class Finding(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "findings"
    __table_args__ = (
        # Speeds up the most common dashboard query: open critical/high
        # findings for a tenant ordered by severity.
        Index("ix_findings_tenant_id_status_severity", "tenant_id", "status", "severity"),
    )

    tenant_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scan_job_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("scan_jobs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asset_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Optional: not every finding maps to a CVE (e.g. ZAP misconfigs).
    cve_id: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)

    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)

    severity: Mapped[FindingSeverity] = mapped_column(
        pg_enum(FindingSeverity, name="finding_severity"),
        nullable=False,
        index=True,
    )
    status: Mapped[FindingStatus] = mapped_column(
        pg_enum(FindingStatus, name="finding_status"),
        nullable=False,
        default=FindingStatus.OPEN,
        server_default=FindingStatus.OPEN.value,
        index=True,
    )
    source: Mapped[FindingSource] = mapped_column(
        pg_enum(FindingSource, name="finding_source"),
        nullable=False,
    )

    # NUMERIC keeps exact CVSS / EPSS values without float drift.
    cvss_score: Mapped[Decimal | None] = mapped_column(Numeric(3, 1), nullable=True)
    epss_score: Mapped[Decimal | None] = mapped_column(Numeric(7, 6), nullable=True)
    epss_percentile: Mapped[Decimal | None] = mapped_column(Numeric(7, 6), nullable=True)

    # Original payload from the scanner — useful for re-parsing without rescanning.
    raw_data: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )

    defectdojo_id: Mapped[int | None] = mapped_column(nullable=True, index=True)

    # NinjaOne ticket id — set best-effort after a ticket is auto-created
    # for Critical/High findings. NULL means either: (a) severity is too low
    # for auto-ticketing, (b) NinjaOne isn't configured, or (c) push failed
    # (details in structlog).
    ninjaone_ticket_id: Mapped[str | None] = mapped_column(
        String(64), nullable=True, index=True
    )

    # ── Relationships ──
    scan_job: Mapped["ScanJob"] = relationship("ScanJob", back_populates="findings")
    asset: Mapped["Asset"] = relationship("Asset", back_populates="findings")

    def __repr__(self) -> str:
        return (
            f"<Finding id={self.id} severity={self.severity.value} "
            f"cve={self.cve_id} status={self.status.value}>"
        )
