"""ScanSchedule model — a recurring scan configuration per tenant/asset.

Driven by a Celery Beat task that polls the table once a minute
(`app/tasks/scheduler_tasks.py:tick_schedules`). For each schedule whose
`next_run_at <= now`, the tick dispatches the corresponding scan task and
recomputes the next run from the cron expression.

Blackout window semantics ("no scans during this time"):
    * Pair of `blackout_start` / `blackout_end` times (in the tenant's
      `timezone`).
    * A fire that lands inside the window is skipped — we bump
      `next_run_at` past the window and wait.
    * Wrap-around supported: 22:00 → 04:00 means 22:00–23:59 and 00:00–04:00.
"""

from __future__ import annotations

from datetime import datetime, time
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Time
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, pg_enum
from app.models.enums import ScanType

if TYPE_CHECKING:
    from app.models.asset import Asset
    from app.models.tenant import Tenant


class ScanSchedule(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "scan_schedules"

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

    # Standard 5-field cron: "minute hour day-of-month month day-of-week".
    # We validate at the schema layer via croniter.
    cron_expression: Mapped[str] = mapped_column(String(128), nullable=False)

    # IANA timezone name, e.g. "Europe/Zurich" or "UTC". Used to interpret
    # both the cron expression and the blackout window.
    timezone: Mapped[str] = mapped_column(
        String(64), nullable=False, default="UTC", server_default="UTC"
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )

    # Optional blackout window — when BOTH columns are set, scans firing
    # inside this local-time range are skipped (not queued).
    blackout_start: Mapped[time | None] = mapped_column(Time, nullable=True)
    blackout_end: Mapped[time | None] = mapped_column(Time, nullable=True)

    # Beat-tick bookkeeping.
    next_run_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    last_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ── Relationships ──
    tenant: Mapped["Tenant"] = relationship("Tenant")
    asset: Mapped["Asset"] = relationship("Asset")

    def __repr__(self) -> str:
        return (
            f"<ScanSchedule id={self.id} cron={self.cron_expression!r} "
            f"type={self.scan_type.value} active={self.is_active}>"
        )
