"""Celery-beat-driven scheduler tick.

Every minute (configured in `app/core/celery_app.py:beat_schedule`) the
tick runs through every active `ScanSchedule` whose `next_run_at` is in the
past:

  * In-blackout-window hits are SKIPPED and their `next_run_at` bumps past
    the window — we don't queue work the customer explicitly forbade.
  * Otherwise, a `ScanJob` row is created (status=QUEUED) and the matching
    scanner task is dispatched via `.delay()`, exactly like the on-demand
    `POST /scans` flow.

Failures per-schedule are logged but never raise — one bad schedule must
never stop the tick from processing the rest.
"""

from __future__ import annotations

import asyncio
import sys
from datetime import UTC, datetime
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.celery_app import celery_app
from app.models.enums import ScanStatus
from app.models.scan_job import ScanJob
from app.models.scan_schedule import ScanSchedule
from app.services.scheduler import (
    InvalidCronError,
    InvalidTimezoneError,
    is_in_blackout,
    next_run_skipping_blackout,
)
from app.tasks.scan_tasks import (
    _get_session_factory,
    run_nuclei_scan,
    run_openvas_scan,
    run_wazuh_scan,
    run_zap_scan,
)

logger = structlog.get_logger()

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


# Same dispatch shape as /api/v1/scans.py:_TASK_DISPATCH — keeping two
# copies rather than importing so circular-import risk stays zero.
_TASK_DISPATCH_BY_TYPE = {
    "fast": run_nuclei_scan,
    "external_full": run_openvas_scan,
    "web_app": run_zap_scan,
    "internal": run_wazuh_scan,
}


async def _process_one(
    session: AsyncSession, schedule: ScanSchedule, now: datetime
) -> str:
    """Result string for logging: 'dispatched' / 'blackout' / 'invalid' / 'error'."""
    # Validate the cron + timezone here so a bad record can't crash the whole
    # tick. If invalid, mark as error (leave next_run_at untouched — operator
    # fixes the record, the next tick picks it up again).
    try:
        if is_in_blackout(
            now,
            tz_name=schedule.timezone,
            blackout_start=schedule.blackout_start,
            blackout_end=schedule.blackout_end,
        ):
            schedule.next_run_at = next_run_skipping_blackout(
                schedule.cron_expression,
                schedule.timezone,
                blackout_start=schedule.blackout_start,
                blackout_end=schedule.blackout_end,
                after=now,
            )
            return "blackout"

        # Dispatch a ScanJob.
        task = _TASK_DISPATCH_BY_TYPE.get(schedule.scan_type.value)
        if task is None:
            logger.warning(
                "scheduler_no_dispatcher",
                schedule_id=str(schedule.id),
                scan_type=schedule.scan_type.value,
            )
            return "invalid"

        job = ScanJob(
            tenant_id=schedule.tenant_id,
            asset_id=schedule.asset_id,
            scan_type=schedule.scan_type,
            status=ScanStatus.QUEUED,
        )
        session.add(job)
        await session.flush()           # get the id without commit

        async_result = task.delay(str(job.id))
        job.celery_task_id = async_result.id

        schedule.last_run_at = now
        schedule.next_run_at = next_run_skipping_blackout(
            schedule.cron_expression,
            schedule.timezone,
            blackout_start=schedule.blackout_start,
            blackout_end=schedule.blackout_end,
            after=now,
        )
        return "dispatched"
    except (InvalidCronError, InvalidTimezoneError) as exc:
        logger.warning(
            "scheduler_invalid_schedule",
            schedule_id=str(schedule.id),
            error=str(exc),
        )
        return "invalid"


async def _tick_async() -> dict[str, int]:
    """Process all due schedules. Returns per-outcome counts."""
    counts = {"dispatched": 0, "blackout": 0, "invalid": 0, "error": 0}
    factory = _get_session_factory()
    now = datetime.now(UTC)

    async with factory() as session:
        due = (
            await session.execute(
                select(ScanSchedule)
                .where(
                    ScanSchedule.is_active.is_(True),
                    ScanSchedule.next_run_at <= now,
                )
                .order_by(ScanSchedule.next_run_at.asc())
            )
        ).scalars().all()

        for schedule in due:
            try:
                outcome = await _process_one(session, schedule, now)
            except Exception as exc:      # isolate per-schedule failures
                logger.error(
                    "scheduler_tick_error",
                    schedule_id=str(schedule.id),
                    error=str(exc),
                )
                outcome = "error"
            counts[outcome] = counts.get(outcome, 0) + 1

        await session.commit()

    if any(counts.values()):
        logger.info("scheduler_tick", **counts)
    return counts


# Small helper so integration tests can invoke `_process_one` against a
# caller-supplied session without spinning up the worker engine.
async def process_one_for_test(
    session: AsyncSession, schedule_id: UUID, now: datetime
) -> str:
    schedule = (
        await session.execute(
            select(ScanSchedule).where(ScanSchedule.id == schedule_id)
        )
    ).scalar_one()
    outcome = await _process_one(session, schedule, now)
    await session.commit()
    return outcome


@celery_app.task(name="scheduler.tick")
def tick_schedules() -> dict[str, int]:
    """Beat entry point. Configured in `celery_app.py:beat_schedule`."""
    return asyncio.run(_tick_async())
