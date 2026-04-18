"""Pure helpers for scan scheduling — cron parsing, blackout windows, next-run math.

Deliberately no DB or Celery imports. The Celery beat task in
`app/tasks/scheduler_tasks.py` orchestrates these helpers.
"""

from __future__ import annotations

from datetime import UTC, datetime, time
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from croniter import CroniterBadCronError, croniter


class InvalidCronError(ValueError):
    """Cron expression can't be parsed / isn't a valid 5-field cron."""


class InvalidTimezoneError(ValueError):
    """Unknown IANA timezone name."""


def validate_cron(expression: str) -> None:
    """Raise `InvalidCronError` if not a valid 5-field cron.

    Explicitly rejects 6-/7-field variants (seconds or year) — our scheduler
    tick only runs once a minute, so sub-minute granularity is meaningless,
    and `0 0 * * * 2027` year-specific cron would silently never fire.
    """
    fields = expression.strip().split()
    if len(fields) != 5:
        raise InvalidCronError(
            f"cron must have exactly 5 fields (got {len(fields)}): {expression!r}"
        )
    try:
        if not croniter.is_valid(expression):
            raise InvalidCronError(f"invalid cron expression: {expression!r}")
    except CroniterBadCronError as exc:
        raise InvalidCronError(f"invalid cron expression: {expression!r}") from exc


def resolve_timezone(tz_name: str) -> ZoneInfo:
    try:
        return ZoneInfo(tz_name)
    except ZoneInfoNotFoundError as exc:
        raise InvalidTimezoneError(f"unknown timezone: {tz_name!r}") from exc


def compute_next_run(
    cron_expression: str, tz_name: str, *, after: datetime | None = None
) -> datetime:
    """Return the next firing strictly after `after` (defaults to now).

    Returned datetime is in UTC for easy DB storage; the cron is evaluated
    in the tenant's timezone so "every day at 03:00" means 03:00 LOCAL.
    """
    validate_cron(cron_expression)
    tz = resolve_timezone(tz_name)

    reference_utc = after or datetime.now(UTC)
    # croniter wants a timezone-aware anchor in the SAME tz as the cron
    # evaluation so DST boundaries resolve correctly.
    reference_local = reference_utc.astimezone(tz)

    iter_ = croniter(cron_expression, reference_local)
    next_local: datetime = iter_.get_next(datetime)
    return next_local.astimezone(UTC)


def is_in_blackout(
    now_utc: datetime,
    *,
    tz_name: str,
    blackout_start: time | None,
    blackout_end: time | None,
) -> bool:
    """True if `now_utc` falls inside [start, end) in the tenant's timezone.

    Supports midnight-wrapping windows (22:00 → 04:00). If either endpoint
    is None, there's no blackout — always returns False.
    """
    if blackout_start is None or blackout_end is None:
        return False
    if blackout_start == blackout_end:
        # Zero-length window — treat as "no blackout" rather than "always
        # blocked" to avoid soft-locking schedules when a user accidentally
        # sets the same start/end.
        return False

    tz = resolve_timezone(tz_name)
    local_now = now_utc.astimezone(tz).time()

    if blackout_start < blackout_end:
        return blackout_start <= local_now < blackout_end
    # Wrap-around: the window spans midnight.
    return local_now >= blackout_start or local_now < blackout_end


def next_run_skipping_blackout(
    cron_expression: str,
    tz_name: str,
    *,
    blackout_start: time | None,
    blackout_end: time | None,
    after: datetime | None = None,
    max_steps: int = 24 * 60,       # a full day of cron firings per-minute
) -> datetime:
    """Walk the cron schedule until we land on a firing that ISN'T in the
    blackout window. `max_steps` caps the walk so a pathological config
    (cron that only fires inside a blackout) doesn't spin forever.
    """
    candidate = compute_next_run(cron_expression, tz_name, after=after)
    for _ in range(max_steps):
        if not is_in_blackout(
            candidate,
            tz_name=tz_name,
            blackout_start=blackout_start,
            blackout_end=blackout_end,
        ):
            return candidate
        candidate = compute_next_run(cron_expression, tz_name, after=candidate)

    raise InvalidCronError(
        f"cron {cron_expression!r} never fires outside the blackout window "
        f"[{blackout_start}, {blackout_end}) after {max_steps} attempts"
    )


__all__ = [
    "InvalidCronError",
    "InvalidTimezoneError",
    "compute_next_run",
    "is_in_blackout",
    "next_run_skipping_blackout",
    "resolve_timezone",
    "validate_cron",
]
