"""Pure helpers: cron validation, blackout windows, next-run math."""

from __future__ import annotations

from datetime import UTC, datetime, time

import pytest

from app.services.scheduler import (
    InvalidCronError,
    InvalidTimezoneError,
    compute_next_run,
    is_in_blackout,
    next_run_skipping_blackout,
    resolve_timezone,
    validate_cron,
)


# ── validate_cron ───────────────────────────────────────────
class TestValidateCron:
    @pytest.mark.parametrize(
        "expression",
        ["0 3 * * *", "*/15 * * * *", "0 9-17 * * 1-5", "30 22 1 * *"],
    )
    def test_valid(self, expression: str) -> None:
        validate_cron(expression)

    @pytest.mark.parametrize(
        "expression",
        [
            "not cron",
            "* * * * * *",          # 6 fields
            "60 0 * * *",           # minute out of range
            "0 25 * * *",           # hour out of range
            "",
        ],
    )
    def test_invalid(self, expression: str) -> None:
        with pytest.raises(InvalidCronError):
            validate_cron(expression)


class TestTimezone:
    def test_valid_tz(self) -> None:
        assert resolve_timezone("Europe/Zurich").key == "Europe/Zurich"
        assert resolve_timezone("UTC").key == "UTC"

    def test_invalid_tz(self) -> None:
        with pytest.raises(InvalidTimezoneError):
            resolve_timezone("Not/A/Real/Zone")


# ── compute_next_run ────────────────────────────────────────
class TestComputeNextRun:
    def test_daily_at_03_local_returns_utc(self) -> None:
        """Europe/Zurich 03:00 in winter = 02:00 UTC; in summer (DST) = 01:00 UTC."""
        after_winter = datetime(2026, 1, 15, 0, 0, tzinfo=UTC)
        result = compute_next_run("0 3 * * *", "Europe/Zurich", after=after_winter)
        # Winter: UTC+1, so 03:00 local = 02:00 UTC.
        assert result.hour == 2
        assert result.tzinfo == UTC

        after_summer = datetime(2026, 7, 15, 0, 0, tzinfo=UTC)
        summer = compute_next_run("0 3 * * *", "Europe/Zurich", after=after_summer)
        # Summer: UTC+2, so 03:00 local = 01:00 UTC.
        assert summer.hour == 1

    def test_strictly_after_reference(self) -> None:
        """Cron firing at the same instant as `after` must return the NEXT one."""
        anchor = datetime(2026, 4, 18, 12, 0, tzinfo=UTC)
        result = compute_next_run("0 12 * * *", "UTC", after=anchor)
        # Should be tomorrow's noon, not today's.
        assert result > anchor


# ── is_in_blackout ──────────────────────────────────────────
class TestIsInBlackout:
    def test_no_window_returns_false(self) -> None:
        now = datetime(2026, 4, 18, 12, 0, tzinfo=UTC)
        assert is_in_blackout(
            now, tz_name="UTC", blackout_start=None, blackout_end=None
        ) is False

    def test_simple_window(self) -> None:
        """09:00–17:00 UTC — a 10:00 UTC timestamp is inside."""
        now = datetime(2026, 4, 18, 10, 0, tzinfo=UTC)
        assert is_in_blackout(
            now,
            tz_name="UTC",
            blackout_start=time(9, 0),
            blackout_end=time(17, 0),
        ) is True

        outside = datetime(2026, 4, 18, 18, 0, tzinfo=UTC)
        assert is_in_blackout(
            outside,
            tz_name="UTC",
            blackout_start=time(9, 0),
            blackout_end=time(17, 0),
        ) is False

    def test_boundary_exclusive_on_end(self) -> None:
        """End is EXCLUSIVE — 17:00 is NOT in a 09:00–17:00 window."""
        edge = datetime(2026, 4, 18, 17, 0, tzinfo=UTC)
        assert is_in_blackout(
            edge,
            tz_name="UTC",
            blackout_start=time(9, 0),
            blackout_end=time(17, 0),
        ) is False

    def test_wrap_around_midnight(self) -> None:
        """22:00–04:00 covers both late-evening AND early-morning."""
        late = datetime(2026, 4, 18, 23, 30, tzinfo=UTC)
        early = datetime(2026, 4, 18, 2, 0, tzinfo=UTC)
        noon = datetime(2026, 4, 18, 12, 0, tzinfo=UTC)

        params: dict[str, object] = {
            "tz_name": "UTC",
            "blackout_start": time(22, 0),
            "blackout_end": time(4, 0),
        }
        assert is_in_blackout(late, **params) is True   # type: ignore[arg-type]
        assert is_in_blackout(early, **params) is True  # type: ignore[arg-type]
        assert is_in_blackout(noon, **params) is False  # type: ignore[arg-type]

    def test_zero_length_window_not_permanent_blackout(self) -> None:
        """Start == end: treat as 'no blackout' (safety net vs. data-entry typo)."""
        now = datetime(2026, 4, 18, 10, 0, tzinfo=UTC)
        assert is_in_blackout(
            now,
            tz_name="UTC",
            blackout_start=time(9, 0),
            blackout_end=time(9, 0),
        ) is False

    def test_timezone_conversion(self) -> None:
        """A 09:00–17:00 Europe/Zurich window excludes 08:00 UTC in winter
        (which is 09:00 local — inside the window)."""
        # Winter morning: 08:00 UTC = 09:00 Zurich → inside.
        winter_morning = datetime(2026, 1, 15, 8, 0, tzinfo=UTC)
        assert is_in_blackout(
            winter_morning,
            tz_name="Europe/Zurich",
            blackout_start=time(9, 0),
            blackout_end=time(17, 0),
        ) is True

        # Winter before: 07:59 UTC = 08:59 Zurich → outside.
        winter_before = datetime(2026, 1, 15, 7, 59, tzinfo=UTC)
        assert is_in_blackout(
            winter_before,
            tz_name="Europe/Zurich",
            blackout_start=time(9, 0),
            blackout_end=time(17, 0),
        ) is False


# ── next_run_skipping_blackout ──────────────────────────────
class TestNextRunSkippingBlackout:
    def test_skips_firings_in_window(self) -> None:
        """Cron "every hour" with blackout 09:00–17:00 UTC must skip past 17."""
        anchor = datetime(2026, 4, 18, 9, 0, tzinfo=UTC)   # exactly on start
        result = next_run_skipping_blackout(
            "0 * * * *",
            "UTC",
            blackout_start=time(9, 0),
            blackout_end=time(17, 0),
            after=anchor,
        )
        assert result.hour == 17
        assert result.date() == anchor.date()

    def test_no_blackout_passes_through(self) -> None:
        anchor = datetime(2026, 4, 18, 9, 0, tzinfo=UTC)
        normal = compute_next_run("0 * * * *", "UTC", after=anchor)
        result = next_run_skipping_blackout(
            "0 * * * *", "UTC",
            blackout_start=None, blackout_end=None, after=anchor,
        )
        assert result == normal

    def test_pathological_cron_raises(self) -> None:
        """Cron that fires only inside the blackout must eventually give up."""
        # Fires 10:30 every day; blackout is 10:00–11:00 forever.
        anchor = datetime(2026, 4, 18, 0, 0, tzinfo=UTC)
        with pytest.raises(InvalidCronError):
            next_run_skipping_blackout(
                "30 10 * * *",
                "UTC",
                blackout_start=time(10, 0),
                blackout_end=time(11, 0),
                after=anchor,
                max_steps=5,
            )
