"""Sentry init — behavioural tests, no real DSN ever used."""

from __future__ import annotations

import pytest

from app.core import observability
from app.core.config import get_settings


@pytest.fixture(autouse=True)
def _reset_state(monkeypatch: pytest.MonkeyPatch) -> None:
    """Restore the module-level one-shot guard after each test."""
    observability._reset_for_tests()
    # Also clear any cached Settings so `SENTRY_DSN_BACKEND` overrides take effect.
    get_settings.cache_clear()
    yield
    observability._reset_for_tests()
    get_settings.cache_clear()


def test_noop_without_dsn(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default test env has no SENTRY_DSN_BACKEND — init must not raise
    and must report that nothing was set up."""
    monkeypatch.delenv("SENTRY_DSN_BACKEND", raising=False)
    get_settings.cache_clear()
    assert observability.init_sentry() is False


def test_init_runs_once_with_dsn(monkeypatch: pytest.MonkeyPatch) -> None:
    """A DSN triggers sentry_sdk.init exactly once; repeat calls are no-ops."""
    calls: list[dict] = []

    def fake_init(**kwargs: object) -> None:
        calls.append(kwargs)

    # Patch where it's used AFTER the deferred import, not on the sentry
    # module itself — observability imports inside the function.
    import sentry_sdk

    monkeypatch.setattr(sentry_sdk, "init", fake_init)
    monkeypatch.setenv("SENTRY_DSN_BACKEND", "https://fake@sentry.test/42")
    get_settings.cache_clear()

    assert observability.init_sentry() is True
    assert observability.init_sentry() is True   # idempotent
    assert len(calls) == 1

    passed = calls[0]
    assert passed["dsn"] == "https://fake@sentry.test/42"
    assert passed["environment"] == "development"
    assert passed["send_default_pii"] is False
    assert passed["traces_sample_rate"] <= 0.2    # conservative default
