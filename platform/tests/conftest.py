"""Shared pytest fixtures.

Bootstrap order matters: we must set environment variables BEFORE any
`app.*` import triggers Pydantic Settings to load. That's why the
`os.environ.setdefault(...)` block runs at module top-level.

Integration tests use a real PostgreSQL database. Configure via:

    TEST_DATABASE_URL=postgresql+psycopg://securesync:pw@localhost:5432/securesync_test
    TEST_REDIS_URL=redis://:pw@localhost:6379/15

If `TEST_DATABASE_URL` is not set, integration tests are skipped.
"""

from __future__ import annotations

import asyncio
import os
import sys
from collections.abc import AsyncGenerator

# ── Windows event-loop fix ──────────────────────────────────
# psycopg's async client refuses ProactorEventLoop (Python 3.8+ default on
# Windows). Production runs on Linux, so this only matters for local dev.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# ── ENV BOOTSTRAP (must run before any `app.*` import) ──────
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("SECRET_KEY", "test-secret-key-32-bytes-minimum-okay")
os.environ.setdefault("JWT_ALGORITHM", "HS256")
os.environ.setdefault(
    "DATABASE_URL",
    os.environ.get(
        "TEST_DATABASE_URL",
        "postgresql+psycopg://securesync:securesync_dev_password@localhost:5432/securesync_test",
    ),
)
os.environ.setdefault(
    "REDIS_URL",
    os.environ.get("TEST_REDIS_URL", "redis://:securesync_dev_password@localhost:6379/15"),
)

import pytest  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import (  # noqa: E402
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool  # noqa: E402

from app.core.config import get_settings  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Base  # noqa: E402


def _integration_db_available() -> bool:
    return os.environ.get("TEST_DATABASE_URL") is not None


integration = pytest.mark.skipif(
    not _integration_db_available(),
    reason="Set TEST_DATABASE_URL to run DB-backed integration tests",
)


@pytest.fixture(scope="session")
async def engine_fixture() -> AsyncGenerator:
    """Session-wide engine pointed at the test DB.

    Uses NullPool so no DB connection is reused across tests — each test
    gets a fresh connection bound to its own event loop. Without this,
    pytest-asyncio's per-test event loops break pooled connections from
    the session-scoped fixture's loop ("Event loop is closed").
    """
    engine = create_async_engine(str(get_settings().DATABASE_URL), poolclass=NullPool)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.fixture
async def db_session(engine_fixture) -> AsyncGenerator[AsyncSession, None]:
    """Per-test DB session.

    Tests + API code call `commit()` freely, so a transaction-wrapping rollback
    won't isolate them. After each test we TRUNCATE every table CASCADE to give
    the next test a clean slate. Cheaper than drop/create_all and reliable when
    the worker (Celery task) opens its own connection.
    """
    async_session = async_sessionmaker(engine_fixture, expire_on_commit=False)
    async with async_session() as session:
        yield session

    table_list = ", ".join(f'"{t.name}"' for t in reversed(Base.metadata.sorted_tables))
    async with engine_fixture.begin() as conn:
        await conn.execute(text(f"TRUNCATE TABLE {table_list} RESTART IDENTITY CASCADE"))


@pytest.fixture(autouse=True)
async def _reset_redis_singleton():
    """Reset the module-level Redis client between tests.

    redis-py's async client binds its socket reader/writer to the event loop
    where it was created. pytest-asyncio gives each test a fresh event loop,
    so a singleton survives but its underlying socket is dead → "Event loop
    is closed" the moment the next test touches it.

    Also flushes rate-limit keys so one test's attempts against
    `/auth/login` can't trip the limiter for a later test — the limiter's
    fixed-window counter is keyed by IP (127.0.0.1 in all tests).
    """
    yield
    from app.core import redis_client as rc

    if rc._redis is not None:
        try:
            # Drop any rate-limit keys before we close the socket.
            keys = await rc._redis.keys("rate:*")
            if keys:
                await rc._redis.delete(*keys)
        except Exception:
            pass
        try:
            await rc._redis.aclose()
        except Exception:
            pass
        rc._redis = None


@pytest.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Async HTTP client pointed at the FastAPI app, with DB override."""
    from app.core.database import get_db

    async def _override_get_db() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac
    finally:
        app.dependency_overrides.pop(get_db, None)
