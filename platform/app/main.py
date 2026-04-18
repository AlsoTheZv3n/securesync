import asyncio
import sys
from contextlib import asynccontextmanager
from typing import Any

# psycopg async refuses Windows' default ProactorEventLoop. Production is
# Linux-only — this guard is purely for local-dev convenience.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.database import engine
from app.core.exceptions import SecureSyncError
from app.core.logging import configure_logging
from app.core.observability import init_sentry
from app.core.security_headers import SecurityHeadersMiddleware

configure_logging()
# Initialise Sentry BEFORE creating the FastAPI app so the integration
# can hook into route registration. No-op without SENTRY_DSN_BACKEND.
init_sentry()
logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(_: FastAPI) -> Any:
    """Startup/shutdown hooks."""
    logger.info("startup", environment=get_settings().ENVIRONMENT)
    yield
    await engine.dispose()
    logger.info("shutdown")


app = FastAPI(
    title="SecureSync Platform API",
    description="Automated security audit platform for Swiss MSPs / MSSPs.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security headers — defence in depth vs. Nginx.
app.add_middleware(SecurityHeadersMiddleware)


@app.exception_handler(SecureSyncError)
async def securesync_exception_handler(_: Request, exc: SecureSyncError) -> JSONResponse:
    logger.warning("application_error", code=type(exc).__name__, message=exc.message)
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.message, "code": type(exc).__name__},
    )


app.include_router(api_router)


@app.get("/health", tags=["meta"])
async def health() -> dict[str, str]:
    """Liveness probe — does NOT touch DB (for fast container health checks)."""
    return {"status": "ok"}


@app.get("/health/ready", tags=["meta"])
async def readiness() -> dict[str, Any]:
    """Readiness probe — verifies DB connectivity."""
    db_ok = False
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
            db_ok = True
    except Exception as exc:
        logger.error("readiness_db_failed", error=str(exc))

    status_str = "ok" if db_ok else "degraded"
    return {"status": status_str, "checks": {"database": db_ok}}
