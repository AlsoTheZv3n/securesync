"""Windows-friendly dev launcher for the FastAPI app.

Sets the SelectorEventLoop policy *before* uvicorn creates its loop.
psycopg's async client refuses Windows' default ProactorEventLoop; the
fix baked into app/main.py runs after uvicorn has already started its
loop, so that guard is load-bearing for workers but not for the server
entry point. Hence this launcher.

On Linux this is a no-op — production runs via the Dockerfile's CMD,
which is plain `uvicorn app.main:app`.

Usage:
    cd platform
    python run_dev.py
"""

from __future__ import annotations

import asyncio
import os
import sys

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import uvicorn  # noqa: E402  — must come after the policy switch


if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=os.getenv("DEV_HOST", "127.0.0.1"),
        port=int(os.getenv("DEV_PORT", "8000")),
        reload=os.getenv("DEV_RELOAD", "1") == "1",
        log_level="info",
    )
