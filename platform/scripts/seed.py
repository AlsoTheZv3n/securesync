"""Seed the database with an initial MSP tenant and platform admin user.

Run AFTER migrations are applied:

    cd platform
    alembic upgrade head
    python -m scripts.seed

Reads credentials from env (safe for dev) — override in production:

    SEED_ADMIN_EMAIL      default: admin@nexo-ai.ch
    SEED_ADMIN_PASSWORD   default: random, printed to stdout (dev only)
    SEED_MSP_NAME         default: NEXO AI
    SEED_MSP_SLUG         default: nexo-ai
"""

from __future__ import annotations

import asyncio
import os
import secrets
import sys

# psycopg async refuses Windows' default ProactorEventLoop. Mirrors the
# guard in app/main.py and alembic/env.py.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import AsyncSessionLocal, engine
from app.core.logging import configure_logging
from app.core.security import hash_password
from app.models.enums import UserRole
from app.models.tenant import Tenant
from app.models.user import User

configure_logging()
logger = structlog.get_logger()


async def _seed(session: AsyncSession) -> None:
    admin_email = os.getenv("SEED_ADMIN_EMAIL", "admin@nexo-ai.ch").lower()
    msp_slug = os.getenv("SEED_MSP_SLUG", "nexo-ai")
    msp_name = os.getenv("SEED_MSP_NAME", "NEXO AI")

    admin_password = os.getenv("SEED_ADMIN_PASSWORD")
    password_was_generated = False
    if not admin_password:
        admin_password = secrets.token_urlsafe(18)
        password_was_generated = True

    # Idempotent: skip if admin already exists.
    existing = await session.execute(select(User).where(User.email == admin_email))
    if existing.scalar_one_or_none() is not None:
        logger.info("seed_skip_existing_admin", email=admin_email)
        return

    # Create MSP tenant (or reuse by slug).
    tenant_result = await session.execute(select(Tenant).where(Tenant.slug == msp_slug))
    msp = tenant_result.scalar_one_or_none()
    if msp is None:
        msp = Tenant(name=msp_name, slug=msp_slug, msp_id=None)
        session.add(msp)
        await session.flush()
        logger.info("seed_msp_created", slug=msp_slug, tenant_id=str(msp.id))

    admin = User(
        email=admin_email,
        hashed_password=hash_password(admin_password),
        role=UserRole.PLATFORM_ADMIN,
        tenant_id=msp.id,
        is_active=True,
    )
    session.add(admin)
    await session.commit()
    logger.info("seed_admin_created", email=admin_email, user_id=str(admin.id))

    if password_was_generated:
        # Printed to stdout (not log) so operators can copy it cleanly.
        print("\n" + "=" * 60)
        print("  INITIAL ADMIN CREATED — STORE THIS PASSWORD NOW")
        print("=" * 60)
        print(f"  Email:    {admin_email}")
        print(f"  Password: {admin_password}")
        print("=" * 60 + "\n")


async def main() -> int:
    async with AsyncSessionLocal() as session:
        await _seed(session)
    await engine.dispose()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
