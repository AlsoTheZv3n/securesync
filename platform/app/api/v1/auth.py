"""Auth endpoints: login, refresh, logout."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.exceptions import AuthenticationError
from app.core.rate_limit import LOGIN_LIMITER
from app.core.redis_client import blacklist_jti, is_jti_blacklisted
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    verify_password,
)
from app.models.user import User
from app.schemas.auth import LoginRequest, LogoutRequest, RefreshRequest, TokenResponse
from app.services.audit import record_audit

router = APIRouter(prefix="/auth", tags=["auth"])
logger = structlog.get_logger()


def _build_token_response(user: User) -> TokenResponse:
    settings = get_settings()
    access, _ = create_access_token(
        subject=user.id, tenant_id=user.tenant_id, role=user.role.value
    )
    refresh, _ = create_refresh_token(
        subject=user.id, tenant_id=user.tenant_id, role=user.role.value
    )
    return TokenResponse(
        access_token=access,
        refresh_token=refresh,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    dependencies=[Depends(LOGIN_LIMITER.as_ip_dependency())],
)
async def login(
    payload: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Username/password → access + refresh token pair."""
    stmt = select(User).where(User.email == payload.email.lower())
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    # Constant-time-ish: always run verify_password even if user is missing,
    # so login response time doesn't reveal whether the email exists.
    dummy_hash = "$2b$12$" + "x" * 53
    password_ok = verify_password(payload.password, user.hashed_password if user else dummy_hash)

    if user is None or not password_ok or not user.is_active:
        logger.info("login_failed", email=payload.email)
        await record_audit(
            db,
            action="auth.login_failed",
            request=request,
            details={"email": payload.email.lower()},
        )
        await db.commit()
        raise AuthenticationError("Invalid credentials")

    logger.info("login_success", user_id=str(user.id), tenant_id=str(user.tenant_id))
    await record_audit(
        db,
        action="auth.login_success",
        user=user,
        request=request,
    )
    await db.commit()
    return _build_token_response(user)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    payload: RefreshRequest, db: AsyncSession = Depends(get_db)
) -> TokenResponse:
    """Trade a valid refresh token for a fresh access+refresh pair."""
    claims = decode_token(payload.refresh_token, expected_type="refresh")

    if await is_jti_blacklisted(claims["jti"]):
        raise AuthenticationError("Refresh token has been revoked")

    stmt = select(User).where(User.id == UUID(claims["sub"]))
    user = (await db.execute(stmt)).scalar_one_or_none()
    if user is None or not user.is_active:
        raise AuthenticationError("User no longer active")

    # Rotate: blacklist the old refresh token so it can't be reused.
    ttl = max(0, claims["exp"] - int(datetime.now(UTC).timestamp()))
    await blacklist_jti(claims["jti"], ttl)

    return _build_token_response(user)


@router.post("/logout", status_code=204)
async def logout(payload: LogoutRequest):
    """Revoke the supplied refresh token (and any access token sharing its jti).

    Stateless tokens cannot be 'invalidated' server-side without a blacklist;
    callers should also drop their access token client-side.
    """
    if not payload.refresh_token:
        return None

    try:
        claims = decode_token(payload.refresh_token)
    except AuthenticationError:
        # Already invalid — nothing to do.
        return None

    ttl = max(0, claims["exp"] - int(datetime.now(UTC).timestamp()))
    await blacklist_jti(claims["jti"], ttl)
    logger.info("logout", user_id=claims.get("sub"))
    return None
