"""User invitation endpoints.

Flow:
    1. An admin POSTs /users/invite → User row created (is_active=False,
       invitation_token set). Response carries the token so the caller
       (frontend) can build an accept-link and deliver it however they want.
    2. Invitee POSTs /users/accept-invitation with {token, password} →
       password is set, user is activated, token is cleared.

Privilege-escalation guards (enforced inline, not via a decorator):
  - PLATFORM_ADMIN can invite any role into any tenant.
  - MSP_ADMIN can invite MSP_ADMIN / MSP_TECHNICIAN / CUSTOMER_READONLY
    into their own MSP tenant or its customer tenants. NOT PLATFORM_ADMIN.
  - Any other caller role → 403 (via `require_role`).
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta

import structlog
from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.dependencies import (
    assert_tenant_access,
    get_current_user,
    require_role,
)
from app.core.exceptions import (
    AuthenticationError,
    PermissionDeniedError,
    ValidationError,
)
from app.core.security import hash_password
from app.models.enums import UserRole
from app.models.user import User
from app.schemas.user import (
    UserAcceptInvitation,
    UserInvite,
    UserInviteResponse,
    UserRead,
)

router = APIRouter(prefix="/users", tags=["users"])
logger = structlog.get_logger()


def _check_invite_privileges(caller: User, target_role: UserRole) -> None:
    """Role-escalation guard. PLATFORM_ADMIN can delegate to any role; MSP
    admins cannot create platform admins."""
    if caller.role is UserRole.PLATFORM_ADMIN:
        return
    if caller.role is UserRole.MSP_ADMIN and target_role is not UserRole.PLATFORM_ADMIN:
        return
    raise PermissionDeniedError(
        f"{caller.role.value} cannot invite role {target_role.value}"
    )


def _generate_token() -> str:
    # 32 bytes → 43-char urlsafe string; well within our 64-char column.
    return secrets.token_urlsafe(32)


def _placeholder_password_hash() -> str:
    """Unusable password hash for invited-but-not-yet-accepted users.

    Keeps `hashed_password` NOT NULL without special-casing the login path.
    A random 32-byte value hashed with bcrypt is astronomically unlikely to
    match anyone's real password. Once the invite is accepted we replace it
    with the actual hash.
    """
    return hash_password(secrets.token_urlsafe(32))


@router.post(
    "/invite",
    response_model=UserInviteResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(require_role(UserRole.PLATFORM_ADMIN, UserRole.MSP_ADMIN))
    ],
)
async def invite_user(
    payload: UserInvite,
    caller: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UserInviteResponse:
    # Role escalation check.
    _check_invite_privileges(caller, payload.role)

    # Target-tenant access: caller must have access to the target tenant.
    await assert_tenant_access(payload.tenant_id, caller, db)

    email = payload.email.lower()
    existing = (
        await db.execute(select(User).where(User.email == email))
    ).scalar_one_or_none()
    if existing is not None:
        raise ValidationError(f"a user with email {email!r} already exists")

    settings = get_settings()
    token = _generate_token()
    expires_at = datetime.now(UTC) + timedelta(days=settings.INVITATION_TTL_DAYS)

    user = User(
        email=email,
        hashed_password=_placeholder_password_hash(),
        role=payload.role,
        tenant_id=payload.tenant_id,
        is_active=False,
        invitation_token=token,
        invitation_expires_at=expires_at,
    )
    db.add(user)
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise ValidationError("could not create invitation (unique conflict)") from exc
    await db.refresh(user)

    logger.info(
        "user_invited",
        user_id=str(user.id),
        email=user.email,
        role=user.role.value,
        tenant_id=str(user.tenant_id),
        by=str(caller.id),
    )
    return UserInviteResponse(
        user_id=user.id,
        email=user.email,
        role=user.role,
        tenant_id=user.tenant_id,
        invitation_token=token,
        invitation_expires_at=expires_at,
    )


@router.post("/accept-invitation", response_model=UserRead)
async def accept_invitation(
    payload: UserAcceptInvitation,
    db: AsyncSession = Depends(get_db),
) -> User:
    """Public endpoint: trade a valid invitation token for an active account.

    Same error response regardless of failure reason (invalid / expired /
    already-accepted) to prevent probing."""
    user = (
        await db.execute(
            select(User).where(User.invitation_token == payload.token)
        )
    ).scalar_one_or_none()

    if user is None or user.invitation_expires_at is None or user.is_active:
        logger.info("invitation_accept_failed", reason="invalid_or_used")
        raise AuthenticationError("invitation token is invalid or has expired")

    if user.invitation_expires_at < datetime.now(UTC):
        logger.info(
            "invitation_accept_failed",
            reason="expired",
            user_id=str(user.id),
        )
        raise AuthenticationError("invitation token is invalid or has expired")

    user.hashed_password = hash_password(payload.password)
    user.is_active = True
    user.invitation_token = None
    user.invitation_expires_at = None

    await db.commit()
    await db.refresh(user)

    logger.info("invitation_accepted", user_id=str(user.id), email=user.email)
    return user
