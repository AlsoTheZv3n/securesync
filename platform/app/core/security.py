"""Authentication primitives: password hashing + JWT encode/decode.

Algorithms:
  - Passwords: bcrypt via passlib (cost factor 12).
  - Tokens:    HS256 in dev (symmetric), RS256 in production (asymmetric).

Token claims (access token):
  sub         → user id (UUID as str)
  tenant_id   → user's tenant id (UUID as str)
  role        → UserRole enum value
  type        → "access" | "refresh"
  exp         → expiry (unix timestamp)
  iat         → issued-at
  jti         → unique token id (used for Redis blacklist)
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Literal, cast
from uuid import UUID, uuid4

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import get_settings
from app.core.exceptions import AuthenticationError

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)

TokenType = Literal["access", "refresh"]


def hash_password(plain_password: str) -> str:
    return _pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return _pwd_context.verify(plain_password, hashed_password)
    except ValueError:
        # passlib raises ValueError on malformed hashes — treat as auth failure.
        return False


def _create_token(
    *,
    subject: UUID,
    tenant_id: UUID,
    role: str,
    token_type: TokenType,
    expires_delta: timedelta,
) -> tuple[str, str]:
    """Returns (encoded_token, jti). `jti` is useful for Redis blacklist lookup."""
    settings = get_settings()
    now = datetime.now(UTC)
    jti = uuid4().hex
    payload: dict[str, Any] = {
        "sub": str(subject),
        "tenant_id": str(tenant_id),
        "role": role,
        "type": token_type,
        "iat": int(now.timestamp()),
        "exp": int((now + expires_delta).timestamp()),
        "jti": jti,
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return token, jti


def create_access_token(
    *, subject: UUID, tenant_id: UUID, role: str
) -> tuple[str, str]:
    settings = get_settings()
    return _create_token(
        subject=subject,
        tenant_id=tenant_id,
        role=role,
        token_type="access",
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )


def create_refresh_token(
    *, subject: UUID, tenant_id: UUID, role: str
) -> tuple[str, str]:
    settings = get_settings()
    return _create_token(
        subject=subject,
        tenant_id=tenant_id,
        role=role,
        token_type="refresh",
        expires_delta=timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )


_REQUIRED_CLAIMS = ("sub", "exp", "jti", "tenant_id", "role", "type")


def decode_token(token: str, *, expected_type: TokenType | None = None) -> dict[str, Any]:
    """Decodes + validates signature, expiry, AND required-claim presence.

    python-jose's `options={"require": [...]}` only supports exp/iat/nbf — we
    enforce the rest manually so missing tenant_id / role / jti can't slip
    through.
    """
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"require_exp": True},
        )
    except JWTError as exc:
        raise AuthenticationError("Invalid or expired token") from exc

    missing = [c for c in _REQUIRED_CLAIMS if c not in payload]
    if missing:
        raise AuthenticationError(f"token missing required claims: {missing}")

    if expected_type is not None and payload.get("type") != expected_type:
        raise AuthenticationError(f"Expected {expected_type} token, got {payload.get('type')}")

    return cast(dict[str, Any], payload)
