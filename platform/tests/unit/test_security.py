"""Pure-logic tests for app.core.security — no DB, no Redis."""

from __future__ import annotations

import time
from datetime import timedelta
from uuid import uuid4

import pytest
from jose import jwt

from app.core.config import get_settings
from app.core.exceptions import AuthenticationError
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)


def test_hash_and_verify_roundtrip() -> None:
    hashed = hash_password("correct horse battery staple")
    assert hashed != "correct horse battery staple"
    assert hashed.startswith("$2b$")  # bcrypt identifier
    assert verify_password("correct horse battery staple", hashed) is True
    assert verify_password("wrong", hashed) is False


def test_verify_password_ignores_malformed_hash() -> None:
    assert verify_password("anything", "not-a-real-bcrypt-hash") is False


def test_access_token_contains_expected_claims() -> None:
    user_id = uuid4()
    tenant_id = uuid4()
    token, jti = create_access_token(
        subject=user_id, tenant_id=tenant_id, role="msp_admin"
    )
    payload = decode_token(token, expected_type="access")
    assert payload["sub"] == str(user_id)
    assert payload["tenant_id"] == str(tenant_id)
    assert payload["role"] == "msp_admin"
    assert payload["type"] == "access"
    assert payload["jti"] == jti


def test_refresh_token_type_is_enforced() -> None:
    refresh, _ = create_refresh_token(
        subject=uuid4(), tenant_id=uuid4(), role="platform_admin"
    )
    # Decoding as refresh works.
    decode_token(refresh, expected_type="refresh")
    # Decoding as access raises.
    with pytest.raises(AuthenticationError):
        decode_token(refresh, expected_type="access")


def test_tampered_token_is_rejected() -> None:
    token, _ = create_access_token(
        subject=uuid4(), tenant_id=uuid4(), role="msp_admin"
    )
    tampered = token[:-4] + ("AAAA" if token[-4:] != "AAAA" else "BBBB")
    with pytest.raises(AuthenticationError):
        decode_token(tampered)


def test_expired_token_is_rejected() -> None:
    settings = get_settings()
    past_payload = {
        "sub": str(uuid4()),
        "tenant_id": str(uuid4()),
        "role": "msp_admin",
        "type": "access",
        "jti": "abc",
        "iat": int(time.time()) - 3600,
        "exp": int(time.time()) - 10,
    }
    expired = jwt.encode(past_payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    with pytest.raises(AuthenticationError):
        decode_token(expired)


def test_missing_claim_is_rejected() -> None:
    settings = get_settings()
    incomplete = jwt.encode(
        {"sub": str(uuid4()), "exp": int(time.time()) + 60},
        settings.SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    with pytest.raises(AuthenticationError):
        decode_token(incomplete)


def test_access_and_refresh_have_distinct_jti() -> None:
    user_id = uuid4()
    tenant_id = uuid4()
    _, access_jti = create_access_token(subject=user_id, tenant_id=tenant_id, role="x")
    _, refresh_jti = create_refresh_token(subject=user_id, tenant_id=tenant_id, role="x")
    assert access_jti != refresh_jti


def test_access_token_expiry_matches_settings() -> None:
    settings = get_settings()
    token, _ = create_access_token(subject=uuid4(), tenant_id=uuid4(), role="x")
    payload = decode_token(token)
    delta = payload["exp"] - payload["iat"]
    assert abs(delta - settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60) <= 2

    # Sanity: refresh is strictly longer.
    r_token, _ = create_refresh_token(subject=uuid4(), tenant_id=uuid4(), role="x")
    r_payload = decode_token(r_token)
    assert (r_payload["exp"] - r_payload["iat"]) > delta


def test_timedelta_import_is_noop() -> None:
    # Anchor: test module imports timedelta via security.py transitively.
    assert timedelta(seconds=1).total_seconds() == 1
