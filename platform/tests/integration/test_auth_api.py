"""End-to-end auth + tenant isolation tests (requires TEST_DATABASE_URL)."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.models.enums import UserRole
from app.models.tenant import Tenant
from app.models.user import User
from tests.conftest import integration


async def _make_user(
    db: AsyncSession,
    *,
    email: str,
    password: str,
    tenant: Tenant,
    role: UserRole = UserRole.MSP_ADMIN,
) -> User:
    user = User(
        email=email.lower(),
        hashed_password=hash_password(password),
        role=role,
        tenant_id=tenant.id,
        is_active=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def _make_tenant(db: AsyncSession, *, slug: str, name: str) -> Tenant:
    tenant = Tenant(name=name, slug=slug, msp_id=None)
    db.add(tenant)
    await db.commit()
    await db.refresh(tenant)
    return tenant


@integration
@pytest.mark.asyncio
class TestLogin:
    async def test_login_returns_token_pair(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        tenant = await _make_tenant(db_session, slug="login-a", name="Login A")
        await _make_user(
            db_session, email="alice@a.example.com", password="CorrectHorseBatteryStaple", tenant=tenant
        )
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": "alice@a.example.com", "password": "CorrectHorseBatteryStaple"},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["token_type"] == "bearer"
        assert body["access_token"]
        assert body["refresh_token"]
        assert body["expires_in"] > 0

    async def test_login_bad_password_rejected(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        tenant = await _make_tenant(db_session, slug="login-b", name="Login B")
        await _make_user(db_session, email="bob@b.example.com", password="Correct123Pass!!", tenant=tenant)
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": "bob@b.example.com", "password": "WrongWrongWrong"},
        )
        assert response.status_code == 401

    async def test_login_unknown_email_rejected(self, client: AsyncClient) -> None:
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": "nobody@nowhere.example.com", "password": "whatever123!!"},
        )
        assert response.status_code == 401


@integration
@pytest.mark.asyncio
class TestProtectedRoutes:
    async def test_me_requires_bearer(self, client: AsyncClient) -> None:
        response = await client.get("/api/v1/me")
        assert response.status_code == 401

    async def test_me_returns_current_user(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        tenant = await _make_tenant(db_session, slug="me-tenant", name="Me Tenant")
        await _make_user(
            db_session, email="me@c.example.com", password="CorrectHorseBatteryStaple", tenant=tenant
        )
        login = await client.post(
            "/api/v1/auth/login",
            json={"email": "me@c.example.com", "password": "CorrectHorseBatteryStaple"},
        )
        token = login.json()["access_token"]

        me = await client.get("/api/v1/me", headers={"Authorization": f"Bearer {token}"})
        assert me.status_code == 200
        body = me.json()
        assert body["email"] == "me@c.example.com"
        assert body["tenant_id"] == str(tenant.id)
        assert body["role"] == UserRole.MSP_ADMIN.value


@integration
@pytest.mark.asyncio
class TestTenantIsolation:
    async def test_jwt_tenant_claim_matches_user(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        """Core isolation guarantee: the tenant_id in the JWT is the user's tenant,
        not a claim the client can forge."""
        tenant_a = await _make_tenant(db_session, slug="iso-a", name="Iso A")
        tenant_b = await _make_tenant(db_session, slug="iso-b", name="Iso B")

        # Two users in different tenants.
        await _make_user(
            db_session, email="user-a@a.example.com", password="UserAPass!!long", tenant=tenant_a
        )
        await _make_user(
            db_session, email="user-b@b.example.com", password="UserBPass!!long", tenant=tenant_b
        )

        resp_a = await client.post(
            "/api/v1/auth/login",
            json={"email": "user-a@a.example.com", "password": "UserAPass!!long"},
        )
        resp_b = await client.post(
            "/api/v1/auth/login",
            json={"email": "user-b@b.example.com", "password": "UserBPass!!long"},
        )

        me_a = (await client.get(
            "/api/v1/me",
            headers={"Authorization": f"Bearer {resp_a.json()['access_token']}"},
        )).json()
        me_b = (await client.get(
            "/api/v1/me",
            headers={"Authorization": f"Bearer {resp_b.json()['access_token']}"},
        )).json()

        assert me_a["tenant_id"] == str(tenant_a.id)
        assert me_b["tenant_id"] == str(tenant_b.id)
        assert me_a["tenant_id"] != me_b["tenant_id"]
