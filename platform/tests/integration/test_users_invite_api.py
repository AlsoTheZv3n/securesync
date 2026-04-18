"""Invitation flow — role matrix, token validation, one-time use, end-to-end login."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.models.enums import UserRole
from app.models.user import User
from tests.conftest import integration
from tests.factories import auth_header, make_tenant, make_user


@integration
@pytest.mark.asyncio
class TestInvitePrivileges:
    async def test_platform_admin_can_invite_any_role(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="pa-msp")
        plat = await make_user(
            db_session, email="plat@pa.example.com", tenant=msp,
            role=UserRole.PLATFORM_ADMIN,
        )

        for role in UserRole:
            email = f"new-{role.value}@pa.example.com"
            resp = await client.post(
                "/api/v1/users/invite",
                headers=auth_header(plat),
                json={"email": email, "role": role.value, "tenant_id": str(msp.id)},
            )
            assert resp.status_code == 201, (role, resp.text)
            body = resp.json()
            assert body["email"] == email
            assert body["role"] == role.value
            assert body["invitation_token"]

    async def test_msp_admin_cannot_invite_platform_admin(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="msp-esc")
        admin = await make_user(db_session, email="a@msp-esc.example.com", tenant=msp)

        resp = await client.post(
            "/api/v1/users/invite",
            headers=auth_header(admin),
            json={
                "email": "root@bad.example.com",
                "role": UserRole.PLATFORM_ADMIN.value,
                "tenant_id": str(msp.id),
            },
        )
        assert resp.status_code == 403

    async def test_msp_admin_can_invite_into_own_customer(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="msp-own")
        cust = await make_tenant(db_session, slug="msp-own-cust", msp_id=msp.id)
        admin = await make_user(db_session, email="a@msp-own.example.com", tenant=msp)

        resp = await client.post(
            "/api/v1/users/invite",
            headers=auth_header(admin),
            json={
                "email": "reader@cust.example.com",
                "role": UserRole.CUSTOMER_READONLY.value,
                "tenant_id": str(cust.id),
            },
        )
        assert resp.status_code == 201

    async def test_msp_admin_cannot_invite_into_other_msp_customer(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp_a = await make_tenant(db_session, slug="msp-cross-a")
        msp_b = await make_tenant(db_session, slug="msp-cross-b")
        cust_b = await make_tenant(db_session, slug="msp-cross-cust-b", msp_id=msp_b.id)
        admin_a = await make_user(db_session, email="a@cross.example.com", tenant=msp_a)

        resp = await client.post(
            "/api/v1/users/invite",
            headers=auth_header(admin_a),
            json={
                "email": "spy@bad.example.com",
                "role": UserRole.CUSTOMER_READONLY.value,
                "tenant_id": str(cust_b.id),
            },
        )
        assert resp.status_code == 403

    async def test_technician_cannot_invite(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="tech-invite-msp")
        tech = await make_user(
            db_session, email="t@tech.example.com", tenant=msp,
            role=UserRole.MSP_TECHNICIAN,
        )
        resp = await client.post(
            "/api/v1/users/invite",
            headers=auth_header(tech),
            json={
                "email": "who@tech.example.com",
                "role": UserRole.MSP_TECHNICIAN.value,
                "tenant_id": str(msp.id),
            },
        )
        assert resp.status_code == 403

    async def test_duplicate_email_rejected(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="dup-invite-msp")
        admin = await make_user(db_session, email="a@dup-inv.example.com", tenant=msp)
        await make_user(db_session, email="taken@dup-inv.example.com", tenant=msp)

        resp = await client.post(
            "/api/v1/users/invite",
            headers=auth_header(admin),
            json={
                "email": "taken@dup-inv.example.com",
                "role": UserRole.MSP_TECHNICIAN.value,
                "tenant_id": str(msp.id),
            },
        )
        assert resp.status_code == 422


@integration
@pytest.mark.asyncio
class TestAcceptInvitation:
    async def test_valid_token_activates_user(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="accept-msp")
        admin = await make_user(db_session, email="a@accept.example.com", tenant=msp)

        invite_resp = await client.post(
            "/api/v1/users/invite",
            headers=auth_header(admin),
            json={
                "email": "newbie@accept.example.com",
                "role": UserRole.MSP_TECHNICIAN.value,
                "tenant_id": str(msp.id),
            },
        )
        token = invite_resp.json()["invitation_token"]

        accept = await client.post(
            "/api/v1/users/accept-invitation",
            json={"token": token, "password": "BrandNewPass123!!"},
        )
        assert accept.status_code == 200
        body = accept.json()
        assert body["email"] == "newbie@accept.example.com"
        assert body["is_active"] is True

        # Login with the new password works.
        login = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "newbie@accept.example.com",
                "password": "BrandNewPass123!!",
            },
        )
        assert login.status_code == 200
        assert login.json()["access_token"]

    async def test_invalid_token_rejected(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/api/v1/users/accept-invitation",
            json={"token": "not-a-real-token-123", "password": "Whatever123!!"},
        )
        assert resp.status_code == 401

    async def test_token_one_time_use(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="one-time-msp")
        admin = await make_user(db_session, email="a@one-time.example.com", tenant=msp)

        invite_resp = await client.post(
            "/api/v1/users/invite",
            headers=auth_header(admin),
            json={
                "email": "once@one-time.example.com",
                "role": UserRole.MSP_TECHNICIAN.value,
                "tenant_id": str(msp.id),
            },
        )
        token = invite_resp.json()["invitation_token"]

        # First acceptance: ok.
        first = await client.post(
            "/api/v1/users/accept-invitation",
            json={"token": token, "password": "FirstAcceptPass!!99"},
        )
        assert first.status_code == 200

        # Second try with the same token: rejected.
        second = await client.post(
            "/api/v1/users/accept-invitation",
            json={"token": token, "password": "SecondTryPass!!99"},
        )
        assert second.status_code == 401

    async def test_expired_token_rejected(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="expired-msp")

        # Seed an already-invited user whose token is in the past.
        expired_token = "expired-token-" + "x" * 20
        user = User(
            email="stale@expired.example.com",
            hashed_password=hash_password("placeholder-never-matches"),
            role=UserRole.MSP_TECHNICIAN,
            tenant_id=msp.id,
            is_active=False,
            invitation_token=expired_token,
            invitation_expires_at=datetime.now(UTC) - timedelta(hours=1),
        )
        db_session.add(user)
        await db_session.commit()

        resp = await client.post(
            "/api/v1/users/accept-invitation",
            json={"token": expired_token, "password": "WouldBeValidPass!!99"},
        )
        assert resp.status_code == 401

    async def test_cannot_login_before_acceptance(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        """Invited-but-unaccepted user row exists but login is blocked —
        is_active=False + random placeholder hash both prevent it."""
        msp = await make_tenant(db_session, slug="pending-msp")
        admin = await make_user(db_session, email="a@pend.example.com", tenant=msp)

        await client.post(
            "/api/v1/users/invite",
            headers=auth_header(admin),
            json={
                "email": "pending@pend.example.com",
                "role": UserRole.MSP_TECHNICIAN.value,
                "tenant_id": str(msp.id),
            },
        )
        # Guess a password; should still fail.
        login = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "pending@pend.example.com",
                "password": "NoIdeaWhatItIs!!99",
            },
        )
        assert login.status_code == 401


@integration
@pytest.mark.asyncio
async def test_invited_row_has_token_and_inactive_state(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """White-box sanity: the DB row after invite has all the expected
    fields set, and clearing happens on accept."""
    msp = await make_tenant(db_session, slug="state-msp")
    admin = await make_user(db_session, email="a@state.example.com", tenant=msp)

    resp = await client.post(
        "/api/v1/users/invite",
        headers=auth_header(admin),
        json={
            "email": "state@state.example.com",
            "role": UserRole.MSP_TECHNICIAN.value,
            "tenant_id": str(msp.id),
        },
    )
    assert resp.status_code == 201
    token = resp.json()["invitation_token"]

    stmt = select(User).where(User.email == "state@state.example.com")
    row = (await db_session.execute(stmt)).scalar_one()
    assert row.is_active is False
    assert row.invitation_token == token
    assert row.invitation_expires_at is not None
    assert row.invitation_expires_at > datetime.now(UTC)

    # Accept.
    await client.post(
        "/api/v1/users/accept-invitation",
        json={"token": token, "password": "StateValidPass!!99"},
    )
    await db_session.refresh(row)
    assert row.is_active is True
    assert row.invitation_token is None
    assert row.invitation_expires_at is None
