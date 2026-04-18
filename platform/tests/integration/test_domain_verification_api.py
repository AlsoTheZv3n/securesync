"""End-to-end domain-verification flow."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import UserRole
from app.models.tenant import Tenant
from app.services.domain_verification import (
    VERIFICATION_SUBDOMAIN_PREFIX,
    build_verification_dns_name,
)
from tests.conftest import integration
from tests.factories import auth_header, make_tenant, make_user


@integration
@pytest.mark.asyncio
class TestStartVerification:
    async def test_happy_path_returns_challenge(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="dom-start-msp")
        admin = await make_user(db_session, email="a@dom-start.example.com", tenant=msp)

        # Set a custom_domain first.
        await client.patch(
            f"/api/v1/tenants/{msp.id}",
            headers=auth_header(admin),
            json={"custom_domain": "portal.acme-corp.ch"},
        )

        resp = await client.post(
            f"/api/v1/tenants/{msp.id}/verify-domain",
            headers=auth_header(admin),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["custom_domain"] == "portal.acme-corp.ch"
        assert body["dns_name"] == f"{VERIFICATION_SUBDOMAIN_PREFIX}.portal.acme-corp.ch"
        assert body["txt_record_value"].startswith("securesync-verify=")
        assert body["expires_at"]

        # Token was persisted.
        row = (
            await db_session.execute(select(Tenant).where(Tenant.id == msp.id))
        ).scalar_one()
        assert row.custom_domain_verification_token is not None
        assert row.custom_domain_verified is False

    async def test_rejects_when_no_custom_domain_set(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="dom-no-domain")
        admin = await make_user(
            db_session, email="a@dom-no-dom.example.com", tenant=msp
        )

        resp = await client.post(
            f"/api/v1/tenants/{msp.id}/verify-domain",
            headers=auth_header(admin),
        )
        assert resp.status_code == 422

    async def test_technician_cannot_start_verification(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="dom-tech-block")
        tech = await make_user(
            db_session, email="t@tech-block.example.com",
            tenant=msp, role=UserRole.MSP_TECHNICIAN,
        )
        resp = await client.post(
            f"/api/v1/tenants/{msp.id}/verify-domain",
            headers=auth_header(tech),
        )
        assert resp.status_code == 403


@integration
@pytest.mark.asyncio
class TestConfirmVerification:
    async def test_matching_txt_marks_verified(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        msp = await make_tenant(db_session, slug="dom-confirm-ok")
        admin = await make_user(
            db_session, email="a@dom-confirm.example.com", tenant=msp
        )

        # Give the tenant a custom domain + initiate challenge.
        await client.patch(
            f"/api/v1/tenants/{msp.id}",
            headers=auth_header(admin),
            json={"custom_domain": "portal.confirm.example.com"},
        )
        start = await client.post(
            f"/api/v1/tenants/{msp.id}/verify-domain",
            headers=auth_header(admin),
        )
        txt_value = start.json()["txt_record_value"]

        # MOCK — DNS lookup would hit the real internet; replace the
        # service's `verify_domain_txt` with one that returns True iff the
        # expected token is embedded in the stored value.
        expected_name = build_verification_dns_name("portal.confirm.example.com")

        async def fake_verify(domain: str, *, expected_token: str, **_) -> bool:
            assert domain == "portal.confirm.example.com"
            assert build_verification_dns_name(domain) == expected_name
            return f"securesync-verify={expected_token}" == txt_value

        monkeypatch.setattr(
            "app.api.v1.tenants.verify_domain_txt", fake_verify
        )

        confirm = await client.post(
            f"/api/v1/tenants/{msp.id}/verify-domain/confirm",
            headers=auth_header(admin),
        )
        assert confirm.status_code == 200
        assert confirm.json() == {
            "verified": True,
            "custom_domain": "portal.confirm.example.com",
        }

        # DB state: verified + token cleared.
        row = (
            await db_session.execute(select(Tenant).where(Tenant.id == msp.id))
        ).scalar_one()
        assert row.custom_domain_verified is True
        assert row.custom_domain_verification_token is None

    async def test_failing_dns_keeps_unverified(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        msp = await make_tenant(db_session, slug="dom-confirm-bad")
        admin = await make_user(
            db_session, email="a@dom-bad.example.com", tenant=msp
        )
        await client.patch(
            f"/api/v1/tenants/{msp.id}",
            headers=auth_header(admin),
            json={"custom_domain": "portal.bad-dns.example.com"},
        )
        await client.post(
            f"/api/v1/tenants/{msp.id}/verify-domain",
            headers=auth_header(admin),
        )

        async def always_false(*_a, **_kw) -> bool:
            return False

        monkeypatch.setattr("app.api.v1.tenants.verify_domain_txt", always_false)

        resp = await client.post(
            f"/api/v1/tenants/{msp.id}/verify-domain/confirm",
            headers=auth_header(admin),
        )
        assert resp.status_code == 200
        assert resp.json()["verified"] is False

        row = (
            await db_session.execute(select(Tenant).where(Tenant.id == msp.id))
        ).scalar_one()
        assert row.custom_domain_verified is False
        # Token NOT cleared — user can retry with same token after fixing DNS.
        assert row.custom_domain_verification_token is not None

    async def test_cannot_confirm_without_starting(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="dom-no-start")
        admin = await make_user(
            db_session, email="a@no-start.example.com", tenant=msp
        )
        await client.patch(
            f"/api/v1/tenants/{msp.id}",
            headers=auth_header(admin),
            json={"custom_domain": "portal.no-start.example.com"},
        )

        resp = await client.post(
            f"/api/v1/tenants/{msp.id}/verify-domain/confirm",
            headers=auth_header(admin),
        )
        assert resp.status_code == 422


@integration
@pytest.mark.asyncio
async def test_changing_custom_domain_resets_verification(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A tenant that's been verified for domain A must re-verify for
    domain B — old TXT clearly doesn't apply."""
    msp = await make_tenant(db_session, slug="dom-change")
    admin = await make_user(db_session, email="a@change.example.com", tenant=msp)

    await client.patch(
        f"/api/v1/tenants/{msp.id}",
        headers=auth_header(admin),
        json={"custom_domain": "first.example.com"},
    )
    await client.post(
        f"/api/v1/tenants/{msp.id}/verify-domain",
        headers=auth_header(admin),
    )
    monkeypatch.setattr(
        "app.api.v1.tenants.verify_domain_txt",
        lambda *_a, **_kw: __import__("asyncio").sleep(0, result=True),  # type: ignore
    )

    # Simple coroutine returning True for confirm.
    async def always_true(*_a, **_kw) -> bool:
        return True

    monkeypatch.setattr("app.api.v1.tenants.verify_domain_txt", always_true)
    await client.post(
        f"/api/v1/tenants/{msp.id}/verify-domain/confirm",
        headers=auth_header(admin),
    )

    row = (
        await db_session.execute(select(Tenant).where(Tenant.id == msp.id))
    ).scalar_one()
    assert row.custom_domain_verified is True

    # Change the domain.
    await client.patch(
        f"/api/v1/tenants/{msp.id}",
        headers=auth_header(admin),
        json={"custom_domain": "second.example.com"},
    )
    await db_session.refresh(row)
    assert row.custom_domain_verified is False
    assert row.custom_domain_verification_token is None
    assert row.custom_domain == "second.example.com"
