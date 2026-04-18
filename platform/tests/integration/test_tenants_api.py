"""Tenant CRUD + isolation tests."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import UserRole
from tests.conftest import integration
from tests.factories import auth_header, make_tenant, make_user


@integration
@pytest.mark.asyncio
class TestListTenants:
    async def test_msp_admin_sees_own_msp_and_customers(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="msp-list")
        cust1 = await make_tenant(db_session, slug="cust-list-1", msp_id=msp.id)
        cust2 = await make_tenant(db_session, slug="cust-list-2", msp_id=msp.id)
        # A second, unrelated MSP — must NOT appear in the list.
        other_msp = await make_tenant(db_session, slug="other-msp")
        await make_tenant(db_session, slug="other-cust", msp_id=other_msp.id)

        admin = await make_user(db_session, email="msp-admin@list.example.com", tenant=msp)

        resp = await client.get("/api/v1/tenants", headers=auth_header(admin))
        assert resp.status_code == 200
        slugs = {t["slug"] for t in resp.json()}
        assert slugs == {"msp-list", "cust-list-1", "cust-list-2"}
        assert "other-msp" not in slugs
        assert "other-cust" not in slugs
        # Sanity: ordering is recent-first.
        assert {cust1.slug, cust2.slug, msp.slug} == slugs

    async def test_customer_readonly_sees_only_own(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="ro-msp")
        cust = await make_tenant(db_session, slug="ro-cust", msp_id=msp.id)
        ro = await make_user(
            db_session,
            email="ro@cust.example.com",
            tenant=cust,
            role=UserRole.CUSTOMER_READONLY,
        )

        resp = await client.get("/api/v1/tenants", headers=auth_header(ro))
        assert resp.status_code == 200
        slugs = {t["slug"] for t in resp.json()}
        assert slugs == {"ro-cust"}


@integration
@pytest.mark.asyncio
class TestCreateTenant:
    async def test_msp_admin_creates_customer(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="create-msp")
        admin = await make_user(db_session, email="a@create.example.com", tenant=msp)

        resp = await client.post(
            "/api/v1/tenants",
            headers=auth_header(admin),
            json={"name": "Acme Corp", "slug": "acme"},
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["slug"] == "acme"
        assert body["msp_id"] == str(msp.id)

    async def test_msp_admin_cannot_target_other_msp(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="own-msp")
        other = await make_tenant(db_session, slug="other-msp-2")
        admin = await make_user(db_session, email="a@own.example.com", tenant=msp)

        resp = await client.post(
            "/api/v1/tenants",
            headers=auth_header(admin),
            json={"name": "Bad", "slug": "bad-cust", "msp_id": str(other.id)},
        )
        assert resp.status_code == 403

    async def test_technician_cannot_create(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="tech-msp")
        tech = await make_user(
            db_session, email="tech@msp.example.com", tenant=msp, role=UserRole.MSP_TECHNICIAN
        )
        resp = await client.post(
            "/api/v1/tenants",
            headers=auth_header(tech),
            json={"name": "X", "slug": "x"},
        )
        assert resp.status_code == 403

    async def test_duplicate_slug_rejected(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="dup-msp")
        admin = await make_user(db_session, email="a@dup.example.com", tenant=msp)
        await client.post(
            "/api/v1/tenants",
            headers=auth_header(admin),
            json={"name": "First", "slug": "shared"},
        )
        resp = await client.post(
            "/api/v1/tenants",
            headers=auth_header(admin),
            json={"name": "Second", "slug": "shared"},
        )
        assert resp.status_code == 422


@integration
@pytest.mark.asyncio
class TestTenantAccessControl:
    async def test_other_msps_tenant_is_inaccessible(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp_a = await make_tenant(db_session, slug="acl-msp-a")
        msp_b = await make_tenant(db_session, slug="acl-msp-b")
        cust_b = await make_tenant(db_session, slug="acl-cust-b", msp_id=msp_b.id)

        admin_a = await make_user(db_session, email="admin@a.example.com", tenant=msp_a)

        # Reading customer of MSP B → 403.
        resp = await client.get(
            f"/api/v1/tenants/{cust_b.id}", headers=auth_header(admin_a)
        )
        assert resp.status_code == 403

    async def test_msp_admin_cannot_delete_own_msp(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="self-del-msp")
        admin = await make_user(db_session, email="admin@self.example.com", tenant=msp)

        resp = await client.delete(
            f"/api/v1/tenants/{msp.id}", headers=auth_header(admin)
        )
        assert resp.status_code == 403


@integration
@pytest.mark.asyncio
async def test_soft_delete_excludes_from_list(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    msp = await make_tenant(db_session, slug="soft-msp")
    cust = await make_tenant(db_session, slug="soft-cust", msp_id=msp.id)
    admin = await make_user(db_session, email="a@soft.example.com", tenant=msp)

    resp = await client.delete(
        f"/api/v1/tenants/{cust.id}", headers=auth_header(admin)
    )
    assert resp.status_code == 204

    listing = await client.get("/api/v1/tenants", headers=auth_header(admin))
    slugs = {t["slug"] for t in listing.json()}
    assert "soft-cust" not in slugs
    # MSP itself is still visible.
    assert "soft-msp" in slugs
