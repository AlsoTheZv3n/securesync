"""Asset CRUD + isolation tests."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import AssetType, UserRole
from tests.conftest import integration
from tests.factories import auth_header, make_tenant, make_user


@integration
@pytest.mark.asyncio
class TestCreateAsset:
    async def test_msp_admin_creates_for_own_customer(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="ast-msp")
        cust = await make_tenant(db_session, slug="ast-cust", msp_id=msp.id)
        admin = await make_user(db_session, email="a@ast.example.com", tenant=msp)

        resp = await client.post(
            "/api/v1/assets",
            headers=auth_header(admin),
            json={
                "tenant_id": str(cust.id),
                "type": AssetType.EXTERNAL_DOMAIN.value,
                "value": "shop.example.com",
                "tags": {"env": "prod"},
            },
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["value"] == "shop.example.com"
        assert body["tenant_id"] == str(cust.id)
        assert body["tags"] == {"env": "prod"}

    async def test_cannot_create_for_other_msp_customer(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp_a = await make_tenant(db_session, slug="cross-a")
        msp_b = await make_tenant(db_session, slug="cross-b")
        cust_b = await make_tenant(db_session, slug="cross-cust-b", msp_id=msp_b.id)

        admin_a = await make_user(db_session, email="a@cross.example.com", tenant=msp_a)
        resp = await client.post(
            "/api/v1/assets",
            headers=auth_header(admin_a),
            json={
                "tenant_id": str(cust_b.id),
                "type": AssetType.EXTERNAL_DOMAIN.value,
                "value": "evil.example.com",
            },
        )
        assert resp.status_code == 403

    async def test_invalid_value_for_type_rejected(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="val-msp")
        admin = await make_user(db_session, email="a@val.example.com", tenant=msp)

        resp = await client.post(
            "/api/v1/assets",
            headers=auth_header(admin),
            json={
                "tenant_id": str(msp.id),
                "type": AssetType.EXTERNAL_IP.value,
                "value": "not-an-ip-at-all",
            },
        )
        assert resp.status_code == 422


@integration
@pytest.mark.asyncio
class TestListAssets:
    async def test_list_returns_only_target_tenant(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="list-msp")
        cust1 = await make_tenant(db_session, slug="list-cust-1", msp_id=msp.id)
        cust2 = await make_tenant(db_session, slug="list-cust-2", msp_id=msp.id)
        admin = await make_user(db_session, email="a@list-ast.example.com", tenant=msp)

        for value in ["a.example.com", "b.example.com"]:
            await client.post(
                "/api/v1/assets",
                headers=auth_header(admin),
                json={
                    "tenant_id": str(cust1.id),
                    "type": AssetType.EXTERNAL_DOMAIN.value,
                    "value": value,
                },
            )
        await client.post(
            "/api/v1/assets",
            headers=auth_header(admin),
            json={
                "tenant_id": str(cust2.id),
                "type": AssetType.EXTERNAL_DOMAIN.value,
                "value": "c.example.com",
            },
        )

        resp = await client.get(
            "/api/v1/assets",
            headers=auth_header(admin),
            params={"tenant_id": str(cust1.id)},
        )
        assert resp.status_code == 200
        values = {a["value"] for a in resp.json()}
        assert values == {"a.example.com", "b.example.com"}

    async def test_list_blocked_for_unrelated_tenant(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp_a = await make_tenant(db_session, slug="blocklist-a")
        msp_b = await make_tenant(db_session, slug="blocklist-b")
        cust_b = await make_tenant(db_session, slug="blocklist-cust-b", msp_id=msp_b.id)

        admin_a = await make_user(db_session, email="a@blocklist.example.com", tenant=msp_a)
        resp = await client.get(
            "/api/v1/assets",
            headers=auth_header(admin_a),
            params={"tenant_id": str(cust_b.id)},
        )
        assert resp.status_code == 403


@integration
@pytest.mark.asyncio
class TestUpdateDeleteAsset:
    async def test_patch_tags(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="upd-msp")
        admin = await make_user(db_session, email="a@upd.example.com", tenant=msp)

        create_resp = await client.post(
            "/api/v1/assets",
            headers=auth_header(admin),
            json={
                "tenant_id": str(msp.id),
                "type": AssetType.EXTERNAL_DOMAIN.value,
                "value": "to-update.example.com",
                "tags": {"env": "staging"},
            },
        )
        asset_id = create_resp.json()["id"]

        resp = await client.patch(
            f"/api/v1/assets/{asset_id}",
            headers=auth_header(admin),
            json={"tags": {"env": "prod", "critical": True}},
        )
        assert resp.status_code == 200
        assert resp.json()["tags"] == {"env": "prod", "critical": True}

    async def test_delete(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="del-msp")
        admin = await make_user(db_session, email="a@del.example.com", tenant=msp)

        create_resp = await client.post(
            "/api/v1/assets",
            headers=auth_header(admin),
            json={
                "tenant_id": str(msp.id),
                "type": AssetType.EXTERNAL_DOMAIN.value,
                "value": "to-delete.example.com",
            },
        )
        asset_id = create_resp.json()["id"]

        resp = await client.delete(
            f"/api/v1/assets/{asset_id}", headers=auth_header(admin)
        )
        assert resp.status_code == 204

        get_resp = await client.get(
            f"/api/v1/assets/{asset_id}", headers=auth_header(admin)
        )
        assert get_resp.status_code == 404

    async def test_technician_cannot_delete(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        msp = await make_tenant(db_session, slug="td-msp")
        admin = await make_user(db_session, email="a@td.example.com", tenant=msp)
        tech = await make_user(
            db_session, email="t@td.example.com", tenant=msp, role=UserRole.MSP_TECHNICIAN
        )

        create_resp = await client.post(
            "/api/v1/assets",
            headers=auth_header(admin),
            json={
                "tenant_id": str(msp.id),
                "type": AssetType.EXTERNAL_DOMAIN.value,
                "value": "tech-cant-delete.example.com",
            },
        )
        asset_id = create_resp.json()["id"]

        resp = await client.delete(
            f"/api/v1/assets/{asset_id}", headers=auth_header(tech)
        )
        assert resp.status_code == 403
