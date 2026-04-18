"""Wiring tests for the Wazuh side-channel hooks.

Low-level HTTP behaviour is in `tests/unit/test_wazuh_client.py`. Here we
verify that `provision_agent_group_for_tenant` is called from the right
place on the tenant-create flow.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import integration
from tests.factories import auth_header, make_tenant, make_user


@integration
@pytest.mark.asyncio
class TestTenantCreateWazuhHook:
    async def test_hook_invoked_on_successful_create(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        captured: list[str] = []

        # MOCK — see docs/mocks.md row #8.
        async def fake_provision(tenant) -> None:
            captured.append(tenant.slug)

        monkeypatch.setattr(
            "app.api.v1.tenants.provision_agent_group_for_tenant", fake_provision
        )

        msp = await make_tenant(db_session, slug="wh-hook-msp")
        admin = await make_user(db_session, email="a@wh-hook.example.com", tenant=msp)

        resp = await client.post(
            "/api/v1/tenants",
            headers=auth_header(admin),
            json={"name": "Acme Corp", "slug": "wh-acme"},
        )
        assert resp.status_code == 201
        assert captured == ["wh-acme"]

    async def test_hook_silent_when_unconfigured(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
    ) -> None:
        """Default test env doesn't set WAZUH_* vars — the hook short-circuits
        via `_wazuh_configured()` and the tenant create still succeeds."""
        msp = await make_tenant(db_session, slug="wh-silent-msp")
        admin = await make_user(db_session, email="a@wh-silent.example.com", tenant=msp)

        resp = await client.post(
            "/api/v1/tenants",
            headers=auth_header(admin),
            json={"name": "Silent Corp", "slug": "wh-silent"},
        )
        assert resp.status_code == 201
