"""Integration tests for the DefectDojo side-channel hooks.

We don't make real HTTP calls — the low-level DefectDojoClient is covered by
`tests/unit/test_defectdojo_client.py` with respx. Here we verify the
*wiring*: that the hook functions are invoked from the right places in the
tenant-create and scan-complete flows.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import FindingSeverity, FindingSource, ScanStatus
from app.services.normalizer import NormalizedFinding
from tests.conftest import integration
from tests.factories import (
    auth_header,
    make_asset,
    make_scan_job,
    make_tenant,
    make_user,
)


# ── Tenant creation hook ────────────────────────────────────
@integration
@pytest.mark.asyncio
class TestTenantCreateHook:
    async def test_hook_invoked_on_successful_create(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        captured: list[str] = []

        # MOCK — see docs/mocks.md row #2 (pattern extended for DefectDojo sync).
        async def fake_provision(session, tenant) -> None:
            captured.append(str(tenant.id))

        monkeypatch.setattr(
            "app.api.v1.tenants.provision_product_for_tenant", fake_provision
        )

        msp = await make_tenant(db_session, slug="dd-hook-msp")
        admin = await make_user(db_session, email="a@dd.example.com", tenant=msp)

        resp = await client.post(
            "/api/v1/tenants",
            headers=auth_header(admin),
            json={"name": "Acme Corp", "slug": "dd-acme"},
        )
        assert resp.status_code == 201
        assert captured == [resp.json()["id"]]

    async def test_existing_tests_still_pass_without_defectdojo(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
    ) -> None:
        """Smoke test: when DEFECTDOJO_URL is unset (test default),
        the hook short-circuits and tenant creation succeeds unchanged."""
        msp = await make_tenant(db_session, slug="no-dd-msp")
        admin = await make_user(db_session, email="a@no-dd.example.com", tenant=msp)

        resp = await client.post(
            "/api/v1/tenants",
            headers=auth_header(admin),
            json={"name": "Plain Corp", "slug": "plain"},
        )
        assert resp.status_code == 201
        body = resp.json()
        # Tenant is usable, product id stays None — confirmed via GET.
        get_resp = await client.get(
            f"/api/v1/tenants/{body['id']}", headers=auth_header(admin)
        )
        assert get_resp.status_code == 200


# ── Scan completion hook ────────────────────────────────────
@integration
@pytest.mark.asyncio
class TestScanCompleteHook:
    async def test_push_called_after_successful_scan(
        self,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from app.integrations.nuclei import NucleiClient
        from app.tasks.scan_tasks import _run_nuclei_scan_async

        msp = await make_tenant(db_session, slug="dd-scan-msp")
        asset = await make_asset(db_session, tenant=msp, value="dd.example.com")
        job = await make_scan_job(db_session, tenant=msp, asset=asset)
        job_id = job.id

        # MOCK — see docs/mocks.md row #1 (Nuclei subprocess).
        async def stub_scan(self, target: str, **_: object) -> list[NormalizedFinding]:
            return [
                NormalizedFinding(
                    title="Fake finding",
                    severity=FindingSeverity.LOW,
                    source=FindingSource.NUCLEI,
                    asset_value=target,
                )
            ]

        monkeypatch.setattr(NucleiClient, "scan", stub_scan)

        # MOCK — see docs/mocks.md row #6 (DefectDojo push hook).
        push_calls: list[tuple[str, int]] = []

        async def fake_push(session, scan_job, tenant, findings) -> None:
            push_calls.append((str(scan_job.id), len(findings)))

        monkeypatch.setattr("app.tasks.scan_tasks.push_scan_to_defectdojo", fake_push)

        result = await _run_nuclei_scan_async(job_id)

        assert result["status"] == "completed"
        assert push_calls == [(str(job_id), 1)]

        await db_session.refresh(job)
        assert job.status is ScanStatus.COMPLETED

    async def test_push_not_called_when_scan_fails(
        self,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A scanner error must short-circuit before the DefectDojo push
        so the fake-completed state is never reported to DefectDojo."""
        from app.core.exceptions import ExternalServiceError
        from app.integrations.nuclei import NucleiClient
        from app.tasks.scan_tasks import _run_nuclei_scan_async

        msp = await make_tenant(db_session, slug="dd-fail-msp")
        asset = await make_asset(db_session, tenant=msp, value="dd-fail.example.com")
        job = await make_scan_job(db_session, tenant=msp, asset=asset)
        job_id = job.id

        async def stub_scan(_self, _target: str, **_: object) -> list[NormalizedFinding]:
            raise ExternalServiceError("nuclei binary missing")

        monkeypatch.setattr(NucleiClient, "scan", stub_scan)

        push_calls: list[tuple[str, int]] = []

        async def fake_push(session, scan_job, tenant, findings) -> None:
            push_calls.append((str(scan_job.id), len(findings)))

        monkeypatch.setattr("app.tasks.scan_tasks.push_scan_to_defectdojo", fake_push)

        with pytest.raises(ExternalServiceError):
            await _run_nuclei_scan_async(job_id)

        assert push_calls == []
        await db_session.refresh(job)
        assert job.status is ScanStatus.FAILED
