"""Phase 4.4 hardening: security headers, rate limit, audit log."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.models.enums import (
    FindingSeverity,
    FindingSource,
    FindingStatus,
    ReportType,
    ScanStatus,
    UserRole,
)
from app.models.finding import Finding
from app.models.rating import Rating
from tests.conftest import integration
from tests.factories import (
    auth_header,
    make_asset,
    make_scan_job,
    make_tenant,
    make_user,
)


# ── Security headers middleware ─────────────────────────────
@pytest.mark.asyncio
async def test_security_headers_on_api_response(client: AsyncClient) -> None:
    """Even dev /health (no auth) should get the hardened headers."""
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert "camera=()" in resp.headers["permissions-policy"]
    # HSTS only over https — ASGI test client is http, so NOT present.
    assert "strict-transport-security" not in resp.headers


@pytest.mark.asyncio
async def test_api_csp_locked_down(client: AsyncClient) -> None:
    """JSON API responses carry a strict no-execute CSP."""
    resp = await client.get("/health")
    assert "default-src 'none'" in resp.headers.get("content-security-policy", "")


# ── Login rate limit ────────────────────────────────────────
# Cross-test rate-limit pollution is handled globally in conftest.py's
# `_reset_redis_singleton` fixture — it flushes `rate:*` keys after each test.


@integration
@pytest.mark.asyncio
async def test_login_rate_limit_kicks_in(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """After 5 failed attempts in the 60s window, further requests → 429."""
    # 5 attempts against unknown email — all 401.
    for _ in range(5):
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "nobody@rate.example.com", "password": "Guess12345!"},
        )
        assert resp.status_code == 401

    # 6th attempt — rate limit kicks in.
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "nobody@rate.example.com", "password": "Guess12345!"},
    )
    assert resp.status_code == 429
    body = resp.json()
    assert body["code"] == "RateLimitError"


# ── Audit log: login ────────────────────────────────────────
@integration
@pytest.mark.asyncio
async def test_audit_log_records_login_success(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    msp = await make_tenant(db_session, slug="aud-login")
    user = await make_user(
        db_session, email="aud@login.example.com", tenant=msp,
        password="AuditedPass!!long",
    )

    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "aud@login.example.com", "password": "AuditedPass!!long"},
    )
    assert resp.status_code == 200

    rows = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.user_id == user.id)
        )
    ).scalars().all()
    assert len(rows) == 1
    assert rows[0].action == "auth.login_success"
    assert rows[0].tenant_id == msp.id
    assert rows[0].ip_address is not None


@integration
@pytest.mark.asyncio
async def test_audit_log_records_login_failure(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await client.post(
        "/api/v1/auth/login",
        json={"email": "ghost@miss.example.com", "password": "DoesNotMatter!!"},
    )
    rows = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "auth.login_failed")
        )
    ).scalars().all()
    assert len(rows) == 1
    assert rows[0].user_id is None
    assert rows[0].details["email"] == "ghost@miss.example.com"


# ── Audit log: finding status change ───────────────────────
@integration
@pytest.mark.asyncio
async def test_audit_log_records_finding_status_change(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    msp = await make_tenant(db_session, slug="aud-find")
    admin = await make_user(db_session, email="admin@find.example.com", tenant=msp)
    asset = await make_asset(db_session, tenant=msp, value="find.example.com")
    job = await make_scan_job(db_session, tenant=msp, asset=asset)

    finding = Finding(
        tenant_id=msp.id,
        scan_job_id=job.id,
        asset_id=asset.id,
        title="Audit check",
        severity=FindingSeverity.HIGH,
        source=FindingSource.NUCLEI,
        status=FindingStatus.OPEN,
    )
    db_session.add(finding)
    await db_session.commit()
    await db_session.refresh(finding)

    await client.patch(
        f"/api/v1/findings/{finding.id}",
        headers=auth_header(admin),
        json={"status": FindingStatus.RESOLVED.value},
    )

    rows = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.resource_id == finding.id)
        )
    ).scalars().all()
    assert len(rows) == 1
    assert rows[0].action == "finding.status.resolved"
    assert rows[0].details["previous_status"] == "open"
    assert rows[0].details["new_status"] == "resolved"


# ── Audit log read endpoint ─────────────────────────────────
@integration
@pytest.mark.asyncio
async def test_list_audit_logs_tenant_scoping(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """MSP admins only see audit entries for their own MSP + customers."""
    msp_a = await make_tenant(db_session, slug="aud-scope-a")
    msp_b = await make_tenant(db_session, slug="aud-scope-b")
    admin_a = await make_user(db_session, email="a@scope.example.com", tenant=msp_a)

    db_session.add_all([
        AuditLog(tenant_id=msp_a.id, action="test.a", details={}),
        AuditLog(tenant_id=msp_b.id, action="test.b", details={}),
    ])
    await db_session.commit()

    resp = await client.get(
        "/api/v1/audit-logs", headers=auth_header(admin_a)
    )
    assert resp.status_code == 200
    actions = {entry["action"] for entry in resp.json()}
    assert "test.a" in actions
    assert "test.b" not in actions


@integration
@pytest.mark.asyncio
async def test_audit_log_blocked_for_technician(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    msp = await make_tenant(db_session, slug="aud-tech-block")
    tech = await make_user(
        db_session, email="t@tech.example.com", tenant=msp,
        role=UserRole.MSP_TECHNICIAN,
    )
    resp = await client.get("/api/v1/audit-logs", headers=auth_header(tech))
    assert resp.status_code == 403


@integration
@pytest.mark.asyncio
async def test_audit_log_filter_by_action(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    msp = await make_tenant(db_session, slug="aud-filter")
    admin = await make_user(db_session, email="a@filter.example.com", tenant=msp)

    db_session.add_all([
        AuditLog(tenant_id=msp.id, action="tenant.create", details={}),
        AuditLog(tenant_id=msp.id, action="finding.status.resolved", details={}),
    ])
    await db_session.commit()

    resp = await client.get(
        "/api/v1/audit-logs",
        headers=auth_header(admin),
        params={"action": "finding.status.resolved"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["action"] == "finding.status.resolved"


# ── Audit log: report download ─────────────────────────────
@integration
@pytest.mark.asyncio
async def test_audit_log_records_report_download(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Reuse the existing WeasyPrint mock so we don't drag in real rendering.
    from app.services import report_generator

    def fake_render_pdf(html: str) -> bytes:
        return b"%PDF-1.4\nfake\n%%EOF"

    monkeypatch.setattr(report_generator, "render_pdf", fake_render_pdf)

    msp = await make_tenant(db_session, slug="aud-rep")
    admin = await make_user(db_session, email="a@rep.example.com", tenant=msp)
    asset = await make_asset(db_session, tenant=msp, value="rep.example.com")
    job = await make_scan_job(
        db_session, tenant=msp, asset=asset, status=ScanStatus.COMPLETED
    )
    from decimal import Decimal
    from app.models.enums import RatingGrade
    db_session.add(
        Rating(
            tenant_id=msp.id, scan_job_id=job.id,
            overall_grade=RatingGrade.B, overall_score=Decimal("80"),
            patch_score=Decimal("80"), network_score=Decimal("80"),
            web_score=Decimal("80"), endpoint_score=Decimal("80"),
            email_score=Decimal("100"), breach_score=Decimal("80"),
            ransomware_score=Decimal("80"),
        )
    )
    await db_session.commit()

    created = await client.post(
        "/api/v1/reports",
        headers=auth_header(admin),
        json={"scan_job_id": str(job.id), "type": ReportType.EXECUTIVE.value},
    )
    report_id = created.json()["id"]

    dl = await client.get(
        f"/api/v1/reports/{report_id}/download", headers=auth_header(admin)
    )
    assert dl.status_code == 200

    rows = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "report.download")
        )
    ).scalars().all()
    assert len(rows) == 1
    assert rows[0].resource_id is not None
    assert rows[0].details["type"] == "executive"
