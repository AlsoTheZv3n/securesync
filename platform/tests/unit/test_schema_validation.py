"""Pure-logic validation tests for Pydantic schemas (no DB)."""

from __future__ import annotations

from uuid import uuid4

import pytest
from pydantic import ValidationError as PydanticValidationError

from app.models.enums import AssetType
from app.schemas.asset import AssetCreate
from app.schemas.tenant import TenantCreate, TenantUpdate


# ── Tenant slug ─────────────────────────────────────────────
class TestTenantSlug:
    @pytest.mark.parametrize(
        "slug",
        ["abc", "nexo-ai", "customer-123", "a1b2c3", "ab-cd-ef"],
    )
    def test_accepts_valid(self, slug: str) -> None:
        TenantCreate(name="X", slug=slug)

    @pytest.mark.parametrize(
        "slug",
        [
            "ab",                # too short
            "-leading",          # leading hyphen
            "trailing-",         # trailing hyphen
            "with_underscore",   # underscore disallowed
            "spaces inside",
            "a" * 64,            # too long
        ],
    )
    def test_rejects_invalid(self, slug: str) -> None:
        with pytest.raises(PydanticValidationError):
            TenantCreate(name="X", slug=slug)

    # NB: uppercase is normalised to lowercase, not rejected — see test_normalises_uppercase.

    def test_normalises_uppercase(self) -> None:
        assert TenantCreate(name="X", slug="MyCo").slug == "myco"


# ── Tenant primary_color ────────────────────────────────────
class TestPrimaryColor:
    def test_accepts_lowercase_hex(self) -> None:
        t = TenantCreate(name="X", slug="x-co", primary_color="#3b82f6")
        assert t.primary_color == "#3b82f6"

    def test_normalises_uppercase_hex(self) -> None:
        t = TenantCreate(name="X", slug="x-co", primary_color="#3B82F6")
        assert t.primary_color == "#3b82f6"

    @pytest.mark.parametrize("color", ["3B82F6", "#fff", "#ZZZZZZ", "blue"])
    def test_rejects_invalid(self, color: str) -> None:
        with pytest.raises(PydanticValidationError):
            TenantCreate(name="X", slug="x-co", primary_color=color)


# ── Tenant custom_domain ────────────────────────────────────
class TestCustomDomain:
    @pytest.mark.parametrize(
        "domain",
        ["customer.example.com", "deep.sub.domain.co.uk", "x-y-z.example.org"],
    )
    def test_accepts_valid(self, domain: str) -> None:
        t = TenantCreate(name="X", slug="x-co", custom_domain=domain)
        assert t.custom_domain == domain

    def test_normalises_case(self) -> None:
        t = TenantCreate(name="X", slug="x-co", custom_domain="EXAMPLE.COM")
        assert t.custom_domain == "example.com"

    @pytest.mark.parametrize(
        "domain", ["no-tld", "a..b.com", "underscore_in.host.com"]
    )
    def test_rejects_invalid(self, domain: str) -> None:
        with pytest.raises(PydanticValidationError):
            TenantCreate(name="X", slug="x-co", custom_domain=domain)


# ── TenantUpdate (partial) ──────────────────────────────────
def test_tenant_update_allows_empty() -> None:
    # Should not raise — every field is optional.
    TenantUpdate()


# ── Asset value ↔ type validation ───────────────────────────
class TestAssetValue:
    def test_external_domain_accepts_hostname(self) -> None:
        a = AssetCreate(type=AssetType.EXTERNAL_DOMAIN, value="api.example.com", tenant_id=uuid4())
        assert a.value == "api.example.com"

    def test_external_domain_rejects_ip(self) -> None:
        with pytest.raises(PydanticValidationError):
            AssetCreate(
                type=AssetType.EXTERNAL_DOMAIN, value="192.168.1.1", tenant_id=uuid4()
            )

    @pytest.mark.parametrize("ip", ["192.168.1.1", "10.0.0.0/8", "2001:db8::1"])
    def test_external_ip_accepts(self, ip: str) -> None:
        AssetCreate(type=AssetType.EXTERNAL_IP, value=ip, tenant_id=uuid4())

    def test_external_ip_rejects_hostname(self) -> None:
        with pytest.raises(PydanticValidationError):
            AssetCreate(
                type=AssetType.EXTERNAL_IP, value="not.an.ip", tenant_id=uuid4()
            )

    def test_value_is_stripped(self) -> None:
        a = AssetCreate(
            type=AssetType.EXTERNAL_DOMAIN, value="  example.com  ", tenant_id=uuid4()
        )
        assert a.value == "example.com"

    def test_internal_endpoint_accepts_short_id(self) -> None:
        AssetCreate(
            type=AssetType.INTERNAL_ENDPOINT, value="agent-001", tenant_id=uuid4()
        )

    def test_internal_endpoint_rejects_too_long(self) -> None:
        with pytest.raises(PydanticValidationError):
            AssetCreate(
                type=AssetType.INTERNAL_ENDPOINT, value="x" * 65, tenant_id=uuid4()
            )
