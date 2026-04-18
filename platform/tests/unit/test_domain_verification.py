"""Unit tests for the DNS TXT domain-verification helper.

We never hit public DNS — the resolver is monkey-patched to return fake
TXT answer objects that match dnspython's shape (rdata with `.strings`).
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from app.services.domain_verification import (
    VERIFICATION_SUBDOMAIN_PREFIX,
    VERIFICATION_VALUE_PREFIX,
    build_expected_txt_value,
    build_verification_dns_name,
    generate_verification_token,
    verify_domain_txt,
)


@dataclass
class _FakeRdata:
    """Minimal stand-in for dnspython's TXT rdata."""
    strings: tuple[bytes, ...]


class _FakeAnswer:
    def __init__(self, rdatas: list[_FakeRdata]) -> None:
        self._rdatas = rdatas

    def __iter__(self):
        return iter(self._rdatas)


class _FakeResolver:
    """Swap in via monkeypatch to avoid real DNS. `records` maps
    'name,rdtype' → list[_FakeRdata] or an exception class to raise."""

    def __init__(self, records: dict) -> None:
        self.records = records
        self.lifetime = 0.0
        self.timeout = 0.0

    def resolve(self, name: str, rdtype: str):
        key = (name.lower().rstrip("."), rdtype)
        hit = self.records.get(key)
        if hit is None:
            # Match real dnspython behaviour: NXDOMAIN when nothing there.
            import dns.resolver
            raise dns.resolver.NXDOMAIN()
        if isinstance(hit, type) and issubclass(hit, Exception):
            raise hit()
        return _FakeAnswer(hit)


def _txt(*parts: bytes) -> _FakeRdata:
    return _FakeRdata(strings=parts)


# ── Pure helpers ────────────────────────────────────────────
class TestHelpers:
    def test_dns_name_uses_prefix(self) -> None:
        assert build_verification_dns_name("customer.example.com") == (
            f"{VERIFICATION_SUBDOMAIN_PREFIX}.customer.example.com"
        )

    def test_txt_value_shape(self) -> None:
        val = build_expected_txt_value("abc123")
        assert val == f"{VERIFICATION_VALUE_PREFIX}abc123"

    def test_generate_token_is_urlsafe_and_long(self) -> None:
        t1, t2 = generate_verification_token(), generate_verification_token()
        assert t1 != t2
        assert len(t1) >= 20
        # token_urlsafe alphabet: A-Z a-z 0-9 - _
        assert all(c.isalnum() or c in "-_" for c in t1)


# ── verify_domain_txt ───────────────────────────────────────
@pytest.mark.asyncio
class TestVerifyDomainTxt:
    async def test_matches_correct_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        token = "hello-world-token"
        dns_name = build_verification_dns_name("customer.example.com")
        fake = _FakeResolver({
            (dns_name, "TXT"): [_txt(f"{VERIFICATION_VALUE_PREFIX}{token}".encode())],
        })

        import dns.resolver as real_resolver

        monkeypatch.setattr(real_resolver, "Resolver", lambda: fake)

        assert await verify_domain_txt(
            "customer.example.com", expected_token=token
        ) is True

    async def test_mismatched_token_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        dns_name = build_verification_dns_name("customer.example.com")
        fake = _FakeResolver({
            (dns_name, "TXT"): [_txt(b"securesync-verify=wrong-token")],
        })
        import dns.resolver as real_resolver
        monkeypatch.setattr(real_resolver, "Resolver", lambda: fake)

        assert await verify_domain_txt(
            "customer.example.com", expected_token="right-token"
        ) is False

    async def test_picks_matching_value_among_many(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Tenants often have unrelated TXT records on the same name —
        we must accept the one that matches without caring about the rest."""
        token = "needle-token"
        dns_name = build_verification_dns_name("customer.example.com")
        fake = _FakeResolver({
            (dns_name, "TXT"): [
                _txt(b"unrelated-spf-like-record"),
                _txt(f"{VERIFICATION_VALUE_PREFIX}{token}".encode()),
                _txt(b"another-one"),
            ],
        })
        import dns.resolver as real_resolver
        monkeypatch.setattr(real_resolver, "Resolver", lambda: fake)

        assert await verify_domain_txt(
            "customer.example.com", expected_token=token
        ) is True

    async def test_concatenates_split_txt_parts(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """DNS TXT records are capped at 255 bytes per chunk and appear as
        tuples. Our parser must concatenate before comparing."""
        token = "concat-split-token"
        expected = build_expected_txt_value(token).encode()
        dns_name = build_verification_dns_name("customer.example.com")
        fake = _FakeResolver({
            (dns_name, "TXT"): [_txt(expected[:10], expected[10:])],
        })
        import dns.resolver as real_resolver
        monkeypatch.setattr(real_resolver, "Resolver", lambda: fake)

        assert await verify_domain_txt(
            "customer.example.com", expected_token=token
        ) is True

    async def test_nxdomain_returns_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _FakeResolver(records={})   # nothing → NXDOMAIN
        import dns.resolver as real_resolver
        monkeypatch.setattr(real_resolver, "Resolver", lambda: fake)

        assert await verify_domain_txt(
            "customer.example.com", expected_token="any"
        ) is False

    async def test_dns_timeout_returns_false(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import dns.exception
        dns_name = build_verification_dns_name("customer.example.com")
        fake = _FakeResolver({
            (dns_name, "TXT"): dns.exception.Timeout,
        })
        import dns.resolver as real_resolver
        monkeypatch.setattr(real_resolver, "Resolver", lambda: fake)

        assert await verify_domain_txt(
            "customer.example.com", expected_token="any"
        ) is False
