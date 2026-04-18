"""Custom-domain ownership verification via a DNS TXT record.

Flow:
    1. Tenant admin sets `custom_domain` on their Tenant.
    2. Calls POST /tenants/{id}/verify-domain — we generate a random token
       and return the expected TXT record ("securesync-verify=<token>"
       on `_securesync.<domain>`).
    3. Tenant adds the TXT record at their DNS provider.
    4. Calls POST /tenants/{id}/verify-domain/confirm — we look up
       `_securesync.<custom_domain>`, confirm the token matches, set
       `custom_domain_verified = True` and clear the token.

Only verified domains are eligible for Nginx vhost + Let's Encrypt cert
provisioning (handled by the operator scripts in `infra/nginx/`).
"""

from __future__ import annotations

import asyncio
import secrets

import structlog

logger = structlog.get_logger()


# The DNS name queried for the token. A sub-record (rather than the apex)
# so we don't clash with SPF/DMARC/etc. TXT records the tenant may already
# have on their main domain.
VERIFICATION_SUBDOMAIN_PREFIX = "_securesync"
VERIFICATION_VALUE_PREFIX = "securesync-verify="


def generate_verification_token() -> str:
    """Cryptographically random token embedded in the TXT record value."""
    return secrets.token_urlsafe(24)


def build_verification_dns_name(custom_domain: str) -> str:
    return f"{VERIFICATION_SUBDOMAIN_PREFIX}.{custom_domain}"


def build_expected_txt_value(token: str) -> str:
    return f"{VERIFICATION_VALUE_PREFIX}{token}"


def _lookup_txt_values(dns_name: str, *, timeout: float) -> list[str]:
    """Sync DNS TXT lookup — wrap caller-side in asyncio.to_thread."""
    # Import inside the function so that tests mocking at the module level
    # via monkeypatch hit the exact symbol we call.
    import dns.exception
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    try:
        answer = resolver.resolve(dns_name, "TXT")
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        return []

    values: list[str] = []
    for record in answer:
        # TXT records come as tuples of byte strings; dnspython wraps them
        # in an rdata object whose .strings attribute is the raw parts.
        raw_strings = getattr(record, "strings", ())
        decoded = "".join(
            s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s)
            for s in raw_strings
        )
        if decoded:
            values.append(decoded)
    return values


async def verify_domain_txt(
    custom_domain: str, *, expected_token: str, timeout: float = 5.0
) -> bool:
    """Resolve the verification TXT record and confirm the token matches.

    Returns True iff any TXT value on `_securesync.<domain>` equals
    `securesync-verify=<expected_token>`. Returns False on missing record,
    DNS failure, or mismatch — callers should not distinguish reasons.
    """
    dns_name = build_verification_dns_name(custom_domain)
    expected = build_expected_txt_value(expected_token)

    try:
        values = await asyncio.to_thread(
            _lookup_txt_values, dns_name, timeout=timeout
        )
    except Exception as exc:  # defensive: dnspython occasionally raises at import time
        logger.warning("domain_verification_lookup_error", domain=custom_domain, error=str(exc))
        return False

    match = any(v.strip() == expected for v in values)
    logger.info(
        "domain_verification_lookup",
        domain=custom_domain,
        dns_name=dns_name,
        candidates=len(values),
        matched=match,
    )
    return match


__all__ = [
    "VERIFICATION_SUBDOMAIN_PREFIX",
    "VERIFICATION_VALUE_PREFIX",
    "build_expected_txt_value",
    "build_verification_dns_name",
    "generate_verification_token",
    "verify_domain_txt",
]
