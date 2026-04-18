"""OWASP ZAP integration via the ZAP REST API.

The `python-owasp-zap-v2.4` client (`zapv2`) is sync-only — wrap each blocking
call in `asyncio.to_thread`.

Workflow per scan:
    1. zap.spider.scan(target)                 → spider_id
    2. poll spider.status(spider_id) until 100
    3. zap.ascan.scan(target)                  → ascan_id
    4. poll ascan.status(ascan_id) until 100
    5. zap.alert.alerts(baseurl=target)        → list[dict]
    6. map each alert → NormalizedFinding

Reference:
  - ZAP API:  https://www.zaproxy.org/docs/api/
  - Python:   https://github.com/zaproxy/zap-api-python
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any
from urllib.parse import urlparse

import structlog
from zapv2 import ZAPv2

from app.core.config import get_settings
from app.core.exceptions import ExternalServiceError
from app.models.enums import FindingSeverity, FindingSource
from app.services.normalizer import NormalizedFinding

logger = structlog.get_logger()


# ── ZAP risk strings → our enum ─────────────────────────────
# ZAP uses risk levels: "High", "Medium", "Low", "Informational".
# (No "Critical" — XSS+SQLi land at "High".)
_RISK_TO_SEVERITY: dict[str, FindingSeverity] = {
    "high": FindingSeverity.HIGH,
    "medium": FindingSeverity.MEDIUM,
    "low": FindingSeverity.LOW,
    "informational": FindingSeverity.INFO,
    "info": FindingSeverity.INFO,
    "false positive": FindingSeverity.INFO,
}

# Pattern to extract CVE IDs from free-form text (alert reference / description).
# ZAP doesn't structurally tag CVEs; this is best-effort.
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _normalize_target_url(value: str) -> str:
    """Accept hostname / IP / URL — ZAP needs an absolute URL with scheme."""
    value = value.strip()
    if value.startswith(("http://", "https://")):
        return value
    return f"https://{value}"


def _extract_cve(alert: dict[str, Any]) -> str | None:
    # Direct field (newer ZAP versions sometimes provide it).
    direct = alert.get("cve") or alert.get("cveid")
    if direct:
        return str(direct).upper()

    # Best-effort: scan reference / description for "CVE-XXXX-YYYY".
    for field in ("reference", "description", "name"):
        text = alert.get(field)
        if text:
            match = _CVE_PATTERN.search(str(text))
            if match:
                return match.group(0).upper()
    return None


def _alert_to_finding(alert: dict[str, Any]) -> NormalizedFinding | None:
    title = alert.get("name") or alert.get("alert") or "Unknown ZAP alert"
    risk_raw = str(alert.get("risk", "informational")).lower().strip()
    severity = _RISK_TO_SEVERITY.get(risk_raw, FindingSeverity.INFO)

    asset_value = (alert.get("url") or "unknown").strip()

    # ZAP uses CWE ids in `cweid`; we keep them in raw_data but don't promote
    # to a top-level field (NormalizedFinding only models CVE).
    description = alert.get("description")
    remediation = alert.get("solution")

    evidence_parts = []
    if alert.get("param"):
        evidence_parts.append(f"param: {alert['param']}")
    if alert.get("attack"):
        evidence_parts.append(f"attack: {alert['attack']}")
    if alert.get("evidence"):
        evidence_parts.append(f"evidence: {alert['evidence']}")
    evidence = "\n".join(evidence_parts)[:4000] if evidence_parts else None

    try:
        return NormalizedFinding(
            title=title[:512],
            severity=severity,
            source=FindingSource.ZAP,
            asset_value=asset_value[:255],
            cve_id=_extract_cve(alert),
            description=description,
            remediation=remediation,
            evidence=evidence,
            raw_data=alert,
        )
    except ValueError as exc:
        logger.warning("zap_alert_skipped", reason=str(exc), alert=alert.get("name"))
        return None


def parse_zap_alerts(alerts: list[dict[str, Any]]) -> list[NormalizedFinding]:
    """Pure function: ZAP alert dicts → NormalizedFindings."""
    out: list[NormalizedFinding] = []
    for alert in alerts:
        finding = _alert_to_finding(alert)
        if finding is not None:
            out.append(finding)
    return out


class ZAPClient:
    """Async wrapper around the sync `zapv2` ZAP API client."""

    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        spider_max_seconds: int = 60 * 10,        # 10 min spider cap
        ascan_max_seconds: int = 60 * 60 * 3,     # 3h active-scan cap
        poll_interval_seconds: int = 5,
    ) -> None:
        s = get_settings()
        self.base_url = base_url or s.ZAP_URL
        self.api_key = api_key or s.ZAP_API_KEY
        self.spider_max_seconds = spider_max_seconds
        self.ascan_max_seconds = ascan_max_seconds
        self.poll_interval_seconds = poll_interval_seconds

        if not self.base_url:
            raise ExternalServiceError("ZAP_URL not configured")
        if not self.api_key:
            raise ExternalServiceError("ZAP_API_KEY not configured")

    # ── Public async API ──
    async def scan(self, target: str) -> list[NormalizedFinding]:
        """Run spider + active scan against `target`, return normalized findings."""
        return await asyncio.to_thread(self._sync_scan, target)

    # ── Sync internals ──
    def _sync_scan(self, target_value: str) -> list[NormalizedFinding]:
        url = _normalize_target_url(target_value)
        # Sanity check: ZAP refuses to scan localhost-only targets without
        # explicit allowlist; we don't need to enforce here, but bad URLs
        # (no host) should fail loudly.
        if not urlparse(url).netloc:
            raise ExternalServiceError(f"refusing to scan invalid URL: {url!r}")

        zap = ZAPv2(
            apikey=self.api_key,
            proxies={"http": self.base_url, "https": self.base_url},
        )
        logger.info("zap_scan_start", target=url)

        # ── Spider ──
        try:
            spider_id = zap.spider.scan(url)
        except Exception as exc:  # zapv2 raises bare Exception on connection errors
            raise ExternalServiceError(f"ZAP spider failed to start: {exc}") from exc

        self._poll_until_done(
            "spider", spider_id, lambda: zap.spider.status(spider_id),
            self.spider_max_seconds,
        )

        # ── Active scan ──
        try:
            ascan_id = zap.ascan.scan(url)
        except Exception as exc:
            raise ExternalServiceError(f"ZAP active scan failed to start: {exc}") from exc

        self._poll_until_done(
            "ascan", ascan_id, lambda: zap.ascan.status(ascan_id),
            self.ascan_max_seconds,
        )

        # ── Collect alerts ──
        try:
            alerts = zap.alert.alerts(baseurl=url)
        except Exception as exc:
            raise ExternalServiceError(f"ZAP alerts fetch failed: {exc}") from exc

        findings = parse_zap_alerts(alerts)
        logger.info("zap_scan_done", target=url, count=len(findings))
        return findings

    def _poll_until_done(
        self, phase: str, scan_id: str, status_fn, max_seconds: int
    ) -> None:
        elapsed = 0
        while elapsed < max_seconds:
            try:
                status = int(status_fn())
            except (TypeError, ValueError) as exc:
                raise ExternalServiceError(f"ZAP {phase} status unparseable: {exc}") from exc
            logger.debug("zap_poll", phase=phase, scan_id=scan_id, progress=status)
            if status >= 100:
                return
            time.sleep(self.poll_interval_seconds)
            elapsed += self.poll_interval_seconds
        raise ExternalServiceError(f"ZAP {phase} {scan_id} exceeded {max_seconds}s")


__all__ = ["ZAPClient", "parse_zap_alerts"]
