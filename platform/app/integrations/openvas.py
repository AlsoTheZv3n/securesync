"""Greenbone / OpenVAS integration via the GMP protocol.

`python-gvm` is sync-only, so every public method on `GreenBoneClient` wraps
its blocking call in `asyncio.to_thread` to keep the surrounding async pipeline
non-blocking.

GMP workflow:
    1. create_target(value)              → target_id
    2. create_task(target_id, config_id) → task_id
    3. start_task(task_id)               → report_id
    4. poll get_tasks(task_id) until status == "Done"
    5. get_report(report_id)             → XML
    6. parse_report(xml)                 → list[NormalizedFinding]

Reference:
  - GMP 22.4: https://docs.greenbone.net/API/GMP/gmp-22.4.html
  - python-gvm: https://python-gvm.readthedocs.io/en/latest/
"""

from __future__ import annotations

import asyncio
import time
from decimal import Decimal, InvalidOperation
from typing import TYPE_CHECKING
from xml.etree import ElementTree as ET

import structlog
from gvm.connections import TLSConnection, UnixSocketConnection
from gvm.errors import GvmError
from gvm.protocols.gmp import Gmp

from app.core.config import get_settings
from app.core.exceptions import ExternalServiceError
from app.models.enums import FindingSeverity, FindingSource
from app.services.normalizer import NormalizedFinding

if TYPE_CHECKING:
    from collections.abc import Iterable

logger = structlog.get_logger()


# ── Well-known Greenbone IDs ────────────────────────────────
# These UUIDs are stable across all Greenbone Community Edition installs.
# Source: docs.greenbone.net/GSM-Manual/gos-22.04/en/scanning.html
SCAN_CONFIG_FULL_AND_FAST = "daba56c8-73ec-11df-a475-002264764cea"
SCAN_CONFIG_DISCOVERY = "8715c877-47a0-438d-98a3-27c7a6ab2196"
DEFAULT_SCANNER_OPENVAS = "08b69003-5fc2-4037-a479-93b440211c73"
REPORT_FORMAT_XML = "a994b278-1f62-11e1-96ac-406186ea4fc5"


# ── Greenbone "threat" / "severity" → our enum ──────────────
# Greenbone uses "threat" (categorical) and "severity" (CVSS-like score).
# We prefer the categorical mapping when present.
_THREAT_TO_SEVERITY: dict[str, FindingSeverity] = {
    "Critical": FindingSeverity.CRITICAL,
    "High": FindingSeverity.HIGH,
    "Medium": FindingSeverity.MEDIUM,
    "Low": FindingSeverity.LOW,
    "Log": FindingSeverity.INFO,
    "Debug": FindingSeverity.INFO,
    "False Positive": FindingSeverity.INFO,
}


def _severity_for_score(score: Decimal | None) -> FindingSeverity:
    """Fallback when a result lacks a Greenbone `<threat>`. CVSS v3 buckets."""
    if score is None:
        return FindingSeverity.INFO
    if score >= Decimal("9.0"):
        return FindingSeverity.CRITICAL
    if score >= Decimal("7.0"):
        return FindingSeverity.HIGH
    if score >= Decimal("4.0"):
        return FindingSeverity.MEDIUM
    if score > Decimal("0.0"):
        return FindingSeverity.LOW
    return FindingSeverity.INFO


def _decimal(text: str | None) -> Decimal | None:
    if text is None:
        return None
    text = text.strip()
    if not text or text in {"None", "NaN"}:
        return None
    try:
        return Decimal(text)
    except (InvalidOperation, ValueError):
        return None


def _result_to_finding(result: ET.Element) -> NormalizedFinding | None:
    """Convert one <result> element to a NormalizedFinding (or None to skip)."""
    name_el = result.find("name")
    title = (name_el.text or "Unknown OpenVAS finding") if name_el is not None else "Unknown"

    threat_el = result.find("threat")
    threat = threat_el.text if threat_el is not None else None

    severity_el = result.find("severity")
    cvss_score = _decimal(severity_el.text if severity_el is not None else None)

    if threat in _THREAT_TO_SEVERITY:
        severity = _THREAT_TO_SEVERITY[threat]
    else:
        severity = _severity_for_score(cvss_score)

    description_el = result.find("description")
    description = description_el.text if description_el is not None else None

    host_el = result.find("host")
    port_el = result.find("port")
    asset_value = (host_el.text or "unknown").strip() if host_el is not None else "unknown"
    if port_el is not None and port_el.text:
        asset_value = f"{asset_value}:{port_el.text.strip()}"

    # CVE: refs are nested under <nvt><refs><ref id="..." type="cve"/></refs></nvt>.
    cve_id: str | None = None
    nvt = result.find("nvt")
    if nvt is not None:
        for ref in nvt.findall("refs/ref"):
            if ref.attrib.get("type", "").lower() == "cve":
                cve_id = ref.attrib.get("id")
                break

    # Raw payload: serialize the element for storage/debugging.
    raw = {child.tag: child.text for child in result if child.text is not None}
    raw["_source_xml"] = ET.tostring(result, encoding="unicode")[:4000]

    try:
        return NormalizedFinding(
            title=title[:512],
            severity=severity,
            source=FindingSource.OPENVAS,
            asset_value=asset_value[:255],
            cve_id=cve_id,
            description=description,
            cvss_score=cvss_score,
            raw_data=raw,
        )
    except ValueError as exc:
        logger.warning("openvas_parse_skipped", reason=str(exc), title=title)
        return None


def parse_report_xml(xml_text: str) -> list[NormalizedFinding]:
    """Parse a Greenbone GMP report XML string into NormalizedFindings."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ExternalServiceError(f"could not parse GMP report XML: {exc}") from exc

    # Greenbone wraps the actual report inside <report><report>...</report></report>
    # (outer element carries the request id, inner the data). `.//result` finds
    # them at any depth so we tolerate both shapes.
    results = root.findall(".//results/result")
    out: list[NormalizedFinding] = []
    for result in results:
        finding = _result_to_finding(result)
        if finding is not None:
            out.append(finding)
    return out


class GreenBoneClient:
    """Async wrapper around the sync `python-gvm` GMP client."""

    def __init__(
        self,
        *,
        host: str | None = None,
        port: int = 9390,
        username: str | None = None,
        password: str | None = None,
        socket_path: str | None = None,
        scan_config_id: str = SCAN_CONFIG_FULL_AND_FAST,
        scanner_id: str = DEFAULT_SCANNER_OPENVAS,
        poll_interval_seconds: int = 30,
        max_wait_seconds: int = 60 * 60 * 2,  # 2h hard ceiling per scan
    ) -> None:
        s = get_settings()
        self.host = host or s.GREENBONE_HOST
        self.port = port
        self.username = username or s.GREENBONE_USERNAME
        self.password = password or s.GREENBONE_PASSWORD
        self.socket_path = socket_path
        self.scan_config_id = scan_config_id
        self.scanner_id = scanner_id
        self.poll_interval_seconds = poll_interval_seconds
        self.max_wait_seconds = max_wait_seconds

        if not self.username or not self.password:
            raise ExternalServiceError("Greenbone credentials not configured")
        if not (self.host or self.socket_path):
            raise ExternalServiceError("Greenbone host or socket_path required")

    # ── Connection factory ──
    def _open_connection(self):
        if self.socket_path:
            return UnixSocketConnection(path=self.socket_path)
        return TLSConnection(hostname=self.host, port=self.port)

    # ── Public async API ──
    async def scan(self, target_value: str, *, scan_label: str = "securesync") -> list[NormalizedFinding]:
        """Run a full GMP scan and return normalized findings.

        `target_value` is a single hostname/IP or a comma-separated list.
        Cleanup of GMP target/task/report artifacts happens best-effort.
        """
        return await asyncio.to_thread(self._sync_scan, target_value, scan_label)

    # ── Sync internals (each blocking GMP call) ──
    def _sync_scan(self, target_value: str, scan_label: str) -> list[NormalizedFinding]:
        hosts = [h.strip() for h in target_value.split(",") if h.strip()]
        if not hosts:
            raise ExternalServiceError("empty target")

        target_id: str | None = None
        task_id: str | None = None

        try:
            with Gmp(self._open_connection()) as gmp:
                gmp.authenticate(self.username, self.password)
                target_id = self._create_target(gmp, scan_label, hosts)
                task_id, report_id = self._create_and_start_task(gmp, scan_label, target_id)
                self._wait_for_completion(gmp, task_id)
                xml = self._get_report(gmp, report_id)
        except GvmError as exc:
            raise ExternalServiceError(f"Greenbone GMP error: {exc}") from exc

        findings = parse_report_xml(xml)

        # Best-effort cleanup so we don't leak target/task entries on the manager.
        if task_id or target_id:
            self._cleanup_safe(task_id, target_id)

        logger.info("openvas_scan_done", target=target_value, count=len(findings))
        return findings

    def _create_target(self, gmp: Gmp, label: str, hosts: Iterable[str]) -> str:
        name = f"{label}-target-{int(time.time())}"
        response = gmp.create_target(name=name, hosts=list(hosts))
        return response.attrib["id"]

    def _create_and_start_task(self, gmp: Gmp, label: str, target_id: str) -> tuple[str, str]:
        name = f"{label}-task-{int(time.time())}"
        task_resp = gmp.create_task(
            name=name,
            config_id=self.scan_config_id,
            target_id=target_id,
            scanner_id=self.scanner_id,
        )
        task_id = task_resp.attrib["id"]
        start_resp = gmp.start_task(task_id=task_id)
        # <start_task_response><report_id>...</report_id></start_task_response>
        report_id_el = start_resp.find("report_id")
        if report_id_el is None or not report_id_el.text:
            raise ExternalServiceError("Greenbone did not return a report_id on start_task")
        return task_id, report_id_el.text

    def _wait_for_completion(self, gmp: Gmp, task_id: str) -> None:
        elapsed = 0
        while elapsed < self.max_wait_seconds:
            status_resp = gmp.get_tasks(task_id=task_id)
            status_el = status_resp.find(".//task/status")
            status = status_el.text if status_el is not None else None
            logger.debug("openvas_poll", task_id=task_id, status=status, elapsed=elapsed)
            if status == "Done":
                return
            if status in {"Stopped", "Interrupted", "Failed"}:
                raise ExternalServiceError(f"Greenbone task {task_id} ended with status={status}")
            time.sleep(self.poll_interval_seconds)
            elapsed += self.poll_interval_seconds
        raise ExternalServiceError(
            f"Greenbone task {task_id} exceeded {self.max_wait_seconds}s wait"
        )

    def _get_report(self, gmp: Gmp, report_id: str) -> str:
        resp = gmp.get_report(
            report_id=report_id,
            report_format_id=REPORT_FORMAT_XML,
            ignore_pagination=True,
            details=True,
        )
        return ET.tostring(resp, encoding="unicode")

    def _cleanup_safe(self, task_id: str | None, target_id: str | None) -> None:
        try:
            with Gmp(self._open_connection()) as gmp:
                gmp.authenticate(self.username, self.password)
                if task_id:
                    try:
                        gmp.delete_task(task_id=task_id)
                    except GvmError as exc:
                        logger.warning("openvas_cleanup_task_failed", task_id=task_id, error=str(exc))
                if target_id:
                    try:
                        gmp.delete_target(target_id=target_id)
                    except GvmError as exc:
                        logger.warning("openvas_cleanup_target_failed", target_id=target_id, error=str(exc))
        except GvmError as exc:
            logger.warning("openvas_cleanup_connect_failed", error=str(exc))


__all__ = ["GreenBoneClient", "parse_report_xml"]
