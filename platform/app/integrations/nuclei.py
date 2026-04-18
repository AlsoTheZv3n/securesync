"""Nuclei (ProjectDiscovery) integration.

Nuclei is a Go binary, executed as a subprocess. We feed it one target at a
time and parse its JSONL output line by line.

Reference:
  - CLI:     https://docs.projectdiscovery.io/tools/nuclei/running
  - Output:  https://docs.projectdiscovery.io/tools/nuclei/output
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
from collections.abc import Iterable
from decimal import Decimal
from typing import Any

import structlog

from app.core.exceptions import ExternalServiceError
from app.models.enums import FindingSeverity, FindingSource
from app.services.normalizer import NormalizedFinding

logger = structlog.get_logger()

# Severity strings nuclei emits → our enum.
_SEVERITY_MAP: dict[str, FindingSeverity] = {
    "critical": FindingSeverity.CRITICAL,
    "high": FindingSeverity.HIGH,
    "medium": FindingSeverity.MEDIUM,
    "low": FindingSeverity.LOW,
    "info": FindingSeverity.INFO,
    "unknown": FindingSeverity.INFO,
}

# We never trust the target string straight from a user. Allow only what a
# scan target should look like — schemes are stripped, then host/IP/CIDR/port.
_TARGET_PATTERN = re.compile(
    r"^(?:https?://)?"               # optional scheme
    r"(?:[a-zA-Z0-9_.-]+|"           # hostname / IP
    r"\[[0-9a-fA-F:]+\])"            # or IPv6 literal
    r"(?::\d{1,5})?"                 # optional port
    r"(?:/[^\s]*)?$"                 # optional path
)


def _validate_target(target: str) -> str:
    target = target.strip()
    if not target or len(target) > 255 or not _TARGET_PATTERN.match(target):
        raise ValueError(f"refusing to pass unsafe target to nuclei: {target!r}")
    return target


def _parse_nuclei_event(event: dict[str, Any]) -> NormalizedFinding | None:
    """Convert one nuclei JSONL event into a NormalizedFinding (or None to skip)."""
    info = event.get("info") or {}
    severity_raw = str(info.get("severity", "info")).lower()
    severity = _SEVERITY_MAP.get(severity_raw, FindingSeverity.INFO)

    title = info.get("name") or event.get("template-id") or "Unknown nuclei finding"
    description = info.get("description")
    remediation = info.get("remediation")

    # CVE: nuclei nests it under info.classification.cve-id (list).
    cve_id: str | None = None
    classification = info.get("classification") or {}
    cve_ids = classification.get("cve-id")
    if isinstance(cve_ids, list) and cve_ids:
        cve_id = str(cve_ids[0])
    elif isinstance(cve_ids, str):
        cve_id = cve_ids

    # CVSS: classification.cvss-score (single float) or info.cvss-score.
    cvss_raw = classification.get("cvss-score") or info.get("cvss-score")
    cvss_score: Decimal | None = None
    if cvss_raw is not None:
        try:
            cvss_score = Decimal(str(cvss_raw))
        except (TypeError, ArithmeticError):
            cvss_score = None

    # Where the scanner saw it: prefer matched-at, fall back to host.
    asset_value = (
        event.get("matched-at")
        or event.get("host")
        or event.get("ip")
        or "unknown"
    )

    # Evidence: extracted-results array → newline-joined snippet, capped.
    extracted = event.get("extracted-results") or []
    evidence = "\n".join(str(e) for e in extracted)[:4000] if extracted else None

    try:
        return NormalizedFinding(
            title=title,
            severity=severity,
            source=FindingSource.NUCLEI,
            asset_value=str(asset_value)[:255],
            cve_id=cve_id,
            description=description,
            remediation=remediation,
            evidence=evidence,
            cvss_score=cvss_score,
            raw_data=event,
        )
    except ValueError as exc:
        logger.warning("nuclei_parse_skipped", reason=str(exc), template=event.get("template-id"))
        return None


def parse_nuclei_jsonl(stdout: str) -> list[NormalizedFinding]:
    """Parse newline-delimited JSON from nuclei stdout into normalized findings."""
    findings: list[NormalizedFinding] = []
    for line_no, raw_line in enumerate(stdout.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            logger.warning("nuclei_invalid_jsonl", line=line_no, error=str(exc))
            continue
        finding = _parse_nuclei_event(event)
        if finding is not None:
            findings.append(finding)
    return findings


class NucleiClient:
    """Async wrapper around the `nuclei` CLI."""

    def __init__(
        self,
        *,
        binary: str = "nuclei",
        rate_limit: int = 50,
        timeout_seconds: int = 600,
        templates: Iterable[str] | None = None,
    ) -> None:
        self.binary = binary
        self.rate_limit = rate_limit
        self.timeout_seconds = timeout_seconds
        # Default to CVE + exposure + misconfig templates per features.md §2.3.
        self.templates = list(templates) if templates else ["cves", "exposures", "misconfiguration"]

    def _build_argv(self, target: str, severities: list[str] | None) -> list[str]:
        sev = ",".join(severities) if severities else "critical,high,medium,low,info"
        argv = [
            self.binary,
            "-target", target,
            "-jsonl",                  # newline-delimited JSON to stdout
            "-disable-update-check",
            "-no-color",
            "-silent",
            "-rate-limit", str(self.rate_limit),
            "-severity", sev,
            "-tags", ",".join(self.templates),
        ]
        return argv

    async def scan(
        self,
        target: str,
        *,
        severities: list[str] | None = None,
    ) -> list[NormalizedFinding]:
        """Run nuclei against `target`, return normalized findings.

        Raises ExternalServiceError if the binary is missing or the process
        fails / times out.
        """
        target = _validate_target(target)

        if shutil.which(self.binary) is None:
            raise ExternalServiceError(f"nuclei binary not found on PATH: {self.binary}")

        argv = self._build_argv(target, severities)
        logger.info("nuclei_scan_start", target=target, argv=argv)

        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise ExternalServiceError(f"failed to spawn nuclei: {exc}") from exc

        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout_seconds
            )
        except TimeoutError:
            proc.kill()
            await proc.wait()
            raise ExternalServiceError(
                f"nuclei scan exceeded {self.timeout_seconds}s timeout"
            ) from None

        stdout = stdout_b.decode("utf-8", errors="replace")
        stderr = stderr_b.decode("utf-8", errors="replace")

        if proc.returncode not in (0, None):
            # Nuclei returns 0 even with findings; non-zero is an actual error.
            logger.error("nuclei_scan_failed", returncode=proc.returncode, stderr=stderr[:500])
            raise ExternalServiceError(f"nuclei exited with code {proc.returncode}")

        findings = parse_nuclei_jsonl(stdout)
        logger.info("nuclei_scan_done", target=target, count=len(findings))
        return findings
