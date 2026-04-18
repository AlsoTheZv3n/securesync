"""Shared enums used across multiple models.

Defined separately so circular imports between models stay impossible
and so each enum has exactly one definition.
"""

from __future__ import annotations

import enum


class UserRole(str, enum.Enum):
    PLATFORM_ADMIN = "platform_admin"
    MSP_ADMIN = "msp_admin"
    MSP_TECHNICIAN = "msp_technician"
    CUSTOMER_READONLY = "customer_readonly"


class AssetType(str, enum.Enum):
    EXTERNAL_DOMAIN = "external_domain"
    EXTERNAL_IP = "external_ip"
    INTERNAL_ENDPOINT = "internal_endpoint"


class ScanType(str, enum.Enum):
    EXTERNAL_FULL = "external_full"   # OpenVAS full network scan
    WEB_APP = "web_app"               # ZAP DAST scan
    INTERNAL = "internal"             # Wazuh poll
    FAST = "fast"                     # Nuclei templates


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FindingSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    ACCEPTED = "accepted"          # accepted risk
    FALSE_POSITIVE = "false_positive"


class FindingSource(str, enum.Enum):
    OPENVAS = "openvas"
    ZAP = "zap"
    NUCLEI = "nuclei"
    WAZUH = "wazuh"
    HIBP = "hibp"
    MANUAL = "manual"


class RatingGrade(str, enum.Enum):
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    E = "E"
    F = "F"


class ReportType(str, enum.Enum):
    EXECUTIVE = "executive"    # customer-facing summary
    TECHNICAL = "technical"    # MSP-internal full-detail
