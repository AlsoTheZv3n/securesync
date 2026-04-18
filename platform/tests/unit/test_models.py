"""Sanity checks for ORM model metadata.

These run without a database — they only verify that mapper configuration
is valid, that the expected tables/columns exist, and that relationships are
wired up correctly. DB-backed integration tests live in tests/integration/.
"""

from __future__ import annotations

from sqlalchemy.orm import configure_mappers

from app.models import (
    Asset,
    AssetType,
    Base,
    Finding,
    FindingSeverity,
    FindingSource,
    FindingStatus,
    Rating,
    RatingGrade,
    ScanJob,
    ScanStatus,
    ScanType,
    Tenant,
    User,
    UserRole,
)


def test_mappers_configure_without_error() -> None:
    """Catches forward-reference typos and missing back_populates early."""
    configure_mappers()


def test_all_expected_tables_registered() -> None:
    expected = {"tenants", "users", "assets", "scan_jobs", "findings", "ratings"}
    assert expected <= set(Base.metadata.tables.keys())


def test_tenant_self_referential_fk() -> None:
    msp_col = Tenant.__table__.c.msp_id
    assert msp_col.nullable is True
    fk = next(iter(msp_col.foreign_keys))
    assert fk.column.table.name == "tenants"


def test_asset_unique_tenant_value_constraint() -> None:
    constraint_names = {c.name for c in Asset.__table__.constraints}
    assert "uq_assets_tenant_id_value" in constraint_names


def test_finding_has_tenant_status_severity_index() -> None:
    index_names = {idx.name for idx in Finding.__table__.indexes}
    assert "ix_findings_tenant_id_status_severity" in index_names


def test_rating_scan_job_is_unique() -> None:
    assert Rating.__table__.c.scan_job_id.unique is True


def test_enum_value_coverage() -> None:
    # Spot-check every enum has the values the rest of the code relies on.
    assert {m.value for m in UserRole} >= {
        "platform_admin",
        "msp_admin",
        "msp_technician",
        "customer_readonly",
    }
    assert {m.value for m in AssetType} == {
        "external_domain",
        "external_ip",
        "internal_endpoint",
    }
    assert {m.value for m in ScanType} == {"external_full", "web_app", "internal", "fast"}
    assert {m.value for m in ScanStatus} >= {"queued", "running", "completed", "failed"}
    assert {m.value for m in FindingSeverity} == {
        "critical",
        "high",
        "medium",
        "low",
        "info",
    }
    assert {m.value for m in FindingStatus} >= {
        "open",
        "resolved",
        "false_positive",
    }
    assert {m.value for m in FindingSource} >= {"openvas", "zap", "nuclei", "wazuh"}
    assert {m.value for m in RatingGrade} == {"A", "B", "C", "D", "E", "F"}


def test_scan_job_back_populates_findings() -> None:
    # Verifies relationship graph round-trip.
    sj_rel = ScanJob.__mapper__.relationships["findings"]
    assert sj_rel.mapper.class_ is Finding
    f_rel = Finding.__mapper__.relationships["scan_job"]
    assert f_rel.mapper.class_ is ScanJob


def test_user_tenant_cascade_delete() -> None:
    fk = next(iter(User.__table__.c.tenant_id.foreign_keys))
    assert fk.ondelete == "CASCADE"
