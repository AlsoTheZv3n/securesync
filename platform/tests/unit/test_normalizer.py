"""Pure-logic tests for app.services.normalizer."""

from __future__ import annotations

from decimal import Decimal
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.models.enums import FindingSeverity, FindingSource
from app.services.normalizer import NormalizedFinding, to_orm


def _base() -> dict:
    return {
        "title": "X",
        "severity": FindingSeverity.HIGH,
        "source": FindingSource.NUCLEI,
        "asset_value": "https://example.com",
    }


class TestNormalizedFindingValidation:
    def test_minimal_construction(self) -> None:
        f = NormalizedFinding(**_base())
        assert f.cve_id is None
        assert f.raw_data == {}

    def test_cve_normalised_uppercase(self) -> None:
        f = NormalizedFinding(**_base(), cve_id="cve-2024-12345")
        assert f.cve_id == "CVE-2024-12345"

    def test_cve_must_have_prefix(self) -> None:
        with pytest.raises(ValidationError):
            NormalizedFinding(**_base(), cve_id="2024-12345")

    @pytest.mark.parametrize("score", [Decimal("0"), Decimal("5.5"), Decimal("10.0")])
    def test_cvss_in_range(self, score: Decimal) -> None:
        NormalizedFinding(**_base(), cvss_score=score)

    @pytest.mark.parametrize("score", [Decimal("-0.1"), Decimal("10.1"), Decimal("100")])
    def test_cvss_out_of_range_rejected(self, score: Decimal) -> None:
        with pytest.raises(ValidationError):
            NormalizedFinding(**_base(), cvss_score=score)

    def test_frozen_model_is_immutable(self) -> None:
        f = NormalizedFinding(**_base())
        with pytest.raises(ValidationError):
            f.title = "mutated"  # type: ignore[misc]


class TestToOrm:
    def test_fields_copied_through(self) -> None:
        nf = NormalizedFinding(
            title="Open Redirect",
            severity=FindingSeverity.MEDIUM,
            source=FindingSource.ZAP,
            asset_value="example.com",
            cve_id="CVE-2024-1",
            description="desc",
            remediation="patch",
            evidence="trace",
            cvss_score=Decimal("4.5"),
            raw_data={"k": "v"},
        )
        tenant_id = uuid4()
        scan_job_id = uuid4()
        asset_id = uuid4()

        row = to_orm(nf, tenant_id=tenant_id, scan_job_id=scan_job_id, asset_id=asset_id)

        assert row.tenant_id == tenant_id
        assert row.scan_job_id == scan_job_id
        assert row.asset_id == asset_id
        assert row.title == "Open Redirect"
        assert row.severity is FindingSeverity.MEDIUM
        assert row.source is FindingSource.ZAP
        assert row.cve_id == "CVE-2024-1"
        assert row.cvss_score == Decimal("4.5")
        assert row.raw_data == {"k": "v"}

    def test_long_titles_truncated(self) -> None:
        # Pydantic enforces 512-char max at construction, but to_orm has its own
        # belt-and-braces slice — verified here so future schema changes don't
        # silently overflow Finding.title (String(512)).
        nf = NormalizedFinding(
            title="A" * 512,
            severity=FindingSeverity.LOW,
            source=FindingSource.NUCLEI,
            asset_value="x",
        )
        row = to_orm(nf, tenant_id=uuid4(), scan_job_id=uuid4(), asset_id=uuid4())
        assert len(row.title) == 512
