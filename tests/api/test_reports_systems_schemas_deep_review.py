"""Deep review tests for schemas/reports.py (FILE-17) and schemas/systems.py (FILE-18).

Proves ReportSummaryResponse includes all dashboard fields without silent
omissions, ReportCountResponse reflects module delegation (counts dict is
module-specific, not hardcoded), SystemCreateRequest/SystemUpdateRequest enforce
required fields and reject invalid input, and all schemas inherit extra='forbid'.

Complementary to test_auth_findings_schemas_deep_review.py -- focuses on
reports and systems.
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from aila.api.schemas import reports as reports_module
from aila.api.schemas import systems as systems_module
from aila.api.schemas.reports import ReportCountResponse, ReportSummaryResponse
from aila.api.schemas.systems import (
    SystemCreateRequest,
    SystemDetailResponse,
    SystemListResponse,
    SystemResponse,
    SystemUpdateRequest,
)

# ---------------------------------------------------------------------------
# ReportSummaryResponse -- field completeness (FILE-17)
# ---------------------------------------------------------------------------


class TestReportSummaryResponseFields:
    """ReportSummaryResponse includes all fields needed for the dashboard."""

    EXPECTED_FIELDS = {
        "run_id", "query_text", "module_id", "status",
        "target_count", "total_findings", "kev_count",
        "severity_breakdown", "created_at", "completed_at",
    }

    def test_all_dashboard_fields_present(self) -> None:
        """No silent omissions -- every dashboard field exists on the schema."""
        actual = set(ReportSummaryResponse.model_fields.keys())
        assert actual == self.EXPECTED_FIELDS

    def test_required_fields_enforced(self) -> None:
        """run_id, query_text, module_id, and status are mandatory."""
        # All four required -- missing any one fails
        with pytest.raises(ValidationError):
            ReportSummaryResponse()  # type: ignore[call-arg]

        with pytest.raises(ValidationError):
            ReportSummaryResponse(query_text="q", module_id="m", status="running")  # type: ignore[call-arg]

        with pytest.raises(ValidationError):
            ReportSummaryResponse(run_id="r", module_id="m", status="running")  # type: ignore[call-arg]

        with pytest.raises(ValidationError):
            ReportSummaryResponse(run_id="r", query_text="q", status="running")  # type: ignore[call-arg]

        with pytest.raises(ValidationError):
            ReportSummaryResponse(run_id="r", query_text="q", module_id="m")  # type: ignore[call-arg]

    def test_defaults_correct(self) -> None:
        """Optional fields default to zero/empty, not None."""
        r = ReportSummaryResponse(
            run_id="run-1", query_text="scan all", module_id="vulnerability", status="completed",
        )
        assert r.target_count == 0
        assert r.total_findings == 0
        assert r.kev_count == 0
        assert r.severity_breakdown == {}
        assert r.created_at is None
        assert r.completed_at is None

    def test_full_construction(self) -> None:
        """All fields populated from a real vulnerability scan response."""
        created = datetime(2026, 3, 15, 10, 0, 0, tzinfo=UTC)
        completed = datetime(2026, 3, 15, 10, 5, 30, tzinfo=UTC)
        r = ReportSummaryResponse(
            run_id="run-abc-123",
            query_text="scan web servers for CVEs",
            module_id="vulnerability",
            status="completed",
            target_count=3,
            total_findings=42,
            kev_count=5,
            severity_breakdown={"CRITICAL": 2, "HIGH": 15, "MEDIUM": 20, "LOW": 5},
            created_at=created,
            completed_at=completed,
        )
        assert r.run_id == "run-abc-123"
        assert r.query_text == "scan web servers for CVEs"
        assert r.module_id == "vulnerability"
        assert r.status == "completed"
        assert r.target_count == 3
        assert r.total_findings == 42
        assert r.kev_count == 5
        assert r.severity_breakdown["CRITICAL"] == 2
        assert r.created_at == created
        assert r.completed_at == completed

    def test_construction_from_workflow_run_record_shape(self) -> None:
        """Schema accepts data shaped like WorkflowRunRecord columns.

        The systems router constructs ReportSummaryResponse from
        WorkflowRunRecord without target_count/total_findings/kev_count/
        severity_breakdown -- those should default correctly.
        """
        r = ReportSummaryResponse(
            run_id="wfr-id-001",
            query_text="list all vulnerabilities",
            module_id="vulnerability",
            status="running",
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
            completed_at=None,
        )
        assert r.target_count == 0
        assert r.total_findings == 0
        assert r.kev_count == 0
        assert r.severity_breakdown == {}


# ---------------------------------------------------------------------------
# ReportSummaryResponse -- extra="forbid" and serialization
# ---------------------------------------------------------------------------


class TestReportSummaryExtraForbid:
    """ReportSummaryResponse rejects unknown fields (inherited from APIModel)."""

    def test_rejects_extra_field(self) -> None:
        """Adding an unknown field raises ValidationError."""
        with pytest.raises(ValidationError, match="extra_forbidden"):
            ReportSummaryResponse(
                run_id="r", query_text="q", module_id="m", status="s",
                bogus="unexpected",  # type: ignore[call-arg]
            )

    def test_datetime_iso_serialization(self) -> None:
        """Datetime fields serialize to ISO 8601."""
        dt = datetime(2026, 7, 4, 16, 45, 0, tzinfo=UTC)
        r = ReportSummaryResponse(
            run_id="r", query_text="q", module_id="m", status="completed",
            created_at=dt, completed_at=dt,
        )
        dumped = r.model_dump(mode="json")
        assert dumped["created_at"] == "2026-07-04T16:45:00Z"
        assert dumped["completed_at"] == "2026-07-04T16:45:00Z"

    def test_datetime_null_serialization(self) -> None:
        """Datetime fields serialize to null when not set."""
        r = ReportSummaryResponse(
            run_id="r", query_text="q", module_id="m", status="running",
        )
        dumped = r.model_dump(mode="json")
        assert dumped["created_at"] is None
        assert dumped["completed_at"] is None

    def test_severity_breakdown_serialization(self) -> None:
        """severity_breakdown serializes as a plain dict."""
        r = ReportSummaryResponse(
            run_id="r", query_text="q", module_id="m", status="completed",
            severity_breakdown={"CRITICAL": 1, "HIGH": 10},
        )
        dumped = r.model_dump(mode="json")
        assert dumped["severity_breakdown"] == {"CRITICAL": 1, "HIGH": 10}


# ---------------------------------------------------------------------------
# ReportCountResponse -- module delegation (FILE-17)
# ---------------------------------------------------------------------------


class TestReportCountResponseModuleDelegation:
    """ReportCountResponse reflects module delegation -- shape is module-specific."""

    def test_required_fields(self) -> None:
        """run_id and module_id are required."""
        with pytest.raises(ValidationError):
            ReportCountResponse()  # type: ignore[call-arg]

        with pytest.raises(ValidationError):
            ReportCountResponse(module_id="m")  # type: ignore[call-arg]

        with pytest.raises(ValidationError):
            ReportCountResponse(run_id="r")  # type: ignore[call-arg]

    def test_counts_defaults_to_empty_dict(self) -> None:
        """counts field defaults to empty dict when not provided."""
        r = ReportCountResponse(run_id="r", module_id="vulnerability")
        assert r.counts == {}

    def test_vulnerability_module_shape(self) -> None:
        """Vulnerability module returns severity breakdown + kev_count in counts."""
        counts = {
            "total": 42,
            "kev_count": 0,
            "critical": 2,
            "high": 15,
            "medium": 20,
            "low": 5,
        }
        r = ReportCountResponse(run_id="run-1", module_id="vulnerability", counts=counts)
        assert r.counts["critical"] == 2
        assert r.counts["kev_count"] == 0
        assert r.counts["total"] == 42

    def test_arbitrary_module_shape(self) -> None:
        """Future modules can return any shape in counts."""
        counts = {
            "compliance_passed": 95,
            "compliance_failed": 5,
            "categories": {"network": 3, "access": 2},
        }
        r = ReportCountResponse(run_id="run-2", module_id="compliance", counts=counts)
        assert r.counts["compliance_passed"] == 95
        assert r.counts["categories"]["network"] == 3

    def test_rejects_extra_field(self) -> None:
        """ReportCountResponse rejects unknown fields."""
        with pytest.raises(ValidationError, match="extra_forbidden"):
            ReportCountResponse(
                run_id="r", module_id="m",
                bogus="unexpected",  # type: ignore[call-arg]
            )


# ---------------------------------------------------------------------------
# SystemCreateRequest -- validation (FILE-18)
# ---------------------------------------------------------------------------


class TestSystemCreateRequestValidation:
    """SystemCreateRequest enforces required fields and rejects invalid input."""

    def test_required_fields(self) -> None:
        """name and host are required (no defaults)."""
        with pytest.raises(ValidationError):
            SystemCreateRequest()  # type: ignore[call-arg]

        with pytest.raises(ValidationError):
            SystemCreateRequest(host="10.0.0.1")  # type: ignore[call-arg]

        with pytest.raises(ValidationError):
            SystemCreateRequest(name="web-1")  # type: ignore[call-arg]

    def test_defaults_correct(self) -> None:
        """Default values: username=root, port=22, distro=unknown, description=empty."""
        r = SystemCreateRequest(name="web-1", host="10.0.0.1")
        assert r.username == "root"
        assert r.port == 22
        assert r.distro == "unknown"
        assert r.description == ""

    def test_full_construction(self) -> None:
        """All fields can be populated."""
        r = SystemCreateRequest(
            name="db-server",
            host="192.168.1.100",
            username="admin",
            port=2222,
            distro="ubuntu",
            description="Production database",
        )
        assert r.name == "db-server"
        assert r.host == "192.168.1.100"
        assert r.username == "admin"
        assert r.port == 2222
        assert r.distro == "ubuntu"
        assert r.description == "Production database"

    def test_name_empty_rejected(self) -> None:
        """Empty name violates min_length=1."""
        with pytest.raises(ValidationError):
            SystemCreateRequest(name="", host="10.0.0.1")

    def test_name_too_long_rejected(self) -> None:
        """Name exceeding 128 chars violates max_length=128."""
        with pytest.raises(ValidationError):
            SystemCreateRequest(name="x" * 129, host="10.0.0.1")

    def test_name_at_max_length_accepted(self) -> None:
        """Exactly 128 chars is valid."""
        r = SystemCreateRequest(name="x" * 128, host="10.0.0.1")
        assert len(r.name) == 128

    def test_host_empty_rejected(self) -> None:
        """Empty host violates min_length=1."""
        with pytest.raises(ValidationError):
            SystemCreateRequest(name="web-1", host="")

    def test_port_zero_rejected(self) -> None:
        """Port 0 violates ge=1."""
        with pytest.raises(ValidationError):
            SystemCreateRequest(name="web-1", host="10.0.0.1", port=0)

    def test_port_negative_rejected(self) -> None:
        """Negative port rejected."""
        with pytest.raises(ValidationError):
            SystemCreateRequest(name="web-1", host="10.0.0.1", port=-1)

    def test_port_above_65535_rejected(self) -> None:
        """Port above 65535 violates le=65535."""
        with pytest.raises(ValidationError):
            SystemCreateRequest(name="web-1", host="10.0.0.1", port=65536)

    def test_port_boundary_values(self) -> None:
        """Port 1 and 65535 are both valid."""
        r1 = SystemCreateRequest(name="s1", host="h", port=1)
        assert r1.port == 1
        r2 = SystemCreateRequest(name="s2", host="h", port=65535)
        assert r2.port == 65535

    def test_rejects_extra_field(self) -> None:
        """SystemCreateRequest rejects unknown fields."""
        with pytest.raises(ValidationError, match="extra_forbidden"):
            SystemCreateRequest(
                name="web-1", host="10.0.0.1",
                bogus="unexpected",  # type: ignore[call-arg]
            )


# ---------------------------------------------------------------------------
# SystemUpdateRequest -- validation (FILE-18)
# ---------------------------------------------------------------------------


class TestSystemUpdateRequestValidation:
    """SystemUpdateRequest: all fields optional, same constraints when provided."""

    def test_empty_body_valid(self) -> None:
        """Empty body (all None) is valid for partial update."""
        r = SystemUpdateRequest()
        assert r.name is None
        assert r.host is None
        assert r.username is None
        assert r.port is None
        assert r.distro is None
        assert r.description is None

    def test_partial_update(self) -> None:
        """Only specified fields are set; others remain None."""
        r = SystemUpdateRequest(name="new-name", port=2222)
        assert r.name == "new-name"
        assert r.port == 2222
        assert r.host is None
        assert r.username is None

    def test_name_empty_rejected(self) -> None:
        """Empty name violates min_length=1 when provided."""
        with pytest.raises(ValidationError):
            SystemUpdateRequest(name="")

    def test_name_too_long_rejected(self) -> None:
        """Name exceeding 128 chars rejected when provided."""
        with pytest.raises(ValidationError):
            SystemUpdateRequest(name="x" * 129)

    def test_host_empty_rejected(self) -> None:
        """Empty host violates min_length=1 when provided."""
        with pytest.raises(ValidationError):
            SystemUpdateRequest(host="")

    def test_port_zero_rejected(self) -> None:
        """Port 0 rejected when provided."""
        with pytest.raises(ValidationError):
            SystemUpdateRequest(port=0)

    def test_port_above_65535_rejected(self) -> None:
        """Port above 65535 rejected when provided."""
        with pytest.raises(ValidationError):
            SystemUpdateRequest(port=65536)

    def test_port_boundary_values(self) -> None:
        """Port 1 and 65535 valid when provided."""
        r1 = SystemUpdateRequest(port=1)
        assert r1.port == 1
        r2 = SystemUpdateRequest(port=65535)
        assert r2.port == 65535

    def test_model_dump_exclude_none(self) -> None:
        """model_dump(exclude_none=True) returns only set fields -- used by router."""
        r = SystemUpdateRequest(name="new-name", port=8022)
        dumped = r.model_dump(exclude_none=True)
        assert dumped == {"name": "new-name", "port": 8022}

    def test_all_none_dump_empty(self) -> None:
        """All-None body produces empty dict when exclude_none=True."""
        r = SystemUpdateRequest()
        dumped = r.model_dump(exclude_none=True)
        assert dumped == {}

    def test_rejects_extra_field(self) -> None:
        """SystemUpdateRequest rejects unknown fields."""
        with pytest.raises(ValidationError, match="extra_forbidden"):
            SystemUpdateRequest(bogus="unexpected")  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# SystemResponse -- field mapping to ManagedSystemRecord
# ---------------------------------------------------------------------------


class TestSystemResponseFieldMapping:
    """SystemResponse mirrors the ManagedSystemRecord shape."""

    EXPECTED_FIELDS = {
        "id", "name", "host", "username", "port",
        "distro", "description", "created_at", "updated_at",
    }

    def test_all_fields_present(self) -> None:
        """SystemResponse declares the expected fields for the API surface."""
        actual = set(SystemResponse.model_fields.keys())
        assert actual == self.EXPECTED_FIELDS

    def test_defaults(self) -> None:
        """Default values match ManagedSystemRecord defaults."""
        r = SystemResponse(id=1, name="web-1", host="10.0.0.1", username="root")
        assert r.port == 22
        assert r.distro == "unknown"
        assert r.description == ""
        assert r.created_at is None
        assert r.updated_at is None

    def test_full_construction(self) -> None:
        """All fields can be populated."""
        created = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
        updated = datetime(2026, 3, 20, 8, 30, 0, tzinfo=UTC)
        r = SystemResponse(
            id=42,
            name="db-primary",
            host="192.168.1.100",
            username="admin",
            port=2222,
            distro="ubuntu",
            description="Primary database",
            created_at=created,
            updated_at=updated,
        )
        assert r.id == 42
        assert r.name == "db-primary"
        assert r.port == 2222
        assert r.created_at == created
        assert r.updated_at == updated

    def test_rejects_extra_field(self) -> None:
        """SystemResponse rejects unknown fields."""
        with pytest.raises(ValidationError, match="extra_forbidden"):
            SystemResponse(
                id=1, name="s", host="h", username="u",
                bogus="unexpected",  # type: ignore[call-arg]
            )

    def test_datetime_serialization(self) -> None:
        """Datetime fields serialize to ISO 8601."""
        dt = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
        r = SystemResponse(
            id=1, name="s", host="h", username="u",
            created_at=dt, updated_at=dt,
        )
        dumped = r.model_dump(mode="json")
        assert dumped["created_at"] == "2026-06-01T12:00:00Z"
        assert dumped["updated_at"] == "2026-06-01T12:00:00Z"


# ---------------------------------------------------------------------------
# SystemDetailResponse -- extends SystemResponse
# ---------------------------------------------------------------------------


class TestSystemDetailResponseExtension:
    """SystemDetailResponse extends SystemResponse with module_summaries and scan_count."""

    def test_extends_system_response(self) -> None:
        """SystemDetailResponse has all SystemResponse fields plus extras."""
        base_fields = set(SystemResponse.model_fields.keys())
        detail_fields = set(SystemDetailResponse.model_fields.keys())
        assert base_fields.issubset(detail_fields)
        assert "module_summaries" in detail_fields
        assert "scan_count" in detail_fields

    def test_defaults(self) -> None:
        """module_summaries defaults to empty dict, scan_count to 0."""
        r = SystemDetailResponse(id=1, name="s", host="h", username="u")
        assert r.module_summaries == {}
        assert r.scan_count == 0

    def test_module_summaries_flexible_shape(self) -> None:
        """module_summaries accepts arbitrary module-contributed data."""
        summaries = {
            "vulnerability": {
                "total_findings": 42,
                "critical": 5,
                "high": 15,
            },
            "compliance": {
                "score": 95,
                "passed": True,
            },
        }
        r = SystemDetailResponse(
            id=1, name="s", host="h", username="u",
            module_summaries=summaries,
            scan_count=10,
        )
        assert r.module_summaries["vulnerability"]["total_findings"] == 42
        assert r.module_summaries["compliance"]["score"] == 95
        assert r.scan_count == 10

    def test_rejects_extra_field(self) -> None:
        """SystemDetailResponse rejects unknown fields."""
        with pytest.raises(ValidationError, match="extra_forbidden"):
            SystemDetailResponse(
                id=1, name="s", host="h", username="u",
                bogus="unexpected",  # type: ignore[call-arg]
            )


# ---------------------------------------------------------------------------
# SystemListResponse -- PaginatedResponse[SystemResponse]
# ---------------------------------------------------------------------------


class TestSystemListResponseAlias:
    """SystemListResponse is PaginatedResponse[SystemResponse]."""

    def test_wraps_system_response(self) -> None:
        """SystemListResponse paginates SystemResponse items."""
        item = SystemResponse(id=1, name="web-1", host="10.0.0.1", username="root")
        r = SystemListResponse(
            total=1, page=1, page_size=50, pages=1, items=[item],
        )
        assert len(r.items) == 1
        assert r.items[0].name == "web-1"
        assert r.total == 1

    def test_empty_response(self) -> None:
        """Empty system list is valid."""
        r = SystemListResponse(
            total=0, page=1, page_size=50, pages=0, items=[],
        )
        assert r.total == 0
        assert r.items == []
        assert r.pages == 0

    def test_pages_auto_computed(self) -> None:
        """Pages auto-computed when pages=0 and total>0."""
        r = SystemListResponse(
            total=51, page=1, page_size=50, pages=0,
            items=[SystemResponse(id=1, name="s", host="h", username="u")],
        )
        assert r.pages == 2


# ---------------------------------------------------------------------------
# Module __all__ exports
# ---------------------------------------------------------------------------


class TestReportsExports:
    """reports module __all__ exports match defined classes."""

    def test_all_exports(self) -> None:
        """reports.__all__ contains exactly the defined schema classes."""
        expected = {"ReportCountResponse", "ReportSummaryResponse"}
        assert set(reports_module.__all__) == expected

    def test_no_extra_exports(self) -> None:
        """No public classes exist that are missing from __all__."""
        from pydantic import BaseModel

        public_classes = {
            name for name, obj in vars(reports_module).items()
            if isinstance(obj, type) and issubclass(obj, BaseModel)
            and not name.startswith("_") and obj.__module__ == reports_module.__name__
        }
        assert public_classes == set(reports_module.__all__)


class TestSystemsExports:
    """systems module __all__ exports match defined classes."""

    def test_all_exports(self) -> None:
        """systems.__all__ contains exactly the expected names."""
        expected = {
            "SystemCreateRequest",
            "SystemDetailResponse",
            "SystemListResponse",
            "SystemResponse",
            "SystemUpdateRequest",
        }
        assert set(systems_module.__all__) == expected

    def test_no_extra_public_classes(self) -> None:
        """No public classes exist that are missing from __all__."""
        from pydantic import BaseModel

        public_classes = {
            name for name, obj in vars(systems_module).items()
            if isinstance(obj, type) and issubclass(obj, BaseModel)
            and not name.startswith("_") and obj.__module__ == systems_module.__name__
        }
        # SystemListResponse is a type alias, not a class defined in this module
        # so it won't appear as a type with __module__ == systems_module.__name__
        # We check that all actual classes are exported
        for cls_name in public_classes:
            assert cls_name in systems_module.__all__, f"{cls_name} missing from __all__"
