"""Tests for Phase 53 Plan 02 domain schema definitions.

Tests cover findings, reports, systems, audit, config, and tools schemas.
Uses TDD: tests written before implementation.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError


class TestFindingSchemas:
    """FindingResponse, FindingsListResponse, FacetsResponse."""

    def test_finding_response_minimal(self):
        """FindingResponse requires only run_id; all other fields optional."""
        from aila.api.schemas.findings import FindingResponse

        f = FindingResponse(run_id="run-abc")
        assert f.run_id == "run-abc"
        assert f.cve_id is None
        assert f.host is None
        assert f.kev is False
        assert f.score is None

    def test_finding_response_full(self):
        """FindingResponse accepts all fields."""
        from aila.api.schemas.findings import FindingResponse

        f = FindingResponse(
            id=1,
            run_id="run-abc",
            cve_id="CVE-2023-12345",
            package="openssl",
            version="1.1.1",
            host="web01",
            severity="CRITICAL",
            kev=True,
            score=0.95,
            status="open",
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        assert f.cve_id == "CVE-2023-12345"
        assert f.kev is True
        assert f.score == 0.95

    def test_findings_list_response_is_paginated(self):
        """FindingsListResponse is PaginatedResponse[FindingResponse]."""
        from aila.api.schemas.findings import FindingResponse, FindingsListResponse

        items = [FindingResponse(run_id="r1"), FindingResponse(run_id="r2")]
        paged = FindingsListResponse(total=2, page=1, page_size=50, pages=0, items=items)
        assert paged.total == 2
        assert paged.pages == 1  # ceil(2/50)
        assert len(paged.items) == 2

    def test_findings_list_response_pages_auto_computed(self):
        """pages is auto-computed for FindingsListResponse."""
        from aila.api.schemas.findings import FindingResponse, FindingsListResponse

        paged = FindingsListResponse(
            total=55,
            page=1,
            page_size=50,
            pages=0,
            items=[FindingResponse(run_id="r1")],
        )
        assert paged.pages == 2

    def test_facets_response_default_empty(self):
        """FacetsResponse defaults to empty facets dict."""
        from aila.api.schemas.findings import FacetsResponse

        f = FacetsResponse()
        assert f.facets == {}

    def test_facets_response_with_data(self):
        """FacetsResponse accepts facet groups."""
        from aila.api.schemas.findings import FacetsResponse

        f = FacetsResponse(facets={"severity": {"CRITICAL": 5, "HIGH": 12}, "kev": {"true": 2}})
        assert f.facets["severity"]["CRITICAL"] == 5
        assert f.facets["kev"]["true"] == 2

    def test_finding_response_extra_fields_forbidden(self):
        """APIModel extra='forbid' applies to FindingResponse."""
        from aila.api.schemas.findings import FindingResponse

        with pytest.raises(ValidationError):
            FindingResponse(run_id="r1", unknown="x")  # type: ignore[call-arg]


class TestReportSchemas:
    """ReportSummaryResponse, ReportCountResponse."""

    def test_report_summary_minimal(self):
        """ReportSummaryResponse requires run_id, query_text, module_id, status."""
        from aila.api.schemas.reports import ReportSummaryResponse

        r = ReportSummaryResponse(
            run_id="run-abc",
            query_text="show vulns",
            module_id="vulnerability",
            status="completed",
        )
        assert r.run_id == "run-abc"
        assert r.target_count == 0
        assert r.total_findings == 0
        assert r.kev_count == 0
        assert r.severity_breakdown == {}

    def test_report_summary_full(self):
        """ReportSummaryResponse accepts all fields."""
        from aila.api.schemas.reports import ReportSummaryResponse

        r = ReportSummaryResponse(
            run_id="run-abc",
            query_text="scan all",
            module_id="vulnerability",
            status="completed",
            target_count=5,
            total_findings=42,
            kev_count=3,
            severity_breakdown={"CRITICAL": 3, "HIGH": 10},
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            completed_at=datetime(2026, 1, 1, 0, 5, tzinfo=timezone.utc),
        )
        assert r.total_findings == 42
        assert r.severity_breakdown["CRITICAL"] == 3

    def test_report_count_response(self):
        """ReportCountResponse wraps module-specific counts dict."""
        from aila.api.schemas.reports import ReportCountResponse

        r = ReportCountResponse(
            run_id="run-abc",
            module_id="vulnerability",
            counts={"CRITICAL": 3, "kev_count": 1},
        )
        assert r.counts["CRITICAL"] == 3

    def test_report_count_defaults_empty(self):
        """ReportCountResponse.counts defaults to empty dict."""
        from aila.api.schemas.reports import ReportCountResponse

        r = ReportCountResponse(run_id="r1", module_id="mod")
        assert r.counts == {}


class TestSystemSchemas:
    """SystemResponse, SystemListResponse, SystemDetailResponse."""

    def test_system_response_minimal(self):
        """SystemResponse requires id, name, host, username."""
        from aila.api.schemas.systems import SystemResponse

        s = SystemResponse(id=1, name="web01", host="192.168.1.1", username="admin")
        assert s.id == 1
        assert s.port == 22
        assert s.distro == "unknown"
        assert s.description == ""

    def test_system_response_full(self):
        """SystemResponse accepts all fields."""
        from aila.api.schemas.systems import SystemResponse

        s = SystemResponse(
            id=1,
            name="web01",
            host="192.168.1.1",
            username="admin",
            port=2222,
            distro="ubuntu-22.04",
            description="Primary web server",
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            updated_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        )
        assert s.port == 2222
        assert s.distro == "ubuntu-22.04"

    def test_system_list_response_is_paginated(self):
        """SystemListResponse is PaginatedResponse[SystemResponse]."""
        from aila.api.schemas.systems import SystemListResponse, SystemResponse

        items = [SystemResponse(id=1, name="s1", host="h1", username="u1")]
        paged = SystemListResponse(total=1, page=1, page_size=50, pages=0, items=items)
        assert paged.total == 1
        assert paged.pages == 1

    def test_system_detail_response_extends_system(self):
        """SystemDetailResponse extends SystemResponse with module_summaries and scan_count."""
        from aila.api.schemas.systems import SystemDetailResponse

        d = SystemDetailResponse(
            id=1,
            name="web01",
            host="192.168.1.1",
            username="admin",
            module_summaries={"vulnerability": {"critical": 3}},
            scan_count=5,
        )
        assert d.scan_count == 5
        assert d.module_summaries["vulnerability"]["critical"] == 3

    def test_system_detail_defaults(self):
        """SystemDetailResponse defaults: empty summaries and scan_count=0."""
        from aila.api.schemas.systems import SystemDetailResponse

        d = SystemDetailResponse(id=1, name="x", host="h", username="u")
        assert d.module_summaries == {}
        assert d.scan_count == 0


class TestAuditSchemas:
    """AuditEventResponse, AuditListResponse."""

    def test_audit_event_minimal(self):
        """AuditEventResponse requires run_id, stage, action."""
        from aila.api.schemas.audit import AuditEventResponse

        e = AuditEventResponse(run_id="r1", stage="scan", action="scan.start")
        assert e.status == "completed"
        assert e.target == ""
        assert e.user_id == "system"
        assert e.details == {}

    def test_audit_event_full(self):
        """AuditEventResponse accepts all fields."""
        from aila.api.schemas.audit import AuditEventResponse

        e = AuditEventResponse(
            id=1,
            run_id="r1",
            stage="scan",
            action="ssh.execute",
            status="failed",
            target="web01",
            user_id="operator",
            details={"cmd": "dpkg -l", "exit_code": 1},
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        assert e.status == "failed"
        assert e.details["exit_code"] == 1

    def test_audit_list_response_is_paginated(self):
        """AuditListResponse is PaginatedResponse[AuditEventResponse]."""
        from aila.api.schemas.audit import AuditEventResponse, AuditListResponse

        items = [AuditEventResponse(run_id="r1", stage="s", action="a")]
        paged = AuditListResponse(total=1, page=1, page_size=50, pages=0, items=items)
        assert paged.pages == 1


class TestConfigSchemas:
    """ConfigEntryResponse, ConfigListResponse, ConfigUpdateRequest."""

    def test_config_entry_response(self):
        """ConfigEntryResponse requires namespace, key, value."""
        from aila.api.schemas.config import ConfigEntryResponse

        c = ConfigEntryResponse(namespace="vulnerability", key="max_cves", value="100")
        assert c.namespace == "vulnerability"
        assert c.value_type == "str"

    def test_config_entry_response_with_type(self):
        """ConfigEntryResponse accepts value_type and updated_at."""
        from aila.api.schemas.config import ConfigEntryResponse

        c = ConfigEntryResponse(
            namespace="vulnerability",
            key="score_threshold",
            value="0.7",
            value_type="float",
            updated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        assert c.value_type == "float"

    def test_config_list_response_is_paginated(self):
        """ConfigListResponse is PaginatedResponse[ConfigEntryResponse]."""
        from aila.api.schemas.config import ConfigEntryResponse, ConfigListResponse

        items = [ConfigEntryResponse(namespace="n", key="k", value="v")]
        paged = ConfigListResponse(total=1, page=1, page_size=50, pages=0, items=items)
        assert paged.total == 1

    def test_config_update_request(self):
        """ConfigUpdateRequest requires value; value_type defaults to 'str'."""
        from aila.api.schemas.config import ConfigUpdateRequest

        r = ConfigUpdateRequest(value="new_val")
        assert r.value == "new_val"
        assert r.value_type == "str"

    def test_config_update_request_with_type(self):
        """ConfigUpdateRequest accepts explicit value_type."""
        from aila.api.schemas.config import ConfigUpdateRequest

        r = ConfigUpdateRequest(value="42", value_type="int")
        assert r.value_type == "int"

    def test_config_update_request_extra_forbidden(self):
        """APIModel extra='forbid' applies to ConfigUpdateRequest."""
        from aila.api.schemas.config import ConfigUpdateRequest

        with pytest.raises(ValidationError):
            ConfigUpdateRequest(value="x", unknown="y")  # type: ignore[call-arg]


class TestToolSchemas:
    """ToolSummaryResponse, ToolDetailResponse, ToolInvokeRequest, ToolInvokeResponse."""

    def test_tool_summary_response(self):
        """ToolSummaryResponse requires tool_key, name, description, module_id."""
        from aila.api.schemas.tools import ToolSummaryResponse

        t = ToolSummaryResponse(
            tool_key="vuln.query_cves",
            name="Query CVEs",
            description="Returns CVE findings",
            module_id="vulnerability",
        )
        assert t.tool_key == "vuln.query_cves"
        assert t.module_id == "vulnerability"

    def test_tool_detail_response_extends_summary(self):
        """ToolDetailResponse extends ToolSummaryResponse with inputs and output_type."""
        from aila.api.schemas.tools import ToolDetailResponse

        t = ToolDetailResponse(
            tool_key="vuln.query_cves",
            name="Query CVEs",
            description="Returns CVE findings",
            module_id="vulnerability",
            inputs={"host": {"type": "string"}, "severity": {"type": "string"}},
            output_type="list[dict]",
        )
        assert t.inputs["host"]["type"] == "string"
        assert t.output_type == "list[dict]"

    def test_tool_detail_defaults(self):
        """ToolDetailResponse defaults: empty inputs, output_type='string'."""
        from aila.api.schemas.tools import ToolDetailResponse

        t = ToolDetailResponse(
            tool_key="k",
            name="n",
            description="d",
            module_id="m",
        )
        assert t.inputs == {}
        assert t.output_type == "string"

    def test_tool_invoke_request_empty_kwargs(self):
        """ToolInvokeRequest defaults to empty kwargs."""
        from aila.api.schemas.tools import ToolInvokeRequest

        r = ToolInvokeRequest()
        assert r.kwargs == {}

    def test_tool_invoke_request_with_kwargs(self):
        """ToolInvokeRequest accepts kwargs dict."""
        from aila.api.schemas.tools import ToolInvokeRequest

        r = ToolInvokeRequest(kwargs={"host": "web01", "severity": "CRITICAL"})
        assert r.kwargs["host"] == "web01"

    def test_tool_invoke_response_success(self):
        """ToolInvokeResponse with result and no error."""
        from aila.api.schemas.tools import ToolInvokeResponse

        r = ToolInvokeResponse(tool_key="vuln.query_cves", result=[{"cve_id": "CVE-2023-12345"}])
        assert r.tool_key == "vuln.query_cves"
        assert r.error is None

    def test_tool_invoke_response_error(self):
        """ToolInvokeResponse with error and null result."""
        from aila.api.schemas.tools import ToolInvokeResponse

        r = ToolInvokeResponse(tool_key="vuln.query_cves", result=None, error="tool not found")
        assert r.result is None
        assert r.error == "tool not found"

    def test_tool_invoke_response_extra_forbidden(self):
        """APIModel extra='forbid' applies to ToolInvokeResponse."""
        from aila.api.schemas.tools import ToolInvokeResponse

        with pytest.raises(ValidationError):
            ToolInvokeResponse(tool_key="k", unknown="x")  # type: ignore[call-arg]


class TestSchemasInitExports:
    """All schemas importable via the schemas package."""

    def test_schemas_package_importable(self):
        """aila.api.schemas package itself imports without error."""
        import aila.api.schemas  # noqa: F401

    def test_all_domain_modules_importable(self):
        """All six domain schema modules can be imported."""
        from aila.api.schemas import findings, reports, systems, audit, config, tools  # noqa: F401
