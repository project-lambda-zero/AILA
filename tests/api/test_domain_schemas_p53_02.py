"""Tests for Phase 53 Plan 02 domain schema definitions.

Tests cover findings, reports, systems, audit, config, and tools schemas.
Uses TDD: tests written before implementation.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError


class TestFindingSchemas:
    """FindingResponse, FindingsListResponse, FacetsResponse."""


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


    def test_finding_response_extra_fields_forbidden(self):
        """APIModel extra='forbid' applies to FindingResponse."""
        from aila.api.schemas.findings import FindingResponse

        with pytest.raises(ValidationError):
            FindingResponse(run_id="r1", unknown="x")  # type: ignore[call-arg]


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


    def test_system_list_response_is_paginated(self):
        """SystemListResponse is PaginatedResponse[SystemEnrichedResponse].

        Source of truth: src/aila/api/schemas/systems.py:75 aliases
        SystemListResponse to PaginatedResponse[SystemEnrichedResponse] so the
        fleet-list endpoint can surface connectivity/tag/scan enrichment fields
        without a second request per system.
        """
        from aila.api.schemas.systems import SystemEnrichedResponse, SystemListResponse

        items = [SystemEnrichedResponse(id=1, name="s1", host="h1", username="u1")]
        paged = SystemListResponse(total=1, page=1, page_size=50, pages=0, items=items)
        assert paged.total == 1
        assert paged.pages == 1


class TestAuditSchemas:
    """AuditEventResponse, AuditListResponse."""


    def test_audit_list_response_is_paginated(self):
        """AuditListResponse is PaginatedResponse[AuditEventResponse]."""
        from aila.api.schemas.audit import AuditEventResponse, AuditListResponse

        items = [AuditEventResponse(run_id="r1", stage="s", action="a")]
        paged = AuditListResponse(total=1, page=1, page_size=50, pages=0, items=items)
        assert paged.pages == 1


class TestConfigSchemas:
    """ConfigEntryResponse, ConfigListResponse, ConfigUpdateRequest."""


    def test_config_update_request(self):
        """ConfigUpdateRequest requires value; value_type defaults to 'str'."""
        from aila.api.schemas.config import ConfigUpdateRequest

        r = ConfigUpdateRequest(value="new_val")
        assert r.value == "new_val"
        assert r.value_type == "str"


    def test_config_update_request_extra_forbidden(self):
        """APIModel extra='forbid' applies to ConfigUpdateRequest."""
        from aila.api.schemas.config import ConfigUpdateRequest

        with pytest.raises(ValidationError):
            ConfigUpdateRequest(value="x", unknown="y")  # type: ignore[call-arg]


class TestToolSchemas:
    """ToolSummaryResponse, ToolDetailResponse, ToolInvokeRequest, ToolInvokeResponse."""


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


    def test_tool_invoke_response_extra_forbidden(self):
        """APIModel extra='forbid' applies to ToolInvokeResponse."""
        from aila.api.schemas.tools import ToolInvokeResponse

        with pytest.raises(ValidationError):
            ToolInvokeResponse(tool_key="k", unknown="x")  # type: ignore[call-arg]


