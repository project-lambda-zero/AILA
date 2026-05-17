"""Schema-level unit tests for sessions, tasks, and tools schemas -- Phase 79 FILE-22/23/24.

Tests validate:
- SessionMessageResponse.role Literal["user","assistant"] constraint
- SessionCreateRequest/SessionMessageRequest field defaults and validation
- TaskResponse.status Literal 7-value constraint
- TaskSubmitResponse.status Literal["submitted"] default
- ScanSubmissionRequest field validation and AnalyzePayload alignment
- ToolDetailResponse.inputs JSON schema round-trip
- extra="forbid" inherited from APIModel on all schemas
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from aila.api.schemas.sessions import (
    SessionCreateRequest,
    SessionMessageRequest,
    SessionMessageResponse,
    SessionMessagesResponse,
    SessionResponse,
)
from aila.api.schemas.tasks import (
    ScanSubmissionRequest,
    TaskCreateRequest,
    TaskListResponse,
    TaskResponse,
    TaskSubmitResponse,
)
from aila.api.schemas.tools import (
    ToolDetailResponse,
    ToolInvokeRequest,
    ToolInvokeResponse,
    ToolSummaryResponse,
)

NOW = datetime.now(UTC)


# ---------------------------------------------------------------------------
# SessionMessageResponse -- role Literal (FILE-22)
# ---------------------------------------------------------------------------


class TestSessionMessageResponseRole:
    """SessionMessageResponse.role must be Literal['user','assistant']."""

    @pytest.mark.parametrize("role", ["user", "assistant"])
    def test_valid_roles_accepted(self, role: str) -> None:
        """Both valid message roles are accepted."""
        msg = SessionMessageResponse(
            message_id="m1",
            role=role,
            content="hello",
            created_at=NOW,
        )
        assert msg.role == role

    @pytest.mark.parametrize("bad_role", ["system", "bot", "admin", "tool", ""])
    def test_invalid_roles_rejected(self, bad_role: str) -> None:
        """Invalid role values are rejected with ValidationError."""
        with pytest.raises(ValidationError):
            SessionMessageResponse(
                message_id="m1",
                role=bad_role,
                content="hello",
                created_at=NOW,
            )

    def test_run_id_nullable(self) -> None:
        """run_id defaults to None and accepts a string."""
        msg_none = SessionMessageResponse(
            message_id="m1",
            role="user",
            content="hello",
            created_at=NOW,
        )
        assert msg_none.run_id is None

        msg_with = SessionMessageResponse(
            message_id="m2",
            role="assistant",
            content="result",
            run_id="run-abc",
            created_at=NOW,
        )
        assert msg_with.run_id == "run-abc"

    def test_extra_fields_rejected(self) -> None:
        """extra='forbid' inherited from APIModel rejects unknown fields."""
        with pytest.raises(ValidationError, match="extra_forbidden"):
            SessionMessageResponse(
                message_id="m1",
                role="user",
                content="hello",
                created_at=NOW,
                unknown_field="x",
            )


# ---------------------------------------------------------------------------
# SessionCreateRequest / SessionMessageRequest (FILE-22)
# ---------------------------------------------------------------------------


class TestSessionCreateRequest:
    """SessionCreateRequest field validation."""

    def test_default_title(self) -> None:
        """Title defaults to 'Untitled' when omitted."""
        req = SessionCreateRequest()
        assert req.title == "Untitled"

    def test_custom_title(self) -> None:
        """Custom title is preserved."""
        req = SessionCreateRequest(title="My Session")
        assert req.title == "My Session"

    def test_extra_fields_rejected(self) -> None:
        """extra='forbid' rejects unknown fields."""
        with pytest.raises(ValidationError, match="extra_forbidden"):
            SessionCreateRequest(title="ok", secret="nope")


class TestSessionMessageRequest:
    """SessionMessageRequest field validation."""

    def test_valid_content(self) -> None:
        """Non-empty content is accepted."""
        req = SessionMessageRequest(content="hello")
        assert req.content == "hello"

    def test_empty_content_rejected(self) -> None:
        """Empty content string is rejected (min_length=1)."""
        with pytest.raises(ValidationError, match="String should have at least 1 character"):
            SessionMessageRequest(content="")

    def test_missing_content_rejected(self) -> None:
        """Missing content field is rejected."""
        with pytest.raises(ValidationError):
            SessionMessageRequest()


class TestSessionResponse:
    """SessionResponse required fields."""

    def test_valid_session_response(self) -> None:
        """All required fields accepted."""
        resp = SessionResponse(
            session_id="s1",
            user_id="u1",
            title="Test",
            created_at=NOW,
        )
        assert resp.session_id == "s1"
        assert resp.user_id == "u1"

    def test_missing_field_rejected(self) -> None:
        """Missing required field raises ValidationError."""
        with pytest.raises(ValidationError):
            SessionResponse(session_id="s1", user_id="u1", title="Test")


class TestSessionMessagesResponse:
    """SessionMessagesResponse is PaginatedResponse[SessionMessageResponse]."""

    def test_paginated_wrapper(self) -> None:
        """Items are properly paginated."""
        items = [
            SessionMessageResponse(
                message_id="m1", role="user", content="hi", created_at=NOW
            ),
        ]
        resp = SessionMessagesResponse(
            total=1, page=1, page_size=50, pages=1, items=items
        )
        assert len(resp.items) == 1
        assert resp.items[0].role == "user"


# ---------------------------------------------------------------------------
# TaskResponse -- status Literal (FILE-23)
# ---------------------------------------------------------------------------


TASK_KWARGS = {
    "task_id": "t1",
    "track": "vulnerability",
    "user_id": "u1",
    "group_id": "admin",
    "fn_path": "aila.platform.runtime.handle",
    "fn_module": "vulnerability",
    "created_at": NOW,
    "has_checkpoint": False,
}


class TestTaskResponseStatus:
    """TaskResponse.status Literal 7-value constraint."""

    @pytest.mark.parametrize(
        "status",
        ["queued", "waiting", "running", "paused", "done", "failed", "cancelled"],
    )
    def test_valid_statuses_accepted(self, status: str) -> None:
        """All 7 valid lifecycle statuses are accepted."""
        resp = TaskResponse(status=status, **TASK_KWARGS)
        assert resp.status == status

    @pytest.mark.parametrize("bad_status", ["pending", "started", "complete", "error", ""])
    def test_invalid_statuses_rejected(self, bad_status: str) -> None:
        """Invalid status values are rejected with ValidationError."""
        with pytest.raises(ValidationError):
            TaskResponse(status=bad_status, **TASK_KWARGS)

    def test_optional_fields_nullable(self) -> None:
        """started_at, completed_at, heartbeat_at, error, result_path default to None."""
        resp = TaskResponse(status="queued", **TASK_KWARGS)
        assert resp.started_at is None
        assert resp.completed_at is None
        assert resp.heartbeat_at is None
        assert resp.error is None
        assert resp.result_path is None

    def test_extra_fields_rejected(self) -> None:
        """extra='forbid' rejects unknown fields."""
        with pytest.raises(ValidationError, match="extra_forbidden"):
            TaskResponse(status="queued", bogus="x", **TASK_KWARGS)


# ---------------------------------------------------------------------------
# TaskSubmitResponse (FILE-23)
# ---------------------------------------------------------------------------


class TestTaskSubmitResponse:
    """TaskSubmitResponse.status defaults to 'submitted'."""

    def test_default_status(self) -> None:
        """Status defaults to 'submitted' when omitted."""
        resp = TaskSubmitResponse(run_id="run-abc")
        assert resp.status == "submitted"

    def test_only_submitted_accepted(self) -> None:
        """Only 'submitted' is accepted by Literal constraint."""
        with pytest.raises(ValidationError):
            TaskSubmitResponse(run_id="run-abc", status="pending")

    def test_extra_fields_rejected(self) -> None:
        """extra='forbid' rejects unknown fields."""
        with pytest.raises(ValidationError, match="extra_forbidden"):
            TaskSubmitResponse(run_id="run-abc", extra="nope")


# ---------------------------------------------------------------------------
# ScanSubmissionRequest -- AnalyzePayload alignment (FILE-23)
# ---------------------------------------------------------------------------


class TestScanSubmissionRequest:
    """ScanSubmissionRequest matches AnalyzePayload contract."""

    def test_valid_request(self) -> None:
        """Full request with query_text and targets accepted."""
        req = ScanSubmissionRequest(
            query_text="scan web01 for vulnerabilities",
            targets=["web01", "db01"],
        )
        assert req.query_text == "scan web01 for vulnerabilities"
        assert req.targets == ["web01", "db01"]

    def test_targets_defaults_to_empty_list(self) -> None:
        """targets defaults to empty list (maps to AnalyzePayload.target_names=[] -> full fleet)."""
        req = ScanSubmissionRequest(query_text="scan all")
        assert req.targets == []

    def test_empty_query_text_rejected(self) -> None:
        """Empty query_text is rejected (min_length=1)."""
        with pytest.raises(ValidationError, match="String should have at least 1 character"):
            ScanSubmissionRequest(query_text="")

    def test_missing_query_text_rejected(self) -> None:
        """Missing query_text field is rejected."""
        with pytest.raises(ValidationError):
            ScanSubmissionRequest(targets=["web01"])

    def test_extra_fields_rejected(self) -> None:
        """extra='forbid' rejects unknown fields."""
        with pytest.raises(ValidationError, match="extra_forbidden"):
            ScanSubmissionRequest(query_text="scan", module_id="vuln")


class TestTaskCreateRequest:
    """TaskCreateRequest field validation."""

    def test_valid_query(self) -> None:
        """Non-empty query_text accepted."""
        req = TaskCreateRequest(query_text="show vulnerabilities")
        assert req.query_text == "show vulnerabilities"

    def test_empty_query_rejected(self) -> None:
        """Empty query_text rejected (min_length=1)."""
        with pytest.raises(ValidationError, match="String should have at least 1 character"):
            TaskCreateRequest(query_text="")


class TestTaskListResponse:
    """TaskListResponse wraps list of TaskResponse."""

    def test_valid_list_response(self) -> None:
        """TaskListResponse accepts tasks list and total."""
        task = TaskResponse(status="queued", **TASK_KWARGS)
        resp = TaskListResponse(tasks=[task], total=1)
        assert resp.total == 1
        assert len(resp.tasks) == 1
        assert resp.tasks[0].task_id == "t1"


# ---------------------------------------------------------------------------
# ToolDetailResponse -- inputs JSON schema (FILE-24)
# ---------------------------------------------------------------------------


TOOL_BASE = {
    "tool_key": "vuln.query_cves",
    "name": "Query CVEs",
    "description": "Search CVE database",
    "module_id": "vulnerability",
}


class TestToolDetailResponseInputs:
    """ToolDetailResponse.inputs carries tool input JSON Schema."""

    def test_inputs_round_trips_json_schema(self) -> None:
        """A realistic JSON Schema dict round-trips through the model."""
        schema = {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Target hostname"},
                "severity": {
                    "type": "string",
                    "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                },
                "limit": {"type": "integer", "minimum": 1, "maximum": 1000},
            },
            "required": ["host"],
        }
        detail = ToolDetailResponse(inputs=schema, output_type="list[dict]", **TOOL_BASE)
        assert detail.inputs["type"] == "object"
        assert detail.inputs["properties"]["host"]["type"] == "string"
        assert detail.inputs["required"] == ["host"]

    def test_inputs_defaults_to_empty_dict(self) -> None:
        """inputs defaults to empty dict when tool has no input schema."""
        detail = ToolDetailResponse(**TOOL_BASE)
        assert detail.inputs == {}

    def test_output_type_defaults_to_string(self) -> None:
        """output_type defaults to 'string'."""
        detail = ToolDetailResponse(**TOOL_BASE)
        assert detail.output_type == "string"

    def test_extends_tool_summary(self) -> None:
        """ToolDetailResponse inherits all ToolSummaryResponse fields."""
        detail = ToolDetailResponse(
            inputs={"type": "object"},
            output_type="dict",
            **TOOL_BASE,
        )
        assert detail.tool_key == "vuln.query_cves"
        assert detail.name == "Query CVEs"
        assert detail.description == "Search CVE database"
        assert detail.module_id == "vulnerability"

    def test_extra_fields_rejected(self) -> None:
        """extra='forbid' rejects unknown fields."""
        with pytest.raises(ValidationError, match="extra_forbidden"):
            ToolDetailResponse(secret="nope", **TOOL_BASE)


class TestToolSummaryResponse:
    """ToolSummaryResponse required fields."""

    def test_valid_summary(self) -> None:
        """All required fields accepted."""
        summary = ToolSummaryResponse(**TOOL_BASE)
        assert summary.tool_key == "vuln.query_cves"
        assert summary.module_id == "vulnerability"

    def test_missing_field_rejected(self) -> None:
        """Missing required field raises ValidationError."""
        with pytest.raises(ValidationError):
            ToolSummaryResponse(tool_key="k", name="n", description="d")


class TestToolInvokeRequestResponse:
    """ToolInvokeRequest and ToolInvokeResponse validation."""

    def test_invoke_request_defaults_empty_kwargs(self) -> None:
        """ToolInvokeRequest.kwargs defaults to empty dict."""
        req = ToolInvokeRequest()
        assert req.kwargs == {}

    def test_invoke_response_success(self) -> None:
        """Successful invocation has result and no error."""
        resp = ToolInvokeResponse(
            tool_key="vuln.query_cves",
            result={"cve_id": "CVE-2023-12345"},
        )
        assert resp.error is None
        assert resp.result["cve_id"] == "CVE-2023-12345"

    def test_invoke_response_error(self) -> None:
        """Error invocation has error and null result."""
        resp = ToolInvokeResponse(
            tool_key="vuln.query_cves",
            result=None,
            error="tool not found",
        )
        assert resp.result is None
        assert resp.error == "tool not found"

    def test_invoke_response_extra_rejected(self) -> None:
        """extra='forbid' rejects unknown fields on ToolInvokeResponse."""
        with pytest.raises(ValidationError, match="extra_forbidden"):
            ToolInvokeResponse(tool_key="k", unknown="x")
