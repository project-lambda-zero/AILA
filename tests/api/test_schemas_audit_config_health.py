"""Schema-level unit tests for audit, config, and health schemas -- Phase 78 FILE-19/20/21.

Tests validate:
- AuditEventResponse field defaults, round-trip, and extra="forbid"
- ConfigUpdateRequest value_type Literal constraint and namespace/key min_length
- HealthCheckResult/HealthCheckResponse Literal status constraints
- StatusResponse required fields
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from aila.api.schemas.audit import AuditEventResponse, AuditListResponse
from aila.api.schemas.config import ConfigEntryResponse, ConfigUpdateRequest
from aila.api.schemas.health import HealthCheckResponse, HealthCheckResult, StatusResponse


# ---------------------------------------------------------------------------
# AuditEventResponse (FILE-19)
# ---------------------------------------------------------------------------


class TestAuditEventResponse:
    """AuditEventResponse field defaults, round-trip, and rejection of extras."""

    def test_defaults_applied(self) -> None:
        """Minimal construction uses correct defaults for optional fields."""
        event = AuditEventResponse(
            run_id="run-1",
            stage="ssh",
            action="connect",
        )
        assert event.status == "completed"
        assert event.user_id == "system"
        assert event.target == ""
        assert event.details == {}
        assert event.id is None
        assert event.created_at is None

    def test_all_fields_round_trip(self) -> None:
        """All fields serialize and deserialize correctly."""
        now = datetime.now(timezone.utc)
        event = AuditEventResponse(
            id=42,
            run_id="run-abc",
            stage="analysis",
            action="scan.start",
            status="failed",
            target="web-01",
            user_id="admin-1",
            details={"count": 5, "nested": {"ok": True}},
            created_at=now,
        )
        data = event.model_dump()
        assert data["id"] == 42
        assert data["run_id"] == "run-abc"
        assert data["stage"] == "analysis"
        assert data["action"] == "scan.start"
        assert data["status"] == "failed"
        assert data["target"] == "web-01"
        assert data["user_id"] == "admin-1"
        assert data["details"]["count"] == 5
        assert data["details"]["nested"]["ok"] is True
        assert data["created_at"] == now

    def test_extra_fields_rejected(self) -> None:
        """extra='forbid' inherited from APIModel rejects unknown fields."""
        with pytest.raises(ValidationError, match="extra_forbidden"):
            AuditEventResponse(
                run_id="run-1",
                stage="ssh",
                action="connect",
                bogus_field="should fail",
            )

    def test_audit_list_response_is_paginated(self) -> None:
        """AuditListResponse wraps AuditEventResponse items in PaginatedResponse."""
        resp = AuditListResponse(
            total=1,
            page=1,
            page_size=50,
            pages=1,
            items=[
                AuditEventResponse(run_id="r1", stage="s", action="a"),
            ],
        )
        assert len(resp.items) == 1
        assert resp.items[0].run_id == "r1"


# ---------------------------------------------------------------------------
# ConfigUpdateRequest / ConfigEntryResponse (FILE-20)
# ---------------------------------------------------------------------------


class TestConfigUpdateRequest:
    """ConfigUpdateRequest value_type Literal constraint."""

    @pytest.mark.parametrize("vtype", ["str", "int", "float", "bool"])
    def test_valid_value_types_accepted(self, vtype: str) -> None:
        """All four valid value_type literals are accepted."""
        req = ConfigUpdateRequest(value="42", value_type=vtype)
        assert req.value_type == vtype

    def test_default_value_type_is_str(self) -> None:
        """value_type defaults to 'str' when omitted."""
        req = ConfigUpdateRequest(value="hello")
        assert req.value_type == "str"

    @pytest.mark.parametrize("bad_type", ["list", "dict", "tuple", "bytes", ""])
    def test_invalid_value_type_rejected(self, bad_type: str) -> None:
        """Invalid value_type values are rejected with ValidationError."""
        with pytest.raises(ValidationError):
            ConfigUpdateRequest(value="x", value_type=bad_type)

    def test_extra_fields_rejected(self) -> None:
        """extra='forbid' rejects unknown fields on ConfigUpdateRequest."""
        with pytest.raises(ValidationError, match="extra_forbidden"):
            ConfigUpdateRequest(value="x", secret="nope")


class TestConfigEntryResponse:
    """ConfigEntryResponse namespace/key min_length constraint."""

    def test_valid_entry(self) -> None:
        """Valid entry with non-empty namespace and key is accepted."""
        entry = ConfigEntryResponse(
            namespace="vulnerability",
            key="max_findings",
            value="100",
        )
        assert entry.namespace == "vulnerability"
        assert entry.key == "max_findings"

    def test_empty_namespace_rejected(self) -> None:
        """Empty namespace string is rejected (min_length=1)."""
        with pytest.raises(ValidationError, match="String should have at least 1 character"):
            ConfigEntryResponse(namespace="", key="some_key", value="v")

    def test_empty_key_rejected(self) -> None:
        """Empty key string is rejected (min_length=1)."""
        with pytest.raises(ValidationError, match="String should have at least 1 character"):
            ConfigEntryResponse(namespace="ns", key="", value="v")


# ---------------------------------------------------------------------------
# HealthCheckResult / HealthCheckResponse (FILE-21)
# ---------------------------------------------------------------------------


class TestHealthCheckResult:
    """HealthCheckResult status Literal constraint and optional fields."""

    @pytest.mark.parametrize("status", ["up", "degraded", "down"])
    def test_valid_status_accepted(self, status: str) -> None:
        """All three valid check-level statuses are accepted."""
        result = HealthCheckResult(status=status)
        assert result.status == status

    def test_invalid_status_rejected(self) -> None:
        """Invalid status value is rejected."""
        with pytest.raises(ValidationError):
            HealthCheckResult(status="unknown")

    def test_latency_ms_optional(self) -> None:
        """latency_ms defaults to None when omitted."""
        result = HealthCheckResult(status="up")
        assert result.latency_ms is None

    def test_latency_ms_populated(self) -> None:
        """latency_ms is preserved when provided."""
        result = HealthCheckResult(status="up", latency_ms=12.5)
        assert result.latency_ms == 12.5

    def test_message_optional(self) -> None:
        """message defaults to None when omitted."""
        result = HealthCheckResult(status="down")
        assert result.message is None

    def test_message_populated(self) -> None:
        """message is preserved when provided."""
        result = HealthCheckResult(status="down", message="connection refused")
        assert result.message == "connection refused"


class TestHealthCheckResponse:
    """HealthCheckResponse top-level status Literal constraint."""

    @pytest.mark.parametrize("status", ["healthy", "degraded", "unhealthy"])
    def test_valid_top_level_status_accepted(self, status: str) -> None:
        """All three valid top-level statuses are accepted."""
        resp = HealthCheckResponse(
            status=status,
            checks={"database": HealthCheckResult(status="up")},
        )
        assert resp.status == status

    def test_invalid_top_level_status_rejected(self) -> None:
        """Invalid top-level status is rejected."""
        with pytest.raises(ValidationError):
            HealthCheckResponse(
                status="broken",
                checks={"database": HealthCheckResult(status="up")},
            )

    def test_checks_dict_required(self) -> None:
        """checks field is required (no default)."""
        with pytest.raises(ValidationError):
            HealthCheckResponse(status="healthy")


class TestStatusResponse:
    """StatusResponse required fields."""

    def test_valid_status_response(self) -> None:
        """StatusResponse accepts valid version and uptime_seconds."""
        resp = StatusResponse(version="1.0.0", uptime_seconds=120)
        assert resp.version == "1.0.0"
        assert resp.uptime_seconds == 120

    def test_missing_version_rejected(self) -> None:
        """Missing version field is rejected."""
        with pytest.raises(ValidationError):
            StatusResponse(uptime_seconds=0)

    def test_missing_uptime_rejected(self) -> None:
        """Missing uptime_seconds field is rejected."""
        with pytest.raises(ValidationError):
            StatusResponse(version="1.0.0")
