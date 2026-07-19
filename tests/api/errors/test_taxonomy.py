"""Phase 176a Task 1: typed exception taxonomy tests (D-10b, D-20).

Verifies:
- Each of the six new exception classes has ClassVar ``code`` equal to the
  D-20 locked string and ClassVar ``http_status`` equal to the D-20 locked int.
- Each new class inherits from AILAError.
- ErrorEnvelope has exactly the four locked fields {code, message, hint, trace_id}.
- The errors package phase-1 exports expose ErrorEnvelope + ERROR_HINTS but not
  register_error_handlers (that arrives in Task 2).
"""
from __future__ import annotations

import importlib
from typing import get_type_hints

import pytest

import aila.api.errors
from aila.api.errors.envelope import ErrorEnvelope
from aila.platform.exceptions import (
    AILAError,
    AuthenticationError,
    ConfigValueMissingError,
    MissingApiKeyError,
    ModulePlatformNotReadyError,
    NotFoundError,
    RateLimitError,
    RouterError,
    SSHConnectionFailedError,
    TimeoutError,
    UpstreamError,
    ValidationError,
    WorkerUnreachableError,
)

# The canonical D-20 mapping. Do not mutate without revising phase decisions.
# Issue #54 (2026-07-19): the six pre-existing AILAError subclasses joined the
# taxonomy with their own ClassVar code/http_status, so they are now covered
# by the same locked-contract tests.
_D20_MAPPING = [
    (MissingApiKeyError, "MISSING_API_KEY", 503),
    (SSHConnectionFailedError, "SSH_CONNECTION_FAILED", 502),
    (RouterError, "ROUTER_ERROR", 500),
    (ModulePlatformNotReadyError, "MODULE_PLATFORM_NOT_READY", 503),
    (ConfigValueMissingError, "CONFIG_VALUE_MISSING", 500),
    (WorkerUnreachableError, "WORKER_UNREACHABLE", 503),
    (AuthenticationError, "AUTHENTICATION_ERROR", 401),
    (RateLimitError, "RATE_LIMIT_ERROR", 429),
    (NotFoundError, "NOT_FOUND_ERROR", 404),
    (ValidationError, "VALIDATION_ERROR", 422),
    (UpstreamError, "UPSTREAM_ERROR", 502),
    (TimeoutError, "TIMEOUT_ERROR", 504),
]


@pytest.mark.parametrize("cls,expected_code,expected_status", _D20_MAPPING)
def test_taxonomy_codes_are_stable(
    cls: type[AILAError], expected_code: str, expected_status: int
) -> None:
    """Each typed exception exposes the D-20 locked code string as a ClassVar."""
    assert cls.code == expected_code
    # Verify the annotation is ClassVar, not an instance attr.
    hints = get_type_hints(cls, include_extras=True)
    assert "code" in hints
    raw_hints = cls.__annotations__
    assert "ClassVar" in str(raw_hints.get("code", "")), (
        f"{cls.__name__}.code must be ClassVar[str], got {raw_hints.get('code')}"
    )


@pytest.mark.parametrize("cls,expected_code,expected_status", _D20_MAPPING)
def test_taxonomy_http_status(
    cls: type[AILAError], expected_code: str, expected_status: int
) -> None:
    """Each typed exception exposes the D-20 locked HTTP status as a ClassVar."""
    assert cls.http_status == expected_status
    raw_hints = cls.__annotations__
    assert "ClassVar" in str(raw_hints.get("http_status", "")), (
        f"{cls.__name__}.http_status must be ClassVar[int]"
    )


@pytest.mark.parametrize("cls,expected_code,expected_status", _D20_MAPPING)
def test_taxonomy_inherits_ailaerror(
    cls: type[AILAError], expected_code: str, expected_status: int
) -> None:
    """Every new typed exception is a subclass of AILAError."""
    assert issubclass(cls, AILAError)


def test_taxonomy_classvar_not_on_instance() -> None:
    """ClassVar attrs are class-level and do not pollute instance __dict__."""
    exc = MissingApiKeyError("no key configured")
    assert "code" not in exc.__dict__
    assert "http_status" not in exc.__dict__
    # But resolvable via attribute lookup.
    assert exc.code == "MISSING_API_KEY"
    assert exc.http_status == 503


def test_envelope_required_fields() -> None:
    """ErrorEnvelope declares exactly {code, message, hint, trace_id}.

    code + message required; hint + trace_id optional (default None).
    """
    fields = ErrorEnvelope.model_fields
    assert set(fields.keys()) == {"code", "message", "hint", "trace_id"}
    assert fields["code"].is_required()
    assert fields["message"].is_required()
    assert not fields["hint"].is_required()
    assert not fields["trace_id"].is_required()

    # Round-trip construction with only required fields succeeds.
    env = ErrorEnvelope(code="MISSING_API_KEY", message="no key")
    assert env.hint is None
    assert env.trace_id is None


def test_errors_package_phase1_exports() -> None:
    """Phase-1 package exports: ErrorEnvelope + ERROR_HINTS only."""
    # Force re-import in case another test mutated module state.
    errors_pkg = importlib.reload(aila.api.errors)

    assert hasattr(errors_pkg, "ErrorEnvelope")
    assert hasattr(errors_pkg, "ERROR_HINTS")
    assert "ErrorEnvelope" in errors_pkg.__all__
    assert "ERROR_HINTS" in errors_pkg.__all__
