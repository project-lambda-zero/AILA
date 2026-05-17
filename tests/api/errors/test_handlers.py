"""Phase 176a Task 2: exception handler behavior tests (D-10a, D-10d, D-20, D-26).

Verifies that every error path through the API produces an ErrorEnvelope with:
- correct code + HTTP status per D-20,
- a stable hint from ERROR_HINTS,
- a trace_id derived from the correlation_id contextvar (or None when absent),
- no leaked traceback / str(exc) / internal paths in ``message``.

A throwaway FastAPI app is constructed per-test, so these tests do not touch
the real DB, middleware chain, or platform lifespan.
"""
from __future__ import annotations

import pytest
import structlog
from fastapi import FastAPI
from fastapi.testclient import TestClient

from aila.api.errors import ErrorEnvelope, register_error_handlers
from aila.api.errors.hints import ERROR_HINTS
from aila.platform.exceptions import (
    AILAError,
    AuthenticationError,
    ConfigValueMissingError,
    MissingApiKeyError,
    ModulePlatformNotReadyError,
    NotFoundError,
    RouterError,
    SSHConnectionFailedError,
    WorkerUnreachableError,
)

_D20_MAPPING = [
    (MissingApiKeyError, "MISSING_API_KEY", 503),
    (SSHConnectionFailedError, "SSH_CONNECTION_FAILED", 502),
    (RouterError, "ROUTER_ERROR", 500),
    (ModulePlatformNotReadyError, "MODULE_PLATFORM_NOT_READY", 503),
    (ConfigValueMissingError, "CONFIG_VALUE_MISSING", 500),
    (WorkerUnreachableError, "WORKER_UNREACHABLE", 503),
]


def _build_app(routes: dict[str, type[Exception]]) -> FastAPI:
    """Return a minimal FastAPI app with registered envelope handlers.

    ``routes`` maps path → exception class. Each path raises a freshly
    constructed instance of the class when called.
    """
    app = FastAPI()
    register_error_handlers(app)

    for path, exc_cls in routes.items():
        def _make_handler(cls: type[Exception]):
            async def _handler() -> None:  # pragma: no cover - always raises
                raise cls("boom")

            return _handler

        app.get(path)(_make_handler(exc_cls))

    return app


def _assert_envelope_shape(body: dict) -> None:
    """Assert the response body matches the four-field envelope."""
    assert set(body.keys()) == {"code", "message", "hint", "trace_id"}
    assert isinstance(body["code"], str) and body["code"]
    assert isinstance(body["message"], str) and body["message"]
    assert body["hint"] is None or isinstance(body["hint"], str)
    assert body["trace_id"] is None or isinstance(body["trace_id"], str)


@pytest.mark.parametrize("cls,expected_code,expected_status", _D20_MAPPING)
def test_handler_emits_envelope_for_each_of_six(
    cls: type[AILAError], expected_code: str, expected_status: int
) -> None:
    """Each of the six D-20 typed errors produces the correct envelope + status."""
    app = _build_app({"/raise": cls})
    client = TestClient(app, raise_server_exceptions=False)

    resp = client.get("/raise")

    assert resp.status_code == expected_status
    body = resp.json()
    _assert_envelope_shape(body)
    assert body["code"] == expected_code
    assert body["hint"] == ERROR_HINTS[expected_code]


def test_handler_emits_envelope_for_typed_error() -> None:
    """Baseline check: MissingApiKeyError → 503 envelope with locked hint."""
    app = _build_app({"/raise": MissingApiKeyError})
    client = TestClient(app, raise_server_exceptions=False)

    resp = client.get("/raise")
    body = resp.json()

    assert resp.status_code == 503
    assert body["code"] == "MISSING_API_KEY"
    assert body["hint"] == ERROR_HINTS["MISSING_API_KEY"]
    # trace_id is str|None; with TestClient no correlation middleware is installed.
    assert body["trace_id"] is None or isinstance(body["trace_id"], str)


def test_handler_handles_pre_existing_aila_error_without_http_status() -> None:
    """Pre-existing AILAError subclasses lack ClassVar http_status — handler must
    fall back to 500 and still emit the envelope shape (preflight BE-E)."""
    app = _build_app({"/raise": AuthenticationError})
    client = TestClient(app, raise_server_exceptions=False)

    resp = client.get("/raise")
    body = resp.json()

    assert resp.status_code == 500
    _assert_envelope_shape(body)
    # Derived code — either a class-name-derived token or INTERNAL_ERROR fallback.
    assert body["code"]
    # message must NOT leak str(exc) ("boom").
    assert "boom" not in body["message"].lower()
    assert "traceback" not in body["message"].lower()


def test_handler_handles_notfound_without_classvar() -> None:
    """NotFoundError (legacy) also goes through the 500 fallback path."""
    app = _build_app({"/raise": NotFoundError})
    client = TestClient(app, raise_server_exceptions=False)

    resp = client.get("/raise")
    body = resp.json()

    assert resp.status_code == 500
    _assert_envelope_shape(body)


def test_handler_fallback_for_generic_exception() -> None:
    """An arbitrary Exception falls through to the generic handler (500 INTERNAL_ERROR)."""
    app = _build_app({"/raise": RuntimeError})
    client = TestClient(app, raise_server_exceptions=False)

    resp = client.get("/raise")
    body = resp.json()

    assert resp.status_code == 500
    _assert_envelope_shape(body)
    assert body["code"] == "INTERNAL_ERROR"
    assert body["hint"] == ERROR_HINTS["INTERNAL_ERROR"]
    assert body["message"] == "An internal error occurred."
    # Never leaks the raw exception message ("boom").
    assert "boom" not in body["message"]
    assert "traceback" not in body["message"].lower()
    assert "RuntimeError" not in body["message"]


def test_handler_includes_trace_id_from_structlog() -> None:
    """When structlog has correlation_id bound, envelope.trace_id reflects it.

    The contextvar name is ``correlation_id`` (preflight BE-F); the envelope
    exposes it as ``trace_id``. We call the handler directly (no HTTP) to
    bind contextvars on the same thread the handler reads them from.
    """
    import asyncio

    from aila.api.errors.handlers import typed_error_handler

    async def _drive() -> ErrorEnvelope:
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(correlation_id="trace-xyz-123")
        try:
            resp = await typed_error_handler(
                request=None,  # type: ignore[arg-type]
                exc=MissingApiKeyError("no key"),
            )
        finally:
            structlog.contextvars.clear_contextvars()
        return ErrorEnvelope.model_validate_json(resp.body)

    envelope = asyncio.run(_drive())
    assert envelope.trace_id == "trace-xyz-123"


def test_handler_handles_middleware_error_with_no_trace_id(monkeypatch) -> None:
    """When contextvars is empty, trace_id is None and no crash occurs (D-26)."""
    import asyncio

    from aila.api.errors.handlers import typed_error_handler

    monkeypatch.setattr(
        "aila.api.errors.handlers.structlog.contextvars.get_contextvars",
        lambda: {},
    )

    async def _drive() -> ErrorEnvelope:
        resp = await typed_error_handler(
            request=None,  # type: ignore[arg-type]
            exc=MissingApiKeyError("no key"),
        )
        return ErrorEnvelope.model_validate_json(resp.body)

    envelope = asyncio.run(_drive())
    assert envelope.trace_id is None
    assert envelope.code == "MISSING_API_KEY"


def test_handler_module_label_derivation_nested_modules() -> None:
    """aila.modules.X.* → module label ``X`` (preflight algorithm)."""
    from aila.api.errors.handlers import _derive_module_label

    class _FakeExc(Exception):
        pass

    _FakeExc.__module__ = "aila.modules.vulnerability.services.reports"
    assert _derive_module_label(_FakeExc("x")) == "vulnerability"


def test_handler_module_label_derivation_platform() -> None:
    """aila.platform.* → module label ``platform``."""
    from aila.api.errors.handlers import _derive_module_label

    class _FakeExc(Exception):
        pass

    _FakeExc.__module__ = "aila.platform.llm.client"
    assert _derive_module_label(_FakeExc("x")) == "platform"


def test_handler_module_label_derivation_api() -> None:
    """aila.api.* → module label ``api``."""
    from aila.api.errors.handlers import _derive_module_label

    class _FakeExc(Exception):
        pass

    _FakeExc.__module__ = "aila.api.routers.foo"
    assert _derive_module_label(_FakeExc("x")) == "api"


def test_handler_module_label_fallback_for_unknown_prefix() -> None:
    """Modules not rooted at ``aila`` fall back to ``platform``."""
    from aila.api.errors.handlers import _derive_module_label

    class _FakeExc(Exception):
        pass

    _FakeExc.__module__ = "some.third.party.lib"
    assert _derive_module_label(_FakeExc("x")) == "platform"


def test_handler_registered_on_app() -> None:
    """After create_app()/register_error_handlers, all three handlers are wired."""
    from fastapi.exceptions import RequestValidationError

    app = FastAPI()
    register_error_handlers(app)

    registered = app.exception_handlers
    assert AILAError in registered
    assert RequestValidationError in registered
    assert Exception in registered


def test_errors_package_phase2_exports() -> None:
    """Phase-2 package exports include register_error_handlers."""
    import aila.api.errors as errors_pkg

    assert hasattr(errors_pkg, "register_error_handlers")
    assert "register_error_handlers" in errors_pkg.__all__


def test_handler_registered_in_create_app() -> None:
    """The real create_app() wires the three envelope handlers."""
    from fastapi.exceptions import RequestValidationError

    from aila.api.app import create_app

    app = create_app()
    from aila.api.errors.handlers import (
        generic_error_handler,
        typed_error_handler,
        validation_error_handler,
    )

    assert app.exception_handlers.get(AILAError) is typed_error_handler
    assert app.exception_handlers.get(RequestValidationError) is validation_error_handler
    assert app.exception_handlers.get(Exception) is generic_error_handler
