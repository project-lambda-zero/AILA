"""Phase 176a Task 2: Prometheus counter emission tests (D-25).

Uses ``prometheus_client.REGISTRY.get_sample_value`` to inspect the
counter value before and after an error-envelope emission, confirming the
(code, status, module) labels match.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from prometheus_client import REGISTRY

from aila.api.errors import register_error_handlers
from aila.api.metrics import (
    AILA_API_ERROR_ENVELOPE_COUNTER,
    API_ERROR_ENVELOPE_COUNTER_NAME,
)
from aila.platform.exceptions import MissingApiKeyError


def _counter_value(code: str, status: str, module: str) -> float:
    # prometheus_client exposes the scraped sample name with a trailing
    # "_total". Our registered metric name is already "aila_api_error_total",
    # and the scraped sample name is also "aila_api_error_total" (the client
    # strips the trailing "_total" from .name but re-appends it on samples).
    value = REGISTRY.get_sample_value(
        API_ERROR_ENVELOPE_COUNTER_NAME,
        {"code": code, "status": status, "module": module},
    )
    return value or 0.0


def test_metrics_counter_name_matches_preflight() -> None:
    """The counter name must equal the preflight BE-C decision.

    Preflight: ``aila_api_error_total`` is free → use that; do NOT fall back
    to ``aila_api_error_envelope_total`` unless BE-C reports a collision.
    """
    assert API_ERROR_ENVELOPE_COUNTER_NAME == "aila_api_error_total"
    # prometheus_client strips the trailing "_total" from ._name (it is appended
    # automatically on scrape). Verify the registered base matches either form.
    base_name = AILA_API_ERROR_ENVELOPE_COUNTER._name
    assert base_name in {
        API_ERROR_ENVELOPE_COUNTER_NAME,
        API_ERROR_ENVELOPE_COUNTER_NAME[: -len("_total")],
    }


def test_metrics_counter_labels_match_d25() -> None:
    """Counter labelnames are exactly (code, status, module) per D-25."""
    assert AILA_API_ERROR_ENVELOPE_COUNTER._labelnames == ("code", "status", "module")


def test_metrics_counter_increments_on_typed_error() -> None:
    """Emitting a typed AILAError envelope increments the counter by exactly 1.

    The module label is derived from the raising module. Here we raise from a
    FastAPI route handler whose exception's ``__module__`` becomes the test
    module; we override ``__module__`` on the exception class to make the
    label deterministic.
    """
    class _TestMissingApiKeyError(MissingApiKeyError):
        pass

    _TestMissingApiKeyError.__module__ = "aila.modules.vulnerability.services.fake"

    app = FastAPI()
    register_error_handlers(app)

    @app.get("/boom")
    async def _boom() -> None:  # pragma: no cover - always raises
        raise _TestMissingApiKeyError("no key")

    before = _counter_value("MISSING_API_KEY", "503", "vulnerability")

    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/boom")
    assert resp.status_code == 503

    after = _counter_value("MISSING_API_KEY", "503", "vulnerability")
    assert after - before == pytest.approx(1.0)


def test_metrics_counter_increments_on_generic_exception() -> None:
    """Unhandled Exception increments counter with code=INTERNAL_ERROR, status=500."""
    app = FastAPI()
    register_error_handlers(app)

    class _TestRuntimeError(RuntimeError):
        pass

    _TestRuntimeError.__module__ = "aila.platform.some.module"

    @app.get("/boom")
    async def _boom() -> None:  # pragma: no cover
        raise _TestRuntimeError("nope")

    before = _counter_value("INTERNAL_ERROR", "500", "platform")

    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/boom")
    assert resp.status_code == 500

    after = _counter_value("INTERNAL_ERROR", "500", "platform")
    assert after - before == pytest.approx(1.0)
