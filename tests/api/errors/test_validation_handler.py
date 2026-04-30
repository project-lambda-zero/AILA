"""Phase 176a Task 2: RequestValidationError → ErrorEnvelope tests (D-10a).

Posting invalid JSON to a Pydantic-validated endpoint yields HTTP 422 with
the four-field envelope (code="VALIDATION_ERROR").
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel

from aila.api.errors import register_error_handlers
from aila.api.errors.hints import ERROR_HINTS


class _Payload(BaseModel):
    name: str
    age: int


def _build_validation_app() -> FastAPI:
    app = FastAPI()
    register_error_handlers(app)

    @app.post("/echo")
    async def _echo(payload: _Payload) -> dict:
        return {"name": payload.name, "age": payload.age}

    return app


def test_validation_error_handler_returns_envelope() -> None:
    app = _build_validation_app()
    client = TestClient(app, raise_server_exceptions=False)

    # Wrong type for age — triggers RequestValidationError.
    resp = client.post("/echo", json={"name": "x", "age": "not-an-int"})

    assert resp.status_code == 422
    body = resp.json()
    assert set(body.keys()) == {"code", "message", "hint", "trace_id"}
    assert body["code"] == "VALIDATION_ERROR"
    assert body["hint"] == ERROR_HINTS["VALIDATION_ERROR"]
    assert "Request validation failed" == body["message"]


def test_validation_error_handler_missing_field() -> None:
    app = _build_validation_app()
    client = TestClient(app, raise_server_exceptions=False)

    resp = client.post("/echo", json={"name": "x"})  # missing age

    assert resp.status_code == 422
    body = resp.json()
    assert body["code"] == "VALIDATION_ERROR"
