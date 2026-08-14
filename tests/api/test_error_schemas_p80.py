"""Tests for Phase 80: Error response shape consistency.

Post D-10a (Phase 176a), the error surface is split:

* ``HTTPException`` responses (401/403/404) still use the Phase 80
  ``ErrorResponse`` shape ``{"detail": str, "code": str|None,
  "errors": list|None}`` emitted by ``app._http_exception_handler``.
* ``RequestValidationError`` (422) now returns the D-10a ``ErrorEnvelope``
  ``{"code": str, "message": str, "hint": str|None, "trace_id": str|None}``
  from :func:`aila.api.errors.handlers.validation_error_handler`. The
  per-field error array (``loc``/``msg``/``type``) is intentionally not
  carried in the 422 body anymore.
* Unhandled 500s go through the catch-all middleware and return
  ``{"detail": "Internal server error", "code": None, "errors": None}``.

Key verifications:
- 422 validation errors return the D-10a envelope with
  ``code == "VALIDATION_ERROR"`` and the fixed ``message``/``hint``/
  ``trace_id`` keys.
- HTTPException responses (401, 404, etc.) return the ErrorResponse shape.
- detail (HTTPException path) is always a string, never a list.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


@pytest_asyncio.fixture(scope="function")
async def client(test_db) -> AsyncClient:
    """Async HTTP client for error shape testing."""
    import time

    from aila.api.app import create_app

    test_app = create_app()
    test_app.state.platform = None
    test_app.state.start_time = time.monotonic()

    async with AsyncClient(
        transport=ASGITransport(app=test_app),
        base_url="http://testserver",
    ) as c:
        yield c


class TestValidationErrorShape:
    """FastAPI 422 validation errors match ErrorResponse shape."""

    @pytest.mark.asyncio
    async def test_422_has_detail_as_string(self, client, admin_token):
        """422 envelope carries a human-readable string ``message`` field.

        Per D-10a, ``detail`` was replaced by ``message`` on the 422 path.
        The intent -- verifying the human-readable field is a plain string,
        not a list of per-field validation records -- carries over to
        ``message``.
        """
        resp = await client.post(
            "/auth/token",
            json={},  # missing required api_key field
        )
        assert resp.status_code == 422
        body = resp.json()
        assert isinstance(body["message"], str), (
            f"message should be str, got {type(body['message']).__name__}"
        )
        assert body["message"] == "Request validation failed"

    @pytest.mark.asyncio
    async def test_422_has_errors_array(self, client, admin_token):
        """422 envelope exposes exactly the four D-10a keys.

        The pre-D-10a ``errors`` array (per-field ``loc``/``msg``/``type``
        records) was deliberately dropped from the 422 body. The remaining
        contract this test defends: the body is the four-key envelope --
        ``code``, ``message``, ``hint``, ``trace_id`` -- and nothing else.
        """
        resp = await client.post(
            "/auth/token",
            json={},  # missing required api_key field
        )
        assert resp.status_code == 422
        body = resp.json()
        assert set(body.keys()) == {"code", "message", "hint", "trace_id"}, (
            f"422 envelope keys drifted: {sorted(body.keys())}"
        )
        # Per-field details no longer live in the 422 body.
        assert "errors" not in body
        assert "detail" not in body

    @pytest.mark.asyncio
    async def test_422_errors_have_loc_msg_type(self, client, admin_token):
        """422 envelope carries ``code`` + ``message`` + ``hint`` (per-field detail moved out).

        Historically this test asserted that each item in the ``errors`` array
        had ``loc``/``msg``/``type`` keys. D-10a moved per-field diagnostic
        detail out of the 422 body: the envelope now carries an operator-facing
        ``hint`` instead of the FastAPI-style structured error list. The
        remaining contract is that the three text fields are populated.
        """
        resp = await client.post(
            "/auth/token",
            json={},  # missing required api_key field
        )
        assert resp.status_code == 422
        body = resp.json()
        assert body["code"] == "VALIDATION_ERROR"
        assert isinstance(body["message"], str) and body["message"]
        assert isinstance(body["hint"], str) and body["hint"], (
            "envelope must carry an operator-facing hint for VALIDATION_ERROR"
        )

    @pytest.mark.asyncio
    async def test_422_has_code_field(self, client, admin_token):
        """422 response includes code field set to VALIDATION_ERROR."""
        resp = await client.post(
            "/auth/token",
            json={},
        )
        assert resp.status_code == 422
        body = resp.json()
        assert body["code"] == "VALIDATION_ERROR"

    @pytest.mark.asyncio
    async def test_422_loc_is_list(self, client, admin_token):
        """422 envelope carries a ``trace_id`` key (per-field ``loc`` moved out).

        Historically this test asserted the ``loc`` field in each per-field
        error record was a list. D-10a dropped the per-field error records
        entirely; the remaining transport-level contract this test defends is
        that the envelope's ``trace_id`` key is present (nullable string --
        ``None`` when the exception fires before CorrelationIdMiddleware has
        bound the context).
        """
        resp = await client.post(
            "/auth/token",
            json={},
        )
        assert resp.status_code == 422
        body = resp.json()
        assert "trace_id" in body
        assert body["trace_id"] is None or isinstance(body["trace_id"], str), (
            f"trace_id should be str|None, got {type(body['trace_id']).__name__}"
        )


class TestHTTPExceptionShape:
    """HTTPException responses conform to ErrorResponse shape."""

    @pytest.mark.asyncio
    async def test_401_has_detail_string(self, client):
        """401 Unauthorized returns detail as string."""
        resp = await client.get(
            "/systems",
            headers={"Authorization": "Bearer invalid-token"},
        )
        assert resp.status_code == 401
        body = resp.json()
        assert isinstance(body["detail"], str)

    @pytest.mark.asyncio
    async def test_401_has_code_null(self, client):
        """401 response has code field (null for generic HTTPException)."""
        resp = await client.get(
            "/systems",
            headers={"Authorization": "Bearer invalid-token"},
        )
        assert resp.status_code == 401
        body = resp.json()
        assert "code" in body
        assert body["code"] is None

    @pytest.mark.asyncio
    async def test_401_has_errors_null(self, client):
        """401 response has errors field (null for non-validation errors)."""
        resp = await client.get(
            "/systems",
            headers={"Authorization": "Bearer invalid-token"},
        )
        assert resp.status_code == 401
        body = resp.json()
        assert "errors" in body
        assert body["errors"] is None

    @pytest.mark.asyncio
    async def test_404_returns_error_response_shape(self, client, admin_token):
        """404 Not Found returns full ErrorResponse envelope."""
        resp = await client.get(
            "/systems/999999",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 404
        body = resp.json()
        assert isinstance(body["detail"], str)
        assert "code" in body
        assert "errors" in body


class TestErrorResponseConsistency:
    """Cross-cutting: all error paths return the same envelope shape."""

    @pytest.mark.asyncio
    async def test_missing_auth_header_shape(self, client):
        """Request with no auth header returns ErrorResponse shape."""
        resp = await client.get("/systems")
        assert resp.status_code == 401
        body = resp.json()
        # Must have all three ErrorResponse fields
        assert "detail" in body
        assert "code" in body
        assert "errors" in body
        assert isinstance(body["detail"], str)

    @pytest.mark.asyncio
    async def test_validation_error_on_keys_endpoint(self, client, admin_token):
        """POST /auth/keys with bad role returns 422 with the D-10a envelope.

        Cross-checks that the envelope handler wins on a non-``/auth/token``
        endpoint too -- i.e. the envelope replaces the ErrorResponse shape
        uniformly for RequestValidationError, not just for one route.
        """
        resp = await client.post(
            "/auth/keys",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"role": "superadmin", "label": "test"},
        )
        assert resp.status_code == 422
        body = resp.json()
        assert body["code"] == "VALIDATION_ERROR"
        assert body["message"] == "Request validation failed"
        assert "hint" in body
        assert "trace_id" in body
