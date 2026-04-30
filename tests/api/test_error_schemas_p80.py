"""Tests for Phase 80: Error response shape consistency.

Proves that every error response from the AILA API conforms to the
ErrorResponse schema: {"detail": str, "code": str|None, "errors": list|None}.

Key verifications:
- 422 validation errors return ErrorResponse shape (not FastAPI default)
- 422 errors array contains structured objects with loc, msg, type
- HTTPException responses (401, 404, etc.) return ErrorResponse shape
- detail is always a string, never a list
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
        """422 response detail is a string, not a list."""
        resp = await client.post(
            "/auth/token",
            json={},  # missing required api_key field
        )
        assert resp.status_code == 422
        body = resp.json()
        assert isinstance(body["detail"], str), (
            f"detail should be str, got {type(body['detail']).__name__}"
        )

    @pytest.mark.asyncio
    async def test_422_has_errors_array(self, client, admin_token):
        """422 response contains errors array with structured error objects."""
        resp = await client.post(
            "/auth/token",
            json={},  # missing required api_key field
        )
        assert resp.status_code == 422
        body = resp.json()
        assert "errors" in body
        assert isinstance(body["errors"], list)
        assert len(body["errors"]) > 0

    @pytest.mark.asyncio
    async def test_422_errors_have_loc_msg_type(self, client, admin_token):
        """Each error in the errors array has loc, msg, type keys."""
        resp = await client.post(
            "/auth/token",
            json={},  # missing required api_key field
        )
        assert resp.status_code == 422
        body = resp.json()
        for err in body["errors"]:
            assert "loc" in err, f"error missing 'loc': {err}"
            assert "msg" in err, f"error missing 'msg': {err}"
            assert "type" in err, f"error missing 'type': {err}"

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
        """The loc field in each error is a list (path components)."""
        resp = await client.post(
            "/auth/token",
            json={},
        )
        assert resp.status_code == 422
        body = resp.json()
        for err in body["errors"]:
            assert isinstance(err["loc"], list), (
                f"loc should be list, got {type(err['loc']).__name__}"
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
        """POST /auth/keys with bad role returns 422 with ErrorResponse shape."""
        resp = await client.post(
            "/auth/keys",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"role": "superadmin", "label": "test"},
        )
        assert resp.status_code == 422
        body = resp.json()
        assert isinstance(body["detail"], str)
        assert isinstance(body["errors"], list)
        assert body["code"] == "VALIDATION_ERROR"
