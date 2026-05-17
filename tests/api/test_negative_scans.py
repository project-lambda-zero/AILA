"""Negative tests for scan endpoints: 403, 404, 422, 503 error paths.

Covers:
  POST /analyze       - 403 reader forbidden, 422 bad body, 503 no platform
  GET  /scans/{id}    - 404 not found
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient

# -- POST /analyze -------------------------------------------------------------


@pytest.mark.asyncio
async def test_analyze_reader_forbidden(
    async_client: AsyncClient, reader_token: str
) -> None:
    """POST /analyze with reader token returns 403 (operator+ required)."""
    resp = await async_client.post(
        "/analyze",
        json={"query_text": "scan web01", "targets": ["web01"]},
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert resp.status_code == 403
    detail = resp.json()["detail"]
    assert "operator" in detail.lower()


@pytest.mark.asyncio
async def test_analyze_empty_body(
    async_client: AsyncClient, admin_token: str
) -> None:
    """POST /analyze with missing required fields returns 422."""
    resp = await async_client.post(
        "/analyze",
        json={},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_analyze_no_platform(
    async_client: AsyncClient, admin_token: str
) -> None:
    """POST /analyze with platform=None returns 503.

    The async_client fixture sets app.state.platform = None.
    """
    resp = await async_client.post(
        "/analyze",
        json={"query_text": "scan web01", "targets": ["web01"]},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 503
    detail = resp.json()["detail"]
    assert "platform" in detail.lower()


# -- GET /scans/{id} -----------------------------------------------------------


@pytest.mark.asyncio
async def test_get_scan_not_found(
    async_client: AsyncClient, admin_token: str
) -> None:
    """GET /scans/nonexistent returns 404."""
    resp = await async_client.get(
        "/scans/nonexistent-run-id",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 404
    detail = resp.json()["detail"]
    assert "not found" in detail.lower()
