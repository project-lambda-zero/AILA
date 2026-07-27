"""#36 -- refresh token is accepted only in the JSON body, never the URL.

The refresh and logout endpoints previously read ``refresh_token`` from
a URL query parameter, leaking the long-lived credential into web-server
access logs, browser history, and any intermediary that captured the
request URI. The contract now requires the token in the JSON body; a
caller that supplies only the query parameter gets a 422.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_refresh_endpoint_reads_body(
    async_client: AsyncClient,
) -> None:
    """POST /auth/refresh/user with a body payload is accepted (schema-level).

    We do not need a valid token to prove the contract shift: an invalid
    body-supplied token returns 401 (validated against the DB), while the
    same token supplied only as a query parameter returns 422 (missing
    required body). The 422/401 split is the observable contract.
    """
    resp = await async_client.post(
        "/auth/refresh/user",
        json={"refresh_token": "not-a-real-token"},
    )
    assert resp.status_code == 401, resp.text


@pytest.mark.asyncio
async def test_refresh_endpoint_rejects_query_only(
    async_client: AsyncClient,
) -> None:
    """The query-parameter form is no longer accepted -- returns 422."""
    resp = await async_client.post(
        "/auth/refresh/user",
        params={"refresh_token": "not-a-real-token"},
    )
    assert resp.status_code == 422, resp.text


@pytest.mark.asyncio
async def test_refresh_endpoint_rejects_missing_body(
    async_client: AsyncClient,
) -> None:
    """POST /auth/refresh/user with no body is a 422 body-validation error."""
    resp = await async_client.post("/auth/refresh/user")
    assert resp.status_code == 422, resp.text


@pytest.mark.asyncio
async def test_logout_endpoint_reads_body(
    async_client: AsyncClient,
) -> None:
    """POST /auth/logout with a body payload is accepted (no matching token yet)."""
    resp = await async_client.post(
        "/auth/logout",
        json={"refresh_token": "not-a-real-token"},
    )
    # Body was accepted (200 with revoked=True or False) -- either way, NOT 422.
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_logout_endpoint_rejects_query_only(
    async_client: AsyncClient,
) -> None:
    """The query-parameter form is no longer accepted -- returns 422."""
    resp = await async_client.post(
        "/auth/logout",
        params={"refresh_token": "not-a-real-token"},
    )
    assert resp.status_code == 422, resp.text
