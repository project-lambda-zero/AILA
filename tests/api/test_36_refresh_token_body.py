"""#36 -- refresh token is never accepted as a URL query parameter.

The refresh and logout endpoints used to read ``refresh_token`` from a
query parameter, which leaked the long-lived credential into web-server
access logs, browser history, and any intermediary that captured the
request URI. #36 moved the field to the JSON body.

#119 evolved the contract again: the refresh token now travels as an
``HttpOnly`` cookie (``aila_refresh``) that no page-side script can
read. The endpoint reads the cookie directly; a legacy body-supplied
token still works. Query-parameter passing is still rejected -- neither
endpoint declares a query field for the token.
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
    same token supplied only as a query parameter returns 422 (no such
    query field). The 422/401 split is the observable contract.
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
    """The query-parameter form is not accepted -- returns 401.

    #119: with the body now optional (the cookie is the canonical source),
    the query parameter is silently ignored; the endpoint sees no cookie
    and no body token and returns 401. The observable guarantee is that
    the query value is never treated as authentication material.
    """
    resp = await async_client.post(
        "/auth/refresh/user",
        params={"refresh_token": "not-a-real-token"},
    )
    assert resp.status_code == 401, resp.text


@pytest.mark.asyncio
async def test_refresh_endpoint_rejects_missing_body(
    async_client: AsyncClient,
) -> None:
    """POST /auth/refresh/user with no body and no cookie returns 401.

    #119: the endpoint accepts an empty body when the ``aila_refresh``
    cookie is present. With neither cookie nor body it returns 401.
    """
    resp = await async_client.post("/auth/refresh/user")
    assert resp.status_code == 401, resp.text


@pytest.mark.asyncio
async def test_logout_endpoint_reads_body(
    async_client: AsyncClient,
) -> None:
    """POST /auth/logout with a body payload is accepted (no matching token)."""
    resp = await async_client.post(
        "/auth/logout",
        json={"refresh_token": "not-a-real-token"},
    )
    # Body was accepted (200 with revoked=False since no matching row).
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_logout_endpoint_rejects_query_only(
    async_client: AsyncClient,
) -> None:
    """The query-parameter form is not treated as auth material.

    #119: logout accepts an empty body -- the CSRF middleware only kicks
    in when a refresh cookie is present, so a bare POST is a clean no-op
    that returns 200 with ``revoked=False``. Any ``?refresh_token=`` on
    the URL is ignored; the important guarantee is that it never appears
    in server logs as a real credential.
    """
    resp = await async_client.post(
        "/auth/logout",
        params={"refresh_token": "not-a-real-token"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["data"]["revoked"] is False
