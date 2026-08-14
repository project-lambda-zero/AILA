"""#119 -- CSRF double-submit enforcement on cookie-authenticated writes.

The refresh token now ships as an HttpOnly cookie so XSS cannot exfiltrate
it. That turns every cookie-authenticated mutating request into a live CSRF
surface -- :class:`aila.api.middleware.csrf.CSRFMiddleware` closes it by
requiring the ``X-CSRF-Token`` header to equal the ``aila_csrf`` cookie on
every ``POST``/``PUT``/``PATCH``/``DELETE`` that carries the refresh cookie.

Bearer-authenticated requests are exempt (the SPA's authenticated API
surface uses Bearer, which is unreachable cross-origin and therefore not
CSRF-susceptible).

We target ``POST /auth/logout`` because it is a mutating route that:
  * requires no valid credential to observe the CSRF gate (the endpoint
    returns 200 with ``revoked=False`` when the cookie value does not
    match any DB row);
  * is exactly the kind of cookie-authenticated route the middleware
    exists to defend.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from aila.api.middleware.csrf import (
    AILA_CSRF_COOKIE,
    AILA_REFRESH_COOKIE,
    CSRF_HEADER_NAME,
)


@pytest.mark.asyncio
async def test_csrf_mismatch_returns_403(async_client: AsyncClient) -> None:
    """Refresh cookie present + header mismatches cookie -> 403 csrf_invalid."""
    resp = await async_client.post(
        "/auth/logout",
        cookies={
            AILA_REFRESH_COOKIE: "opaque-refresh-value",
            AILA_CSRF_COOKIE: "canonical-token",
        },
        headers={CSRF_HEADER_NAME: "wrong-token"},
    )
    assert resp.status_code == 403, resp.text
    assert resp.json().get("code") == "csrf_invalid"


@pytest.mark.asyncio
async def test_csrf_missing_header_returns_403(async_client: AsyncClient) -> None:
    """Refresh cookie present + no X-CSRF-Token header -> 403 csrf_invalid."""
    resp = await async_client.post(
        "/auth/logout",
        cookies={
            AILA_REFRESH_COOKIE: "opaque-refresh-value",
            AILA_CSRF_COOKIE: "canonical-token",
        },
    )
    assert resp.status_code == 403, resp.text
    assert resp.json().get("code") == "csrf_invalid"


@pytest.mark.asyncio
async def test_csrf_match_passes(async_client: AsyncClient) -> None:
    """Refresh cookie present + header equals CSRF cookie -> handler runs (200)."""
    resp = await async_client.post(
        "/auth/logout",
        cookies={
            AILA_REFRESH_COOKIE: "opaque-refresh-value",
            AILA_CSRF_COOKIE: "canonical-token",
        },
        headers={CSRF_HEADER_NAME: "canonical-token"},
    )
    assert resp.status_code == 200, resp.text
    # Handler ran end-to-end; no matching DB row, so revoked=False.
    assert resp.json()["data"]["revoked"] is False


@pytest.mark.asyncio
async def test_csrf_no_session_cookie_passes(async_client: AsyncClient) -> None:
    """No refresh cookie -> middleware skips; bootstrap /auth/login stays reachable."""
    resp = await async_client.post(
        "/auth/login",
        json={"username": "does-not-exist", "password": "x"},
    )
    # Handler ran (returned 401 for unknown user); middleware did not 403 it.
    assert resp.status_code == 401, resp.text


@pytest.mark.asyncio
async def test_csrf_bearer_request_is_exempt(async_client: AsyncClient) -> None:
    """Authorization: Bearer request skips CSRF entirely, even with a refresh cookie."""
    resp = await async_client.post(
        "/auth/logout",
        cookies={
            AILA_REFRESH_COOKIE: "opaque-refresh-value",
            # Deliberately omit the CSRF cookie -- Bearer path must not care.
        },
        headers={"Authorization": "Bearer fake-token"},
    )
    # Handler ran end-to-end (no matching DB row).
    assert resp.status_code == 200, resp.text
