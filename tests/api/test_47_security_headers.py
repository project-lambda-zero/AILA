"""#47 -- SecurityHeadersMiddleware attaches a defensive-baseline header set.

Every response (success, 4xx, 5xx) MUST carry the security headers so a
browser gets the layered protection whether the request hit an endpoint,
a validation failure, or a missing route.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from aila.api.middleware.security_headers import default_security_headers

_EXPECTED = default_security_headers()


@pytest.mark.asyncio
async def test_health_endpoint_carries_all_security_headers(
    async_client: AsyncClient,
) -> None:
    """The public /health endpoint is a stable target -- every response
    MUST carry the entire security-header baseline."""
    resp = await async_client.get("/health")
    assert resp.status_code == 200, resp.text
    for name, expected in _EXPECTED.items():
        assert resp.headers.get(name) == expected, (
            f"missing or wrong {name}: got {resp.headers.get(name)!r}, "
            f"expected {expected!r}"
        )


@pytest.mark.asyncio
async def test_headers_present_on_404(async_client: AsyncClient) -> None:
    """A missing-route 404 MUST also carry the baseline -- error pages
    are the exact case where a browser is most likely to try to render
    the response as HTML."""
    resp = await async_client.get("/this-route-does-not-exist-47")
    assert resp.status_code == 404
    for name in _EXPECTED:
        assert name in resp.headers, f"missing {name} on 404"


@pytest.mark.asyncio
async def test_csp_default_denies_everything(async_client: AsyncClient) -> None:
    """The default API CSP MUST be locked down -- default-src 'none' plus
    frame-ancestors 'none' means even a mis-served JSON body cannot fetch
    or embed anything."""
    resp = await async_client.get("/health")
    csp = resp.headers.get("Content-Security-Policy", "")
    assert "default-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp


@pytest.mark.asyncio
async def test_middleware_respects_existing_response_headers(
    async_client: AsyncClient,
) -> None:
    """Middleware MUST NOT overwrite a header a downstream handler set.
    We verify the correlation-id header (set by CorrelationIdMiddleware)
    survives the security-headers pass untouched."""
    resp = await async_client.get(
        "/health", headers={"X-Correlation-ID": "cid-47-test"}
    )
    assert resp.headers.get("X-Correlation-ID") == "cid-47-test"
