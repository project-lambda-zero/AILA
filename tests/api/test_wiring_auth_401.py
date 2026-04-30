"""Wiring verification: auth 401 sweep for all protected endpoints.

WIRE-03: Every protected endpoint returns 401 when called without a Bearer token.

Uses httpx.AsyncClient + ASGITransport (D-11), real DB (D-12).
"""
from __future__ import annotations

import re

import pytest
from fastapi.routing import APIRoute
from httpx import ASGITransport, AsyncClient

from aila.api.app import create_app

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Public endpoints that must NOT require auth
_PUBLIC_PATHS: set[str] = {
    "/health",
    "/status",
    "/auth/token",
    "/auth/refresh",
    "/docs",
    "/redoc",
    "/openapi.json",
}

# SSE endpoints stream indefinitely and cannot be tested with a simple
# request/response cycle. They are excluded from this sweep.
_SSE_SUFFIX = "/events"

_PATH_PARAM_RE = re.compile(r"\{[^}]+\}")


def _dummy_path(path: str) -> str:
    """Replace path parameters like {run_id} with dummy values."""
    return _PATH_PARAM_RE.sub("nonexistent", path)


def _collect_protected_routes() -> list[tuple[str, str]]:
    """Collect all (method, path) pairs for protected routes.

    Protected = everything except the known public paths.
    Skips SSE endpoints (they stream indefinitely).
    """
    app = create_app()
    pairs: list[tuple[str, str]] = []
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        path = route.path
        if path in _PUBLIC_PATHS:
            continue
        if path.endswith(_SSE_SUFFIX):
            continue
        for method in route.methods:
            pairs.append((method.upper(), path))
    return pairs


_PROTECTED_ROUTES = _collect_protected_routes()


# ---------------------------------------------------------------------------
# WIRE-03: Every protected endpoint returns 401 without Bearer token
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method,path",
    _PROTECTED_ROUTES,
    ids=[f"{m} {p}" for m, p in _PROTECTED_ROUTES],
)
async def test_protected_endpoint_returns_401_without_bearer(
    test_db,
    method: str,
    path: str,
) -> None:
    """Every protected endpoint must return 401 when called without
    an Authorization header.

    This proves that auth wiring (HTTPBearer + require_api_key) is
    applied correctly on every non-public route.
    """
    import time

    from aila.api.app import create_app as _create_app

    app = _create_app()
    app.state.platform = None
    app.state.start_time = time.monotonic()

    url = _dummy_path(path)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.request(method, url)

    assert response.status_code == 401, (
        f"{method} {path} -> {url} returned {response.status_code}, expected 401. "
        f"Body: {response.text[:300]}"
    )
