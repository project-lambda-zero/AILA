"""Wiring verification: route sweep and auto-discovery tests.

WIRE-01: Every registered route responds non-500 with admin auth.
WIRE-02: Vulnerability module routes appear under /vulnerability/*.
Public endpoints are accessible without auth.

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

# Routes to skip: SSE endpoints don't terminate cleanly in test, and
# OpenAPI/docs/redoc are static generated routes (not APIRoute instances
# or not meaningful for wiring checks).
_SKIP_PATHS: set[str] = {
    "/docs",
    "/redoc",
    "/openapi.json",
}

# SSE paths contain "/events" — they stream indefinitely and can't be
# tested with a simple request/response cycle.
_SSE_SUFFIX = "/events"

_PATH_PARAM_RE = re.compile(r"\{[^}]+\}")


def _dummy_path(path: str) -> str:
    """Replace path parameters like {run_id} with dummy values."""
    return _PATH_PARAM_RE.sub("nonexistent", path)


def _collect_routes() -> list[tuple[str, str]]:
    """Collect all (method, path) pairs from the app's registered routes.

    Returns a list of (HTTP_METHOD, path_template) tuples. Filters out
    non-APIRoute entries (Mount, static, etc.) and skips /docs/redoc/openapi.
    """
    app = create_app()
    pairs: list[tuple[str, str]] = []
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        path = route.path
        if path in _SKIP_PATHS:
            continue
        if path.endswith(_SSE_SUFFIX):
            continue
        for method in route.methods:
            pairs.append((method.upper(), path))
    return pairs


_ALL_ROUTES = _collect_routes()


# ---------------------------------------------------------------------------
# WIRE-01: Every registered route returns non-500 with admin auth
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("method,path", _ALL_ROUTES, ids=[f"{m} {p}" for m, p in _ALL_ROUTES])
async def test_every_registered_route_returns_non_500(
    test_db,
    admin_token: str,
    method: str,
    path: str,
) -> None:
    """Every registered route must respond with status != 500 when called
    with a valid admin Bearer token.

    Non-500 means the route resolves and the handler runs without crashing.
    404, 422, 401, 503, etc. are all acceptable — only 500 (unhandled
    exception) is a wiring failure.
    """
    import time

    from aila.api.app import create_app as _create_app

    app = _create_app()
    app.state.platform = None
    app.state.start_time = time.monotonic()

    url = _dummy_path(path)
    headers = {"Authorization": f"Bearer {admin_token}"}

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.request(method, url, headers=headers)

    assert response.status_code != 500, (
        f"{method} {path} -> {url} returned 500: {response.text[:300]}"
    )


# ---------------------------------------------------------------------------
# WIRE-02: Vulnerability module routes registered under /vulnerability/*
# ---------------------------------------------------------------------------

# Expected vulnerability routes from the module's api_router.py
_EXPECTED_VULN_PATHS: set[str] = {
    "/vulnerability/findings",
    "/vulnerability/findings/facets",
    "/vulnerability/findings/bulk",
    "/vulnerability/reports/{run_id}",
    "/vulnerability/reports/{run_id}/count",
    "/vulnerability/reports/{run_id}/explain",
}


def test_vulnerability_module_routes_registered() -> None:
    """All vulnerability module routes must be present in the app's route table.

    This proves _mount_module_routers auto-discovery works: the vulnerability
    module's route_specs() is called and each ModuleRouteSpec.router_factory()
    router is included with the /vulnerability prefix.
    """
    app = create_app()
    registered_paths: set[str] = set()
    for route in app.routes:
        if isinstance(route, APIRoute):
            registered_paths.add(route.path)

    missing = _EXPECTED_VULN_PATHS - registered_paths
    assert not missing, f"Missing vulnerability routes: {sorted(missing)}"


# ---------------------------------------------------------------------------
# Public endpoints accessible without auth
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_public_endpoints_accessible_without_auth(
    async_client: AsyncClient,
) -> None:
    """GET /health and GET /status return 200 without auth.
    POST /auth/token returns 401 or 422 (not 500) without body.
    """
    # GET /health — no auth needed
    resp_health = await async_client.get("/health")
    assert resp_health.status_code == 200, f"/health returned {resp_health.status_code}"

    # GET /status — no auth needed
    resp_status = await async_client.get("/status")
    assert resp_status.status_code == 200, f"/status returned {resp_status.status_code}"

    # POST /auth/token — public endpoint, but requires body; expect 422 (missing body)
    # or 401 (invalid key). Either way, NOT 500.
    resp_token = await async_client.post("/auth/token")
    assert resp_token.status_code in (401, 422), (
        f"POST /auth/token without body returned {resp_token.status_code}, expected 401 or 422"
    )
