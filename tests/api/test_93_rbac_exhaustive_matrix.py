"""RBAC exhaustive matrix -- Phase 93 (XCUT-01).

Tests every API endpoint (42 total) against every role dimension
(admin, operator, reader, no-auth) for a total of 168 parametrized cases.

Assertions per cell:
- Public endpoints: any caller (including no-auth) should NOT get 403.
  They may return 401 from business logic (e.g. invalid key) but never
  from auth middleware.
- Protected reader+ endpoints:
    admin/operator/reader -> status != 403  (200/201/204/404/409/422/503 all OK)
    no-auth              -> status == 401
- Protected operator+ endpoints:
    admin/operator       -> status != 403
    reader               -> status == 403
    no-auth              -> status == 401
- Protected admin-only endpoints:
    admin                -> status != 403
    operator/reader      -> status == 403
    no-auth              -> status == 401

NOTE: Many endpoints return 404, 422, 409, 503 with synthetic IDs or
platform=None.  That is expected -- the test proves *authorization*
decisions, not business logic.  A 404 or 503 after auth passes is correct.
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient

# ---------------------------------------------------------------------------
# Role hierarchy levels (mirrors auth.py ROLE_LEVELS)
# ---------------------------------------------------------------------------
ROLE_LEVELS: dict[str, int] = {"reader": 0, "operator": 1, "admin": 2}
ALL_ROLES: list[str] = ["admin", "operator", "reader", "no-auth"]

# ---------------------------------------------------------------------------
# Exhaustive endpoint inventory
#
# (method, path, body, min_role, description)
#
# min_role semantics:
#   "public"   -> no auth required, all callers including no-auth succeed
#   "reader"   -> any authenticated role succeeds, no-auth gets 401
#   "operator" -> admin+operator succeed, reader gets 403, no-auth gets 401
#   "admin"    -> only admin succeeds, operator+reader get 403, no-auth 401
# ---------------------------------------------------------------------------
RBAC_MATRIX: list[tuple[str, str, dict | None, str, str]] = [
    # ── Public endpoints (no auth required) ───────────────────────────────
    ("GET", "/health", None, "public", "health check"),
    ("GET", "/status", None, "public", "status check"),
    ("POST", "/auth/token", {"api_key": "aila_sk_nonexistent000000000000000000"}, "public", "exchange key for JWT"),
    ("POST", "/auth/refresh", {"refresh_token": "invalid.jwt.token"}, "public", "refresh token"),

    # ── Admin-only endpoints ──────────────────────────────────────────────
    ("POST", "/auth/keys", {"role": "reader", "label": "rbac-test"}, "admin", "create API key"),
    ("GET", "/auth/keys", None, "admin", "list API keys"),
    ("DELETE", "/auth/keys/nonexistent-id", None, "admin", "revoke API key"),
    ("PUT", "/config/test-ns/test-key", {"value": "x"}, "admin", "update config value"),

    # ── Operator+ endpoints ───────────────────────────────────────────────
    ("POST", "/analyze", {"query_text": "scan", "targets": ["x"]}, "operator", "submit scan"),
    ("POST", "/task", {"query_text": "test"}, "operator", "submit freeform task"),
    ("POST", "/systems", {"name": "rbac-sys", "host": "1.2.3.4", "username": "u", "port": 22, "distro": "ubuntu"}, "operator", "register system"),
    ("PUT", "/systems/999", {"name": "updated"}, "operator", "update system"),
    ("DELETE", "/systems/999", None, "operator", "delete system"),
    ("POST", "/tools/nonexistent.tool", {"kwargs": {}}, "operator", "invoke tool"),
    ("PATCH", "/vulnerability/findings/bulk", {"finding_ids": [], "status": "open"}, "operator", "bulk update findings"),

    # ── Reader+ endpoints (any authenticated role) ────────────────────────
    # Audit
    ("GET", "/audit/events", None, "reader", "list audit events"),
    ("GET", "/audit/events/run-nonexistent", None, "reader", "get audit events for run"),

    # Config
    ("GET", "/config", None, "reader", "list all config"),
    ("GET", "/config/test-ns", None, "reader", "list namespace config"),
    ("GET", "/config/test-ns/test-key", None, "reader", "get config value"),

    # Systems
    ("GET", "/systems", None, "reader", "list systems"),
    ("GET", "/systems/999", None, "reader", "get system detail"),
    ("GET", "/systems/999/findings", None, "reader", "get system findings"),
    ("GET", "/systems/999/scans", None, "reader", "get system scans"),

    # Tasks
    ("GET", "/tasks", None, "reader", "list tasks"),
    ("GET", "/tasks/nonexistent-task", None, "reader", "get single task"),
    ("POST", "/tasks/nonexistent-task/cancel", None, "reader", "cancel task"),
    ("POST", "/tasks/nonexistent-task/resume", None, "reader", "resume task"),
    ("GET", "/tasks/nonexistent-task/events", None, "reader", "stream task events"),

    # Tools
    ("GET", "/tools", None, "reader", "list tools"),
    ("GET", "/tools/nonexistent.tool", None, "reader", "get tool detail"),

    # Sessions
    ("POST", "/sessions", {"title": "rbac-test"}, "reader", "create session"),
    ("POST", "/sessions/nonexistent-session/messages", {"content": "hello"}, "reader", "post session message"),
    ("GET", "/sessions/nonexistent-session/messages", None, "reader", "get session messages"),

    # Scans
    ("GET", "/scans/nonexistent-run", None, "reader", "get scan status"),
    ("GET", "/scans/nonexistent-run/events", None, "reader", "stream scan events"),

    # Hello World module (auto-discovered)
    ("GET", "/hello_world/status", None, "reader", "hello_world module status"),

    # Vulnerability module
    ("GET", "/vulnerability/findings", None, "reader", "list vulnerability findings"),
    ("GET", "/vulnerability/findings/facets", None, "reader", "get findings facets"),
    ("GET", "/vulnerability/reports/nonexistent-run", None, "reader", "get vulnerability report"),
    ("GET", "/vulnerability/reports/nonexistent-run/count", None, "reader", "get report count"),
    ("GET", "/vulnerability/reports/nonexistent-run/explain", None, "reader", "get report explain"),
]


def _build_params() -> list[tuple[str, str, dict | None, str, str, str]]:
    """Expand matrix: each row x each role = one test case."""
    params = []
    for method, path, body, min_role, desc in RBAC_MATRIX:
        for role in ALL_ROLES:
            params.append((method, path, body, min_role, role, desc))
    return params


def _build_ids() -> list[str]:
    """Build readable parametrize IDs."""
    ids = []
    for method, path, _body, min_role, desc in RBAC_MATRIX:
        for role in ALL_ROLES:
            if min_role == "public":
                expected = "ok"
            elif role == "no-auth":
                expected = "401"
            elif min_role in ROLE_LEVELS and role in ROLE_LEVELS:
                expected = "ok" if ROLE_LEVELS[role] >= ROLE_LEVELS[min_role] else "403"
            else:
                expected = "ok"
            ids.append(f"{role}|{method}|{path}|{expected}|{desc}")
    return ids


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "path", "body", "min_role", "caller_role", "desc"),
    _build_params(),
    ids=_build_ids(),
)
async def test_rbac_exhaustive_matrix(
    async_client: AsyncClient,
    admin_token: str,
    operator_token: str,
    reader_token: str,
    method: str,
    path: str,
    body: dict | None,
    min_role: str,
    caller_role: str,
    desc: str,
) -> None:
    """Verify correct auth/role response for each (role, endpoint) cell.

    168 parametrized cases covering all 42 endpoints x 4 role dimensions.
    """
    token_map: dict[str, str | None] = {
        "admin": admin_token,
        "operator": operator_token,
        "reader": reader_token,
        "no-auth": None,
    }
    token = token_map[caller_role]

    headers: dict[str, str] = {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"

    kwargs: dict = {"headers": headers}
    if body is not None:
        kwargs["json"] = body

    response = await async_client.request(method, path, **kwargs)

    # ── Public endpoints: reachable without auth middleware blocking ──────
    # Public endpoints never return 403 (role-based denial).  They may
    # return 401 from *business logic* (e.g. POST /auth/token with an
    # invalid key returns 401 because the key is wrong, not because auth
    # middleware blocked the request).  The test proves no auth gate fired.
    if min_role == "public":
        assert response.status_code != 403, (
            f"Public endpoint {method} {path} ({desc}) must not return 403 "
            f"but {caller_role} got 403: {response.text[:200]}"
        )
        return

    # ── Protected endpoints ───────────────────────────────────────────────
    if caller_role == "no-auth":
        # No Bearer header -> must be 401
        assert response.status_code == 401, (
            f"No-auth request to {method} {path} ({desc}) should get 401 "
            f"but got {response.status_code}: {response.text[:200]}"
        )
        return

    # Authenticated caller
    caller_level = ROLE_LEVELS[caller_role]
    required_level = ROLE_LEVELS[min_role]

    if caller_level >= required_level:
        # Authorized: must NOT be 403 (any other status is fine)
        assert response.status_code != 403, (
            f"{caller_role} should access {method} {path} ({desc}, min_role={min_role}) "
            f"but got 403: {response.text[:200]}"
        )
    else:
        # Insufficient role: must be 403
        assert response.status_code == 403, (
            f"{caller_role} should be blocked from {method} {path} ({desc}, min_role={min_role}) "
            f"but got {response.status_code}: {response.text[:200]}"
        )
