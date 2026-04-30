"""RBAC matrix verification for the AILA API (WIRE-04).

Proves that role-based access control is wired correctly by making real
requests with admin/operator/reader JWT tokens and asserting the expected
200/403 response pattern on every endpoint.

Key assertion per row:
- caller_role >= min_role  ->  status_code != 403 (200/201/204/404/409/422/503 all OK)
- caller_role <  min_role  ->  status_code == 403
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import AsyncClient

# ---------------------------------------------------------------------------
# RBAC matrix: (method, path, body, min_role, description)
#
# min_role is the minimum role that should NOT get 403.
# "admin"    -> only admin succeeds, operator and reader get 403
# "operator" -> admin and operator succeed, reader gets 403
# "reader"   -> all three succeed (any authenticated user)
# ---------------------------------------------------------------------------

RBAC_MATRIX: list[tuple[str, str, dict | None, str, str]] = [
    # ── Admin-only endpoints ────────────────────────────────────────────────
    ("POST", "/auth/keys", {"role": "reader", "label": "rbac-test"}, "admin", "create API key"),
    ("GET", "/auth/keys", None, "admin", "list API keys"),
    ("DELETE", "/auth/keys/nonexistent-id", None, "admin", "revoke API key"),
    ("PUT", "/config/test-ns/test-key", {"value": "x", "value_type": "str"}, "admin", "update config value"),

    # ── Operator+ endpoints ─────────────────────────────────────────────────
    ("POST", "/analyze", {"query_text": "scan", "targets": ["x"]}, "operator", "submit scan"),
    ("POST", "/task", {"query_text": "test"}, "operator", "submit freeform task"),
    ("POST", "/systems", {"name": "rbac-test", "host": "1.2.3.4", "username": "u", "port": 22, "distro": "ubuntu"}, "operator", "register system"),
    ("PUT", "/systems/999", {"name": "updated"}, "operator", "update system"),
    ("DELETE", "/systems/999", None, "operator", "delete system"),
    ("POST", "/tools/nonexistent", {"kwargs": {}}, "operator", "invoke tool"),
    ("PATCH", "/vulnerability/findings/bulk", {"finding_ids": [], "status": "open"}, "operator", "bulk update findings"),

    # ── Reader+ endpoints (any authenticated role) ──────────────────────────
    ("GET", "/audit/events", None, "reader", "list audit events"),
    ("GET", "/config", None, "reader", "list all config"),
    ("GET", "/systems", None, "reader", "list systems"),
    ("GET", "/tasks", None, "reader", "list tasks"),
    ("GET", "/vulnerability/findings", None, "reader", "list vulnerability findings"),
    # cancel/resume use require_api_key (reader+), not require_role("operator")
    ("POST", "/tasks/nonexistent/cancel", None, "reader", "cancel task"),
    ("POST", "/tasks/nonexistent/resume", None, "reader", "resume task"),
]

ROLE_LEVELS: dict[str, int] = {"reader": 0, "operator": 1, "admin": 2}
ALL_ROLES = ["admin", "operator", "reader"]


def _build_test_ids() -> list[str]:
    """Build readable test IDs for parametrize."""
    ids = []
    for method, path, _body, min_role, desc in RBAC_MATRIX:
        for role in ALL_ROLES:
            expected = "pass" if ROLE_LEVELS[role] >= ROLE_LEVELS[min_role] else "403"
            ids.append(f"{role}-{method}-{path}-{expected}-{desc}")
    return ids


def _build_test_params() -> list[tuple[str, str, dict | None, str, str]]:
    """Expand matrix: each row x each role = one test case."""
    params = []
    for method, path, body, min_role, desc in RBAC_MATRIX:
        for role in ALL_ROLES:
            params.append((method, path, body, min_role, role))
    return params


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "path", "body", "min_role", "caller_role"),
    _build_test_params(),
    ids=_build_test_ids(),
)
async def test_rbac_matrix(
    async_client: AsyncClient,
    admin_token: str,
    operator_token: str,
    reader_token: str,
    method: str,
    path: str,
    body: dict | None,
    min_role: str,
    caller_role: str,
) -> None:
    """Verify correct 200/403 response for each (role, endpoint) pair."""
    token_map = {
        "admin": admin_token,
        "operator": operator_token,
        "reader": reader_token,
    }
    token = token_map[caller_role]
    headers = {"Authorization": f"Bearer {token}"}

    kwargs: dict = {"headers": headers}
    if body is not None:
        kwargs["json"] = body

    response = await async_client.request(method, path, **kwargs)

    caller_level = ROLE_LEVELS[caller_role]
    required_level = ROLE_LEVELS[min_role]

    if caller_level >= required_level:
        # Authorized: any non-403 is correct (200, 201, 204, 404, 409, 422, 503)
        assert response.status_code != 403, (
            f"{caller_role} should access {method} {path} (min_role={min_role}) "
            f"but got 403: {response.text}"
        )
    else:
        # Unauthorized: must be 403
        assert response.status_code == 403, (
            f"{caller_role} should be blocked from {method} {path} (min_role={min_role}) "
            f"but got {response.status_code}: {response.text}"
        )
