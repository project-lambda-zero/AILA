"""GET /config/platform/schema and the platform write gate (#246)."""
from __future__ import annotations

import time
import uuid
from collections.abc import AsyncGenerator, Iterator
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from aila.api import platform_onboarding
from aila.api.app import create_app
from aila.api.auth import AuthContext, require_user_or_api_key
from aila.platform.config import PlatformConfigSchema
from aila.platform.runtime.tools import ToolRegistry
from aila.storage.registry import ConfigRegistry

_SCHEMA_URL = "/config/platform/schema"
_PINNED_ENV_KEYS = (
    "AILA_PLATFORM_SANDBOX_BACKEND",
    "AILA_PLATFORM_SANDBOX_SSH_HOST",
    "AILA_PLATFORM_SYMBOLIC_ENABLED",
    "AILA_PLATFORM_DYNAMIC_EXECUTION_ENABLED",
    "AILA_PLATFORM_SPECULATIVE_ENABLED",
    "AILA_PLATFORM_ONBOARDING_COMPLETED",
    "AILA_PLATFORM_RETRIEVAL_BACKEND_VOYAGE_API_KEY",
)


@pytest.fixture(autouse=True)
def _clear_platform_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for env_key in _PINNED_ENV_KEYS:
        monkeypatch.delenv(env_key, raising=False)
    yield


@pytest_asyncio.fixture(scope="function")
async def platform_app(test_db):
    config_registry = ConfigRegistry()
    await config_registry.register("platform", PlatformConfigSchema)

    stub_runtime = MagicMock()
    stub_runtime.config_registry = config_registry
    stub_runtime.tool_registry = ToolRegistry()
    stub_platform = MagicMock()
    stub_platform.runtime = stub_runtime

    app = create_app()
    app.state.platform = stub_platform
    app.state.start_time = time.monotonic()
    return app


@pytest_asyncio.fixture(scope="function")
async def client(platform_app) -> AsyncGenerator[AsyncClient, None]:
    async with AsyncClient(transport=ASGITransport(app=platform_app), base_url="http://testserver") as c:
        yield c


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _entries(body: dict) -> dict[str, dict]:
    return {entry["key"]: entry for entry in body["entries"]}


@pytest.mark.asyncio
async def test_schema_route_is_not_shadowed_and_describes_entries(
    client: AsyncClient, admin_token: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AILA_PLATFORM_SPECULATIVE_ENABLED", "true")
    resp = await client.get(_SCHEMA_URL, headers=_auth(admin_token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["onboarding_completed"] is False
    entries = _entries(body)
    assert {"vr_lateral_llm_enabled", "vr_explorer_enabled", "sandbox_backend", "symbolic_enabled"} <= set(entries)
    for entry in entries.values():
        assert entry["description"].strip(), entry["key"]
        assert entry["effective_source"] in {"env", "db", "default"}
        assert entry["category"] in {"capability", "infra", "operational"}
    lateral = entries["vr_lateral_llm_enabled"]
    assert lateral["value_type"] == "bool"
    assert lateral["default_value"] == "False"
    assert lateral["description"] == PlatformConfigSchema.model_fields["vr_lateral_llm_enabled"].description
    speculative = entries["speculative_enabled"]
    assert speculative["effective_source"] == "env"
    assert speculative["overridden_by_env"] is True
    assert speculative["env_key"] == "AILA_PLATFORM_SPECULATIVE_ENABLED"
    assert entries["sandbox_backend"]["choices"] == ["none", "nsjail", "firecracker"]
    assert entries["llm_kill_switch"]["read_only"] is True
    assert entries["vr_lateral_llm_enabled"]["read_only"] is False


@pytest.mark.asyncio
async def test_secret_keys_never_return_values(client: AsyncClient, admin_token: str) -> None:
    secret = f"sk-onboarding-{uuid.uuid4().hex}"
    put = await client.put(
        "/config/platform/retrieval_backend_voyage_api_key",
        json={"value": secret},
        headers=_auth(admin_token),
    )
    assert put.status_code == 200, put.text
    resp = await client.get(_SCHEMA_URL, headers=_auth(admin_token))
    assert resp.status_code == 200
    assert secret not in resp.text
    voyage = _entries(resp.json())["retrieval_backend_voyage_api_key"]
    assert voyage["secret"] is True
    assert voyage["effective_value"] is None
    assert voyage["default_value"] is None
    assert voyage["is_set"] is True
    assert voyage["prerequisite"]["ok"] is True
    jina = _entries(resp.json())["retrieval_backend_jina_api_key"]
    assert jina["is_set"] is False
    assert jina["prerequisite"]["ok"] is False


@pytest.mark.asyncio
async def test_symbolic_enable_blocked_without_miasm(
    client: AsyncClient, admin_token: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(platform_onboarding, "find_spec", lambda name: None)
    resp = await client.put(
        "/config/platform/symbolic_enabled", json={"value": "true"}, headers=_auth(admin_token),
    )
    assert resp.status_code == 422
    assert "miasm" in resp.json()["detail"]
    assert "pip install .[symbolic]" in resp.json()["detail"]
    schema = await client.get(_SCHEMA_URL, headers=_auth(admin_token))
    symbolic = _entries(schema.json())["symbolic_enabled"]
    assert symbolic["prerequisite"]["ok"] is False
    assert symbolic["effective_value"] == "False"
    disable = await client.put(
        "/config/platform/symbolic_enabled", json={"value": "false"}, headers=_auth(admin_token),
    )
    assert disable.status_code == 200, disable.text


@pytest.mark.asyncio
async def test_dynamic_execution_blocked_without_sandbox_backend(client: AsyncClient, admin_token: str) -> None:
    resp = await client.put(
        "/config/platform/dynamic_execution_enabled", json={"value": "true"}, headers=_auth(admin_token),
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert "sandbox_backend is 'none'" in detail
    assert "Sandbox page" in detail


@pytest.mark.asyncio
async def test_sandbox_backend_rejects_unknown_value(client: AsyncClient, admin_token: str) -> None:
    bad = await client.put("/config/platform/sandbox_backend", json={"value": "docker"}, headers=_auth(admin_token))
    assert bad.status_code == 422
    assert "none, nsjail, firecracker" in bad.json()["detail"]
    good = await client.put("/config/platform/sandbox_backend", json={"value": "nsjail"}, headers=_auth(admin_token))
    assert good.status_code == 200, good.text
    assert good.json()["effective_value"] == "nsjail"


@pytest.mark.asyncio
async def test_onboarding_completed_round_trips(client: AsyncClient, admin_token: str) -> None:
    put = await client.put(
        "/config/platform/onboarding_completed", json={"value": "true"}, headers=_auth(admin_token),
    )
    assert put.status_code == 200, put.text
    resp = await client.get(_SCHEMA_URL, headers=_auth(admin_token))
    assert resp.json()["onboarding_completed"] is True


@pytest.mark.asyncio
async def test_schema_rejects_non_admin(client: AsyncClient, reader_token: str, operator_token: str) -> None:
    for token in (reader_token, operator_token):
        resp = await client.get(_SCHEMA_URL, headers=_auth(token))
        assert resp.status_code == 403


@pytest.mark.asyncio
async def test_schema_rejects_team_scoped_admin(platform_app) -> None:
    team_admin = AuthContext(user_id="team-admin", role="admin", auth_type="user", team_id=f"team-{uuid.uuid4().hex}")
    platform_app.dependency_overrides[require_user_or_api_key] = lambda: team_admin
    async with AsyncClient(transport=ASGITransport(app=platform_app), base_url="http://testserver") as c:
        resp = await c.get(_SCHEMA_URL)
    assert resp.status_code == 403
    assert "god-tier" in resp.json()["detail"]
