"""Unit tests for aila.platform.llm.config.

Uses lightweight fakes for ConfigRegistry and SecretStore -- no DB needed.
The config resolvers are async (they await registry.get and secret_store
resolve_provider_secret), so the fakes expose async methods and each test
awaits the resolver under test.
"""

from __future__ import annotations

import pytest

from aila.platform.llm.config import LLMConfigProvider, LLMRouting
from aila.platform.llm.errors import LLMError

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class FakeRegistry:
    """In-memory ConfigRegistry fake that stores values in a dict."""

    def __init__(self, data: dict[str, object] | None = None) -> None:
        self._data: dict[str, object] = data or {}

    async def get(self, namespace: str, key: str) -> object:
        return self._data.get(f"{namespace}.{key}")

    def set(self, namespace: str, key: str, value: str) -> None:
        self._data[f"{namespace}.{key}"] = value


class FakeSecretStore:
    """In-memory SecretStore fake."""

    def __init__(self, secrets: dict[str, str] | None = None) -> None:
        self._secrets: dict[str, str] = secrets or {}

    async def resolve_provider_secret(self, secret_key: str) -> str | None:
        return self._secrets.get(secret_key)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def provider() -> LLMConfigProvider:
    """Provider with empty registry and no secrets."""
    return LLMConfigProvider(
        registry=FakeRegistry(),  # type: ignore[arg-type]
        secret_store=FakeSecretStore(),  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# API Key Resolution (D-05)
# ---------------------------------------------------------------------------

class TestResolveApiKey:
    """API key resolution: SecretStore > env var > None."""

    async def test_from_secret_store(self) -> None:
        store = FakeSecretStore({"openai_api_key": "sk-secret-123"})
        p = LLMConfigProvider(FakeRegistry(), store)  # type: ignore[arg-type]
        assert await p.resolve_api_key() == "sk-secret-123"

    async def test_from_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-env-456")
        p = LLMConfigProvider(FakeRegistry(), FakeSecretStore())  # type: ignore[arg-type]
        assert await p.resolve_api_key() == "sk-env-456"

    async def test_secret_store_wins_over_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-env")
        store = FakeSecretStore({"openai_api_key": "sk-db"})
        p = LLMConfigProvider(FakeRegistry(), store)  # type: ignore[arg-type]
        assert await p.resolve_api_key() == "sk-db"

    async def test_returns_none_when_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        p = LLMConfigProvider(FakeRegistry(), FakeSecretStore())  # type: ignore[arg-type]
        assert await p.resolve_api_key() is None


# ---------------------------------------------------------------------------
# Model Routing (D-06)
# ---------------------------------------------------------------------------

_FALLBACK_MODEL = "antigravity/claude-opus-4-6-thinking"


class TestResolveModel:
    """Model routing: task-specific > default > hardcoded fallback."""

    async def test_task_specific_model(self) -> None:
        reg = FakeRegistry({"platform.llm_model_scoring": "anthropic/claude-haiku-4-5-20251001"})
        p = LLMConfigProvider(reg, FakeSecretStore())  # type: ignore[arg-type]
        assert await p.resolve_model("scoring") == "anthropic/claude-haiku-4-5-20251001"

    async def test_default_model_fallback(self) -> None:
        reg = FakeRegistry({"platform.llm_default_model": "openai/gpt-4o"})
        p = LLMConfigProvider(reg, FakeSecretStore())  # type: ignore[arg-type]
        assert await p.resolve_model("unknown_task") == "openai/gpt-4o"

    async def test_hardcoded_fallback(self, provider: LLMConfigProvider) -> None:
        assert await provider.resolve_model("anything") == _FALLBACK_MODEL

    async def test_empty_string_treated_as_missing(self) -> None:
        reg = FakeRegistry({"platform.llm_model_scoring": ""})
        p = LLMConfigProvider(reg, FakeSecretStore())  # type: ignore[arg-type]
        assert await p.resolve_model("scoring") == _FALLBACK_MODEL

    async def test_open_ended_routing(self) -> None:
        """Any task_type string maps to any model_id (per D-04, D-06)."""
        reg = FakeRegistry({
            "platform.llm_model_custom_task_xyz": "meta-llama/llama-3-70b",
        })
        p = LLMConfigProvider(reg, FakeSecretStore())  # type: ignore[arg-type]
        assert await p.resolve_model("custom_task_xyz") == "meta-llama/llama-3-70b"


# ---------------------------------------------------------------------------
# Base URL (D-07)
# ---------------------------------------------------------------------------

class TestResolveBaseUrl:
    """Base URL resolution."""

    async def test_default_openrouter(self, provider: LLMConfigProvider) -> None:
        assert await provider.resolve_base_url() == "https://openrouter.ai/api/v1"

    async def test_custom_url(self) -> None:
        reg = FakeRegistry({"platform.llm_base_url": "http://localhost:11434/v1"})
        p = LLMConfigProvider(reg, FakeSecretStore())  # type: ignore[arg-type]
        assert await p.resolve_base_url() == "http://localhost:11434/v1"


# ---------------------------------------------------------------------------
# Max Tokens
# ---------------------------------------------------------------------------

class TestResolveMaxTokens:
    """Max tokens resolution."""

    async def test_default_4096(self, provider: LLMConfigProvider) -> None:
        assert await provider.resolve_max_tokens("scoring") == 4096

    async def test_task_specific(self) -> None:
        reg = FakeRegistry({"platform.llm_max_tokens_scoring": 8192})
        p = LLMConfigProvider(reg, FakeSecretStore())  # type: ignore[arg-type]
        assert await p.resolve_max_tokens("scoring") == 8192

    async def test_default_override(self) -> None:
        reg = FakeRegistry({"platform.llm_default_max_tokens": 2048})
        p = LLMConfigProvider(reg, FakeSecretStore())  # type: ignore[arg-type]
        assert await p.resolve_max_tokens("anything") == 2048


# ---------------------------------------------------------------------------
# Temperature
# ---------------------------------------------------------------------------

class TestResolveTemperature:
    """Temperature resolution."""

    async def test_default_zero(self, provider: LLMConfigProvider) -> None:
        assert await provider.resolve_temperature("scoring") == 0.0

    async def test_task_specific(self) -> None:
        reg = FakeRegistry({"platform.llm_temperature_scoring": 0.7})
        p = LLMConfigProvider(reg, FakeSecretStore())  # type: ignore[arg-type]
        assert await p.resolve_temperature("scoring") == 0.7


# ---------------------------------------------------------------------------
# Max Tool Steps (D-20)
# ---------------------------------------------------------------------------

class TestResolveMaxToolSteps:
    """Tool loop max_steps -- no hardcoded default, returns 0 if not set."""

    async def test_default_zero(self, provider: LLMConfigProvider) -> None:
        assert await provider.resolve_max_tool_steps("scoring") == 0

    async def test_configured(self) -> None:
        reg = FakeRegistry({"platform.llm_max_tool_steps_scoring": 5})
        p = LLMConfigProvider(reg, FakeSecretStore())  # type: ignore[arg-type]
        assert await p.resolve_max_tool_steps("scoring") == 5


# ---------------------------------------------------------------------------
# Kill Switch (D-08)
# ---------------------------------------------------------------------------

class TestIsDisabled:
    """Kill switch."""

    async def test_default_not_disabled(self, provider: LLMConfigProvider) -> None:
        assert await provider.is_disabled() is False

    async def test_disabled_true(self) -> None:
        reg = FakeRegistry({"platform.llm_kill_switch": True})
        p = LLMConfigProvider(reg, FakeSecretStore())  # type: ignore[arg-type]
        assert await p.is_disabled() is True

    async def test_disabled_string_true(self) -> None:
        reg = FakeRegistry({"platform.llm_kill_switch": "true"})
        p = LLMConfigProvider(reg, FakeSecretStore())  # type: ignore[arg-type]
        assert await p.is_disabled() is True

    async def test_disabled_string_false(self) -> None:
        reg = FakeRegistry({"platform.llm_kill_switch": "false"})
        p = LLMConfigProvider(reg, FakeSecretStore())  # type: ignore[arg-type]
        assert await p.is_disabled() is False


# ---------------------------------------------------------------------------
# Full Routing Resolution
# ---------------------------------------------------------------------------

class TestResolveRouting:
    """resolve_routing() combines all resolvers."""

    async def test_full_routing(self) -> None:
        store = FakeSecretStore({"openai_api_key": "sk-test"})
        reg = FakeRegistry({
            "platform.llm_model_scoring": "anthropic/claude-haiku-4-5-20251001",
            "platform.llm_base_url": "https://openrouter.ai/api/v1",
            "platform.llm_max_tokens_scoring": 8192,
            "platform.llm_temperature_scoring": 0.1,
            "platform.llm_max_tool_steps_scoring": 3,
        })
        p = LLMConfigProvider(reg, store)  # type: ignore[arg-type]
        routing = await p.resolve_routing("scoring")
        assert isinstance(routing, LLMRouting)
        assert routing.model_id == "anthropic/claude-haiku-4-5-20251001"
        assert routing.api_key == "sk-test"
        assert routing.max_tokens == 8192
        assert routing.temperature == 0.1
        assert routing.max_tool_steps == 3

    async def test_routing_frozen(self) -> None:
        store = FakeSecretStore({"openai_api_key": "sk-test"})
        p = LLMConfigProvider(FakeRegistry(), store)  # type: ignore[arg-type]
        routing = await p.resolve_routing("scoring")
        with pytest.raises(AttributeError):
            routing.model_id = "other"  # type: ignore[misc]

    async def test_routing_raises_without_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        p = LLMConfigProvider(FakeRegistry(), FakeSecretStore())  # type: ignore[arg-type]
        with pytest.raises(LLMError, match="No API key configured"):
            await p.resolve_routing("scoring")
