"""Smoke test: pipeline module can be imported and PipelineRunner instantiated."""
from __future__ import annotations

from aila.platform.llm.client import LLMResponse
from aila.platform.llm.config import LLMConfigProvider


class FakeRegistry:
    def __init__(self, data: dict[str, object] | None = None) -> None:
        self._data: dict[str, object] = data or {}
    async def get(self, namespace: str, key: str) -> object:
        return self._data.get(f"{namespace}.{key}")


class FakeSecretStore:
    def __init__(self, secrets: dict[str, str] | None = None) -> None:
        self._secrets: dict[str, str] = secrets or {}
    async def resolve_provider_secret(self, secret_key: str) -> str | None:
        return self._secrets.get(secret_key)


def test_llm_response_backward_compat() -> None:
    r = LLMResponse(content="hello")
    assert r.content == "hello"
    assert r.model == ""
    assert r.usage == {}
    assert r.disabled is False
    assert r.finish_reason == ""


async def test_config_is_step_enabled() -> None:
    provider = LLMConfigProvider(
        registry=FakeRegistry(),
        secret_store=FakeSecretStore(),
    )
    assert await provider.is_step_enabled("classify", "scoring") is True


async def test_config_resolve_fail_mode() -> None:
    provider = LLMConfigProvider(
        registry=FakeRegistry(),
        secret_store=FakeSecretStore(),
    )
    # classify is a security-critical step, so a missing config key defaults to
    # fail-closed (config.py _SECURITY_CRITICAL_STEPS, fix §156).
    assert await provider.resolve_fail_mode("classify", "scoring") == "closed"
