"""Smoke test: pipeline module can be imported and PipelineRunner instantiated."""
from __future__ import annotations

from aila.platform.llm.client import LLMResponse
from aila.platform.llm.config import LLMConfigProvider, LLMRouting
from aila.platform.llm.pipeline import POST_CALL_STEPS, PRE_CALL_STEPS, PipelineRunner


class FakeRegistry:
    def __init__(self, data: dict[str, object] | None = None) -> None:
        self._data: dict[str, object] = data or {}
    def get(self, namespace: str, key: str) -> object:
        return self._data.get(f"{namespace}.{key}")


class FakeSecretStore:
    def __init__(self, secrets: dict[str, str] | None = None) -> None:
        self._secrets: dict[str, str] = secrets or {}
    def resolve_provider_secret(self, secret_key: str) -> str | None:
        return self._secrets.get(secret_key)


def test_pipeline_import() -> None:
    assert PRE_CALL_STEPS == ("classify",)
    assert POST_CALL_STEPS == ("validate", "gate", "seal")


def test_pipeline_runner_instantiate() -> None:
    provider = LLMConfigProvider(
        registry=FakeRegistry({"platform.llm_default_model": "test-model"}),
        secret_store=FakeSecretStore({"openai_api_key": "sk-test"}),
    )
    runner = PipelineRunner(config_provider=provider)
    assert runner is not None


def test_llm_response_new_fields() -> None:
    r = LLMResponse(content="test")
    assert r.classification is None
    assert r.confidence is None
    assert r.seal_id is None
    assert r.pipeline_metadata is None


def test_llm_response_backward_compat() -> None:
    r = LLMResponse(content="hello")
    assert r.content == "hello"
    assert r.model == ""
    assert r.usage == {}
    assert r.disabled is False
    assert r.finish_reason == ""


def test_llm_routing_task_type() -> None:
    routing = LLMRouting(
        model_id="test",
        base_url="http://test",
        api_key="sk-test",
        max_tokens=100,
        temperature=0.0,
        max_tool_steps=0,
        task_type="scoring",
    )
    assert routing.task_type == "scoring"


def test_config_is_step_enabled() -> None:
    provider = LLMConfigProvider(
        registry=FakeRegistry(),
        secret_store=FakeSecretStore(),
    )
    assert provider.is_step_enabled("classify", "scoring") is True


def test_config_resolve_fail_mode() -> None:
    provider = LLMConfigProvider(
        registry=FakeRegistry(),
        secret_store=FakeSecretStore(),
    )
    assert provider.resolve_fail_mode("classify", "scoring") == "open"
