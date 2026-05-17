"""Unit tests for aila.platform.llm.pipeline.

Tests the PipelineRunner in isolation using fake steps, fake config,
and async mock call functions. No real API calls.

Also contains integration tests (TestPipelineWiring) that verify the pipeline
is correctly wired into AilaLLMClient.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aila.platform.llm.client import AilaLLMClient, LLMResponse, _enrich_response
from aila.platform.llm.config import LLMConfigProvider, LLMRouting
from aila.platform.llm.errors import LLMError
from aila.platform.llm.pipeline import (
    PipelineRunner,
    StepFn,
)

# ---------------------------------------------------------------------------
# Fakes (same pattern as test_config.py)
# ---------------------------------------------------------------------------

class FakeRegistry:
    """In-memory ConfigRegistry fake."""

    def __init__(self, data: dict[str, object] | None = None) -> None:
        self._data: dict[str, object] = data or {}

    def get(self, namespace: str, key: str) -> object:
        return self._data.get(f"{namespace}.{key}")


class FakeSecretStore:
    """In-memory SecretStore fake."""

    def __init__(self, secrets: dict[str, str] | None = None) -> None:
        self._secrets: dict[str, str] = secrets or {}

    def resolve_provider_secret(self, secret_key: str) -> str | None:
        return self._secrets.get(secret_key)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def config_provider() -> LLMConfigProvider:
    return LLMConfigProvider(
        registry=FakeRegistry({"platform.llm_default_model": "test-model"}),  # type: ignore[arg-type]
        secret_store=FakeSecretStore({"openai_api_key": "sk-test"}),  # type: ignore[arg-type]
    )


@pytest.fixture()
def routing() -> LLMRouting:
    return LLMRouting(
        model_id="test-model",
        base_url="http://test",
        api_key="sk-test",
        max_tokens=100,
        temperature=0.0,
        max_tool_steps=0,
        task_type="scoring",
    )


@pytest.fixture()
def runner(config_provider: LLMConfigProvider) -> PipelineRunner:
    return PipelineRunner(config_provider=config_provider)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_tracking_step(name: str, order_list: list[str]) -> StepFn:
    """Create an async step that appends its name to order_list."""
    async def step(ctx: dict[str, Any], messages: list[dict[str, Any]], routing: LLMRouting) -> None:
        order_list.append(name)
    return step


def _make_failing_step(exc: Exception) -> StepFn:
    """Create an async step that raises the given exception."""
    async def step(ctx: dict[str, Any], messages: list[dict[str, Any]], routing: LLMRouting) -> None:
        raise exc
    return step


# ---------------------------------------------------------------------------
# TestStepOrder
# ---------------------------------------------------------------------------

class TestStepOrder:
    """Register all 4 steps. Assert execution order."""

    @pytest.mark.asyncio
    async def test_step_order(self, runner: PipelineRunner, routing: LLMRouting) -> None:
        order: list[str] = []

        runner.register("classify", _make_tracking_step("classify", order))
        runner.register("validate", _make_tracking_step("validate", order))
        runner.register("gate", _make_tracking_step("gate", order))
        runner.register("seal", _make_tracking_step("seal", order))

        call_fn = AsyncMock(return_value=LLMResponse(content="test"))

        def call_fn_side_effect(**kwargs: Any) -> Any:
            order.append("call")
            return LLMResponse(content="test")

        call_fn.side_effect = call_fn_side_effect

        response, ctx = await runner.run(
            task_type="scoring",
            messages=[{"role": "user", "content": "hello"}],
            routing=routing,
            call_fn=call_fn,
            call_kwargs={},
        )

        assert order == ["classify", "call", "validate", "gate", "seal"]
        assert response.content == "test"


# ---------------------------------------------------------------------------
# TestPassthroughNoSteps
# ---------------------------------------------------------------------------

class TestPassthroughNoSteps:
    """No steps registered -- direct call."""

    @pytest.mark.asyncio
    async def test_passthrough_no_steps(self, runner: PipelineRunner, routing: LLMRouting) -> None:
        call_fn = AsyncMock(return_value=LLMResponse(content="direct"))

        response, ctx = await runner.run(
            task_type="scoring",
            messages=[{"role": "user", "content": "hello"}],
            routing=routing,
            call_fn=call_fn,
            call_kwargs={},
        )

        call_fn.assert_called_once_with()
        assert response.content == "direct"
        assert ctx == {"task_type": "scoring", "run_id": ""}


# ---------------------------------------------------------------------------
# TestStepToggle
# ---------------------------------------------------------------------------

class TestStepToggle:
    """Step toggling via config."""

    @pytest.mark.asyncio
    async def test_step_toggle_off(self, routing: LLMRouting) -> None:
        """Classify disabled via config -- should not run."""
        provider = LLMConfigProvider(
            registry=FakeRegistry({
                "platform.llm_default_model": "test-model",
                "platform.llm_pipeline_classify_scoring": "false",
            }),  # type: ignore[arg-type]
            secret_store=FakeSecretStore({"openai_api_key": "sk-test"}),  # type: ignore[arg-type]
        )
        runner = PipelineRunner(config_provider=provider)

        called = False

        async def classify_step(ctx: dict[str, Any], messages: list[dict[str, Any]], r: LLMRouting) -> None:
            nonlocal called
            called = True

        runner.register("classify", classify_step)
        call_fn = AsyncMock(return_value=LLMResponse(content="test"))

        await runner.run(
            task_type="scoring",
            messages=[],
            routing=routing,
            call_fn=call_fn,
            call_kwargs={},
        )

        assert called is False

    @pytest.mark.asyncio
    async def test_step_toggle_on(self, routing: LLMRouting) -> None:
        """Classify explicitly enabled via config -- should run."""
        provider = LLMConfigProvider(
            registry=FakeRegistry({
                "platform.llm_default_model": "test-model",
                "platform.llm_pipeline_classify_scoring": "true",
            }),  # type: ignore[arg-type]
            secret_store=FakeSecretStore({"openai_api_key": "sk-test"}),  # type: ignore[arg-type]
        )
        runner = PipelineRunner(config_provider=provider)

        called = False

        async def classify_step(ctx: dict[str, Any], messages: list[dict[str, Any]], r: LLMRouting) -> None:
            nonlocal called
            called = True

        runner.register("classify", classify_step)
        call_fn = AsyncMock(return_value=LLMResponse(content="test"))

        await runner.run(
            task_type="scoring",
            messages=[],
            routing=routing,
            call_fn=call_fn,
            call_kwargs={},
        )

        assert called is True


# ---------------------------------------------------------------------------
# TestFailModes
# ---------------------------------------------------------------------------

class TestFailModes:
    """Fail-open and fail-closed behavior."""

    @pytest.mark.asyncio
    async def test_fail_open(self, routing: LLMRouting) -> None:
        """Classify raises, fail-mode is open (default) -- pipeline continues."""
        provider = LLMConfigProvider(
            registry=FakeRegistry({"platform.llm_default_model": "test-model"}),  # type: ignore[arg-type]
            secret_store=FakeSecretStore({"openai_api_key": "sk-test"}),  # type: ignore[arg-type]
        )
        runner = PipelineRunner(config_provider=provider)
        runner.register("classify", _make_failing_step(RuntimeError("classify failed")))
        call_fn = AsyncMock(return_value=LLMResponse(content="survived"))

        response, ctx = await runner.run(
            task_type="scoring",
            messages=[],
            routing=routing,
            call_fn=call_fn,
            call_kwargs={},
        )

        call_fn.assert_called_once()
        assert response.content == "survived"

    @pytest.mark.asyncio
    async def test_fail_closed(self, routing: LLMRouting) -> None:
        """Classify raises, fail-mode is closed -- LLMError raised."""
        provider = LLMConfigProvider(
            registry=FakeRegistry({
                "platform.llm_default_model": "test-model",
                "platform.llm_pipeline_classify_fail_mode_scoring": "closed",
            }),  # type: ignore[arg-type]
            secret_store=FakeSecretStore({"openai_api_key": "sk-test"}),  # type: ignore[arg-type]
        )
        runner = PipelineRunner(config_provider=provider)
        runner.register("classify", _make_failing_step(RuntimeError("classify failed")))
        call_fn = AsyncMock(return_value=LLMResponse(content="should-not-reach"))

        with pytest.raises(LLMError, match="fail-closed"):
            await runner.run(
                task_type="scoring",
                messages=[],
                routing=routing,
                call_fn=call_fn,
                call_kwargs={},
            )

        call_fn.assert_not_called()


# ---------------------------------------------------------------------------
# TestResponseEnrichment
# ---------------------------------------------------------------------------

class TestResponseEnrichment:
    """_enrich_response copies fields and adds pipeline metadata."""

    def test_response_enrichment(self) -> None:
        response = LLMResponse(
            content="test content",
            model="test-model",
            usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            disabled=False,
            finish_reason="stop",
        )
        ctx: dict[str, Any] = {
            "classification": "PUBLIC",
            "confidence": "HIGH",
            "seal_id": "seal-123",
            "pipeline_metadata": {"extra": "data"},
        }
        enriched = _enrich_response(response, ctx)

        # Original fields preserved
        assert enriched.content == "test content"
        assert enriched.model == "test-model"
        assert enriched.usage == {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        assert enriched.disabled is False
        assert enriched.finish_reason == "stop"
        # New fields set
        assert enriched.classification == "PUBLIC"
        assert enriched.confidence == "HIGH"
        assert enriched.seal_id == "seal-123"
        assert enriched.pipeline_metadata == {"extra": "data"}

    def test_no_metadata_returns_original(self) -> None:
        """If ctx has no pipeline metadata, return the same object."""
        response = LLMResponse(content="original")
        ctx: dict[str, Any] = {"task_type": "scoring"}
        result = _enrich_response(response, ctx)
        assert result is response


# ---------------------------------------------------------------------------
# TestResponseDefaults
# ---------------------------------------------------------------------------

class TestResponseDefaults:
    """LLMResponse backward compatibility."""

    def test_response_defaults(self) -> None:
        r = LLMResponse(content="test")
        assert r.content == "test"
        assert r.model == ""
        assert r.usage == {}
        assert r.disabled is False
        assert r.finish_reason == ""
        assert r.classification is None
        assert r.confidence is None
        assert r.seal_id is None
        assert r.pipeline_metadata is None


# ---------------------------------------------------------------------------
# TestRegisterUnknown
# ---------------------------------------------------------------------------

class TestRegisterUnknown:
    """Unknown step name raises ValueError."""

    def test_register_unknown_step(self, runner: PipelineRunner) -> None:
        async def dummy(ctx: dict[str, Any], messages: list[dict[str, Any]], r: LLMRouting) -> None:
            pass

        with pytest.raises(ValueError, match="Unknown pipeline step"):
            runner.register("unknown", dummy)


# ---------------------------------------------------------------------------
# TestContextIsolation
# ---------------------------------------------------------------------------

class TestContextIsolation:
    """Two consecutive runs get independent ctx dicts."""

    @pytest.mark.asyncio
    async def test_context_dict_isolation(self, runner: PipelineRunner, routing: LLMRouting) -> None:
        call_fn = AsyncMock(return_value=LLMResponse(content="test"))

        _, ctx1 = await runner.run(
            task_type="scoring",
            messages=[],
            routing=routing,
            call_fn=call_fn,
            call_kwargs={},
        )
        _, ctx2 = await runner.run(
            task_type="scoring",
            messages=[],
            routing=routing,
            call_fn=call_fn,
            call_kwargs={},
        )

        assert ctx1 is not ctx2
        assert ctx1 == ctx2  # same content, different objects


# ---------------------------------------------------------------------------
# TestConfigMethods
# ---------------------------------------------------------------------------

class TestConfigMethods:
    """is_step_enabled and resolve_fail_mode edge cases."""

    def test_is_step_enabled_none_means_true(self) -> None:
        """No config key set -> enabled."""
        provider = LLMConfigProvider(
            registry=FakeRegistry(),  # type: ignore[arg-type]
            secret_store=FakeSecretStore(),  # type: ignore[arg-type]
        )
        assert provider.is_step_enabled("classify", "scoring") is True

    @pytest.mark.parametrize("value", ["false", "0", "no", False])
    def test_is_step_enabled_false_values(self, value: object) -> None:
        """Values that disable a step."""
        provider = LLMConfigProvider(
            registry=FakeRegistry({"platform.llm_pipeline_classify_scoring": value}),  # type: ignore[arg-type]
            secret_store=FakeSecretStore(),  # type: ignore[arg-type]
        )
        assert provider.is_step_enabled("classify", "scoring") is False

    @pytest.mark.parametrize("value", [True, "true", "1", "yes"])
    def test_is_step_enabled_true_values(self, value: object) -> None:
        """Values that enable a step."""
        provider = LLMConfigProvider(
            registry=FakeRegistry({"platform.llm_pipeline_classify_scoring": value}),  # type: ignore[arg-type]
            secret_store=FakeSecretStore(),  # type: ignore[arg-type]
        )
        assert provider.is_step_enabled("classify", "scoring") is True

    def test_resolve_fail_mode_none_means_open(self) -> None:
        """No config key -> open."""
        provider = LLMConfigProvider(
            registry=FakeRegistry(),  # type: ignore[arg-type]
            secret_store=FakeSecretStore(),  # type: ignore[arg-type]
        )
        assert provider.resolve_fail_mode("classify", "scoring") == "open"

    @pytest.mark.parametrize("value,expected", [
        ("closed", "closed"),
        ("close", "closed"),
        ("open", "open"),
        ("anything_else", "open"),
    ])
    def test_resolve_fail_mode_values(self, value: str, expected: str) -> None:
        provider = LLMConfigProvider(
            registry=FakeRegistry({
                "platform.llm_pipeline_classify_fail_mode_scoring": value,
            }),  # type: ignore[arg-type]
            secret_store=FakeSecretStore(),  # type: ignore[arg-type]
        )
        assert provider.resolve_fail_mode("classify", "scoring") == expected


# ---------------------------------------------------------------------------
# Mock helpers (same pattern as test_client.py)
# ---------------------------------------------------------------------------

def _make_completion(
    content: str = "Hello",
    finish_reason: str = "stop",
    prompt_tokens: int = 10,
    completion_tokens: int = 5,
) -> MagicMock:
    """Build a mock ChatCompletion response."""
    usage = MagicMock()
    usage.prompt_tokens = prompt_tokens
    usage.completion_tokens = completion_tokens
    usage.total_tokens = prompt_tokens + completion_tokens

    message = MagicMock()
    message.content = content
    message.tool_calls = []

    choice = MagicMock()
    choice.message = message
    choice.finish_reason = finish_reason

    completion = MagicMock()
    completion.choices = [choice]
    completion.usage = usage
    return completion


# ---------------------------------------------------------------------------
# TestPipelineWiring -- integration tests for pipeline inside client
# ---------------------------------------------------------------------------

class TestPipelineWiring:
    """Tests that verify PipelineRunner is wired into AilaLLMClient."""

    @pytest.fixture()
    def client(self) -> AilaLLMClient:
        registry = FakeRegistry({
            "platform.llm_default_model": "test-model",
        })
        secret_store = FakeSecretStore({"openai_api_key": "sk-test"})
        return AilaLLMClient(
            registry=registry,  # type: ignore[arg-type]
            secret_store=secret_store,  # type: ignore[arg-type]
        )

    def test_pipeline_accessible(self, client: AilaLLMClient) -> None:
        """client.pipeline returns the PipelineRunner instance."""
        assert isinstance(client.pipeline, PipelineRunner)

    @pytest.mark.asyncio
    async def test_chat_transparent_no_steps(self, client: AilaLLMClient) -> None:
        """No steps registered: chat() returns response with None pipeline fields."""
        mock_completion = _make_completion(content="transparent response")
        with patch("aila.platform.llm.client.AsyncOpenAI") as MockOAI:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_completion)
            MockOAI.return_value = mock_instance

            response = await client.chat(
                "scoring",
                [{"role": "user", "content": "test"}],
            )

        assert response.content == "transparent response"
        assert response.classification is None
        assert response.confidence is None
        assert response.seal_id is None
        assert response.pipeline_metadata is None

    @pytest.mark.asyncio
    async def test_chat_with_classify_step(self, client: AilaLLMClient) -> None:
        """Register classify step that writes ctx. Assert response carries metadata."""
        async def fake_classify(
            ctx: dict[str, Any],
            messages: list[dict[str, Any]],
            routing: LLMRouting,
        ) -> None:
            ctx["classification"] = "PUBLIC"
            ctx["confidence"] = "HIGH"

        client.pipeline.register("classify", fake_classify)

        mock_completion = _make_completion(content="classified response")
        with patch("aila.platform.llm.client.AsyncOpenAI") as MockOAI:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_completion)
            MockOAI.return_value = mock_instance

            response = await client.chat(
                "scoring",
                [{"role": "user", "content": "test"}],
            )

        assert response.content == "classified response"
        assert response.classification == "PUBLIC"
        assert response.confidence == "HIGH"
        assert response.seal_id is None

    @pytest.mark.asyncio
    async def test_chat_pipeline_run_invoked(self, client: AilaLLMClient) -> None:
        """Verify pipeline.run() is called by tracking via a registered step."""
        invoked = []

        async def tracking_step(
            ctx: dict[str, Any],
            messages: list[dict[str, Any]],
            routing: LLMRouting,
        ) -> None:
            invoked.append(ctx["task_type"])

        client.pipeline.register("classify", tracking_step)

        mock_completion = _make_completion(content="tracked")
        with patch("aila.platform.llm.client.AsyncOpenAI") as MockOAI:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_completion)
            MockOAI.return_value = mock_instance

            await client.chat("scoring", [{"role": "user", "content": "test"}])

        assert invoked == ["scoring"]
