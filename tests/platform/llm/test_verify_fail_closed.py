"""#31: the verify pipeline step fails closed.

An internal failure (e.g. the second-model call raising) must propagate
instead of being swallowed, so PipelineRunner's fail-closed policy for the
security-critical ``verify`` step can block the call. The previous code
caught everything, set ``verification_status='error'`` (a value with no
consumer), and continued -- silently passing an unverified response.
"""
from __future__ import annotations

from typing import Any

import pytest

from aila.platform.llm.config import LLMRouting
from aila.platform.llm.verify import make_verify_step


class _FakeProvider:
    """Minimal config provider: verify enabled, always-triggering threshold."""

    async def is_step_enabled(self, step: str, task_type: str) -> bool:
        return True

    async def resolve_verify_threshold(self, task_type: str) -> float:
        return 1.0  # any confidence < 1.0 triggers verification

    async def resolve_verify_model(self, task_type: str) -> str:
        return "verifier-model"


class _Resp:
    content = "primary output"


@pytest.mark.asyncio
async def test_verify_step_reraises_when_second_call_fails() -> None:
    async def _boom(**_kwargs: object) -> Any:
        raise RuntimeError("verifier model unreachable")

    step = make_verify_step(_FakeProvider(), _boom, emitter=None)  # type: ignore[arg-type]
    routing = LLMRouting(
        model_id="primary-model",
        base_url="http://test",
        api_key="sk-test",
        max_tokens=100,
        temperature=0.0,
        max_tool_steps=0,
        task_type="scoring",
    )
    ctx: dict[str, Any] = {
        "task_type": "scoring",
        "response": _Resp(),
        "confidence": "LOW",
        "pipeline_metadata": {"confidence_gating": {"confidence_score": 0.0}},
    }

    with pytest.raises(RuntimeError, match="verifier model unreachable"):
        await step(ctx, [{"role": "user", "content": "score this"}], routing)

    # The status is still recorded for the audit trail, but the exception
    # propagates (fail-closed) rather than being swallowed.
    assert ctx["verification_status"] == "error"
