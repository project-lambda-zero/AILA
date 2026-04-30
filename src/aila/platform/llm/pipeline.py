"""Fixed-order middleware pipeline for LLM calls.

Step order is hardcoded: classify -> call -> validate -> gate -> seal.
"call" is the existing _single_call logic -- not a registered step.
Pre-call steps run before the API call; post-call steps run after.

Steps are async callables: async def step(ctx, messages, routing) -> None.
Steps write results into the ctx dict. Registration happens at platform
startup via pipeline.register("classify", fn).

When no steps are registered, pipeline is a transparent pass-through.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Awaitable

from .config import LLMConfigProvider, LLMRouting
from .errors import ClassificationBlockedError, ConfidenceRejectedError, LLMError

logger = logging.getLogger(__name__)

StepFn = Callable[[dict[str, Any], list[dict[str, Any]], LLMRouting], Awaitable[None]]

PRE_CALL_STEPS: tuple[str, ...] = ("classify",)
POST_CALL_STEPS: tuple[str, ...] = ("validate", "gate", "verify", "seal")


class PipelineRunner:
    """Fixed-order middleware pipeline for LLM calls."""

    def __init__(self, config_provider: LLMConfigProvider) -> None:
        self._config = config_provider
        self._steps: dict[str, StepFn] = {}

    def register(self, name: str, step_fn: StepFn) -> None:
        """Register a step function for a named pipeline slot.

        Args:
            name: One of the known step names (classify, validate, gate, seal).
            step_fn: Async callable that receives (ctx, messages, routing).

        Raises:
            ValueError: If name is not a known pipeline step.
        """
        if name not in (*PRE_CALL_STEPS, *POST_CALL_STEPS):
            raise ValueError(f"Unknown pipeline step: {name!r}")
        self._steps[name] = step_fn

    async def run(
        self,
        *,
        task_type: str,
        messages: list[dict[str, Any]],
        routing: LLMRouting,
        call_fn: Callable[..., Awaitable[Any]],
        call_kwargs: dict[str, Any],
        run_id: str = "",
    ) -> tuple[Any, dict[str, Any]]:
        """Execute the pipeline: pre-call steps, call, post-call steps.

        Args:
            task_type: The task type string for config lookups.
            messages: OpenAI-format message list.
            routing: Resolved LLMRouting for this call.
            call_fn: The actual API call function (_single_call or similar).
            call_kwargs: Keyword arguments to pass to call_fn.
            run_id: Optional run identifier for cost tracking and audit sealing.

        Returns:
            Tuple of (response, ctx) where ctx is the pipeline context dict.
        """
        ctx: dict[str, Any] = {"task_type": task_type, "run_id": run_id}

        if not self._steps:
            response = await call_fn(**call_kwargs)
            return response, ctx

        for step_name in PRE_CALL_STEPS:
            await self._run_step(step_name, ctx, messages, routing)

        response = await call_fn(**call_kwargs)
        ctx["response"] = response

        for step_name in POST_CALL_STEPS:
            await self._run_step(step_name, ctx, messages, routing)

        # Re-read: gate step may have replaced ctx["response"] (D-15, Phase 119).
        final_response = ctx.get("response", response)
        return final_response, ctx

    async def _run_step(
        self,
        name: str,
        ctx: dict[str, Any],
        messages: list[dict[str, Any]],
        routing: LLMRouting,
    ) -> None:
        """Run a single pipeline step with config checks and error handling.

        - If step is not registered, returns immediately (no error).
        - If step is disabled via config, skips silently.
        - Fail-open: exception logged, pipeline continues.
        - Fail-closed: exception re-raised as LLMError.
        """
        step_fn = self._steps.get(name)
        if step_fn is None:
            return

        if not await self._config.is_step_enabled(name, ctx["task_type"]):
            return

        fail_mode = await self._config.resolve_fail_mode(name, ctx["task_type"])
        try:
            await step_fn(ctx, messages, routing)
        except (ClassificationBlockedError, ConfidenceRejectedError):
            raise  # Intentional blocks -- always propagate regardless of fail_mode
        except Exception as exc:
            if fail_mode == "closed":
                raise LLMError(
                    f"Pipeline step {name!r} failed (fail-closed): {exc}",
                    retryable=False,
                ) from exc
            logger.warning("Pipeline step %r failed (fail-open): %s", name, exc)
