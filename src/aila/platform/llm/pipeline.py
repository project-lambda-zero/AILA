"""Fixed-order middleware pipeline for LLM calls.

Step order is hardcoded: classify -> call -> validate -> gate -> verify -> seal.
"call" is the existing _single_call logic -- not a registered step.
Pre-call steps run before the API call; post-call steps run after.

Steps are async callables: async def step(ctx, messages, routing) -> None.
Steps write results into the ctx dict. Registration happens at platform
startup via pipeline.register("classify", fn).

When no steps are registered, pipeline is a transparent pass-through.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from .config import LLMConfigProvider, LLMRouting
from .errors import ClassificationBlockedError, ConfidenceRejectedError, LLMError

logger = logging.getLogger(__name__)

StepFn = Callable[[dict[str, Any], list[dict[str, Any]], LLMRouting], Awaitable[None]]

# Default step order. Operators can override per task_type via
# ``llm_pipeline_pre_call_steps_{task_type}`` /
# ``llm_pipeline_post_call_steps_{task_type}`` (comma-separated) in
# ConfigRegistry -- see :meth:`LLMConfigProvider.resolve_step_order` (§157).
# These constants are still the SOURCE of TRUTH for which step names are
# even legal: ``register`` rejects any name not present here so a typo in
# the override config can't silently add a step the pipeline doesn't know.
PRE_CALL_STEPS: tuple[str, ...] = ("classify",)
POST_CALL_STEPS: tuple[str, ...] = ("validate", "gate", "verify", "seal")
_KNOWN_STEPS: frozenset[str] = frozenset(PRE_CALL_STEPS + POST_CALL_STEPS)

class PipelineRunner:
    """Fixed-order middleware pipeline for LLM calls."""

    def __init__(self, config_provider: LLMConfigProvider) -> None:
        self._config = config_provider
        self._steps: dict[str, StepFn] = {}

    def register(self, name: str, step_fn: StepFn) -> None:
        """Register a step function for a named pipeline slot.

        Args:
            name: One of the known step names (classify, validate, gate, verify, seal).
            step_fn: Async callable that receives (ctx, messages, routing).

        Raises:
            ValueError: If name is not a known pipeline step.
        """
        if name not in _KNOWN_STEPS:
            raise ValueError(f"Unknown pipeline step: {name!r}")
        self._steps[name] = step_fn

    async def _resolve_steps(
        self,
        *,
        phase: str,
        task_type: str,
        default: tuple[str, ...],
    ) -> tuple[str, ...]:
        """Resolve step order for ``phase`` (``pre_call`` / ``post_call``).

        fix §157 -- looks up ``llm_pipeline_{phase}_steps_{task_type}`` (a
        comma-separated list) in ConfigRegistry. Unknown step names are
        silently dropped -- operators get to opt out of a step by name
        without breaking the run, but cannot inject a slot the pipeline
        does not handle. Falls back to ``default`` when no override exists.
        """
        getter = getattr(self._config, "_registry", None)
        if getter is None:
            return default
        try:
            raw = await getter.get(
                "platform", f"llm_pipeline_{phase}_steps_{task_type}",
            )
        except Exception:
            return default
        if not raw:
            return default
        wanted = [s.strip() for s in str(raw).split(",") if s.strip()]
        filtered = tuple(s for s in wanted if s in _KNOWN_STEPS)
        dropped = [s for s in wanted if s not in _KNOWN_STEPS]
        if dropped:
            logger.warning(
                "pipeline._resolve_steps: dropping unknown step name(s) %r "
                "for phase=%s task_type=%s", dropped, phase, task_type,
            )
        return filtered or default

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

        pre_steps = await self._resolve_steps(
            phase="pre_call", task_type=task_type, default=PRE_CALL_STEPS,
        )
        for step_name in pre_steps:
            await self._run_step(step_name, ctx, messages, routing)

        response = await call_fn(**call_kwargs)
        ctx["response"] = response

        post_steps = await self._resolve_steps(
            phase="post_call", task_type=task_type, default=POST_CALL_STEPS,
        )
        for step_name in post_steps:
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
