"""Template module workflow: drives execution through state handlers.

Demonstrates the state machine pattern with explicit stage ordering,
pure-function handlers, and import-time handler validation.

Real module state handlers are async functions with the signature
(state_input: dict, services: <Module>WorkflowServices) -> StateResult.
They emit progress via the platform emitter:

    async def state_prepare(
        state_input: dict, services: YourModuleServices
    ) -> StateResult:
        await services.emitter.emit(stage="prepare", message="Preparing...")
        return StateResult(output={...}, next_state="next_stage")

All imports in real modules must come from aila.platform.* or the module's
own package -- never from another module's internals.

The template uses a simplified TemplateWorkflowContext to keep the skeleton
import-clean. Wire into the durable workflow engine by creating a
WorkflowServices subclass and defining handlers as async def
state_*(state_input, services) -> StateResult.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum

from aila.platform.contracts._common import JsonObject
from aila.platform.contracts.runtime import PlatformResponse

__all__ = ["TemplateWorkflow"]


class TemplateStage(StrEnum):
    """Lifecycle stages for the template workflow."""

    PREPARE = "prepare"
    EXECUTE = "execute"
    RESPONSE_EMIT = "response_emit"


@dataclass(slots=True)
class TemplateWorkflowContext:
    """Mutable state carrier threaded through all template workflow stages.

    Each stage handler receives this context, reads from it, and writes results
    back before returning. The final stage assembles PlatformResponse from it.
    """

    run_id: str
    action_id: str
    module_id: str
    target_names: list[str]
    force_refresh: bool
    message: str = ""
    module_payload: JsonObject = field(default_factory=dict)
    artifacts: dict[str, str] = field(default_factory=dict)


# --- State handlers (pure functions) ---


def state_prepare(context: TemplateWorkflowContext) -> TemplateStage | None:
    """Prepare the workflow execution context.

    Writes the normalized request metadata into module_payload so downstream
    stages can rely on a consistent structure.

    Args:
        context: Mutable workflow context. Writes to context.module_payload.

    Returns:
        None to advance to the next stage in STAGE_ORDER.
    """
    context.module_payload["request"] = {
        "module_id": context.module_id,
        "target_names": list(context.target_names),
        "force_refresh": context.force_refresh,
    }
    return None


def state_execute(context: TemplateWorkflowContext) -> TemplateStage | None:
    """Execute the module's primary action.

    Replace the placeholder result with real domain logic. Write output
    into context.module_payload and set context.message.

    Args:
        context: Mutable workflow context. Writes to context.module_payload
            and context.message.

    Returns:
        None to advance to the next stage in STAGE_ORDER.
    """
    context.module_payload["result"] = {
        "status": "replace_with_real_execution",
        "target_count": len(context.target_names),
    }
    if context.target_names:
        context.message = (
            f"{context.module_id} module prepared execution for {len(context.target_names)} target(s)."
        )
    else:
        context.message = f"{context.module_id} module prepared an untargeted execution."
    return None


def state_response_emit(context: TemplateWorkflowContext) -> TemplateStage | None:
    """Emit stage result and finalize the response.

    In real modules, call emit_stage_result() here to publish the completed
    stage to the platform event emitter (audit DB, run history, progress).

    Args:
        context: Mutable workflow context. No mutations needed in the base template.

    Returns:
        None; the orchestrator detects this as the final stage.
    """
    return None


# Handler concurrency safety annotations (HCS-01, HCS-02)
state_prepare.parallel_safe = False
state_prepare.writes_fields = ["module_payload"]

state_execute.parallel_safe = False
state_execute.writes_fields = ["module_payload", "message"]

state_response_emit.parallel_safe = True
state_response_emit.writes_fields = []


# --- Handler registry (validated at import time) ---


STAGE_ORDER: tuple[TemplateStage, ...] = (
    TemplateStage.PREPARE,
    TemplateStage.EXECUTE,
    TemplateStage.RESPONSE_EMIT,
)

HANDLER_REGISTRY: dict[TemplateStage, Callable[[TemplateWorkflowContext], TemplateStage | None]] = {
    TemplateStage.PREPARE: state_prepare,
    TemplateStage.EXECUTE: state_execute,
    TemplateStage.RESPONSE_EMIT: state_response_emit,
}

# Import-time validation: every stage must have a handler.
_missing = set(TemplateStage) - set(HANDLER_REGISTRY)
if _missing:
    raise RuntimeError(f"Template workflow missing handlers for: {_missing}")



# --- Orchestrator ---


class TemplateWorkflow:
    """Drives execution through the template workflow stages.

    Iterates STAGE_ORDER, dispatches each stage to its handler via
    HANDLER_REGISTRY, and builds PlatformResponse when the final stage
    is reached.
    """

    def run(
        self,
        *,
        run_id: str,
        action_id: str,
        module_id: str,
        target_names: list[str],
        force_refresh: bool,
    ) -> PlatformResponse:
        """Execute all workflow stages and return the response.

        Args:
            run_id: Unique identifier for this analysis run.
            action_id: The module action being executed.
            module_id: The module identifier (must match folder name).
            target_names: List of target system names to act on.
            force_refresh: When True, re-execute instead of reusing prior results.

        Returns:
            A PlatformResponse with run_id, action_id, message, module_payload,
            and artifacts populated by the completed workflow.

        Raises:
            RuntimeError: If the workflow finishes all stages without emitting
                a response (should not happen if STAGE_ORDER is correct).
        """
        context = TemplateWorkflowContext(
            run_id=run_id,
            action_id=action_id,
            module_id=module_id,
            target_names=list(target_names),
            force_refresh=force_refresh,
        )
        current_stage = STAGE_ORDER[0]
        while current_stage is not None:
            handler = HANDLER_REGISTRY[current_stage]
            next_stage = handler(context)
            if current_stage == TemplateStage.RESPONSE_EMIT:
                return PlatformResponse(
                    run_id=context.run_id,
                    action_id=context.action_id,
                    message=context.message,
                    module_payload=context.module_payload,
                    artifacts=context.artifacts,
                )
            current_stage = next_stage or _next_stage(current_stage)
        raise RuntimeError("Template workflow finished without emitting a response.")


def _next_stage(stage: TemplateStage) -> TemplateStage | None:
    try:
        index = STAGE_ORDER.index(stage)
    except ValueError as exc:
        raise RuntimeError(f"Unknown template stage '{stage}'.") from exc
    if index + 1 >= len(STAGE_ORDER):
        return None
    return STAGE_ORDER[index + 1]
