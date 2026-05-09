"""Hello-world module workflow: drives execution through state handlers.

Minimal state machine for platform contract smoke testing.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum

from aila.platform.contracts._common import JsonObject
from aila.platform.contracts.runtime import PlatformResponse

__all__ = ["HelloWorldWorkflow"]


class HelloWorldStage(StrEnum):
    """Lifecycle stages for the hello_world workflow."""

    PREPARE = "prepare"
    EXECUTE = "execute"
    RESPONSE_EMIT = "response_emit"


@dataclass(slots=True)
class HelloWorldWorkflowContext:
    """Mutable state carrier threaded through all hello_world workflow stages."""

    run_id: str
    action_id: str
    module_id: str
    target_names: list[str]
    force_refresh: bool
    message: str = ""
    module_payload: JsonObject = field(default_factory=dict)
    artifacts: dict[str, str] = field(default_factory=dict)


# --- State handlers (pure functions) ---


def state_prepare(context: HelloWorldWorkflowContext) -> HelloWorldStage | None:
    """Prepare the workflow execution context.

    Args:
        context: Mutable workflow context.

    Returns:
        None to advance to the next stage.
    """
    context.module_payload["request"] = {
        "module_id": context.module_id,
        "target_names": list(context.target_names),
        "force_refresh": context.force_refresh,
    }
    return None


def state_execute(context: HelloWorldWorkflowContext) -> HelloWorldStage | None:
    """Execute the hello_world primary action.

    Args:
        context: Mutable workflow context.

    Returns:
        None to advance to the next stage.
    """
    context.message = "Hello from hello_world module!"
    context.module_payload["greeting"] = "hello"
    return None


def state_response_emit(context: HelloWorldWorkflowContext) -> HelloWorldStage | None:
    """Finalize the response.

    Args:
        context: Mutable workflow context.

    Returns:
        None; the orchestrator detects this as the final stage.
    """
    del context
    return None


# Handler concurrency safety annotations (HCS-01, HCS-02)
state_prepare.parallel_safe = False
state_prepare.writes_fields = ["module_payload"]

state_execute.parallel_safe = False
state_execute.writes_fields = ["message", "module_payload"]

state_response_emit.parallel_safe = True
state_response_emit.writes_fields = []


# --- Handler registry (validated at import time) ---


STAGE_ORDER: tuple[HelloWorldStage, ...] = (
    HelloWorldStage.PREPARE,
    HelloWorldStage.EXECUTE,
    HelloWorldStage.RESPONSE_EMIT,
)

HANDLER_REGISTRY: dict[HelloWorldStage, Callable[[HelloWorldWorkflowContext], HelloWorldStage | None]] = {
    HelloWorldStage.PREPARE: state_prepare,
    HelloWorldStage.EXECUTE: state_execute,
    HelloWorldStage.RESPONSE_EMIT: state_response_emit,
}

# Import-time validation: every stage must have a handler.
_missing = set(HelloWorldStage) - set(HANDLER_REGISTRY)
if _missing:
    raise RuntimeError(f"HelloWorld workflow missing handlers for: {_missing}")



# --- Orchestrator ---


class HelloWorldWorkflow:
    """Drives execution through the hello_world workflow stages."""

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
            run_id: Unique identifier for this run.
            action_id: The module action being executed.
            module_id: The module identifier.
            target_names: List of target system names.
            force_refresh: When True, re-execute instead of reusing prior results.

        Returns:
            A PlatformResponse with the completed workflow output.

        Raises:
            RuntimeError: If the workflow finishes without emitting a response.
        """
        context = HelloWorldWorkflowContext(
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
            if current_stage == HelloWorldStage.RESPONSE_EMIT:
                return PlatformResponse(
                    run_id=context.run_id,
                    action_id=context.action_id,
                    message=context.message,
                    module_payload=context.module_payload,
                    artifacts=context.artifacts,
                )
            current_stage = next_stage or _next_stage(current_stage)
        raise RuntimeError("HelloWorld workflow finished without emitting a response.")


def _next_stage(stage: HelloWorldStage) -> HelloWorldStage | None:
    try:
        index = STAGE_ORDER.index(stage)
    except ValueError as exc:
        raise RuntimeError(f"Unknown hello_world stage '{stage}'.") from exc
    if index + 1 >= len(STAGE_ORDER):
        return None
    return STAGE_ORDER[index + 1]
