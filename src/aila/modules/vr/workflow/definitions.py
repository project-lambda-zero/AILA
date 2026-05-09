"""WorkflowDefinition objects for the VR (vulnerability research) module.

Defines ``VR_NDAY_V1``: a five-state pipeline that takes a target binary
(plus optional patched build) and emits a confirmed advisory:

    setup -> research -> poc_development -> advisory -> response_emit
                                                          -> __succeeded__

State graph:
- ``setup`` uploads binaries to the IDA headless MCP, polls until
  analysis is ready, runs checksec, and primes the budget.
- ``research`` drives the bounded N-day investigation loop.
- ``poc_development`` generates / compiles / runs / verifies the PoC.
- ``advisory`` scores CVSS, maps CWE, and persists the finding.
- ``response_emit`` finalizes project status and shapes the terminal
  payload.

Retry policy: setup and poc_development touch SSH/HTTP transports that
flap under load; the engine retries them once or twice on transport-class
exceptions (TimeoutError / ConnectionError / OSError). The reasoning
states (research, advisory) and the terminal emitter are not retried —
they own their own LLM-error handling so an automatic retry would only
double up on cost.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, cast

from aila.modules.vr.workflow.states.advisory import state_advisory
from aila.modules.vr.workflow.states.poc_development import state_poc_development
from aila.modules.vr.workflow.states.research import state_research
from aila.modules.vr.workflow.states.response_emit import state_response_emit
from aila.modules.vr.workflow.states.setup import state_setup
from aila.platform.workflows.types import (
    RESERVED_SUCCEEDED,
    HandlerFn,
    StateSpec,
    WorkflowDefinition,
)

if TYPE_CHECKING:
    from aila.platform.workflows.types import WorkflowServices

__all__ = ["VR_NDAY_V1"]


def _h(handler: object) -> HandlerFn:
    """Cast concrete handler to the engine's HandlerFn type."""
    return cast("HandlerFn", handler)


async def _build_services(run_id: str) -> WorkflowServices:
    """Lazy construction of VRWorkflowServices to avoid import cycles."""
    from aila.modules.vr.workflow.services import VRWorkflowServices

    return await VRWorkflowServices.build(run_id)


# Bucket the SSH / HTTP transient family for engine-level retries on the
# states that touch the IDA bridge over HTTP and the analyzer over SSH.
# Reasoning states are excluded — their handlers own their own LLM error
# handling and a blind retry would just double LLM cost.
_TRANSPORT_TRANSIENT: tuple[type[BaseException], ...] = (
    TimeoutError,
    ConnectionError,
    OSError,
)


VR_NDAY_V1: WorkflowDefinition = WorkflowDefinition(
    definition_id="vr.nday.v1",
    start_state="setup",
    states={
        "setup": StateSpec(
            handler=_h(state_setup),
            timeout_s=120.0,
            max_retries=2,
            retriable_on=_TRANSPORT_TRANSIENT,
            on_success="research",
        ),
        "research": StateSpec(
            handler=_h(state_research),
            timeout_s=7200.0,
            max_retries=1,
            on_success="poc_development",
        ),
        "poc_development": StateSpec(
            handler=_h(state_poc_development),
            timeout_s=3600.0,
            max_retries=2,
            retriable_on=_TRANSPORT_TRANSIENT,
            on_success="advisory",
        ),
        "advisory": StateSpec(
            handler=_h(state_advisory),
            timeout_s=600.0,
            max_retries=1,
            on_success="response_emit",
        ),
        "response_emit": StateSpec(
            handler=_h(state_response_emit),
            timeout_s=60.0,
            max_retries=0,
            on_success=RESERVED_SUCCEEDED,
        ),
    },
    services_factory=_build_services,
)
