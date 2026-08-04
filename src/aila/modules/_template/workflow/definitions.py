"""Template workflow definitions.

The template ships one three-state investigation workflow
(``TEMPLATE_INVESTIGATE_V1``) built from the platform state factories:

    investigation_setup -> investigation_loop -> investigation_emit

Copiers extend the pipeline with module-specific phases the same way
vr layers ``poc_development`` / ``advisory`` / ``response_emit`` after
the shared investigation triple.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, cast

from aila.modules._template.workflow.states.investigation_emit import (
    state_investigation_emit,
)
from aila.modules._template.workflow.states.investigation_loop import (
    state_investigation_loop,
)
from aila.modules._template.workflow.states.investigation_setup import (
    state_investigation_setup,
)
from aila.platform.workflows.types import (
    RESERVED_SUCCEEDED,
    HandlerFn,
    StateSpec,
    WorkflowDefinition,
)

if TYPE_CHECKING:
    from aila.platform.workflows.types import WorkflowServices

__all__ = ["TEMPLATE_INVESTIGATE_V1"]


def _h(handler: object) -> HandlerFn:
    """Cast a concrete handler to the workflow engine's HandlerFn type."""
    return cast("HandlerFn", handler)


async def _build_services(run_id: str) -> WorkflowServices:
    """Lazy construction of :class:`TemplateWorkflowServices` per run.

    Deferred import: workflow.services pulls in ServiceFactory + the
    platform LLM client, and those import chains reach back into other
    workflow surfaces. A module-scope import here is safe today, but
    the deferred shape matches vr's ``_build_services`` and future-
    proofs the scaffold against a later import-cycle if the services
    bag grows.
    """
    from aila.modules._template.workflow.services import (
        TemplateWorkflowServices,
    )
    return await TemplateWorkflowServices.build(run_id)


TEMPLATE_INVESTIGATE_V1: WorkflowDefinition = WorkflowDefinition(
    definition_id="template.investigate.v1",
    start_state="investigation_setup",
    states={
        "investigation_setup": StateSpec(
            handler=_h(state_investigation_setup),
            timeout_s=60.0,
            max_retries=1,
            on_success="investigation_loop",
        ),
        "investigation_loop": StateSpec(
            handler=_h(state_investigation_loop),
            # Long timeout -- each turn is one LLM round trip.
            timeout_s=7200.0,
            max_retries=0,
            on_success="investigation_emit",
        ),
        "investigation_emit": StateSpec(
            handler=_h(state_investigation_emit),
            timeout_s=60.0,
            max_retries=0,
            on_success=RESERVED_SUCCEEDED,
        ),
    },
    services_factory=_build_services,
)
