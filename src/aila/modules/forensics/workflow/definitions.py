"""WorkflowDefinition objects for the forensics module.

Mirrors the vulnerability module's architecture (Phase 180/183):

- ``FORENSICS_DISPATCHER_V1`` -- ``routing -> mode_selection -> __succeeded__``.
  Uses ``is_dispatcher=True`` + ``dispatches_to`` so the platform
  ``@platform_task`` wrapper (``_run_two_phase_dispatch``) drives both the
  dispatcher run and the inner-definition run through ``DurableStateMachine``,
  giving us cursor persistence, audit trails, retries, and resumability.

- ``FORENSICS_FULL_ANALYSIS_V1`` -- full evidence pipeline:
  ``intake -> collection -> deep_analysis -> promotion -> resolution -> writeup -> response_emit -> __succeeded__``;
  any state's failure routes to ``analysis_failed -> __failed__``, which marks
  the project failed with a reason.

- ``FORENSICS_FREEFLOW_V1`` -- bounded investigation:
  ``freeflow -> promotion -> writeup -> response_emit -> __succeeded__``

Every ``StateSpec`` declares ``on_success`` to make the graph edges
statically visible (not just dynamically returned by handlers).
"""
from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any, cast

from aila.modules.forensics.config_schema import FORENSICS_DEFAULTS
from aila.modules.forensics.contracts.status import InvestigationStatus, ProjectStatus
from aila.modules.forensics.workflow.states.collection import state_collection
from aila.modules.forensics.workflow.states.deep_analysis import state_deep_analysis
from aila.modules.forensics.workflow.states.freeflow import state_freeflow
from aila.modules.forensics.workflow.states.intake import state_intake
from aila.modules.forensics.workflow.states.promotion import state_freeflow_promotion, state_promotion
from aila.modules.forensics.workflow.states.resolution import state_resolution
from aila.modules.forensics.workflow.states.writeup import state_writeup
from aila.platform.exceptions import AILAError
from aila.platform.workflows.types import (
    RESERVED_FAILED,
    RESERVED_SUCCEEDED,
    HandlerFn,
    StateResult,
    StateSpec,
    WorkflowDefinition,
)

if TYPE_CHECKING:
    from aila.modules.forensics.workflow.services import ForensicsWorkflowServices
    from aila.platform.workflows.types import WorkflowServices

__all__ = [
    "FORENSICS_DISPATCHER_V1",
    "FORENSICS_FREEFLOW_V1",
    "FORENSICS_FULL_ANALYSIS_V1",
    "FORENSICS_MODE_DEFINITIONS",
    "FORENSICS_RAW_DIRECTORY_V1",
]


def _h(handler: object) -> HandlerFn:
    """Cast concrete handler to the engine's HandlerFn type."""
    return cast("HandlerFn", handler)


async def _build_services(run_id: str) -> WorkflowServices:
    """Lazy construction of ForensicsWorkflowServices to avoid import cycles."""
    from aila.modules.forensics.workflow.services import ForensicsWorkflowServices

    return await ForensicsWorkflowServices.build(run_id)


# Mirrors vulnerability._HTTP_TRANSIENT: bucket the *parent* of every SSH
# transient so transport hiccups trigger engine-level retries (per state's
# max_retries) instead of terminating the state. SSH layer raises AILAError
# subclasses for both command-exit-nonzero *and* transport failures -- we
# treat the whole family as transient and let the per-file emit loops inside
# each collector decide which specific failures are actually unrecoverable.
_SSH_TRANSIENT: tuple[type[BaseException], ...] = (
    TimeoutError,
    ConnectionError,
    OSError,
    asyncio.TimeoutError,
    AILAError,
)


# ---------------------------------------------------------------------------
# Terminal emitter -- assembles the final response payload
# ---------------------------------------------------------------------------

async def _state_response_emit(
    input: dict[str, Any], _services: object,
) -> StateResult:
    """Preserve terminal record status and assemble the response."""
    project_id = input.get("project_id", "")
    investigation_id = input.get("investigation_id")
    resolved_status = input.get("status", ProjectStatus.COMPLETED.value)

    if project_id or investigation_id:
        from sqlmodel import select as _select

        from aila.modules.forensics.db_models import ForensicsProjectRecord, InvestigationRunRecord
        from aila.platform.uow import UnitOfWork

        async with UnitOfWork() as uow:
            if project_id and not investigation_id:
                # Full-analysis path -- complete only an active project.
                proj = (await uow.session.exec(
                    _select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
                )).first()
                if proj is not None:
                    if proj.status in {
                        ProjectStatus.CREATED.value,
                        ProjectStatus.READY.value,
                        ProjectStatus.ANALYZING.value,
                    }:
                        proj.status = ProjectStatus.COMPLETED.value
                    resolved_status = proj.status
                    uow.session.add(proj)

            if investigation_id:
                # Freeflow path -- complete only a pending or running investigation.
                inv = (await uow.session.exec(
                    _select(InvestigationRunRecord).where(InvestigationRunRecord.id == investigation_id)
                )).first()
                if inv is not None:
                    if inv.status in {
                        InvestigationStatus.PENDING.value,
                        InvestigationStatus.RUNNING.value,
                    }:
                        inv.status = InvestigationStatus.COMPLETED.value
                    resolved_status = inv.status
                    uow.session.add(inv)

            await uow.commit()

    return StateResult(
        next_state=RESERVED_SUCCEEDED,
        output={**input, "status": resolved_status},
    )


_FAILURE_REASON_MAX_CHARS = 500


async def _state_analysis_failed(
    input: dict[str, Any], services: ForensicsWorkflowServices,
) -> StateResult:
    """Failure terminal for project analysis runs: mark the project failed.

    The engine routes here from any state's ``on_failure`` with only the
    failure facts (``failed_state`` / ``error_class`` / ``error_message`` on a
    raise or timeout, ``previous_state`` / ``error`` / ``error_detail`` on an
    output-validation failure), so the project id comes from the run's
    ``TaskRecord`` kwargs (``run_id`` is the task id). Only an active project
    (created / ready / analyzing) is moved to failed, so a terminal status
    another path already wrote (intake's own failure and reason) stands.
    """
    from sqlmodel import select as _select

    from aila.modules.forensics.db_models import ForensicsProjectRecord
    from aila.platform.tasks.models import TaskRecord
    from aila.platform.uow import UnitOfWork

    failed_state = str(input.get("failed_state") or input.get("previous_state") or "unknown")
    error = str(input.get("error_class") or input.get("error") or "unknown error")
    detail = input.get("error_message") or input.get("error_detail")
    reason = f"{failed_state} failed: {error}"
    if detail and detail != error:
        reason = f"{reason}: {detail}"
    reason = reason[:_FAILURE_REASON_MAX_CHARS]

    project_id = ""
    project_status: str | None = None
    async with UnitOfWork() as uow:
        task = (await uow.session.exec(
            _select(TaskRecord).where(TaskRecord.id == services.run_id)
        )).first()
        if task is not None and task.kwargs_json:
            project_id = str(json.loads(task.kwargs_json).get("project_id") or "")
        if project_id:
            proj = (await uow.session.exec(
                _select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
            )).first()
            if proj is not None:
                if proj.status in {
                    ProjectStatus.CREATED.value,
                    ProjectStatus.READY.value,
                    ProjectStatus.ANALYZING.value,
                }:
                    proj.status = ProjectStatus.FAILED.value
                    proj.failure_reason = reason
                    uow.session.add(proj)
                project_status = proj.status
        await uow.commit()

    return StateResult(
        next_state=RESERVED_FAILED,
        output={
            "project_id": project_id,
            "status": project_status,
            "failed_state": failed_state,
            "error_class": error,
            "failure_reason": reason,
        },
    )


# ---------------------------------------------------------------------------
# Mode: FULL_ANALYSIS
# ---------------------------------------------------------------------------

FORENSICS_FULL_ANALYSIS_V1: WorkflowDefinition = WorkflowDefinition(
    definition_id="forensics.full_analysis.v1",
    start_state="intake",
    allow_phase_handoff=True,
    states={
        "intake": StateSpec(
            handler=_h(state_intake),
            timeout_s=300.0,
            max_retries=2,
            retriable_on=_SSH_TRANSIENT,
            on_success="collection",
            on_failure="analysis_failed",
        ),
        "collection": StateSpec(
            handler=_h(state_collection),
            timeout_s=FORENSICS_DEFAULTS.collection_timeout_seconds,
            max_retries=1,
            retriable_on=_SSH_TRANSIENT,
            on_success="deep_analysis",
            on_failure="analysis_failed",
        ),
        "deep_analysis": StateSpec(
            handler=_h(state_deep_analysis),
            timeout_s=7200.0,
            max_retries=1,
            retriable_on=_SSH_TRANSIENT,
            on_success="promotion",
            on_failure="analysis_failed",
        ),
        "promotion": StateSpec(
            handler=_h(state_promotion),
            timeout_s=300.0,
            max_retries=1,
            on_success="resolution",
            on_failure="analysis_failed",
        ),
        "resolution": StateSpec(
            handler=_h(state_resolution),
            timeout_s=300.0,
            max_retries=1,
            on_success="writeup",
            on_failure="analysis_failed",
        ),
        "writeup": StateSpec(
            handler=_h(state_writeup),
            timeout_s=600.0,
            max_retries=1,
            on_success="response_emit",
            on_failure="analysis_failed",
        ),
        "response_emit": StateSpec(
            handler=_h(_state_response_emit),
            timeout_s=30.0,
            on_success=RESERVED_SUCCEEDED,
            on_failure="analysis_failed",
        ),
        "analysis_failed": StateSpec(
            handler=_h(_state_analysis_failed),
            timeout_s=30.0,
            on_success=RESERVED_FAILED,
        ),
    },
    services_factory=_build_services,
)


# ---------------------------------------------------------------------------
# Mode: FREEFLOW
# ---------------------------------------------------------------------------

FORENSICS_FREEFLOW_V1: WorkflowDefinition = WorkflowDefinition(
    definition_id="forensics.freeflow.v1",
    start_state="freeflow",
    allow_phase_handoff=True,
    states={
        "freeflow": StateSpec(
            handler=_h(state_freeflow),
            timeout_s=6000.0,
            max_retries=1,
            retriable_on=_SSH_TRANSIENT,
            on_success="promotion",
        ),
        "promotion": StateSpec(
            handler=_h(state_freeflow_promotion),
            timeout_s=300.0,
            max_retries=1,
            on_success="writeup",
        ),
        "writeup": StateSpec(
            handler=_h(state_writeup),
            timeout_s=600.0,
            max_retries=1,
            on_success="response_emit",
        ),
        "response_emit": StateSpec(
            handler=_h(_state_response_emit),
            timeout_s=30.0,
            on_success=RESERVED_SUCCEEDED,
        ),
    },
    services_factory=_build_services,
)


# ---------------------------------------------------------------------------
# Mode: RAW_DIRECTORY (intake-only)
# ---------------------------------------------------------------------------
#
# Raw-directory projects skip collection / deep_analysis / promotion / writeup
# entirely. ``state_intake`` enumerates and persists the files, then routes
# directly to ``__succeeded__``. The free-flow investigator queries the
# resulting ProjectEvidenceRecord rows when the analyst asks a question.

FORENSICS_RAW_DIRECTORY_V1: WorkflowDefinition = WorkflowDefinition(
    definition_id="forensics.raw_directory.v1",
    start_state="intake",
    allow_phase_handoff=True,
    states={
        "intake": StateSpec(
            handler=_h(state_intake),
            timeout_s=300.0,
            max_retries=2,
            retriable_on=_SSH_TRANSIENT,
            on_success=RESERVED_SUCCEEDED,
            on_failure="analysis_failed",
        ),
        "analysis_failed": StateSpec(
            handler=_h(_state_analysis_failed),
            timeout_s=30.0,
            on_success=RESERVED_FAILED,
        ),
    },
    services_factory=_build_services,
)


# ---------------------------------------------------------------------------
# Mode registry (consumed by dispatcher via dispatches_to)
# ---------------------------------------------------------------------------

FORENSICS_MODE_DEFINITIONS: dict[str, WorkflowDefinition] = {
    FORENSICS_FULL_ANALYSIS_V1.definition_id: FORENSICS_FULL_ANALYSIS_V1,
    FORENSICS_FREEFLOW_V1.definition_id: FORENSICS_FREEFLOW_V1,
    FORENSICS_RAW_DIRECTORY_V1.definition_id: FORENSICS_RAW_DIRECTORY_V1,
}


# ---------------------------------------------------------------------------
# Dispatcher: routing -> mode_selection -> __succeeded__
# Uses platform two-phase dispatch (is_dispatcher=True + dispatches_to)
# ---------------------------------------------------------------------------

async def _state_routing(
    input: dict[str, Any], _services: object,
) -> StateResult:
    """Determine which workflow mode to execute based on input.

    Reads ``input["mode"]`` (default ``"full_analysis"``) and maps it to the
    corresponding ``WorkflowDefinition.definition_id``.
    """
    mode = input.get("mode", "full_analysis")
    if mode == "freeflow":
        selected_id = FORENSICS_FREEFLOW_V1.definition_id
    elif mode == "raw_directory":
        selected_id = FORENSICS_RAW_DIRECTORY_V1.definition_id
    else:
        # RFC-13 (#68): full_analysis (and any unknown mode) runs the
        # discovery-driven evidence hub, which composes the same forensic
        # state handlers (intake, collection, deep_analysis, promotion) as the
        # fixed pipeline, evidence-gated. ``definitions_hub`` imports this
        # module's builders, so the hub is imported + registered lazily here --
        # only when full-analysis is actually routed. That avoids an import
        # cycle AND keeps a hub-import fault from gating the fixed-mode task
        # registration or the freeflow / raw_directory paths: a broken hub
        # would fail only a full-analysis dispatch, nothing else.
        from aila.modules.forensics.workflow.definitions_hub import (
            FORENSICS_INVESTIGATE_HUB,
        )

        FORENSICS_MODE_DEFINITIONS.setdefault(
            FORENSICS_INVESTIGATE_HUB.definition_id, FORENSICS_INVESTIGATE_HUB,
        )
        selected_id = FORENSICS_INVESTIGATE_HUB.definition_id
    return StateResult(
        next_state="mode_selection",
        output={"selected_definition_id": selected_id, **input},
    )


async def _state_mode_selection(
    input: dict[str, Any], _services: object,
) -> StateResult:
    """Confirm the selected definition and hand off to the platform dispatcher.

    The platform ``_run_two_phase_dispatch`` reads ``selected_definition_id``
    from the terminal output to resolve which inner workflow to execute.
    """
    return StateResult(
        next_state=RESERVED_SUCCEEDED,
        output=input,
    )


FORENSICS_DISPATCHER_V1: WorkflowDefinition = WorkflowDefinition(
    definition_id="forensics.dispatcher.v1",
    start_state="routing",
    is_dispatcher=True,
    dispatches_to=FORENSICS_MODE_DEFINITIONS,
    states={
        "routing": StateSpec(
            handler=_h(_state_routing),
            timeout_s=60.0,
            max_retries=1,
            on_success="mode_selection",
        ),
        "mode_selection": StateSpec(
            handler=_h(_state_mode_selection),
            timeout_s=30.0,
            max_retries=0,
            on_success=RESERVED_SUCCEEDED,
        ),
    },
    services_factory=_build_services,
)
