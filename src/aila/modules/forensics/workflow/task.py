"""Platform task entry points for forensics workflows.

Both functions are pure seed stubs decorated with ``@platform_task``.
All platform orchestration (WorkflowRunRecord creation, plan_json writes,
DurableStateMachine execution, inner definition resolution) is owned by
``@platform_task`` via ``_run_two_phase_dispatch`` when
``definition.is_dispatcher=True`` -- the same pattern used by the
vulnerability module (Phase 183).

This satisfies the v5.0 core principle: modules write pure state handlers
and nothing else.
"""
from __future__ import annotations

import logging
from typing import Any

from sqlmodel import select

from aila.config import get_settings
from aila.modules.forensics._task_queue import default_task_queue
from aila.modules.forensics.contracts.status import ProjectStatus
from aila.modules.forensics.db_models import ForensicsProjectRecord
from aila.modules.forensics.services.integration import build_integration_payload
from aila.modules.forensics.services.machine_readiness import MachineReadinessService
from aila.modules.forensics.workflow.definitions import FORENSICS_DISPATCHER_V1

# Import the panel task modules at the ordinary forensics task import root so
# worker boot registers every forensics callable without a separate import list.
from aila.modules.forensics.workflow.panel.task import run_forensics_panel_investigate
from aila.modules.forensics.workflow.panel.writeup import run_forensics_panel_writeup
from aila.platform.tasks.artifacts import store_task_json_result
from aila.platform.tasks.context import TaskContext
from aila.platform.tasks.models import TaskRecord
from aila.platform.tasks.queue import qualified_task_name
from aila.platform.tasks.template import platform_task
from aila.platform.uow import UnitOfWork
from aila.storage.db_models import ManagedSystemRecord

_log = logging.getLogger(__name__)

__all__ = [
    "run_forensics_analysis",
    "run_forensics_investigation",
    "run_forensics_panel_investigate",
    "run_forensics_panel_writeup",
    "run_forensics_readiness",
]


@platform_task(
    track="forensics",
    module_id="forensics",
    max_tries=3,
    timeout_s=10800.0,
    definition=FORENSICS_DISPATCHER_V1,
)
async def run_forensics_analysis(
    ctx: TaskContext,
    **kwargs: Any,
) -> dict[str, Any]:
    """Seed -- platform dispatch handles two-phase execution via FORENSICS_DISPATCHER_V1."""
    ...


@platform_task(
    track="forensics",
    module_id="forensics",
    max_tries=3,
    timeout_s=7200.0,
    definition=FORENSICS_DISPATCHER_V1,
)
async def run_forensics_investigation(
    ctx: TaskContext,
    **kwargs: Any,
) -> dict[str, Any]:
    """Seed -- platform dispatch handles two-phase execution via FORENSICS_DISPATCHER_V1."""
    ...


async def _active_analysis_task_id(session: Any, project_id: str) -> str | None:
    """Return the id of an active ``run_forensics_analysis`` task for this
    project, or None.

    One analysis pipeline per project: readiness and full-analysis may both
    try to enqueue one, and two would race on ArtifactRecord inserts. The
    fn_path is derived from the task callable the same way ``TaskQueue.submit``
    stores it.
    """
    fn_path = qualified_task_name(run_forensics_analysis)
    return (await session.exec(
        select(TaskRecord.id).where(
            TaskRecord.fn_path == fn_path,
            TaskRecord.status.in_(["queued", "running", "waiting"]),  # type: ignore[union-attr]
            TaskRecord.kwargs_json.like(f'%"project_id": "{project_id}"%'),
        ).limit(1)
    )).first()


@platform_task(
    track="forensics_readiness",
    module_id="forensics",
    max_tries=1,
    timeout_s=1200.0,
)
async def run_forensics_readiness(
    ctx: TaskContext,
    **kwargs: Any,
) -> dict[str, Any]:
    """Check analyzer readiness for one project and persist the result.

    The submitting endpoint validates team ownership. The platform wrapper
    binds the ambient team scope from ``ctx.team_id``, so the project and
    system reads here are scoped the same way.

    When the analyzer is ready and the project is still CREATED, the project
    flips to READY and the analysis pipeline is enqueued, unless one is already
    active for the project (then ``already_queued`` / ``existing_task_id`` are
    set instead). The result is stored as a task JSON artifact keyed by
    ``ctx.task_id``.
    """
    project_id = str(kwargs["project_id"])

    async with UnitOfWork() as uow:
        project = (await uow.session.exec(
            select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
        )).first()
        if project is None:
            raise LookupError(f"Project {project_id} not found for readiness check.")
        system = (await uow.session.exec(
            select(ManagedSystemRecord).where(ManagedSystemRecord.id == project.system_id)
        )).first()
        if system is None:
            raise LookupError(f"System {project.system_id} not found for readiness check.")
        # The follow-up analysis task keeps the caller's group, which the
        # worker cannot see in its context; it is read from this task's record.
        group_id = (await uow.session.exec(
            select(TaskRecord.group_id).where(TaskRecord.id == ctx.task_id)
        )).first()
        if group_id is None:
            raise LookupError(f"Task {ctx.task_id} not found for readiness check.")
        integration = build_integration_payload(system)
        system_id = system.id
        system_name = system.name
        evidence_directory = project.evidence_directory
        analyzer_os = project.analyzer_os
        project_kind = project.project_kind

    async def _log_progress(event: dict[str, Any]) -> None:
        _log.debug(
            "Readiness check progress: %s -- %s",
            event.get("tool", "system"),
            event.get("message"),
        )

    result = await MachineReadinessService(get_settings()).check_readiness(
        integration=integration,
        system_id=system_id,
        system_name=system_name,
        evidence_directory=evidence_directory,
        analyzer_os=analyzer_os,
        progress_cb=_log_progress,
    )

    enqueue_mode: str | None = None
    if result.ready:
        async with UnitOfWork() as uow:
            existing_task_id = await _active_analysis_task_id(uow.session, project_id)
            if existing_task_id is not None:
                result.already_queued = True
                result.existing_task_id = existing_task_id
            else:
                proj = (await uow.session.exec(
                    select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
                )).first()
                if proj is not None and proj.status == ProjectStatus.CREATED.value:
                    proj.status = ProjectStatus.READY.value
                    uow.session.add(proj)
                    await uow.session.commit()
                    enqueue_mode = (
                        "raw_directory" if project_kind == "raw_directory" else "full_analysis"
                    )

    # Enqueue OUTSIDE the DB session: the queue submit is a network await and
    # must not pin the pooled DB connection. The status flip is already
    # committed above; enqueue only if it fired.
    if enqueue_mode is not None:
        await default_task_queue().submit(
            track="forensics",
            fn=run_forensics_analysis,
            kwargs={
                "project_id": project_id,
                "mode": enqueue_mode,
                "integration": integration,
                "analyzer_os": analyzer_os,
                "evidence_directory": evidence_directory,
                "project_kind": project_kind,
            },
            user_id=ctx.user_id,
            group_id=group_id,
            team_id=ctx.team_id,
        )
        _log.info("Auto-enqueued %s for project %s", enqueue_mode, project_id)

    payload = result.model_dump(mode="json")
    await store_task_json_result(
        task_id=ctx.task_id,
        module_id="forensics",
        payload=payload,
        team_id=ctx.team_id,
    )
    return payload
