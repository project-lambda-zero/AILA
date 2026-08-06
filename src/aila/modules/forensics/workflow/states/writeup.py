"""Write-up generation state handler.

Generates a professional security engineering write-up from
investigation steps, artifacts found, and methodology used.
"""
from __future__ import annotations

import logging
from typing import Any

from aila.platform.events import (
    ModuleWorkflowCompleted,
    ModuleWorkflowCompletedPayload,
    publish,
)

__all__ = ["state_writeup"]

_log = logging.getLogger(__name__)

state_writeup_parallel_safe = True
state_writeup_writes_fields = ["writeup"]


async def state_writeup(
    input: dict[str, Any],
    services: Any,
) -> dict[str, Any]:
    """Generate professional write-up from investigation results.

    Args:
        input: Workflow input with investigation/analysis results.
        services: ForensicsWorkflowServices instance.

    Returns:
        Dict with 'writeup_id', 'next_state'.
    """
    project_id = input.get("project_id", "")
    investigation_id = input.get("investigation_id")
    steps = input.get("steps", [])

    import time as _time
    await services.emitter.emit(
        "writeup",
        f"Generating write-up from {len(steps)} agent step(s) + prior artifacts...",
        {"stage": "writeup_start", "step_count": len(steps)},
    )

    from aila.modules.forensics.reporting.writeup_builder import build_writeup

    build_start = _time.monotonic()
    writeup_data = await build_writeup(
        project_id=project_id,
        investigation_id=investigation_id,
        steps=steps,
        input_context=input,
    )
    build_elapsed = _time.monotonic() - build_start
    content_chars = len(writeup_data.get("content", "") or "")
    await services.emitter.emit(
        "writeup",
        f"Write-up built in {build_elapsed:.1f}s -- {content_chars:,} markdown chars",
        {
            "stage": "writeup_built",
            "elapsed_s": round(build_elapsed, 1),
            "content_chars": content_chars,
            "title": writeup_data.get("title", ""),
        },
    )

    from sqlmodel import select as _select

    from aila.modules.forensics.db_models import ForensicsProjectRecord, WriteUpRecord
    from aila.platform.uow import UnitOfWork

    async with UnitOfWork() as uow:
        # Load the parent project's team_id so the write-up row carries
        # the same tenant marker (#59). The team-scope listener
        # auto-filters read queries on ``forensics_writeups`` by team_id,
        # so a row inserted with the wrong / missing team_id is
        # invisible to the tenant that owns the investigation. A missing
        # project row (deletion race) leaves the write-up unowned; the
        # response_emit state downstream still lets the primary caller
        # finish, and the write-up will only be visible to admins.
        project = (await uow.session.exec(
            _select(ForensicsProjectRecord).where(
                ForensicsProjectRecord.id == project_id
            )
        )).first()
        record = WriteUpRecord(
            project_id=project_id,
            team_id=project.team_id if project is not None else None,
            investigation_id=investigation_id,
            title=writeup_data.get("title", "Investigation Write-Up"),
            content_markdown=writeup_data.get("content", ""),
            methodology=writeup_data.get("methodology", ""),
            artifacts_referenced_json=writeup_data.get("artifacts_json", "[]"),
        )
        uow.session.add(record)
        await uow.commit()
        writeup_id = record.id

    await services.emitter.emit(
        "writeup",
        f"Write-up persisted: {writeup_id[:8]} -- ready in the Write-ups tab",
        {"stage": "writeup_persisted", "writeup_id": writeup_id},
    )

    # Domain-event emission for the investigation workflow terminal
    # state (RFC-05 Phase 3). Fired after the write-up row is
    # persisted; the following ``response_emit`` state is a terminal
    # gate only. Guarded so a payload-construction fault cannot break
    # the write-up handoff.
    try:
        run_id = str(getattr(services, "run_id", "") or "")
        publish(
            ModuleWorkflowCompleted(
                source_module="forensics",
                payload=ModuleWorkflowCompletedPayload(
                    module_id="forensics",
                    run_id=run_id,
                    workflow_id="investigation",
                    metrics={
                        "writeup_id": writeup_id,
                        "content_chars": content_chars,
                        "build_elapsed_s": round(build_elapsed, 3),
                        "step_count": len(steps),
                    },
                ),
            ),
        )
    except (RuntimeError, ValueError, TypeError, AttributeError) as exc:
        _log.warning(
            "module.workflow.completed publish failed for project %s: %s",
            project_id,
            exc,
        )

    from aila.platform.workflows.types import StateResult

    return StateResult(
        next_state="response_emit",
        output={
            "writeup_id": writeup_id,
            "project_id": project_id,
            "investigation_id": investigation_id,
            "integration": input.get("integration", {}),
            "evidence_directory": input.get("evidence_directory", ""),
            "analyzer_os": input.get("analyzer_os", "linux"),
        },
    )


state_writeup.parallel_safe = state_writeup_parallel_safe  # type: ignore[attr-defined]
state_writeup.writes_fields = state_writeup_writes_fields  # type: ignore[attr-defined]
