"""Write-up generation state handler.

Generates a professional security engineering write-up from
investigation steps, artifacts found, and methodology used.
"""
from __future__ import annotations

import logging
from typing import Any

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
        f"Write-up built in {build_elapsed:.1f}s — {content_chars:,} markdown chars",
        {
            "stage": "writeup_built",
            "elapsed_s": round(build_elapsed, 1),
            "content_chars": content_chars,
            "title": writeup_data.get("title", ""),
        },
    )

    from aila.modules.forensics.db_models import WriteUpRecord
    from aila.platform.uow import UnitOfWork

    async with UnitOfWork() as uow:
        record = WriteUpRecord(
            project_id=project_id,
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
        f"Write-up persisted: {writeup_id[:8]} — ready in the Write-ups tab",
        {"stage": "writeup_persisted", "writeup_id": writeup_id},
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
