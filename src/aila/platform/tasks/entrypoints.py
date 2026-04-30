from __future__ import annotations

from typing import Any

from aila.platform.runtime import get_worker_platform
from aila.platform.tasks.context import TaskContext
from aila.platform.tasks.template import platform_task

__all__ = ["run_platform_handle"]


@platform_task(
    track="vulnerability",
    module_id="__platform__",
    max_tries=3,
    timeout_s=3600.0,
)
async def run_platform_handle(
    ctx: TaskContext,
    *,
    query: str,
    module_payload: dict[str, Any] | None = None,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generic platform task entrypoint for queued scan submissions.

    Unlike module-local task entrypoints, this stays in platform code and lets
    API routes enqueue work without importing module internals directly.
    """
    platform = await get_worker_platform()
    response = await platform.handle(
        query=query,
        module_payload=module_payload or {},
        module_options=options or {},
        run_id=ctx.task_id,
    )
    return {"response": response.model_dump(mode="json")}
