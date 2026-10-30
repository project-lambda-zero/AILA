"""ARQ task entry points for the benchmark-measurement harness.

``run_vr_eval_suite`` starts a measurement run (spins + enqueues one
investigation per benchmark task). ``run_vr_eval_collect`` scores the run
once its investigations have finished. Both are module-prefixed so they do
not collide with other modules' task names on the shared ARQ function table
(CLAUDE.md #19).
"""
from __future__ import annotations

import logging
from typing import Any

from aila.platform.tasks.context import TaskContext
from aila.platform.tasks.template import platform_task
from aila.platform.uow import UnitOfWork
from aila.storage.registry import ConfigRegistry

from .suite_runner import collect_suite_run, start_suite_run

__all__ = ["run_vr_eval_suite", "run_vr_eval_collect"]

_log = logging.getLogger(__name__)

_CFG_NAMESPACE = "vr"
_CFG_DATASET_ROOT = "eval_suite_dataset_root"
_CFG_DEFAULT_BUDGET = "eval_suite_default_budget_usd"


async def _resolve_suite_config() -> tuple[str, float]:
    """Return (dataset_root, default_budget_usd) from the VR config namespace."""
    reg = ConfigRegistry()
    dataset_root = await reg.get(_CFG_NAMESPACE, _CFG_DATASET_ROOT)
    default_budget = await reg.get(_CFG_NAMESPACE, _CFG_DEFAULT_BUDGET)
    return str(dataset_root or ""), float(default_budget or 50.0)


@platform_task(track="vr", module_id="vr", max_tries=1, timeout_s=600.0)
async def run_vr_eval_suite(
    ctx: TaskContext,
    suite: str,
    requested_by: str | None = None,
    team_id: str | None = None,
    **_: Any,
) -> dict[str, Any]:
    """Start a measurement run over ``suite``: spin + enqueue per task."""
    del ctx
    from aila.modules.vr._task_queue import default_task_queue  # noqa: PLC0415

    dataset_root, default_budget = await _resolve_suite_config()
    async with UnitOfWork() as uow:
        run = await start_suite_run(
            uow,
            suite=suite,
            dataset_root=dataset_root,
            default_budget_usd=default_budget,
            requested_by=requested_by,
            team_id=team_id,
            task_queue=default_task_queue(),
        )
        run_id = run.id
        total = run.total_count
    _log.info("eval suite run started suite=%s run_id=%s tasks=%d", suite, run_id, total)
    return {"run_id": run_id, "suite": suite, "total_count": total}


@platform_task(track="vr", module_id="vr", max_tries=1, timeout_s=600.0)
async def run_vr_eval_collect(
    ctx: TaskContext,
    run_id: str,
    **_: Any,
) -> dict[str, Any]:
    """Score a measurement run from its terminal investigations."""
    del ctx
    async with UnitOfWork() as uow:
        run = await collect_suite_run(uow, run_id)
        if run is None:
            return {"run_id": run_id, "status": "not_found"}
        return {
            "run_id": run.id,
            "status": run.status,
            "solved_count": run.solved_count,
            "total_count": run.total_count,
        }
