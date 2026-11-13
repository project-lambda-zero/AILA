"""Re-dispatch for stuck forensics investigations (#450).

A freeflow investigation has no branch rows and is re-driven from its project
row as ``run_forensics_investigation``. A panel investigation is re-driven once
per active branch as ``run_forensics_panel_investigate``. A branched
investigation with no active branch is refused: it is never re-driven as
freeflow.
"""

from __future__ import annotations

from typing import Any

from sqlmodel import select

from aila.modules.forensics.db_models import (
    ForensicsInvestigationBranchRecord,
    ForensicsProjectRecord,
    InvestigationRunRecord,
)
from aila.modules.forensics.services.integration import build_integration_payload
from aila.platform.services.investigation_lifecycle import (
    PreparedSubmit,
    ReenqueueInvestigationError,
)
from aila.platform.uow import UnitOfWork
from aila.storage.db_models import ManagedSystemRecord

__all__ = ["prepare_recovery_submit"]

# Attribution group the stuck healer has always used for its panel re-drives.
_RECOVERY_GROUP_ID = "forensics_stuck_healer"


async def prepare_recovery_submit(inv_id: str, branch_id: str | None) -> PreparedSubmit:
    """Build the send closure that re-drives one worker task of ``inv_id``.

    ``branch_id`` set: the send enqueues the panel task for that branch.
    ``branch_id`` None: the investigation has no active branch, so it must be
    freeflow. Every lookup runs here, before the reset commits.

    Raises ``ReenqueueInvestigationError`` when the dispatch cannot be built.
    """
    from aila.modules.forensics._task_queue import default_task_queue
    from aila.modules.forensics.workflow.panel.task import (
        run_forensics_panel_investigate,
    )
    from aila.modules.forensics.workflow.task import run_forensics_investigation

    task_queue = default_task_queue()

    if branch_id is not None:
        panel_kwargs: dict[str, Any] = {"investigation_id": inv_id, "branch_id": branch_id}

        async def _send_panel() -> None:
            await task_queue.submit(
                track="forensics",
                fn=run_forensics_panel_investigate,
                kwargs=panel_kwargs,
                user_id="system",
                group_id=_RECOVERY_GROUP_ID,
                team_id=None,
                bypass_dedup=True,
            )

        return _send_panel

    freeflow_kwargs, team_id = await _load_freeflow_dispatch(inv_id)

    async def _send_freeflow() -> None:
        handle = await task_queue.submit(
            track="forensics",
            fn=run_forensics_investigation,
            kwargs=freeflow_kwargs,
            user_id="system",
            group_id=_RECOVERY_GROUP_ID,
            team_id=team_id,
            bypass_dedup=True,
        )
        await _link_task(inv_id, handle.task_id)

    return _send_freeflow


async def _load_freeflow_dispatch(inv_id: str) -> tuple[dict[str, Any], str | None]:
    """Return the freeflow task kwargs and the investigation's team id."""
    async with UnitOfWork() as uow:
        has_branches = (await uow.session.exec(
            select(ForensicsInvestigationBranchRecord.id)
            .where(ForensicsInvestigationBranchRecord.investigation_id == inv_id)
            .limit(1)
        )).first()
        if has_branches is not None:
            raise ReenqueueInvestigationError(
                f"Investigation {inv_id!r} has branch rows but no active branch; "
                "refusing to re-drive it as freeflow.",
            )

        inv = (await uow.session.exec(
            select(InvestigationRunRecord).where(InvestigationRunRecord.id == inv_id)
        )).first()
        if inv is None:
            raise ReenqueueInvestigationError(f"Investigation {inv_id!r} not found.")

        project = (await uow.session.exec(
            select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == inv.project_id)
        )).first()
        if project is None:
            raise ReenqueueInvestigationError(
                f"Project {inv.project_id!r} of investigation {inv_id!r} not found.",
            )

        system = (await uow.session.exec(
            select(ManagedSystemRecord).where(ManagedSystemRecord.id == project.system_id)
        )).first()
        if system is None:
            raise ReenqueueInvestigationError(
                f"Analyzer system {project.system_id} of investigation {inv_id!r} no longer exists.",
            )

        kwargs: dict[str, Any] = {
            "investigation_id": inv.id,
            "project_id": inv.project_id,
            "question": inv.question,
            "max_attempts": inv.max_attempts,
            "integration": build_integration_payload(system),
            "analyzer_os": project.analyzer_os,
            "evidence_directory": project.evidence_directory,
            "mode": "freeflow",
        }
        if inv.parent_investigation_id is not None:
            kwargs["parent_investigation_id"] = inv.parent_investigation_id
        return kwargs, inv.team_id


async def _link_task(inv_id: str, task_id: str) -> None:
    """Point the investigation row at the re-driven worker task.

    The reset keeps the stale ``task_id``; cancel reads this column, so it must
    name the live task. Mirrors the start and rerun routes.
    """
    async with UnitOfWork() as uow:
        inv = (await uow.session.exec(
            select(InvestigationRunRecord).where(InvestigationRunRecord.id == inv_id)
        )).first()
        if inv is not None:
            inv.task_id = task_id
            await uow.commit()
