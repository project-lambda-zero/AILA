"""Test binding of the platform investigation lifecycle to VR models.

The production api_router pause / resume / re-enqueue handlers inline the
VR binding of :mod:`aila.platform.services.investigation_lifecycle`
(platform-bound: the handler is the call site, no module wrapper module).
The lifecycle unit tests exercise that same platform atomic sequence
through VR concrete models; this helper supplies the binding plus the VR
pause-reason coercion so the tests stay focused on lifecycle behaviour
rather than model plumbing.
"""
from __future__ import annotations

from typing import Any

from aila.modules.vr.contracts.investigation import InvestigationPauseReason
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationRecord,
)
from aila.modules.vr.workflow.task import run_vr_investigate
from aila.platform.services.investigation_lifecycle import (
    PauseInvestigationError,
    ReenqueueInvestigationError,
    ResumeInvestigationError,
)
from aila.platform.services.investigation_lifecycle import (
    pause_investigation as _platform_pause,
)
from aila.platform.services.investigation_lifecycle import (
    reenqueue_investigation as _platform_reenqueue,
)
from aila.platform.services.investigation_lifecycle import (
    resume_investigation as _platform_resume,
)

__all__ = [
    "PauseInvestigationError",
    "ReenqueueInvestigationError",
    "ResumeInvestigationError",
    "pause_investigation_atomic",
    "reenqueue_investigation_atomic",
    "resume_investigation_atomic",
]

_VR_BRANCH_TABLE = "vr_investigation_branches"


def _pause_reason_value(reason: str | None) -> str:
    """Coerce a caller-supplied reason to a contract-enum value."""
    if reason is None:
        return InvestigationPauseReason.OPERATOR.value
    try:
        return InvestigationPauseReason(reason).value
    except ValueError:
        return InvestigationPauseReason.OPERATOR.value


async def pause_investigation_atomic(
    investigation_id: str,
    *,
    user_id: str | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    """Pause every active task for ``investigation_id`` (VR binding)."""
    return await _platform_pause(
        investigation_id,
        inv_model=VRInvestigationRecord,
        branch_model=VRInvestigationBranchRecord,
        branch_table=_VR_BRANCH_TABLE,
        track="vr",
        pause_reason=_pause_reason_value(reason),
        user_id=user_id,
    )


async def resume_investigation_atomic(
    investigation_id: str,
    *,
    user_id: str | None = None,
    task_queue: Any = None,
    auth_user_id: str | None = None,
    auth_role: str | None = None,
    auth_team_id: str | None = None,
) -> dict[str, Any]:
    """Resume every paused cursor for ``investigation_id`` (VR binding)."""
    return await _platform_resume(
        investigation_id,
        inv_model=VRInvestigationRecord,
        branch_model=VRInvestigationBranchRecord,
        branch_table=_VR_BRANCH_TABLE,
        track="vr",
        task_fn=run_vr_investigate,
        task_queue=task_queue,
        user_id=user_id,
        auth_user_id=auth_user_id,
        auth_role=auth_role,
        auth_team_id=auth_team_id,
    )


async def reenqueue_investigation_atomic(
    investigation_id: str,
    *,
    new_kind: str | None = None,
    new_strategy: str | None = None,
    task_queue: Any = None,
    user_id: str | None = None,
    group_id: str | None = None,
    team_id: str | None = None,
) -> dict[str, Any]:
    """Reset + re-submit ``investigation_id`` (VR binding)."""
    if task_queue is None:
        raise ReenqueueInvestigationError(
            "task_queue argument required (auth-bound for safety)",
        )

    async def _submit_one(inv_id: str, branch_id: str | None) -> None:
        del branch_id  # VR submits once; setup owns branch spawn
        await task_queue.submit(
            track="vr",
            fn=run_vr_investigate,
            kwargs={"investigation_id": inv_id},
            user_id=user_id,
            group_id=group_id,
            team_id=team_id,
        )

    return await _platform_reenqueue(
        investigation_id,
        inv_model=VRInvestigationRecord,
        fn_path_pattern="%run_vr_investigate%",
        submit_one=_submit_one,
        new_kind=new_kind,
        new_strategy=new_strategy,
    )
