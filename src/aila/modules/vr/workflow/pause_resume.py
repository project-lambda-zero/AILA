"""VR binding of the platform investigation lifecycle service.

Thin wrappers over :mod:`aila.platform.services.investigation_lifecycle`:
pause / resume are bound to the VR record models, the vr branch table,
the ``vr`` ARQ track, and ``run_vr_investigate``. The pause-reason enum
coercion stays here (VR owns its reason vocabulary); the platform takes
the already-coerced value. The api_router pause / resume handlers keep
the ``pause_investigation_atomic`` / ``resume_investigation_atomic``
call surface unchanged.
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
    ResumeInvestigationError,
)
from aila.platform.services.investigation_lifecycle import (
    pause_investigation as _platform_pause,
)
from aila.platform.services.investigation_lifecycle import (
    resume_investigation as _platform_resume,
)

__all__ = [
    "PauseInvestigationError",
    "ResumeInvestigationError",
    "pause_investigation_atomic",
    "resume_investigation_atomic",
]

_VR_BRANCH_TABLE = "vr_investigation_branches"


def _pause_reason_value(reason: str | None) -> str:
    """Coerce caller-supplied reason to a contract-enum value.

    Empty / unknown strings degrade to ``OPERATOR`` so the column never
    holds a free-form string.
    """
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
