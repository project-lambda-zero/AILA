"""Response emit state -- finalize project status and surface the result.

The workflow's terminal handler. Walks the project row to either
``completed`` (a finding was persisted) or ``stalled`` (research surfaced
no concrete primitive) and returns a compact summary so the platform's
response transport has a deterministic payload to ship.

DB write failures are logged and swallowed: the workflow has already
done its work; refusing to emit because of an unrelated transport error
would convert a successful run into a misleading failure on the API
surface.
"""
from __future__ import annotations

import logging
from typing import Any

from sqlmodel import select as _select

from aila.modules.vr.contracts.project import VRProjectStatus
from aila.modules.vr.db_models import VRProjectRecord
from aila.platform.contracts import utc_now
from aila.platform.exceptions import AILAError
from aila.platform.uow import UnitOfWork
from aila.platform.workflows.types import RESERVED_SUCCEEDED, StateResult

__all__ = ["state_response_emit"]

_log = logging.getLogger(__name__)


def _resolve_status(input: dict[str, Any]) -> str:
    if input.get("finding_id"):
        return VRProjectStatus.COMPLETED.value
    if input.get("research_status") == "stalled":
        return VRProjectStatus.STALLED.value
    poc = input.get("poc") or {}
    if poc.get("status") in {"untested", "unverified"}:
        return VRProjectStatus.STALLED.value
    return VRProjectStatus.COMPLETED.value


async def _set_status(project_id: str, status: str) -> None:
    if not project_id:
        return
    try:
        async with UnitOfWork() as uow:
            row = (
                await uow.session.exec(
                    _select(VRProjectRecord).where(VRProjectRecord.id == project_id)
                )
            ).first()
            if row is None:
                return
            row.status = status
            row.updated_at = utc_now()
            uow.session.add(row)
            await uow.commit()
    except (OSError, RuntimeError, AILAError) as exc:
        _log.warning("response_emit DB write failed (project_id=%s): %s", project_id, exc)


async def state_response_emit(input: dict[str, Any], services: Any) -> StateResult:
    """Mark the project as completed/stalled and emit the terminal payload."""
    del services  # unused -- terminal state needs no services
    project_id = str(input.get("project_id") or "")
    status = _resolve_status(input)
    await _set_status(project_id, status)
    poc = input.get("poc") or {}
    return StateResult(
        next_state=RESERVED_SUCCEEDED,
        output={
            "status": status,
            "project_id": project_id,
            "finding_id": input.get("finding_id"),
            "advisory": input.get("advisory"),
            "crash_type": input.get("crash_type"),
            "poc_status": poc.get("status"),
            "poc_reliability": poc.get("reliability"),
        },
    )
