"""FastAPI router scaffold for the template investigation lifecycle.

Copy-me scaffold demonstrating the canonical platform-bound wiring for a
new module's investigation lifecycle endpoints. Every handler in this
file is a thin dispatcher over a shared platform service:

* ``pause`` / ``resume`` / ``re-enqueue`` call
  :mod:`aila.platform.services.investigation_lifecycle` directly with the
  module's record models, branch table, ARQ track, and task function.
* ``cost`` calls
  :mod:`aila.platform.services.investigation_cost.compute_live_investigation_cost`
  so the budget gauge reads from ``LLMCostRecord`` rather than the dead
  ``cost_actual_usd`` column.

The four-source-of-truth atomic transition body (inv row, workflow
cursors, taskrecord rows, ARQ Redis) is platform-owned; the module never
re-implements it. Rule 69 in ``aila.tools.honesty_audit`` (
``lifecycle_binding_copy_of_platform``) locks the module out of
reintroducing a duplicated adapter under ``workflow/pause_resume.py``.

To turn this scaffold into a real router:

1. Rename ``Template`` / ``template`` / ``TEMPLATE`` to the module's
   identifier throughout.
2. Wire ``create_template_router()`` into
   :meth:`TemplateModule.route_specs` (see the commented example in
   ``module.py``).
3. Replace the placeholder ``run_template_investigate`` task import with
   the module's actual ``@platform_task``-decorated task function.
4. Add per-module response envelopes / auth visibility checks alongside
   these handlers as the module grows -- keep the lifecycle bodies
   themselves as thin as they are here.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status

from aila.api.limiter import limiter
from aila.api.schemas.envelope import DataEnvelope
from aila.platform.contracts.auth import AuthContext, require_auth
from aila.platform.contracts.enums import BranchStatus
from aila.platform.services.investigation_cost import (
    compute_live_investigation_cost,
)
from aila.platform.services.investigation_lifecycle import (
    PauseInvestigationError,
    ReenqueueInvestigationError,
    ResumeInvestigationError,
    pause_investigation,
    reenqueue_investigation,
    resume_investigation,
)
from aila.platform.uow import UnitOfWork

from .db_models import (
    TemplateInvestigationBranchRecord,
    TemplateInvestigationRecord,
)

__all__ = ["create_template_router"]

_log = logging.getLogger(__name__)

# ARQ track (== queue name) the module's worker runs under. Must match
# the ``track`` argument threaded through ``@platform_task`` and every
# ``TaskQueue.submit`` call in this module. Rename in one place; the
# lifecycle dispatchers below pick it up.
_TEMPLATE_TRACK = "template"

# Raw branch table name. The pause / resume atomic flip projects
# ``TemplateInvestigationBranchRecord.status`` via a direct UPDATE (the
# operator-facing chip colour), so it needs the concrete table name.
_TEMPLATE_BRANCH_TABLE = "template_investigation_branches"

# Default pause reason value written into the investigation row when the
# operator triggers a pause via the endpoint. Modules that carry a
# richer reason enum (e.g. VR's ``InvestigationPauseReason``) coerce
# the caller-supplied value module-side and pass the enum ``.value``
# in; the platform service takes the already-coerced string.
_DEFAULT_PAUSE_REASON = "operator"


def create_template_router() -> APIRouter:
    """Create and return the template investigation-lifecycle router.

    Called by the platform via ``TemplateModule.route_specs`` after the
    scaffold is renamed and wired up. Returns a FastAPI ``APIRouter``
    with the four lifecycle endpoints bound to the platform services.
    """
    router = APIRouter(tags=["template"])

    @router.post(
        "/investigations/{investigation_id}/pause",
        response_model=DataEnvelope[dict[str, Any]],
        summary="Operator-initiated pause via the shared platform service.",
    )
    @limiter.limit("30/minute")
    async def pause_template_investigation(
        request: Request,
        investigation_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[dict[str, Any]]:
        """Dispatch pause straight through to the platform lifecycle service.

        The atomic pause -- inv row + workflow cursors + taskrecord rows
        in one transaction, followed by best-effort ARQ purge -- lives
        on the platform. This handler owns the auth visibility check +
        the reason coercion (a placeholder here) and forwards everything
        else.
        """
        del request
        try:
            summary = await pause_investigation(
                investigation_id,
                inv_model=TemplateInvestigationRecord,
                branch_model=TemplateInvestigationBranchRecord,
                branch_table=_TEMPLATE_BRANCH_TABLE,
                track=_TEMPLATE_TRACK,
                pause_reason=_DEFAULT_PAUSE_REASON,
                user_id=auth.user_id,
            )
        except PauseInvestigationError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc
        return DataEnvelope(data=summary)

    @router.post(
        "/investigations/{investigation_id}/resume",
        response_model=DataEnvelope[dict[str, Any]],
        summary="Operator-initiated resume via the shared platform service.",
    )
    @limiter.limit("30/minute")
    async def resume_template_investigation(
        request: Request,
        investigation_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[dict[str, Any]]:
        """Dispatch resume straight through to the platform lifecycle service.

        The atomic resume restores every paused cursor and fans one
        worker task out per resumed branch through the module's
        ``TaskQueue``. The task queue is auth-bound (constructed against
        the request context) for safety; the platform service enforces
        it is non-None.
        """
        from aila.api.deps import get_task_queue

        from .workflow.task import run_template_investigate

        try:
            summary = await resume_investigation(
                investigation_id,
                inv_model=TemplateInvestigationRecord,
                branch_model=TemplateInvestigationBranchRecord,
                branch_table=_TEMPLATE_BRANCH_TABLE,
                track=_TEMPLATE_TRACK,
                task_fn=run_template_investigate,
                task_queue=get_task_queue(_TEMPLATE_TRACK, request),
                user_id=auth.user_id,
                auth_user_id=auth.user_id,
                auth_role=auth.role,
                auth_team_id=auth.team_id,
            )
        except ResumeInvestigationError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc
        return DataEnvelope(data=summary)

    @router.post(
        "/investigations/{investigation_id}/re-enqueue",
        response_model=DataEnvelope[dict[str, Any]],
        summary="Reset a stalled investigation and submit fresh worker tasks.",
    )
    @limiter.limit("10/minute")
    async def reenqueue_template_investigation(
        request: Request,
        investigation_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[dict[str, Any]]:
        """Reset the row to CREATED and submit one worker task per branch.

        The reset (status flip, stale-task cancel, ``__crashed__``
        cursor wipe) lives on the platform. The module supplies a
        ``submit_one`` primitive that submits exactly one task; the
        platform fan-out iterates active branches or submits once when
        no branch is active.
        """
        del request
        del auth
        from .workflow.task import run_template_investigate

        async def _submit_one(inv_id: str, branch_id: str | None) -> None:
            # A real module dispatches via its own ``default_task_queue``
            # so the submit picks up the module's config-driven Redis
            # binding + team-id inheritance. This scaffold constructs
            # the queue lazily so the file compiles without the
            # ``_task_queue.py`` helper that a fresh copy has not
            # written yet.
            from aila.platform.tasks.queue import TaskQueue
            from aila.storage.registry import ConfigRegistry

            queue = TaskQueue(
                config_registry=ConfigRegistry(),
                module_id="template",
            )
            await queue.submit(
                track=_TEMPLATE_TRACK,
                fn=run_template_investigate,
                kwargs={
                    "investigation_id": inv_id,
                    "branch_id": branch_id,
                },
            )

        try:
            summary = await reenqueue_investigation(
                investigation_id,
                inv_model=TemplateInvestigationRecord,
                fn_path_pattern="%run_template_investigate%",
                submit_one=_submit_one,
                branch_model=TemplateInvestigationBranchRecord,
                branch_status_active=BranchStatus.ACTIVE.value,
            )
        except ReenqueueInvestigationError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc
        return DataEnvelope(data=summary)

    @router.get(
        "/investigations/{investigation_id}/cost",
        response_model=DataEnvelope[dict[str, Any]],
        summary="Live LLM cost aggregated from LLMCostRecord.",
    )
    @limiter.limit("60/minute")
    async def get_template_investigation_cost(
        request: Request,
        investigation_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[dict[str, Any]]:
        """Aggregate live LLM cost for an investigation.

        The stored ``cost_actual_usd`` column has no writers, so a direct
        read reports a permanent $0. Rule 39 in
        ``aila.tools.honesty_audit`` (``cost_read_stored_actual``)
        blocks that anti-pattern; the canonical replacement is a live
        aggregation via the platform service on every read.
        """
        del request
        del auth
        async with UnitOfWork() as uow:
            live_cost = await compute_live_investigation_cost(
                uow, investigation_id,
            )
        # A real handler reloads the inv row and returns budget +
        # remaining + budget_used_pct alongside the live aggregate;
        # the scaffold returns just the aggregate so the file stays a
        # pure lifecycle-binding demonstration.
        return DataEnvelope(
            data={
                "investigation_id": investigation_id,
                "actual_usd": live_cost,
            },
        )

    return router
