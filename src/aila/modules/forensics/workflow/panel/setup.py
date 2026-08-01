"""Forensics panel setup state (#18).

Resolves the investigation, guarantees a primary branch exists, spawns
one sibling branch per non-primary role via
:func:`aila.platform.workflows.persona_spawn.spawn_persona_siblings`,
marks the investigation RUNNING, and forwards the primary branch id
into the loop.

Not built on top of
:func:`aila.platform.workflows.investigation_setup_base.state_investigation_setup`:
that factory requires an ``InvestigationRecordBase`` (target_id +
strategy_family + team_id + platform status enum), and the forensics
free-flow ``InvestigationRunRecord`` predates the platform base and
uses a different shape (project_id + question, no target_id). Rather
than migrate the entire free-flow / hub / dispatcher graphs onto the
platform base in this ticket (out of scope, RFC-05 boundary rule),
this handler is a slim module-owned wrapper that reuses the KEY
PLATFORM PRIMITIVE :func:`spawn_persona_siblings` -- the same code
path VR + malware use for their sibling spawn -- bound to the
forensics record models.

The 3-role spine:

  halvar (primary)  researcher   -- proposes findings from the evidence
  maddie            critic       -- falsifies claims, demands proof
  renzo             implementer  -- validates / reproduces the finding

Sibling additions (specialists, additional critics) are optional and
routed via the same platform on-demand specialist path; the baseline
here is the 3-role spine, mirroring VR's default panel.
"""
from __future__ import annotations

import logging
from typing import Any

from sqlmodel import select as _select

from aila.modules.forensics._task_queue import default_task_queue
from aila.modules.forensics.contracts.status import InvestigationStatus
from aila.modules.forensics.db_models import (
    ForensicsInvestigationBranchRecord,
    InvestigationRunRecord,
)
from aila.platform.agents.branch_pool import (
    _strip_directives_from_state,
    _strip_rejected_from_state,
)
from aila.platform.contracts.enums import PersonaVoice
from aila.platform.uow import UnitOfWork
from aila.platform.workflows.persona_spawn import spawn_persona_siblings
from aila.platform.workflows.types import StateResult

__all__ = ["state_forensics_panel_setup"]

_log = logging.getLogger(__name__)

# The 3-role spine. Primary branch runs the researcher role (halvar); one
# sibling branch runs the critic role (maddie); one sibling runs the
# implementer role (renzo). Extra specialists are spawned on demand via
# the platform oracle path -- not part of the baseline panel.
_PRIMARY_PERSONA: PersonaVoice = PersonaVoice.HALVAR
_PANEL_SIBLINGS: tuple[PersonaVoice, ...] = (
    PersonaVoice.MADDIE,
    PersonaVoice.RENZO,
)


async def _resolve_or_create_primary_branch(
    investigation_id: str,
) -> str:
    """Return the primary branch id for *investigation_id*, forking one if absent.

    Idempotent: a re-entry from a resumed / re-enqueued cursor returns the
    same primary id rather than proliferating branches.
    """
    async with UnitOfWork() as uow:
        existing = (await uow.session.exec(
            _select(ForensicsInvestigationBranchRecord).where(
                ForensicsInvestigationBranchRecord.investigation_id == investigation_id,
                ForensicsInvestigationBranchRecord.fork_reason == "primary",
            )
        )).first()
        if existing is not None:
            return existing.id
        branch = ForensicsInvestigationBranchRecord(
            investigation_id=investigation_id,
            parent_branch_id=None,
            status="active",
            persona_voice=_PRIMARY_PERSONA.value,
            fork_reason="primary",
            fork_at_turn=0,
            case_state_json="{}",
            turn_count=0,
            branch_cost_usd=0.0,
        )
        uow.session.add(branch)
        await uow.session.flush()
        branch_id = branch.id
        await uow.commit()
    return branch_id


async def _mark_investigation_running(investigation_id: str) -> None:
    """Flip the InvestigationRunRecord to RUNNING when it is not already terminal.

    Terminal statuses (COMPLETED / EXHAUSTED / FAILED / CANCELLED) are
    preserved so a re-enqueued cursor on a terminated investigation
    does not silently reopen it.
    """
    async with UnitOfWork() as uow:
        inv = (await uow.session.exec(
            _select(InvestigationRunRecord).where(
                InvestigationRunRecord.id == investigation_id,
            )
        )).first()
        if inv is None:
            return
        terminal = {
            InvestigationStatus.COMPLETED.value,
            InvestigationStatus.EXHAUSTED.value,
            InvestigationStatus.FAILED.value,
            InvestigationStatus.CANCELLED.value,
        }
        if inv.status not in terminal:
            inv.status = InvestigationStatus.RUNNING.value
            uow.session.add(inv)
            await uow.commit()


async def _spawn_forensics_panel(
    *,
    investigation_id: str,
    primary_branch_id: str,
    team_id: str | None,
) -> None:
    """Bind the platform persona spawn to forensics models and enqueue."""
    from aila.modules.forensics.workflow.panel.task import (
        run_forensics_panel_investigate,
    )

    await spawn_persona_siblings(
        investigation_id,
        primary_branch_id,
        # #59: forensics_investigations now carries its own denormalised
        # ``team_id`` column. Thread it through the sibling spawn so the
        # enqueued task's TaskRecord stamps the correct tenant even if
        # the primary task's ambient team_id is somehow out of sync
        # (e.g. resumed by an admin sweep). ``None`` still means
        # admin-owned, matching the parent project's convention.
        team_id,
        siblings=_PANEL_SIBLINGS,
        branch_model=ForensicsInvestigationBranchRecord,
        inv_table="forensics_investigations",
        message_table="forensics_investigation_messages",
        task_fn=run_forensics_panel_investigate,
        track="forensics",
        group_id="forensics_panel_deliberation",
        task_queue=default_task_queue(),
        strip_case_state=lambda raw: _strip_rejected_from_state(
            _strip_directives_from_state(raw),
        ),
    )


def state_forensics_panel_setup(next_state: str) -> Any:
    """Return the setup handler bound to *next_state* (the loop entry).

    A phase-graph passes its first phase name here so the setup output
    routes into the loop; used by ``build_phase_workflow``.
    """
    async def _handler(input: dict[str, Any], services: Any) -> StateResult:
        del services  # forensics setup does not need the services bag
        investigation_id = str(input.get("investigation_id") or "")
        if not investigation_id:
            raise ValueError(
                "forensics_panel_setup: missing investigation_id",
            )
        explicit_branch_id = str(input.get("branch_id") or "")

        primary_branch_id = explicit_branch_id or await _resolve_or_create_primary_branch(
            investigation_id,
        )
        if not explicit_branch_id:
            # Only the primary-task path spawns siblings; a sibling task
            # already carries its own branch_id and MUST NOT recursively
            # spawn (the platform spawn is idempotent per persona but
            # skipping the call keeps the hot path cheap).
            # Resolve the investigation's team_id up-front so the sibling
            # spawn stamps it onto every child TaskRecord (#59). Returns
            # ``None`` (admin) if the row is missing -- spawn_persona_siblings
            # already tolerates that case.
            async with UnitOfWork() as uow:
                inv_row = (await uow.session.exec(
                    _select(InvestigationRunRecord).where(
                        InvestigationRunRecord.id == investigation_id,
                    )
                )).first()
            inv_team_id = inv_row.team_id if inv_row is not None else None
            await _spawn_forensics_panel(
                investigation_id=investigation_id,
                primary_branch_id=primary_branch_id,
                team_id=inv_team_id,
            )
            await _mark_investigation_running(investigation_id)

        _log.info(
            "forensics_panel_setup READY investigation_id=%s branch_id=%s "
            "explicit=%s next=%s",
            investigation_id, primary_branch_id, bool(explicit_branch_id),
            next_state,
        )
        return StateResult(
            next_state=next_state,
            output={
                "investigation_id": investigation_id,
                "branch_id": primary_branch_id,
                "project_id": str(input.get("project_id") or ""),
                "question": str(input.get("question") or ""),
            },
        )

    return _handler
