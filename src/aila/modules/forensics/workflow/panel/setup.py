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

from sqlalchemy.exc import SQLAlchemyError
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


async def _load_investigation_context(
    investigation_id: str,
) -> tuple[str | None, str, str]:
    """Return ``(team_id, project_id, question)`` for *investigation_id*.

    A missing row yields ``(None, "", "")`` so the caller falls back
    gracefully; this is not a spawn dependency and the panel graph
    already tolerates a vanished investigation elsewhere (branch load
    in the loop returns ``branch_not_found``).

    Pulled out as a module-level helper so the setup handler has one
    UoW-owning read for both the spawn ``team_id`` and the pattern
    retrieval scope; tests can monkeypatch it to keep the handler
    free of DB dependencies.
    """
    async with UnitOfWork() as uow:
        inv = (await uow.session.exec(
            _select(InvestigationRunRecord).where(
                InvestigationRunRecord.id == investigation_id,
            )
        )).first()
    if inv is None:
        return None, "", ""
    return inv.team_id, str(inv.project_id or ""), str(inv.question or "")


def _pattern_store_factory() -> Any:
    """Construct the forensics :class:`PatternStore` for retrieval.

    Deferred imports keep module load off the KnowledgeService +
    embedding-model boot path (mirrors the lazy-import pattern used
    by the panel task import above and already whitelisted for this
    file in ``pyproject.toml`` / ``honesty_whitelist.py``).

    A tiny factory (rather than an inline ``PatternStore(...)`` call
    in the handler) so tests can monkeypatch this one seam and keep
    the retrieval logic free of the live pattern catalog + embedding
    service.
    """
    from aila.modules.forensics.services.pattern_store import PatternStore
    from aila.platform.services.knowledge import KnowledgeService

    return PatternStore(knowledge=KnowledgeService())


async def _resolve_applicable_patterns(
    *,
    investigation_id: str,
    project_id: str,
    team_id: str | None,
    question: str,
) -> list[dict[str, Any]]:
    """Best-effort forensics pattern retrieval scoped to the project.

    The forensics module has no workspace table -- the project IS the
    workspace, so ``project_id`` is passed as ``workspace_id`` to the
    platform :meth:`PatternStoreBase.applicable`. A retrieval failure
    NEVER blocks panel setup (the panel is not built on
    ``investigation_setup_base`` and has no framework-level safety net);
    every failure path logs with traceback and returns an empty list so
    the loop still runs.
    """
    if not project_id or not question:
        return []
    try:
        store = _pattern_store_factory()
        results = await store.applicable(
            workspace_id=project_id,
            team_id=team_id,
            query=question,
            k=10,
        )
    except (SQLAlchemyError, OSError, RuntimeError, ValueError, TypeError) as exc:
        _log.warning(
            "forensics_panel_setup: pattern lookup failed inv=%s: %s",
            investigation_id, exc, exc_info=True,
        )
        return []

    out: list[dict[str, Any]] = []
    for r in results:
        try:
            out.append(r.pattern.model_dump(mode="json"))
        except (AttributeError, TypeError, ValueError) as exc:
            _log.warning(
                "forensics_panel_setup: pattern serialize failed inv=%s: %s",
                investigation_id, exc, exc_info=True,
            )
    return out


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

        # Read the investigation row once for BOTH the spawn team_id
        # stamp (#59) and the pattern retrieval scope. A missing row
        # yields (None, "", "") -- the spawn path tolerates None team_id,
        # and empty project/question skips pattern retrieval.
        inv_team_id, inv_project_id, inv_question = await _load_investigation_context(
            investigation_id,
        )
        project_id = str(input.get("project_id") or "") or inv_project_id
        question = str(input.get("question") or "") or inv_question

        if not explicit_branch_id:
            # Only the primary-task path spawns siblings; a sibling task
            # already carries its own branch_id and MUST NOT recursively
            # spawn (the platform spawn is idempotent per persona but
            # skipping the call keeps the hot path cheap).
            await _spawn_forensics_panel(
                investigation_id=investigation_id,
                primary_branch_id=primary_branch_id,
                team_id=inv_team_id,
            )
            await _mark_investigation_running(investigation_id)

        # RFC-12 pattern retrieval: pull prior forensics techniques /
        # triage rules scoped to this project so the loop can surface
        # them on the first branch turn. Best-effort -- see the helper
        # docstring; failure never blocks setup.
        applicable_patterns = await _resolve_applicable_patterns(
            investigation_id=investigation_id,
            project_id=project_id,
            team_id=inv_team_id,
            question=question,
        )

        _log.info(
            "forensics_panel_setup READY investigation_id=%s branch_id=%s "
            "explicit=%s patterns=%d next=%s",
            investigation_id, primary_branch_id, bool(explicit_branch_id),
            len(applicable_patterns), next_state,
        )
        return StateResult(
            next_state=next_state,
            output={
                "investigation_id": investigation_id,
                "branch_id": primary_branch_id,
                "project_id": project_id,
                "question": question,
                "team_id": inv_team_id,
                "applicable_patterns": applicable_patterns,
                "scope": {
                    "project_id": project_id,
                    "team_id": inv_team_id,
                    "question": question,
                },
            },
        )

    return _handler
