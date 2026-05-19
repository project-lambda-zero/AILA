"""Investigation setup state (M3.R-7).

Validates that the investigation + primary branch exist, marks status
as RUNNING, stamps started_at. Forwards investigation_id + branch_id to
the loop state.
"""
from __future__ import annotations

import logging
import os
from typing import Any

from sqlmodel import select as _select

from aila.modules.vr.contracts.branch import PersonaVoice
from aila.modules.vr.contracts.investigation import InvestigationStatus
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationRecord,
)
from aila.platform.contracts._common import utc_now
from aila.platform.uow import UnitOfWork
from aila.platform.workflows.types import StateResult

# Auto-deliberation toggle. When 1 (default), investigation_setup
# spawns sibling branches for critic + implementer personas and
# enqueues a separate run_vr_investigate task per sibling so each
# persona reasons independently against its own task_type-routed
# LLM. Set VR_AUTO_PERSONA_DELIBERATION=0 to disable (single-branch
# fallback — operator forks personas manually).
_AUTO_DELIBERATION = os.environ.get("VR_AUTO_PERSONA_DELIBERATION", "1") == "1"

# The personas assigned to the auto-spawned siblings. Primary branch
# becomes the researcher; each entry below spawns a sibling.
_DELIBERATION_SIBLINGS: tuple[PersonaVoice, ...] = (
    PersonaVoice.MADDIE,  # critic
    PersonaVoice.RENZO,   # implementer
)
_PRIMARY_PERSONA: PersonaVoice = PersonaVoice.HALVAR  # researcher

__all__ = ["state_investigation_setup"]

_log = logging.getLogger(__name__)


async def state_investigation_setup(input: dict[str, Any], services: Any) -> StateResult:
    """Validate + mark RUNNING. Returns input + resolved branch_id."""
    del services

    investigation_id = str(input.get("investigation_id") or "")
    if not investigation_id:
        raise ValueError("investigation_setup: missing investigation_id")

    # When set, we are a sibling task spawned by the primary's setup —
    # skip the auto-spawn block and just hydrate the named branch.
    explicit_branch_id = str(input.get("branch_id") or "")

    async with UnitOfWork() as uow:
        inv = (await uow.session.exec(
            _select(VRInvestigationRecord).where(
                VRInvestigationRecord.id == investigation_id,
            )
        )).first()
        if inv is None:
            raise ValueError(
                f"investigation_setup: investigation {investigation_id} not found",
            )

        if explicit_branch_id:
            branch = (await uow.session.exec(
                _select(VRInvestigationBranchRecord).where(
                    VRInvestigationBranchRecord.id == explicit_branch_id,
                )
            )).first()
            if branch is None:
                raise ValueError(
                    f"investigation_setup: branch {explicit_branch_id} not found",
                )
        else:
            branch = (await uow.session.exec(
                _select(VRInvestigationBranchRecord).where(
                    VRInvestigationBranchRecord.investigation_id == investigation_id,
                    VRInvestigationBranchRecord.parent_branch_id.is_(None),
                ).limit(1)
            )).first()
            if branch is None:
                raise ValueError(
                    f"investigation_setup: no primary branch for {investigation_id}",
                )
            # Primary persona: researcher. Idempotent — only set when
            # the operator didn't pick a persona explicitly.
            if not branch.persona_voice:
                branch.persona_voice = _PRIMARY_PERSONA.value
                uow.session.add(branch)

        now = utc_now()
        inv.status = InvestigationStatus.RUNNING.value
        if inv.started_at is None:
            inv.started_at = now
        inv.updated_at = now
        uow.session.add(inv)
        await uow.commit()

    # Auto-deliberation: spawn sibling branches and enqueue per-sibling
    # tasks ONLY on the primary task. Sibling tasks (explicit_branch_id
    # set) skip this block — they just run their assigned branch's loop.
    if not explicit_branch_id and _AUTO_DELIBERATION:
        await _spawn_persona_siblings_and_enqueue(
            investigation_id=investigation_id,
            primary_branch_id=branch.id,
            team_id=inv.team_id,
        )

    # Resolve any CVE ids mentioned in the operator's question so the
    # agent gets honest "found" / "not_found" / "error" status instead
    # of inventing details when NVD has nothing. Mirrors the existing
    # IntelService path used by the vulnerability module's read
    # endpoint, but produces a structured list the prompt builder
    # renders explicitly.
    from aila.modules.vr.services.cve_intel_resolver import (  # noqa: PLC0415
        extract_cve_ids,
        resolve_cve_intel,
    )
    cve_ids = extract_cve_ids(inv.initial_question)
    cve_intel: list[dict[str, Any]] = []
    if cve_ids:
        try:
            resolutions = await resolve_cve_intel(cve_ids)
            cve_intel = [r.to_dict() for r in resolutions]
        except Exception as exc:  # noqa: BLE001 — never block setup on intel failure
            _log.warning(
                "investigation_setup: CVE intel resolve failed: %s", exc,
            )

    _log.info(
        "investigation_setup READY investigation_id=%s branch_id=%s "
        "strategy=%s cve_intel=%d",
        investigation_id, branch.id, inv.strategy_family, len(cve_intel),
    )

    return StateResult(
        next_state="investigation_loop",
        output={
            "investigation_id": investigation_id,
            "branch_id": branch.id,
            "strategy_family": inv.strategy_family,
            "auto_pilot": inv.auto_pilot,
            "cost_budget_usd": inv.cost_budget_usd,
            "team_id": inv.team_id,
            "cve_intel": cve_intel,
        },
    )

async def _spawn_persona_siblings_and_enqueue(
    *,
    investigation_id: str,
    primary_branch_id: str,
    team_id: str | None,
) -> None:
    """Fork one sibling branch per persona in _DELIBERATION_SIBLINGS and
    enqueue a separate run_vr_investigate task for each. Each sibling
    runs its own setup→loop→emit chain against its assigned branch_id,
    so each persona reasons with its own task_type-routed LLM in
    parallel with the primary researcher branch.

    Idempotent: if siblings with the configured personas already exist
    on this investigation (e.g. re-enqueue after a transient failure),
    skip the spawn for that persona but still re-enqueue its task so
    work resumes.
    """
    from aila.modules.vr._task_queue import default_task_queue  # noqa: PLC0415
    from aila.modules.vr.agents.branch_manager import BranchManager  # noqa: PLC0415
    from aila.modules.vr.workflow.task import run_vr_investigate  # noqa: PLC0415

    async with UnitOfWork() as uow:
        existing = (await uow.session.exec(
            _select(VRInvestigationBranchRecord).where(
                VRInvestigationBranchRecord.investigation_id == investigation_id,
                VRInvestigationBranchRecord.parent_branch_id == primary_branch_id,
            )
        )).all()
        existing_by_persona = {b.persona_voice: b for b in existing if b.persona_voice}

    manager = BranchManager(investigation_id)
    task_queue = default_task_queue()
    enqueued: list[str] = []
    for persona in _DELIBERATION_SIBLINGS:
        sibling = existing_by_persona.get(persona.value)
        if sibling is None:
            try:
                op = await manager.fork(
                    primary_branch_id,
                    persona_voice=persona.value,
                    fork_reason=f"auto_deliberation:{persona.value}",
                    at_turn=0,
                )
                sibling_branch_id = op.new_branch_id or op.primary_branch_id
            except Exception as exc:  # noqa: BLE001 — never block primary on sibling fork
                _log.warning(
                    "auto_deliberation: fork failed persona=%s err=%s",
                    persona.value, exc,
                )
                continue
        else:
            sibling_branch_id = sibling.id

        try:
            await task_queue.submit(
                track="vr",
                fn=run_vr_investigate,
                kwargs={
                    "investigation_id": investigation_id,
                    "branch_id": sibling_branch_id,
                },
                user_id="system",
                group_id="vr_auto_deliberation",
                team_id=team_id,
            )
            enqueued.append(f"{persona.value}={sibling_branch_id[:8]}")
        except Exception as exc:  # noqa: BLE001 — log + continue, primary still runs
            _log.warning(
                "auto_deliberation: enqueue failed persona=%s err=%s",
                persona.value, exc,
            )

    if enqueued:
        _log.info(
            "auto_deliberation: spawned siblings for %s: %s",
            investigation_id, enqueued,
        )
