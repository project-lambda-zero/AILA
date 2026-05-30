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

from aila.modules.vr.contracts.branch import BranchStatus, PersonaVoice
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
# becomes the first researcher; each entry below spawns a sibling.
#
# Full 6-persona panel (2 researchers + 2 critics + 2 implementers):
#   halvar (primary) + noor  = researchers — propose hypotheses
#   maddie + yuki            = critics — falsify, demand evidence
#   renzo + wei              = implementers — build PoCs, settle disputes
_DELIBERATION_SIBLINGS: tuple[PersonaVoice, ...] = (
    PersonaVoice.NOOR,    # researcher (alternative style to halvar)
    PersonaVoice.MADDIE,  # critic (aggressive falsifier)
    PersonaVoice.YUKI,    # critic (methodical falsifier)
    PersonaVoice.RENZO,   # implementer (PoC builder)
    PersonaVoice.WEI,     # implementer (cost-efficient prioritizer)
)
_PRIMARY_PERSONA: PersonaVoice = PersonaVoice.HALVAR  # researcher

__all__ = ["state_investigation_setup"]

_log = logging.getLogger(__name__)

# Branches in any of these statuses are "dead" — investigation_loop
# cannot make meaningful progress against them. ACTIVE + PAUSED are
# the only resumable states; everything else has already reached a
# terminal disposition. Used by state_investigation_setup to self-heal
# stale cursors that resumed against a now-closed branch.
_DEAD_BRANCH_STATUSES: frozenset[str] = frozenset({
    BranchStatus.COMPLETED.value,
    BranchStatus.MERGED.value,
    BranchStatus.PROMOTED.value,
    BranchStatus.ABANDONED.value,
})


async def state_investigation_setup(input: dict[str, Any], services: Any) -> StateResult:
    """Validate + mark RUNNING. Returns input + resolved branch_id.

    Stale-branch self-healing (added after observing investigation
    e864f065 polling a closed halvar branch 736ceb58 after re-enqueue):

      * **Primary task path** (no explicit branch_id): when picking the
        primary branch via ``parent_branch_id IS NULL``, filter to
        ``status IN (ACTIVE, PAUSED)`` AND order by ``created_at ASC``
        for determinism. If ALL prior primary branches are terminal
        (COMPLETED / MERGED / PROMOTED / ABANDONED) — which is the
        post-completion / post-failure re-enqueue case — fork a fresh
        primary branch instead of resuming a closed one. Without this,
        ``re-enqueue`` after a successful or failed run silently
        operates on the prior terminal branch, drives investigation_loop
        against a dead branch, and the workflow never makes progress.

      * **Sibling task path** (explicit_branch_id set): when the named
        branch is already terminal, return a clean terminal exit
        (``next_state="investigation_emit"`` with
        ``exit_reason="branch_already_terminal"``) instead of entering
        investigation_loop. This catches the case where a sibling task
        was queued, the branch terminal-submitted via another path
        before the task ran, and the cursor would otherwise enter the
        loop on a closed branch.

    Both paths leave a structured log line so the operator can audit
    when the self-heal fired.
    """
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
            # Self-heal: refuse to drive investigation_loop on a branch
            # that's already reached a terminal disposition. Transition
            # straight to investigation_emit with a recognisable exit
            # reason so the finalizer skips re-enqueue and the run ends
            # cleanly.
            if branch.status in _DEAD_BRANCH_STATUSES:
                _log.warning(
                    "investigation_setup: sibling task targeted terminal "
                    "branch inv=%s branch=%s status=%s closed_reason=%r "
                    "— skipping investigation_loop and emitting clean exit",
                    investigation_id, branch.id, branch.status,
                    branch.closed_reason,
                )
                return StateResult(
                    next_state="investigation_emit",
                    output={
                        "investigation_id": investigation_id,
                        "branch_id": branch.id,
                        "strategy_family": inv.strategy_family,
                        "auto_pilot": inv.auto_pilot,
                        "cost_budget_usd": inv.cost_budget_usd,
                        "team_id": inv.team_id,
                        "cve_intel": [],
                        "exit_reason": "branch_already_terminal",
                        "last_turn_idx": branch.turn_count or 0,
                        "last_action": "",
                        "outcome_id": None,
                    },
                )
        else:
            # Pick the OLDEST resumable primary branch — deterministic
            # across re-enqueues. The prior LIMIT 1 with no filter and
            # no ORDER BY would silently pick a terminal branch when
            # one happened to sort first under PG's storage order, then
            # investigation_loop would spin forever on a closed branch.
            branch = (await uow.session.exec(
                _select(VRInvestigationBranchRecord).where(
                    VRInvestigationBranchRecord.investigation_id == investigation_id,
                    VRInvestigationBranchRecord.parent_branch_id.is_(None),
                    VRInvestigationBranchRecord.status.not_in(_DEAD_BRANCH_STATUSES),
                ).order_by(VRInvestigationBranchRecord.created_at.asc()).limit(1)
            )).first()
            if branch is None:
                # Either the investigation row was created without its
                # initial primary branch (defensive — API contract says
                # this can't happen) OR all prior primaries reached
                # terminal disposition and re-enqueue wants a fresh
                # round. Fork a new ACTIVE primary so the run has
                # somewhere live to land. Prior outcomes context loads
                # via the existing re-enqueue blindness fix
                # (vuln_researcher.run_turn loads prior_outcomes from
                # the investigation, not from a single branch).
                _log.warning(
                    "investigation_setup: no live primary branch for "
                    "inv=%s — forking fresh primary (persona=%s); prior "
                    "primaries were terminal or absent",
                    investigation_id, _PRIMARY_PERSONA.value,
                )
                branch = VRInvestigationBranchRecord(
                    investigation_id=investigation_id,
                    parent_branch_id=None,
                    status=BranchStatus.ACTIVE.value,
                    fork_reason="primary_reenqueue_after_terminal",
                    persona_voice=_PRIMARY_PERSONA.value,
                )
                uow.session.add(branch)
                await uow.session.flush()

                # When the self-heal forks a fresh primary, ANY other
                # branches in this investigation that are still ACTIVE
                # (or PAUSED) are orphans from the prior round — their
                # parent primary is COMPLETED / MERGED / etc., they
                # were never explicitly closed when the primary
                # terminal-submitted, and now they will race the fresh
                # branches we just spawned, write duplicate findings,
                # and waste budget. ABANDON them with a closed_reason
                # that points back at this fresh primary so the audit
                # trail is debuggable.
                #
                # Observed live on investigation e864f065 after the
                # 2026-05-28 self-heal: 3 fresh branches got spawned
                # on top of 2 still-running siblings from days
                # earlier, leaving 5 active branches plus 1 completed
                # = 6 total instead of the expected 3. Operator
                # noticed in the UI before this cleanup landed.
                orphans = (await uow.session.exec(
                    _select(VRInvestigationBranchRecord).where(
                        VRInvestigationBranchRecord.investigation_id == investigation_id,
                        VRInvestigationBranchRecord.id != branch.id,
                        VRInvestigationBranchRecord.status.in_(
                            (BranchStatus.ACTIVE.value, BranchStatus.PAUSED.value),
                        ),
                    )
                )).all()
                if orphans:
                    superseded_by = branch.id
                    closed_at = utc_now()
                    for o in orphans:
                        o.status = BranchStatus.ABANDONED.value
                        o.closed_reason = (
                            f"superseded_by_reenqueue_self_heal:{superseded_by}"
                        )
                        o.closed_at = closed_at
                        uow.session.add(o)
                    _log.warning(
                        "investigation_setup: abandoned %d orphan active/paused "
                        "branches on inv=%s after fresh-primary self-heal (new "
                        "primary=%s); orphans=%s",
                        len(orphans), investigation_id, branch.id,
                        [o.id for o in orphans],
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

    # Knowledge Transfer: query the pattern catalog for techniques
    # extracted from prior investigations on similar targets. Store
    # JSON-serialisable dicts in the run context so investigation_loop
    # can thread them into the per-turn user prompt. Failure to load
    # patterns NEVER blocks setup — every new investigation must still
    # boot even if the pattern store is empty / broken.
    applicable_patterns: list[dict[str, Any]] = []
    try:
        from aila.modules.vr.db_models import VRTargetRecord  # noqa: PLC0415
        from aila.modules.vr.services.pattern_store import (  # noqa: PLC0415
            PatternStore,
        )
        from aila.platform.services.knowledge import (  # noqa: PLC0415
            KnowledgeService,
        )

        async with UnitOfWork() as uow:
            target = (await uow.session.exec(
                _select(VRTargetRecord).where(VRTargetRecord.id == inv.target_id),
            )).first()
        if target is not None:
            query = (inv.initial_question or inv.title or "").strip()
            if query:
                store = PatternStore(knowledge=KnowledgeService())
                results = await store.applicable(
                    workspace_id=target.workspace_id,
                    team_id=inv.team_id,
                    query=query,
                    target_kind=target.kind,
                    primary_language=target.primary_language,
                    k=10,
                )
                for r in results:
                    applicable_patterns.append(r.pattern.model_dump(mode="json"))
    except Exception as exc:  # noqa: BLE001 — never block setup on pattern lookup
        _log.warning(
            "investigation_setup: pattern lookup failed: %s", exc,
        )

    _log.info(
        "investigation_setup READY investigation_id=%s branch_id=%s "
        "strategy=%s cve_intel=%d patterns=%d",
        investigation_id, branch.id, inv.strategy_family, len(cve_intel),
        len(applicable_patterns),
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
            "applicable_patterns": applicable_patterns,
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
