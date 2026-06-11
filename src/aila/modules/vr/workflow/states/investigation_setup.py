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
#
# fix §295 — lazy getter (was module-load `_AUTO_DELIBERATION`).
# Reading env at module load makes the toggle unchangeable for the
# worker lifetime; operator-flipped env after a worker restart never
# took effect until full process bounce. Lazy getter is read each
# time setup runs, so a worker that sees a fresh env on next ARQ
# task wakeup honours it.
def _is_auto_deliberation_enabled() -> bool:
    return os.environ.get("VR_AUTO_PERSONA_DELIBERATION", "1") == "1"

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

# Investigation statuses that block the run loop. The status flip near
# the top of state_investigation_setup is unconditional and would
# bypass any PAUSED / COMPLETED / FAILED state set after the ARQ task
# was enqueued (operator pauses + cap_exceeded sweeps both land in
# this window). Without this guard, a paused investigation's pending
# ARQ task wakes up, flips status back to RUNNING, runs the full turn
# loop, and the operator's pause is silently undone.
_STATUS_LOCKED: frozenset[str] = frozenset({
    InvestigationStatus.PAUSED.value,
    InvestigationStatus.COMPLETED.value,
    InvestigationStatus.FAILED.value,
})

# fix §293 — module-level consecutive failure counters for the two
# best-effort lookups (CVE intel, knowledge-transfer pattern store)
# that surround the main UoW. The prior bare `except Exception` +
# `_log.warning(...)` swallowed silent infrastructure rot: a broken
# NVD mirror, a missing IntelService dependency, or a corrupted
# pattern_store could fail every investigation for hours while only
# producing WARN noise. After 5 consecutive failures on either path,
# escalate to _log.error so log destinations (Grafana / Loki) can
# page on it. Reset to 0 on each success. Module-level state is
# correct here — counters are per-worker-process and reset on
# restart, which is the right granularity (an operator that
# restarts a worker has actively re-checked the integration).
_CONSECUTIVE_CVE_INTEL_FAILURES: int = 0
_CONSECUTIVE_PATTERN_LOOKUP_FAILURES: int = 0
_FAILURE_ESCALATION_THRESHOLD: int = 5


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

    UoW contract (fix §291 — explicit doc of the all-or-nothing
    invariant that already holds structurally):

    The single ``async with UnitOfWork() as uow`` block that wraps
    investigation load → STATUS_LOCKED check → primary branch
    resolve → orphan-abandon → fresh-primary INSERT → status flip
    → ``uow.commit()`` is an **atomic transaction**. The orphan
    cleanup (mark sibling ACTIVE/PAUSED branches ABANDONED with
    ``superseded_by_reenqueue_self_heal:<new>``) and the fresh
    primary INSERT MUST commit together. If any pre-commit step
    raises (engine error, integrity violation, transient DB hiccup),
    the surrounding ``with`` block rolls everything back — orphan
    rows stay ACTIVE, no fresh primary row leaks, the cursor
    re-fires next ARQ task wakeup.

    Anyone editing this block: do NOT split the orphan-abandon and
    fresh-primary INSERT into separate UoWs. The whole point is
    that a half-applied self-heal (new primary lives, orphans stay
    racing) is worse than no self-heal — it produces exactly the
    "6 branches instead of 3" state we just fixed in 2026-05-28.
    """
    # fix §297 — was \`del services\` (orphaning the bag). The handler
    # signature is fixed by HandlerFn; keep the bag accessible so
    # downstream code paths can reach \`services.llm_client\` /
    # \`services.config\` etc. The current setup-time operations
    # (CVE intel resolver, KnowledgeService-backed pattern_store) own
    # their own dependencies because VRWorkflowServices does not yet
    # carry a \`knowledge\` field; once it does, switch PatternStore
    # construction below to \`PatternStore(knowledge=services.knowledge)\`.
    _ = services  # held for future wiring; no-op today, NOT \`del\`.

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

        # Honor operator pause + terminal investigation states. See
        # _STATUS_LOCKED at module top for the comment block; surface
        # the skip loudly so the operator can see WHY their pause held.
        if inv.status in _STATUS_LOCKED:
            # fix §290 — re-resolve cve_intel from the (possibly
            # operator-edited) initial_question before the early-exit
            # so investigation_emit + downstream renderers don't lose
            # CVE context when a paused investigation resumes via
            # /reopen. Failing intel resolve NEVER blocks the early
            # exit — empty list is the existing degraded default.
            locked_initial_question = inv.initial_question or ""
            await uow.commit()  # flush nothing; release UoW cleanly
            locked_cve_intel: list[dict[str, Any]] = []
            try:
                from aila.modules.vr.services.cve_intel_resolver import (  # noqa: PLC0415
                    extract_cve_ids,
                    resolve_cve_intel,
                )
                locked_cve_ids = extract_cve_ids(locked_initial_question)
                if locked_cve_ids:
                    resolutions = await resolve_cve_intel(locked_cve_ids)
                    locked_cve_intel = [r.to_dict() for r in resolutions]
            except Exception as exc:  # noqa: BLE001 — never block status-locked exit
                _log.warning(
                    "investigation_setup STATUS_LOCKED cve_intel re-fetch "
                    "failed inv=%s: %s", investigation_id, exc,
                )
            _log.info(
                "investigation_setup STATUS_LOCKED inv=%s status=%s "
                "pause_reason=%s cve_intel=%d — skipping setup + loop, "
                "emitting clean exit",
                investigation_id, inv.status, inv.pause_reason,
                len(locked_cve_intel),
            )
            return StateResult(
                next_state="investigation_emit",
                output={
                    "investigation_id": investigation_id,
                    "branch_id": explicit_branch_id or "",
                    "strategy_family": inv.strategy_family,
                    "auto_pilot": inv.auto_pilot,
                    "cost_budget_usd": inv.cost_budget_usd,
                    "team_id": inv.team_id,
                    "cve_intel": locked_cve_intel,
                    "exit_reason": f"status_locked:{inv.status}",
                    "last_turn_idx": 0,
                    "last_action": "",
                    "outcome_id": None,
                },
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
    if not explicit_branch_id and _is_auto_deliberation_enabled():
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
        global _CONSECUTIVE_CVE_INTEL_FAILURES  # noqa: PLW0603 — module counter
        try:
            resolutions = await resolve_cve_intel(cve_ids)
            cve_intel = [r.to_dict() for r in resolutions]
            _CONSECUTIVE_CVE_INTEL_FAILURES = 0  # fix §293 — reset on success
        except Exception as exc:  # noqa: BLE001 — never block setup on intel failure
            _CONSECUTIVE_CVE_INTEL_FAILURES += 1
            if _CONSECUTIVE_CVE_INTEL_FAILURES >= _FAILURE_ESCALATION_THRESHOLD:
                _log.error(
                    "investigation_setup: CVE intel resolve failed %d times in "
                    "a row (last err: %s) — escalating; check NVD mirror + "
                    "cve_intel_resolver IntelService dependency",
                    _CONSECUTIVE_CVE_INTEL_FAILURES, exc,
                )
            else:
                _log.warning(
                    "investigation_setup: CVE intel resolve failed "
                    "(consecutive=%d): %s",
                    _CONSECUTIVE_CVE_INTEL_FAILURES, exc,
                )

    # Knowledge Transfer: query the pattern catalog for techniques
    # extracted from prior investigations on similar targets. Store
    # JSON-serialisable dicts in the run context so investigation_loop
    # can thread them into the per-turn user prompt. Failure to load
    # patterns NEVER blocks setup — every new investigation must still
    # boot even if the pattern store is empty / broken.
    applicable_patterns: list[dict[str, Any]] = []
    global _CONSECUTIVE_PATTERN_LOOKUP_FAILURES  # noqa: PLW0603 — module counter
    try:
        from aila.modules.vr.db_models import VRTargetRecord  # noqa: PLC0415
        from aila.modules.vr.services.pattern_store import (  # noqa: PLC0415
            PatternStore,
        )
        from aila.platform.services.knowledge import (  # noqa: PLC0415
            KnowledgeService,
        )

        # fix §294 — read every needed target column into local vars
        # BEFORE the UoW closes. The prior code dereferenced
        # target.workspace_id / target.kind / target.primary_language
        # AFTER the `async with UnitOfWork()` block exited, which
        # works today (sqlmodel attaches loaded columns to the
        # detached instance) but is silently fragile — any future
        # lazy-load relationship on VRTargetRecord, expire_on_commit
        # flip, or SQLAlchemy version bump turns those accesses into
        # DetachedInstanceError. Pull primitives out while the
        # session is still live; reference locals after.
        target_kind: str | None = None
        target_lang: str | None = None
        target_ws: str | None = None
        async with UnitOfWork() as uow:
            target = (await uow.session.exec(
                _select(VRTargetRecord).where(VRTargetRecord.id == inv.target_id),
            )).first()
            if target is not None:
                target_kind = target.kind
                target_lang = target.primary_language
                target_ws = target.workspace_id
        if target_ws is not None:
            query = (inv.initial_question or inv.title or "").strip()
            if query:
                store = PatternStore(knowledge=KnowledgeService())
                results = await store.applicable(
                    workspace_id=target_ws,
                    team_id=inv.team_id,
                    query=query,
                    target_kind=target_kind,
                    primary_language=target_lang,
                    k=10,
                )
                for r in results:
                    applicable_patterns.append(r.pattern.model_dump(mode="json"))
        _CONSECUTIVE_PATTERN_LOOKUP_FAILURES = 0  # fix §293 — reset on success
    except Exception as exc:  # noqa: BLE001 — never block setup on pattern lookup
        _CONSECUTIVE_PATTERN_LOOKUP_FAILURES += 1
        if _CONSECUTIVE_PATTERN_LOOKUP_FAILURES >= _FAILURE_ESCALATION_THRESHOLD:
            _log.error(
                "investigation_setup: pattern lookup failed %d times in a "
                "row (last err: %s) — escalating; check pattern_store + "
                "KnowledgeService dependency",
                _CONSECUTIVE_PATTERN_LOOKUP_FAILURES, exc,
            )
        else:
            _log.warning(
                "investigation_setup: pattern lookup failed "
                "(consecutive=%d): %s",
                _CONSECUTIVE_PATTERN_LOOKUP_FAILURES, exc,
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
    """Fork one sibling branch per persona and enqueue tasks.

    Searches ALL branches of the investigation by persona_voice — not
    just children of the current primary. This survives re-enqueue:

    - Persona has a branch with turns → reuse it, enqueue task to continue
    - Persona has abandoned/0-turn branch → reactivate it, enqueue task
    - Persona has no branch at all → fork a new one

    This prevents branch accumulation across re-enqueues (the bug where
    each re-enqueue added 6 new branches because parent_branch_id changed).

    Two-phase atomicity contract (fix §292):

    * **Phase 1 (atomic UoW):** reactivate winners, abandon duplicates,
      AND INSERT new branches for personas without an existing branch
      — all in ONE `async with UnitOfWork()` block, one commit. If any
      step raises (cap check, integrity violation, parent load failure,
      transient DB hiccup), the surrounding `with` block rolls back
      every pending change. No half-spawned panel: either all 5
      sibling branches resolve to a stable id, or none do.

    * **Phase 2 (best-effort):** enqueue one ARQ task per resolved
      sibling branch_id. Per-task try/except — a single enqueue failure
      logs + continues; the branch row already persists from phase 1,
      so a reaper-on-cursor sweep can submit it later. Phase 2 NEVER
      rolls back phase 1 (the branches are real even if their tasks
      didn't land).

    The prior implementation called `BranchManager.fork()` inside the
    per-persona enqueue loop, after the phase-1 UoW had already
    committed. Each fork opened its OWN UoW; partial failure left
    some siblings born and some missing, with no way to roll back to
    a consistent panel.
    """
    from aila.modules.vr._task_queue import default_task_queue  # noqa: PLC0415
    from aila.modules.vr.agents.branch_manager import (  # noqa: PLC0415
        _strip_directives_from_state,
        _strip_rejected_from_state,
    )
    from aila.modules.vr.workflow.task import run_vr_investigate  # noqa: PLC0415

    # Phase 1 — atomic dedup + reactivate + insert new branches.
    # On any exception inside the `async with` block, the UoW rolls
    # back: no branch INSERT survives, no status flip persists, and
    # the operator's next /reopen retries cleanly.
    sibling_branch_ids: dict[str, str] = {}  # persona_value -> branch_id
    async with UnitOfWork() as uow:
        all_branches = (await uow.session.exec(
            _select(VRInvestigationBranchRecord).where(
                VRInvestigationBranchRecord.investigation_id == investigation_id,
            )
        )).all()

        # Group by persona — pick the one with the most turns
        best_by_persona: dict[str, VRInvestigationBranchRecord] = {}
        for b in all_branches:
            if not b.persona_voice:
                continue
            existing = best_by_persona.get(b.persona_voice)
            if existing is None or b.turn_count > existing.turn_count:
                best_by_persona[b.persona_voice] = b

        # Reactivate best branch per persona, ABANDON duplicates
        for b in all_branches:
            if not b.persona_voice:
                continue
            best = best_by_persona.get(b.persona_voice)
            if best is None:
                continue
            if b.id == best.id:
                # This is the winner — reactivate if needed
                if b.status in ("abandoned", "completed"):
                    b.status = "active"
                    b.closed_reason = ""
                    b.closed_at = None
                    uow.session.add(b)
                    _log.info(
                        "auto_deliberation: reactivated %s branch %s (turns=%d)",
                        b.persona_voice, b.id, b.turn_count,
                    )
            else:
                # This is a duplicate — abandon it
                if b.status not in ("abandoned",):
                    b.status = "abandoned"
                    b.closed_reason = "duplicate_persona_cleanup"
                    b.closed_at = utc_now()
                    uow.session.add(b)
                    _log.info(
                        "auto_deliberation: abandoned duplicate %s branch %s (turns=%d, keeping %s)",
                        b.persona_voice, b.id, b.turn_count, best.id,
                    )

        # Phase 1 — INSERT new branches for personas without one. Done
        # INSIDE this same UoW so the entire panel is all-or-nothing.
        # Load the primary's case_state once for inheritance via the
        # strip helpers (matches BranchManager.fork's behaviour).
        parent = (await uow.session.exec(
            _select(VRInvestigationBranchRecord).where(
                VRInvestigationBranchRecord.id == primary_branch_id,
            )
        )).first()
        parent_case_state = (parent.case_state_json or "{}") if parent is not None else "{}"
        inherited_case_state = _strip_rejected_from_state(
            _strip_directives_from_state(parent_case_state),
        )

        for persona in _DELIBERATION_SIBLINGS:
            existing_branch = best_by_persona.get(persona.value)
            if existing_branch is not None:
                sibling_branch_ids[persona.value] = existing_branch.id
                continue
            child = VRInvestigationBranchRecord(
                investigation_id=investigation_id,
                parent_branch_id=primary_branch_id,
                status=BranchStatus.ACTIVE.value,
                persona_voice=persona.value,
                fork_reason=f"auto_deliberation:{persona.value}",
                fork_at_turn=0,
                case_state_json=inherited_case_state,
                turn_count=0,
                branch_cost_usd=0.0,
            )
            uow.session.add(child)
            await uow.session.flush()  # populate child.id within the UoW
            sibling_branch_ids[persona.value] = child.id

        await uow.commit()

    # Phase 2 — best-effort enqueue per resolved branch. A single
    # enqueue failure logs + continues; the branch row persists from
    # phase 1, so a future reaper-on-cursor sweep can pick it up.
    task_queue = default_task_queue()
    enqueued: list[str] = []
    for persona in _DELIBERATION_SIBLINGS:
        sibling_branch_id = sibling_branch_ids.get(persona.value)
        if not sibling_branch_id:
            continue
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
        except Exception as exc:  # noqa: BLE001 — phase 2 is best-effort
            _log.warning(
                "auto_deliberation: enqueue failed persona=%s branch=%s "
                "err=%s (branch row persists; reaper-on-cursor can resubmit)",
                persona.value, sibling_branch_id, exc,
            )

    if enqueued:
        _log.info(
            "auto_deliberation: spawned siblings for %s: %s",
            investigation_id, enqueued,
        )
