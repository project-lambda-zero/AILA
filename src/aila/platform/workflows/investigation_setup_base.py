"""Investigation setup state factory (RFC-02 Phase 4).

Extracted from the vr and malware setup states, which were byte-identical
apart from the CVE-intel weaving. That weaving is now the optional
``resolve_cve_intel`` hook: vr binds a resolver, malware leaves it unset
and the ``cve_intel`` output is an empty list the malware loop ignores.

The module binds its record models, primary persona, sibling-spawn
function, pattern-store factory, and auto-deliberation toggle; the
platform owns the stale-branch self-heal, orphan-abandon, status-flip
whitelist, and knowledge-transfer pattern lookup. One implementation
forces one behavior across every module.
"""
from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import select as _select

from aila.platform.contracts import utc_now
from aila.platform.contracts.enums import BranchStatus, InvestigationStatus
from aila.platform.services.specialist_registry import SpecialistAgentRegistry
from aila.platform.uow import UnitOfWork
from aila.platform.workflows.types import StateResult

if TYPE_CHECKING:
    from aila.platform.eval.routing_learner import (
        RoutingRecommendation,
        RoutingSample,
    )

_log = logging.getLogger(__name__)

__all__ = [
    "InvestigationStateBindings",
    "InvestigationStateHooks",
    "state_investigation_setup",
]

# Branch dispositions past which a branch cannot resume; the setup
# self-heal forks a fresh primary rather than driving the loop on one.
_DEAD_BRANCH_STATUSES: frozenset[str] = frozenset({
    BranchStatus.COMPLETED.value,
    BranchStatus.MERGED.value,
    BranchStatus.PROMOTED.value,
    BranchStatus.ABANDONED.value,
})
# Investigation statuses that block the run loop (operator pause +
# terminal). Setup honors these instead of clobbering them with RUNNING.
_STATUS_LOCKED: frozenset[str] = frozenset({
    InvestigationStatus.PAUSED.value,
    InvestigationStatus.COMPLETED.value,
    InvestigationStatus.FAILED.value,
})
_FAILURE_ESCALATION_THRESHOLD: int = 5
# Per-worker-process consecutive-failure counter for the best-effort
# pattern lookup. Shared across modules on the platform; escalation is a
# log-severity signal only, so cross-module counting is harmless.
_CONSECUTIVE_PATTERN_LOOKUP_FAILURES: int = 0


@dataclass(frozen=True)
class InvestigationStateBindings:
    """Concrete per-module inputs the state factories close over.

    Setup uses the record models, personas, spawn function, pattern-store
    factory, and auto-deliberation toggle. The loop/emit fields land with
    RFC-02 Phase 4b/4c and default to unset until then.
    """

    inv_model: type[Any]
    branch_model: type[Any]
    # setup-state (Phase 4a) inputs -- optional so a loop/emit-only
    # bindings can omit them (only the two models above are shared).
    target_model: type[Any] | None = None
    primary_persona_value: str | None = None
    unspecified_persona_value: str | None = None
    spawn_fn: Callable[..., Awaitable[Any]] | None = None
    # RFC-08 pre-execution sizing: an optional per-module history
    # provider consumed by :class:`RoutingLearner.recommend` to build a
    # :class:`RoutingRecommendation` for this target_kind. When set, the
    # setup handler passes the recommendation to ``spawn_fn`` as the
    # ``sizing_hint`` kwarg so ``spawn_persona_siblings`` can cap the
    # sibling panel when the evidence is strong. When None, spawn_fn is
    # called without ``sizing_hint`` (module still gets full-panel spawn).
    routing_history_provider: (
        Callable[[str], Awaitable[Sequence[RoutingSample]]] | None
    ) = None
    pattern_store_factory: Callable[[], Any] | None = None
    auto_deliberation_enabled: Callable[[], bool] | None = None
    module_id: str | None = None
    message_model: type[Any] | None = None
    outcome_model: type[Any] | None = None
    task_fn: Callable[..., Awaitable[Any]] | None = None
    track: str | None = None
    run_turn: Callable[..., Awaitable[Any]] | None = None
    config_source: Any = None
    persona_siblings: tuple[Any, ...] = field(default_factory=tuple)
    # loop-state (Phase 4b) inputs -- optional until the loop binds them.
    researcher_factory: Callable[..., Any] | None = None
    executor_factory: Callable[[], Any] | None = None
    max_turns_reader: Callable[[], Awaitable[int]] | None = None
    researcher_error: type[BaseException] | None = None
    # on-demand specialist spawn. Polls ratified request_specialist
    # capabilities for the investigation and spawns the matching registry
    # specialist (idempotent per persona_voice). Bound by modules that
    # support specialists; called at setup AND at every loop-cycle entry so
    # a request ratified mid-run spawns on the next cycle, not only when the
    # request predates setup. None -> the module has no specialist support.
    specialist_spawn_fn: Callable[[str], Awaitable[None]] | None = None
    # emit-state (Phase 4c) inputs -- optional until the emit binds them.
    synthesis_task_fn: Callable[..., Awaitable[Any]] | None = None
    verifier_task_fn: Callable[..., Awaitable[Any]] | None = None
    task_queue_factory: Callable[[], Any] | None = None
    get_int: Callable[[str], Awaitable[int]] | None = None
    get_float: Callable[[str], Awaitable[float]] | None = None
    outcome_dispatcher_cls: type[Any] | None = None
    pattern_extractor_cls: type[Any] | None = None
    approved_state: str | None = None
    evaluate_quorum: Callable[..., Awaitable[Any]] | None = None
    post_draft_review_request: Callable[..., Awaitable[Any]] | None = None
    finalize: Callable[..., Awaitable[Any]] | None = None
    branch_table: str | None = None
    # RFC-08 step 1 wire-in: a module-provided async callback that turns
    # a terminal quorum verdict (approved | rejected) into a signed row
    # in the module's PatternStore via ``ExperienceWriter``. Called from
    # ``state_investigation_emit`` immediately after ``evaluate_quorum``
    # returns a transitioning verdict; wrapped in a defensive try/except
    # so a write failure never disturbs the dispatch/approve path.
    # ``None`` (default) leaves the emit path unchanged -- module
    # bindings that predate the wire-in stay behavior-identical.
    #
    # Called as::
    #
    #     await bindings.record_experience(
    #         verdict=quorum,
    #         investigation_id=investigation_id,
    #         outcome_id=str(outcome_id),
    #         summary=<one-line summary>,
    #         body=<full body>,
    #     )
    #
    # The module closure resolves ``workspace_id`` from
    # ``investigation_id`` (via its own investigation -> target chain)
    # and calls ``ExperienceWriter.record`` -- the writer itself skips
    # non-terminal states + empty summary/body, so a DRAFT verdict is
    # a safe no-op even without gating.
    record_experience: Callable[..., Awaitable[None]] | None = None


@dataclass(frozen=True)
class InvestigationStateHooks:
    """Optional per-module hooks woven into the state handlers.

    Every hook is per-module residue. ``resolve_cve_intel`` takes the
    operator question and returns the cve-intel dict list (vr only); the
    others land with the loop/emit factories.
    """

    resolve_cve_intel: Callable[[str], Awaitable[list[dict[str, Any]]]] | None = None
    propose_playbook: Callable[..., Awaitable[Any]] | None = None
    propose_pattern: Callable[..., Awaitable[Any]] | None = None
    finalize_investigation: Callable[..., Awaitable[Any]] | None = None


def state_investigation_setup(
    bindings: InvestigationStateBindings,
    hooks: InvestigationStateHooks,
    *,
    next_state: str = "investigation_loop",
) -> Callable[[dict[str, Any], Any], Awaitable[StateResult]]:
    """Build the setup-state handler bound to *bindings* + *hooks*.

    *next_state* is the transition taken after a successful setup (default
    ``investigation_loop`` -- the single-loop V1 shape). A phase-graph
    passes its first phase. The already-terminal short-circuits still route
    straight to ``investigation_emit``.
    """

    async def _handler(input: dict[str, Any], services: Any) -> StateResult:
        """Validate + mark RUNNING. Returns input + resolved branch_id.

        Stale-branch self-healing (added after observing an investigation
        polling a closed halvar branch after re-enqueue):

          * **Primary task path** (no explicit branch_id): when picking the
            primary branch via ``parent_branch_id IS NULL``, filter to
            ``status IN (ACTIVE, PAUSED)`` AND order by ``created_at ASC``
            for determinism. If ALL prior primary branches are terminal
            (COMPLETED / MERGED / PROMOTED / ABANDONED) -- which is the
            post-completion / post-failure re-enqueue case -- fork a fresh
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

        UoW contract (fix §291 -- explicit doc of the all-or-nothing
        invariant that already holds structurally):

        The single ``async with UnitOfWork() as uow`` block that wraps
        investigation load → STATUS_LOCKED check → primary branch
        resolve → orphan-abandon → fresh-primary INSERT → status flip
        → ``uow.commit()`` is an **atomic transaction**. The orphan
        cleanup (mark sibling ACTIVE/PAUSED branches ABANDONED with
        ``superseded_by_reenqueue_self_heal:<new>``) and the fresh
        primary INSERT MUST commit together. If any pre-commit step
        raises (engine error, integrity violation, transient DB hiccup),
        the surrounding ``with`` block rolls everything back -- orphan
        rows stay ACTIVE, no fresh primary row leaks, the cursor
        re-fires next ARQ task wakeup.

        Anyone editing this block: do NOT split the orphan-abandon and
        fresh-primary INSERT into separate UoWs. The whole point is
        that a half-applied self-heal (new primary lives, orphans stay
        racing) is worse than no self-heal -- it produces exactly the
        "6 branches instead of 3" state we just fixed in 2026-05-28.
        """
        # fix §297 -- was \`del services\` (orphaning the bag). The handler
        # signature is fixed by HandlerFn; keep the bag accessible so
        # downstream code paths can reach \`services.llm_client\` /
        # \`services.config\` etc. The current setup-time operations
        # (CVE intel resolver, KnowledgeService-backed pattern_store) own
        # their own dependencies because the module workflow-services bag does not yet
        # carry a \`knowledge\` field; once it does, switch PatternStore
        # construction below to \`PatternStore(knowledge=services.knowledge)\`.
        _ = services  # held for future wiring; no-op today, NOT \`del\`.

        investigation_id = str(input.get("investigation_id") or "")
        if not investigation_id:
            raise ValueError("investigation_setup: missing investigation_id")

        # When set, we are a sibling task spawned by the primary's setup --
        # skip the auto-spawn block and just hydrate the named branch.
        explicit_branch_id = str(input.get("branch_id") or "")

        # RFC-13 wiring audit: forward the dispatch walk + cycle counter
        # out of setup's input into setup's output so the dispatch hub picks
        # them back up after an auto_continue re-enqueue. Without this a
        # resumed branch would re-walk every phase from scratch and the
        # researcher_error auto_continue counter would reset every task
        # boundary, defeating _MAX_AUTO_CONTINUE_CYCLES.
        dispatch_visited_pass_through = list(input.get("_dispatch_visited") or [])
        auto_continue_count_pass_through = int(input.get("_auto_continue_count") or 0)

        async with UnitOfWork() as uow:
            inv = (await uow.session.exec(
                _select(bindings.inv_model).where(
                    bindings.inv_model.id == investigation_id,
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
                # fix §290 -- re-resolve cve_intel from the (possibly
                # operator-edited) initial_question before the early-exit
                # so investigation_emit + downstream renderers don't lose
                # CVE context when a paused investigation resumes via
                # /reopen. Failing intel resolve NEVER blocks the early
                # exit -- empty list is the existing degraded default.
                await uow.commit()  # flush nothing; release UoW cleanly
                locked_cve_intel: list[dict[str, Any]] = []
                if hooks.resolve_cve_intel is not None:
                    locked_cve_intel = await hooks.resolve_cve_intel(
                        inv.initial_question or "",
                    )
                _log.info(
                    "investigation_setup STATUS_LOCKED inv=%s status=%s "
                    "pause_reason=%s cve_intel=%d -- skipping setup + loop, "
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
                        # Preserve so a paused-then-resumed run does not
                        # reset the dispatch walk / cycle counter.
                        "_dispatch_visited": dispatch_visited_pass_through,
                        "_auto_continue_count": auto_continue_count_pass_through,
                    },
                )

            if explicit_branch_id:
                branch = (await uow.session.exec(
                    _select(bindings.branch_model).where(
                        bindings.branch_model.id == explicit_branch_id,
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
                        "-- skipping investigation_loop and emitting clean exit",
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
                            "_dispatch_visited": dispatch_visited_pass_through,
                            "_auto_continue_count": auto_continue_count_pass_through,
                        },
                    )
            else:
                # Pick the OLDEST resumable primary branch -- deterministic
                # across re-enqueues. The prior LIMIT 1 with no filter and
                # no ORDER BY would silently pick a terminal branch when
                # one happened to sort first under PG's storage order, then
                # investigation_loop would spin forever on a closed branch.
                branch = (await uow.session.exec(
                    _select(bindings.branch_model).where(
                        bindings.branch_model.investigation_id == investigation_id,
                        bindings.branch_model.parent_branch_id.is_(None),
                        bindings.branch_model.status.not_in(_DEAD_BRANCH_STATUSES),
                    ).order_by(bindings.branch_model.created_at.asc()).limit(1)
                )).first()
                if branch is None:
                    # Either the investigation row was created without its
                    # initial primary branch (defensive -- API contract says
                    # this can't happen) OR all prior primaries reached
                    # terminal disposition and re-enqueue wants a fresh
                    # round. Fork a new ACTIVE primary so the run has
                    # somewhere live to land. Prior outcomes context loads
                    # via the existing re-enqueue blindness fix
                    # (vuln_researcher.run_turn loads prior_outcomes from
                    # the investigation, not from a single branch).
                    _log.warning(
                        "investigation_setup: no live primary branch for "
                        "inv=%s -- forking fresh primary (persona=%s); prior "
                        "primaries were terminal or absent",
                        investigation_id, bindings.primary_persona_value,
                    )
                    branch = bindings.branch_model(
                        investigation_id=investigation_id,
                        parent_branch_id=None,
                        status=BranchStatus.ACTIVE.value,
                        fork_reason="primary_reenqueue_after_terminal",
                        persona_voice=bindings.primary_persona_value,
                    )
                    uow.session.add(branch)
                    await uow.session.flush()

                    # When the self-heal forks a fresh primary, ANY other
                    # branches in this investigation that are still ACTIVE
                    # (or PAUSED) are orphans from the prior round -- their
                    # parent primary is COMPLETED / MERGED / etc., they
                    # were never explicitly closed when the primary
                    # terminal-submitted, and now they will race the fresh
                    # branches we just spawned, write duplicate findings,
                    # and waste budget. ABANDON them with a closed_reason
                    # that points back at this fresh primary so the audit
                    # trail is debuggable.
                    #
                    # Observed live on one investigation after the
                    # 2026-05-28 self-heal: 3 fresh branches got spawned
                    # on top of 2 still-running siblings from days
                    # earlier, leaving 5 active branches plus 1 completed
                    # = 6 total instead of the expected 3. Noticed
                    # in the UI before this cleanup landed.
                    orphans = (await uow.session.exec(
                        _select(bindings.branch_model).where(
                            bindings.branch_model.investigation_id == investigation_id,
                            bindings.branch_model.id != branch.id,
                            bindings.branch_model.status.in_(
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
                # Primary persona: researcher. Idempotent -- only set when
                # the operator didn't pick a persona explicitly.
                # fix §177/§178 -- promote primary branches with no persona OR
                # alembic-064's 'unspecified' default to the lead-researcher
                # persona so the frontend renders 'Halvar' instead of
                # 'Unnamed branch'.
                if (
                    not branch.persona_voice
                    or branch.persona_voice == bindings.unspecified_persona_value
                ):
                    branch.persona_voice = bindings.primary_persona_value
                    uow.session.add(branch)

            # fix §296 -- whitelist allowable prior status before flipping
            # to RUNNING. The prior unconditional flip silently overrode
            # operator-paused investigations that re-entered setup via a
            # racing dispatcher. Phase B's cursor SSOT writes '__paused__'
            # to the cursor; investigation_setup must NOT clobber that.
            # CREATED + RUNNING are the only legitimate transition sources
            # (CREATED → RUNNING on first dispatch; RUNNING → RUNNING is
            # idempotent on resume / re-enqueue).
            now = utc_now()
            allowed_prior_statuses = {
                InvestigationStatus.CREATED.value,
                InvestigationStatus.RUNNING.value,
            }
            if inv.status not in allowed_prior_statuses:
                _log.warning(
                    "investigation_setup REFUSE_FLIP inv=%s prior_status=%s "
                    "(allowed=%s) -- operator likely paused mid-setup; preserving",
                    investigation_id, inv.status, sorted(allowed_prior_statuses),
                )
            else:
                inv.status = InvestigationStatus.RUNNING.value
                if inv.started_at is None:
                    inv.started_at = now
            inv.updated_at = now
            uow.session.add(inv)
            await uow.commit()

        # Auto-deliberation: ensure the full 6-persona panel exists for
        # this investigation. Called on EVERY setup invocation (regardless
        # of whether the caller passed an explicit branch_id) because the
        # spawn function is idempotent: it reads all current branches,
        # keeps the best-turn-count per persona, abandons duplicates, and
        # inserts missing personas. Phase 2's task enqueue uses the queue
        # dedup so existing in-flight sibling tasks aren't duplicated.
        #
        # Prior to 2026-06-13, this was gated on `not explicit_branch_id`.
        # That gate caused a structural bug where any caller that passed
        # branch_id (`_wake_stale_branches`, the stall-recovery sweep when
        # an inv had 1+ active branches, MASVS re-enqueue paths after the
        # first task got killed mid-setup) skipped panel spawn entirely.
        # The investigation got stuck single-persona forever even though
        # the operator-configured auto_deliberation panel was supposed to
        # land. Diagnosed on three MASVS investigations --
        # all three stuck at 1 branch (halvar) after stall-recovery
        # re-enqueued them with branch_id.
        #
        # RFC-13 SETUP IDEMPOTENCY (2026-07-26): re-enqueued tasks on a
        # RUNNING investigation with an already-active branch MUST NOT
        # wipe branch state. persona_spawn.spawn_persona_siblings enforces
        # this at the reactivation guard: it only fires the fresh-slot
        # reset (``turn_count = 0``, stripped case_state, DELETE FROM
        # messages) when the WINNER branch's status is ``abandoned`` or
        # ``completed``. Active / paused branches skip that entire block.
        # Setup can therefore call spawn_fn safely on every invocation --
        # the only mutations that survive for an active branch are
        # idempotent (missing-persona INSERT, duplicate-persona abandon).
        # See persona_spawn.py "Reactivate the winner per persona" block.
        # RFC-08 pre-execution sizing seam: consult the routing learner
        # for a per-target_kind recommendation BEFORE spawning siblings
        # so a well-known target_kind + task_type can cap the panel via
        # ``spawn_persona_siblings``'s ``sizing_hint`` argument. Failure
        # of the learner NEVER blocks setup -- an unrecommended spawn
        # falls back to the full panel with a warn log.
        target_kind: str | None = None
        if (
            bindings.routing_history_provider is not None
            and bindings.target_model is not None
            and getattr(inv, "target_id", None)
        ):
            async with UnitOfWork() as _tk_uow:
                _target_row = (await _tk_uow.session.exec(
                    _select(bindings.target_model).where(
                        bindings.target_model.id == inv.target_id,
                    )
                )).first()
                if _target_row is not None:
                    target_kind = getattr(_target_row, "kind", None)
        routing_recommendation: RoutingRecommendation | None = None
        if (
            bindings.routing_history_provider is not None
            and target_kind is not None
            and target_kind.strip()
        ):
            try:
                from aila.platform.eval.routing_learner import RoutingLearner

                learner = RoutingLearner()
                routing_recommendation = await learner.recommend(
                    target_kind, bindings.routing_history_provider,
                )
                _log.info(
                    "investigation_setup routing_recommendation inv=%s "
                    "target_kind=%s ranked=%d samples=%d seam=%s",
                    investigation_id, target_kind,
                    len(routing_recommendation.ranked_task_types),
                    routing_recommendation.total_samples,
                    routing_recommendation.seam_status,
                )
            except (SQLAlchemyError, OSError, RuntimeError, ValueError, TypeError) as exc:
                _log.warning(
                    "investigation_setup routing_recommendation failed "
                    "inv=%s target_kind=%s: %s (falling back to full panel)",
                    investigation_id, target_kind, exc, exc_info=True,
                )
                routing_recommendation = None

        if bindings.auto_deliberation_enabled():
            spawn_kwargs: dict[str, Any] = {
                "investigation_id": investigation_id,
                "primary_branch_id": branch.id,
                "team_id": inv.team_id,
            }
            if routing_recommendation is not None:
                spawn_kwargs["sizing_hint"] = routing_recommendation
            await bindings.spawn_fn(**spawn_kwargs)

        # Resolve any CVE ids in the operator's question via the module's
        # optional hook (vr resolves via NVD; malware has no CVE surface).
        cve_intel: list[dict[str, Any]] = []
        if hooks.resolve_cve_intel is not None:
            cve_intel = await hooks.resolve_cve_intel(inv.initial_question)

        # Knowledge Transfer: query the pattern catalog for techniques
        # extracted from prior investigations on similar targets. Store
        # JSON-serialisable dicts in the run context so investigation_loop
        # can thread them into the per-turn user prompt. Failure to load
        # patterns NEVER blocks setup -- every new investigation must still
        # boot even if the pattern store is empty / broken.
        applicable_patterns: list[dict[str, Any]] = []
        global _CONSECUTIVE_PATTERN_LOOKUP_FAILURES
        try:
            # fix §294 -- read every needed target column into local vars
            # BEFORE the UoW closes. The prior code dereferenced
            # target.workspace_id / target.kind / target.primary_language
            # AFTER the `async with UnitOfWork()` block exited, which
            # works today (sqlmodel attaches loaded columns to the
            # detached instance) but is silently fragile -- any future
            # lazy-load relationship on bindings.target_model, expire_on_commit
            # flip, or SQLAlchemy version bump turns those accesses into
            # DetachedInstanceError. Pull primitives out while the
            # session is still live; reference locals after.
            target_kind: str | None = None
            target_lang: str | None = None
            target_ws: str | None = None
            async with UnitOfWork() as uow:
                target = (await uow.session.exec(
                    _select(bindings.target_model).where(bindings.target_model.id == inv.target_id),
                )).first()
                if target is not None:
                    target_kind = target.kind
                    target_lang = target.primary_language
                    target_ws = target.workspace_id
            if target_ws is not None:
                query = (inv.initial_question or inv.title or "").strip()
                if query:
                    store = bindings.pattern_store_factory()
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
            _CONSECUTIVE_PATTERN_LOOKUP_FAILURES = 0  # fix §293 -- reset on success
        except (SQLAlchemyError, ImportError, OSError, RuntimeError, ValueError, TypeError) as exc:
            _CONSECUTIVE_PATTERN_LOOKUP_FAILURES += 1
            if _CONSECUTIVE_PATTERN_LOOKUP_FAILURES >= _FAILURE_ESCALATION_THRESHOLD:
                # fix §350 -- escalation now carries the traceback so on-call
                # sees the failure shape (KnowledgeService, store, DB) in
                # one line.
                _log.error(
                    "investigation_setup: pattern lookup failed %d times in a "
                    "row (last err: %s) -- escalating; check pattern_store + "
                    "KnowledgeService dependency",
                    _CONSECUTIVE_PATTERN_LOOKUP_FAILURES, exc,
                    exc_info=True,
                )
            else:
                # fix §350 -- per-occurrence warning includes traceback.
                _log.warning(
                    "investigation_setup: pattern lookup failed "
                    "(consecutive=%d): %s",
                    _CONSECUTIVE_PATTERN_LOOKUP_FAILURES, exc,
                    exc_info=True,
                )

        _log.info(
            "investigation_setup READY investigation_id=%s branch_id=%s "
            "strategy=%s cve_intel=%d patterns=%d",
            investigation_id, branch.id, inv.strategy_family, len(cve_intel),
            len(applicable_patterns),
        )

        branch_capability: str | None = None
        if bindings.module_id and branch.persona_voice:
            branch_capability = await SpecialistAgentRegistry().resolve_capability(
                bindings.module_id, branch.persona_voice,
            )

        # RFC-08: forward the routing recommendation (if any) into the
        # loop / emit states as an operator-inspectable payload. Kept
        # JSON-serializable via a plain dict so a resumed task's
        # kwargs_json round-trips through ARQ without a Pydantic
        # BaseModel dependency. None when the module supplied no
        # history provider OR the learner errored.
        routing_recommendation_payload: dict[str, Any] | None = None
        if routing_recommendation is not None:
            routing_recommendation_payload = {
                "target_kind": routing_recommendation.target_kind,
                "total_samples": routing_recommendation.total_samples,
                "seam_status": routing_recommendation.seam_status,
                "reasoning": routing_recommendation.reasoning,
                "ranked_task_types": [
                    {
                        "task_type": s.task_type,
                        "score": s.score,
                        "approval_rate": s.approval_rate,
                        "mean_cost_usd": s.mean_cost_usd,
                        "accepted": s.accepted,
                        "rejected": s.rejected,
                    }
                    for s in routing_recommendation.ranked_task_types
                ],
            }

        return StateResult(
            next_state=next_state,
            output={
                "investigation_id": investigation_id,
                "branch_id": branch.id,
                "strategy_family": inv.strategy_family,
                "auto_pilot": inv.auto_pilot,
                "cost_budget_usd": inv.cost_budget_usd,
                "team_id": inv.team_id,
                "cve_intel": cve_intel,
                "applicable_patterns": applicable_patterns,
                "routing_recommendation": routing_recommendation_payload,
                # Specialist capability routing: a spawned specialist branch
                # carries the specialist name as its persona_voice; resolve it
                # back to a capability so the dispatch hub's _pick filter
                # routes it to the capability-scoped phases. Core roles
                # (researcher/critic/implementer) are not registered
                # specialists, so this resolves to None and they walk every
                # phase -- the correct all-branches dialectic.
                "_branch_capability": branch_capability,
                # RFC-13 wiring audit: forward across setup so the dispatch
                # hub picks up its walk + the cycle counter for the
                # resumed branch. Empty defaults are harmless on a fresh
                # run.
                "_dispatch_visited": dispatch_visited_pass_through,
                "_auto_continue_count": auto_continue_count_pass_through,
            },
        )

    return _handler
