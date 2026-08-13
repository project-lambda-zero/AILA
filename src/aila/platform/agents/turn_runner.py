"""Shared agent turn runner (RFC-03 Phase 7).

``AgentTurnRunnerBase.run_turn`` is the single per-branch reasoning turn:
load state, build the prompt, call the engine (idempotency-cached),
absorb the decision, persist the message + branch state, upsert the
canonical outcome on a terminal submit, and handle the outcome-review /
edit-outcome side paths. It was lifted verbatim from the byte-shared
skeleton of the vr and malware researchers; the per-module differences
are expressed as:

* class attributes -- ``_LOG_LABEL``, ``_error_cls``, ``_result_cls``,
  ``_message_model``, ``_branch_model``, ``_OUTCOME_STATE_APPROVED``.
* staticmethod bindings for the per-module module-level helpers
  (``_fetch_tool_specs``, ``_load_prompt``, ``_decision_to_message_payload``,
  ``_terminal_outcome_kind``, ``_outcome_payload``, ``_upsert_canonical_outcome``,
  ``_resolve_task_type``, ``_evaluate_quorum``, ``_upsert_review``).
* override hooks -- ``_extra_user_prompt_kwargs``,
  ``_maybe_reject_fanout_submit``, ``_review_vote_and_comment``,
  ``_dispatch_approved_outcome``, ``_handle_edit_outcome``.

Subclasses also provide the shared instance methods the runner calls on
``self`` (``_load``, ``_build_user_prompt``,
``_consume_pending_operator_messages``, ``_load_prior_outcomes``,
``_load_sibling_context``, the three pre-submit gates) and the
``_engine`` / ``investigation_id`` / ``branch_id`` / ``_applicable_patterns``
instance state.
"""
from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, ClassVar

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select as _select

from aila.platform.agents.sibling_consensus import inject_sibling_consensus
from aila.platform.agents.turn_helpers import (
    auto_resolve_live_on_terminal,
    decode_case_state,
    encode_case_state,
    to_outcome_confidence,
)
from aila.platform.contracts import utc_now
from aila.platform.contracts.enums import BranchStatus, SenderKind
from aila.platform.contracts.reasoning import ReasoningTurnDecision
from aila.platform.llm.correlation import correlation_scope
from aila.platform.llm.errors import LLMError
from aila.platform.llm.idempotency_cache import (
    lookup_cached_response,
    make_request_key,
    store_response,
)
from aila.platform.services.ledger import LedgerPermissionError, LedgerService
from aila.platform.services.oracle import Oracle, OracleError
from aila.platform.uow import UnitOfWork

__all__ = ["AgentTurnResult", "AgentTurnRunnerBase"]

_log = logging.getLogger(__name__)

# RFC-13 (#68): per-turn ceiling on agent ledger appends (mirrors the
# observable-set caps) and the size of the shared-ledger digest rendered
# back into the next turn's prompt.
_MAX_LEDGER_WRITES_PER_TURN = 5
_LEDGER_BOARD_MAX_ENTRIES = 15
_LEDGER_BOARD_PREVIEW = 160


@dataclass
class AgentTurnResult:
    """What one ``run_turn`` produced.

    ``terminal`` is True when the engine chose ``submit`` -- the caller
    (the workflow state) stops driving the branch.
    """

    investigation_id: str
    branch_id: str
    turn: int
    decision: ReasoningTurnDecision
    message_id: str
    outcome_id: str | None = None
    terminal: bool = False


class AgentTurnRunnerBase:
    """Per-branch reasoning-turn runner shared by the module researchers.

    Subclasses set the config class attributes, bind the per-module
    module-level helpers as staticmethods, override the behavior hooks
    that follow, and supply the shared instance methods the runner calls
    on ``self``.
    """

    # Config -- every subclass sets these (declared for readers; the
    # runner reads them off ``self`` at call time).
    _LOG_LABEL: ClassVar[str] = "agent"
    # RFC-08: optional per-module hook (bound by the researcher subclass) that
    # writes a signed experience pattern when a sibling review vote flips
    # quorum to a terminal verdict on THIS (inline-dispatch) path. Default
    # None -> no-op, so any subclass that does not bind it is unaffected.
    _record_experience_on_verdict: ClassVar[
        Callable[..., Awaitable[None]] | None
    ] = None
    _result_cls: ClassVar[type[AgentTurnResult]] = AgentTurnResult
    _EMPTY_TOOLRUN_DIRECTIVE: ClassVar[str] = (
        "*** EMPTY tool_run COERCED TO reasoning ***\n\n"
        "Your prior turn emitted action='tool_run' but command "
        "was empty. (Could also have come from an internal gate "
        "that rejected your submit and converted to tool_run as "
        "a no-op.) Engine treated it as action='reasoning'.\n\n"
        "Valid actions: tool_run / reasoning / submit / "
        "submit_outcome_review / script_execute. There is no "
        "'observe' action. Empty tool_run wastes a turn -- pick "
        "'reasoning' to think, or check the directives in this "
        "prompt for what you actually need to do next."
    )

    # ---- override hooks (subclasses specialize) -------------------------
    async def _load_turn_config(self) -> None:
        """Load per-turn operator-tunable caps onto ``self`` before the gates.

        Default: no-op. Modules that read submit-gate caps from
        ConfigRegistry override this to stash them as instance attributes so
        the (sync) gate methods read a resolved value without an await.
        """

    async def _build_recall_fetcher(
        self, recall_keys: list[str],
    ) -> Callable[[str], str | None] | None:
        """Return a sync fetcher that rehydrates recalled observable bodies.

        The runner calls this immediately before :meth:`CyberReasoningEngine.absorb`
        whenever the agent emits ``action=\"recall\"``. The returned callable
        is invoked (synchronously, inside ``absorb``) for every pinned key
        that is no longer in the live ``case_state.observables`` and
        must return the durable body or ``None`` when the key is not
        retrievable from history.

        Default: ``None`` (no fetcher). Modules whose ``_message_model``
        payload rows carry a ``_observable_bodies`` mapping (written by
        :meth:`ToolExecutorHelpersBase._persist_result_and_observables`)
        override this to pre-load the requested keys and return a sync
        closure. ``None`` degrades gracefully -- absorb injects a short
        \"not available\" marker so the render layer still surfaces the
        recall attempt without crashing.

        ``recall_keys`` is the exact list from the current decision;
        subclasses may narrow the DB scan to just the requested keys
        rather than loading every message on the branch.
        """
        del recall_keys
        return None

    def _extra_user_prompt_kwargs(self) -> dict[str, Any]:
        """Per-module extra kwargs merged into the user-prompt build.

        Default: none. VR adds ``cve_intel``.
        """
        return {}

    async def _refresh_retrieved_knowledge(
        self,
        *,
        inv: Any,
        target_snapshot: dict[str, Any] | None,
        case_state: Any,
    ) -> None:
        """RFC-12 Phase 1: per-pivot refresh of the RETRIEVED prompt tier.

        Default no-op. A module overrides this to re-run knowledge retrieval
        keyed on the branch's CURRENT focus (its live hypotheses) rather than
        the boot question, and update the retrieved-knowledge the next prompt
        renders. Called each turn after ``case_state`` is decoded and before
        the prompt is built. Best-effort by contract: an override must swallow
        its own failures and never raise into the turn.
        """
        del inv, target_snapshot, case_state
        return None

    async def _load_ledger_board(self) -> str:
        """Render a bounded digest of the shared ledger for the turn prompt.

        Reads the whole ledger oldest-first and keeps the most recent
        entries so a branch sees the current state of the shared board.
        Returns an empty string when the ledger is empty so the render
        layer omits the section entirely (RFC-13 #68).
        """
        async with UnitOfWork() as uow:
            entries = await LedgerService().read_general(
                self.investigation_id, session=uow.session,
            )
        # RFC-07 #31: recovery events are an operator / audit trail, not an
        # agent-facing observable -- keep them out of the prompt board.
        entries = [e for e in entries if e.get("kind") != "recovery"]
        if not entries:
            return ""
        recent = entries[-_LEDGER_BOARD_MAX_ENTRIES:]
        lines: list[str] = []
        for entry in recent:
            payload = entry.get("payload") or {}
            preview = json.dumps(payload, ensure_ascii=False)
            if len(preview) > _LEDGER_BOARD_PREVIEW:
                preview = preview[:_LEDGER_BOARD_PREVIEW] + "..."
            author = entry.get("author_branch_id") or "?"
            status = entry.get("status")
            status_tag = f" status={status}" if status else ""
            lines.append(
                f"  #{entry.get('id')} [{entry.get('kind')}] "
                f"by {author}{status_tag}: {preview}"
            )
        header = f"Investigation ledger (shared, {len(entries)} entries"
        if len(recent) < len(entries):
            header += f", showing last {len(recent)}"
        header += "):"
        return header + "\n" + "\n".join(lines)

    async def _post_ledger_writes(
        self,
        decision: ReasoningTurnDecision,
        turn_number: int,
        session: AsyncSession,
        case_state: Any,
    ) -> None:
        """Append the turn's capped ledger writes inside the post-turn UoW.

        Each write derives a deterministic idempotency key from the branch,
        turn, entry index, and payload so an ARQ retry of the same turn
        re-posts nothing new. The contract restricts the kind to discovery /
        note / request, so no objective or decision entry reaches here.

        RFC-13 (#8) wiring coercion: in the RECON phase, agent-emitted
        ``note`` writes ARE the phase's discoveries -- recon is where the
        agent characterizes the target and surfaces the promising audit
        surfaces. The audit phases' activation conditions gate on
        ``make_discovery_condition('discovery')`` (exact kind equality),
        so notes posted during recon never satisfy them and the graph
        stalls. Coerce ``note`` -> ``discovery`` for the duration of the
        recon phase (``_directive.phase_mission`` begins with ``RECON``);
        leave ``request`` untouched and leave all non-recon phases
        untouched. The idempotency key is derived from the COERCED kind
        so an ARQ retry replays the same append and is deduped.
        """
        phase_mission = ""
        if case_state is not None:
            phase_mission = str(
                case_state.observables.get("_directive.phase_mission", "") or ""
            )
        in_recon = phase_mission.upper().startswith("RECON")
        service = LedgerService()
        # RFC-13 recon->audit feeder. The audit phases gate on
        # make_discovery_condition('discovery'); the hub's design expects
        # recon to POST discoveries. Agents route their target
        # characterization into decision.hypotheses (and a terminal scoping
        # outcome), not ledger notes, so the ledger stays empty of
        # discoveries, every audit phase is blocked, and the hub replans ->
        # stalls -> the branch short-circuits to a draft. Coerce each live
        # hypothesis raised during recon into a ledger discovery, idempotent
        # per hypothesis id so it posts once regardless of how many recon
        # turns keep it live. This unlocks source_audit / variant_hunt off
        # the shared ledger.
        if in_recon:
            for hyp in decision.hypotheses:
                hid = (hyp.id or "").strip()
                if not hid:
                    continue
                await service.append_general(
                    self.investigation_id,
                    self.branch_id,
                    "discovery",
                    {
                        "hypothesis_id": hid,
                        "claim": hyp.claim,
                        "why_plausible": hyp.why_plausible,
                        "kill_criterion": hyp.kill_criterion,
                        "source": "recon_hypothesis",
                    },
                    idempotency_key=f"{self.branch_id}:hyp:{hid}",
                    session=session,
                )
        writes = decision.ledger_writes[:_MAX_LEDGER_WRITES_PER_TURN]
        if not writes:
            return
        for index, write in enumerate(writes):
            kind = write.kind
            if in_recon and kind == "note":
                kind = "discovery"
            idem = AgentTurnRunnerBase._ledger_write_idem_key(
                write, kind, self.branch_id, turn_number, index,
            )
            await service.append_general(
                self.investigation_id,
                self.branch_id,
                kind,
                write.payload,
                idempotency_key=idem,
                session=session,
            )

    @staticmethod
    def _ledger_write_idem_key(
        write: Any, kind: str, branch_id: str, turn_number: int, index: int,
    ) -> str:
        """Idempotency key for one ledger write.

        A ``request_specialist`` is deduped per (investigation, capability).
        The specialist mechanism spawns exactly one branch per capability
        and the oracle dedups ratified capabilities, so the same request
        re-filed across turns, by a different branch, or by the spawned
        specialist itself is pure noise on the shared ledger. A stable
        capability-scoped key collapses every such filing to one row
        through the ledger's ``UNIQUE(investigation_id, idempotency_key)``
        constraint (``append_general`` conflicts are no-ops that return the
        existing id). Every other write keeps the per-turn key, which dedups
        only an ARQ retry of the same turn.
        """
        payload = write.payload or {}
        if (
            write.kind == "request"
            and payload.get("intent") == "request_specialist"
        ):
            capability = str(payload.get("target_capability") or "").strip()
            if capability:
                return f"request_specialist:{capability}"
        payload_hash = hashlib.sha256(
            json.dumps(write.payload, sort_keys=True).encode()
        ).hexdigest()[:16]
        return f"{branch_id}:{turn_number}:{index}:{kind}:{payload_hash}"

    async def _post_ledger_approvals(
        self,
        decision: ReasoningTurnDecision,
        session: AsyncSession,
    ) -> None:
        """Record this branch's request approvals through the oracle.

        Each vote is idempotency-keyed by (request, approver) inside the
        oracle. A branch approving its own request is refused by the
        distinct-approver rule; that is a no-op here, not a turn failure.
        """
        approvals = decision.ledger_approvals[:_MAX_LEDGER_WRITES_PER_TURN]
        if not approvals:
            return
        oracle = Oracle()
        for request_id in approvals:
            try:
                await oracle.record_decision(
                    self.investigation_id,
                    int(request_id),
                    self.branch_id,
                    approve=True,
                    session=session,
                )
            except (LedgerPermissionError, OracleError):
                # Self-approval blocked by the distinct-approver rule, or the
                # request id does not exist; skip without failing the turn.
                continue

    def _maybe_reject_fanout_submit(
        self, *, decision: Any, inv: Any, case_state: Any, turn_number: int,
    ) -> Any:
        """Gate a terminal submit on fan-out completeness. Default: allow.

        VR rejects a variant-hunt submit carrying no orders; malware runs
        its fan-out gate.
        """
        del inv, case_state, turn_number
        return decision

    def _maybe_reject_no_finding_while_sibling_open_hyp(
        self,
        *,
        decision: Any,
        case_state: Any,
        sibling_context: list[dict[str, Any]] | None,
        turn_number: int,
    ) -> Any:
        """Gate a terminal no-finding submit on sibling closure. Default: allow.

        VR overrides this to block a no_finding / inconclusive submit
        while a sibling still holds a live hypothesis that no branch has
        rejected -- the panel's dialectic requires the branch to
        confirm, refute, or coordinate before shipping a closure that
        would override a still-live sibling thread. Modules without
        that panel semantics (malware today) leave the default.
        """
        del case_state, sibling_context, turn_number
        return decision

    def _review_vote_and_comment(self, decision: Any) -> tuple[str, str]:
        """Resolve the effective (vote, comment) for an outcome review.

        Default behavior: read the raw ``review_vote`` / ``review_comment``
        (falling back to ``reasoning``) off the decision, but downgrade
        an empty-rationale ``reject`` to ``abstain`` -- an unevidenced
        veto MUST NOT swing quorum. The downgrade is logged and the
        stored comment carries a ``[system]`` marker so operators can
        see why the vote flipped. Subclasses that recognize additional
        vote flavors (e.g. VR's ``not_ready``) SHOULD handle those
        first and delegate the reject path back to this base via
        ``super()._review_vote_and_comment(decision)``.
        """
        raw_vote = decision.review_vote or "abstain"
        raw_comment = (decision.review_comment or decision.reasoning or "").strip()
        if raw_vote == "reject" and not raw_comment:
            _log.warning(
                "%s REVIEW DOWNGRADE inv=%s branch=%s outcome=%s "
                "vote=reject -> abstain (empty rationale; unevidenced veto)",
                self._LOG_LABEL, self.investigation_id, self.branch_id,
                getattr(decision, "review_outcome_id", None),
            )
            return (
                "abstain",
                "[system] reject vote downgraded to abstain: no "
                "rationale provided in review_comment or reasoning",
            )
        return (raw_vote, raw_comment)

    async def _dispatch_approved_outcome(self, outcome_id: str) -> None:
        """Enqueue the module's outcome dispatcher for an approved outcome.

        Required override -- each module submits its own dispatch task.
        """
        del outcome_id
        raise NotImplementedError

    async def _handle_edit_outcome(self, decision: Any) -> str | None:
        """Apply an ``edit_outcome`` action, returning an edit-state label.

        Default: no edit_outcome action for this module. Malware merges
        edit patches into the draft outcome.
        """
        del decision
        return None


    async def run_turn(self) -> AgentTurnResult:
        """Run one turn for this branch and write the result to the DB.

        On a ``submit`` decision, also writes a VRInvestigationOutcomeRecord
        and returns ``terminal=True`` so the workflow state knows to
        stop driving the branch.
        """
        inv, branch, target_snapshot = await self._load()
        await self._load_turn_config()

        case_state = decode_case_state(branch.case_state_json)
        turn_number = branch.turn_count + 1

        pending_operator_messages = await self._consume_pending_operator_messages(
            turn_number,
        )

        # Re-enqueue blindness fix: on a continuation run (operator
        # re-enqueued a completed investigation), the agent has zero
        # awareness it already submitted DIRECT_FINDINGs in prior
        # passes. Without this, it re-investigates from scratch every
        # time and lands on the same root cause -- 6 outcomes, 0 new
        # variants. Loading prior outcomes into the prompt forces it
        # to acknowledge prior work and EXTEND instead of REPEAT.
        prior_outcomes = await self._load_prior_outcomes()
        sibling_context = await self._load_sibling_context()

        # Sibling-consensus rejection pressure. When this branch's live
        # hypotheses include an id that 2+ siblings have rejected (with
        # source-citing claims), inject a directive forcing the agent
        # to either reject it this turn or explain disagreement.
        # Without this, the dialectic produces local rejection but
        # never converges across branches: halvar keeps h1 alive
        # forever even after maddie + renzo reject it with verbatim
        # source proof (observed live on investigation <inv-uuid>).
        my_live_ids = {h.id for h in case_state.hypotheses if h.id}
        case_state = inject_sibling_consensus(
            case_state, sibling_context, my_live_ids,
        )
        # RFC-13 (#68): render the shared investigation ledger into this
        # turn's prompt via a reserved observable. The render layer lifts
        # the board digest into its own section, and the runner re-derives
        # it from the DB each turn so it reflects sibling appends.
        ledger_board = await self._load_ledger_board()
        if ledger_board:
            case_state.observables["_ledger.board"] = ledger_board
        # RFC-09 criterion 4: thread the investigation id so the module
        # ``_load_prompt`` applies the pin-per-investigation rule (first
        # turn pins the current production version; later turns resolve
        # that exact version, insulating a running investigation from a
        # live production-alias flip). The returned ``version`` is None
        # only on the file-registry fallback path.
        # Per-phase prompt family (RFC-13): a dispatch phase may override the
        # investigation-level strategy_family via the
        # ``_directive.phase_strategy_family`` observable the loop writes at
        # phase entry. None (no phase override) falls back to the
        # investigation family, preserving single-loop V1 behavior.
        effective_strategy_family = (
            case_state.observables.get("_directive.phase_strategy_family")
            or inv.strategy_family
        )
        # v0.4 GA-52: branch persona maps to a per-role task_type
        # (researcher / implementer / critic). Falls back to the
        # investigation's strategy_family when no persona is assigned.
        # Resolved BEFORE the prompt load so an RFC-09 model-family prompt
        # variant can be selected for the model this turn routes to.
        task_type = self._resolve_task_type(branch.persona_voice) if branch.persona_voice else effective_strategy_family
        # RFC-09: pick the coarse model family this turn will run on so a
        # family-specific prompt variant wins when one exists (falls back to
        # the default variant then the file). Best effort -- a resolve fault
        # (including an engine without the accessor) leaves model_family None
        # and the prompt loads exactly as before.
        try:
            model_family = await self._engine.resolve_model_family(task_type)
        except (OSError, RuntimeError, ValueError, TypeError, AttributeError):
            model_family = None
        loaded_prompt = await self._load_prompt(
            effective_strategy_family,
            branch.persona_voice,
            investigation_id=self.investigation_id,
            model_family=model_family,
        )
        system_prompt = loaded_prompt.body
        resolved_prompt_version = loaded_prompt.version
        system_prompt_hash = hashlib.sha256(
            (system_prompt or "").encode()
        ).hexdigest()
        tool_specs = await self._fetch_tool_specs(
            target_kind=(target_snapshot or {}).get("kind"),
            primary_language=(target_snapshot or {}).get("primary_language"),
        )
        # RFC-12 Phase 1: refresh the RETRIEVED tier on the branch's current
        # focus before the prompt is built, so recalled knowledge tracks the
        # live pivot instead of the boot question. No-op by default.
        await self._refresh_retrieved_knowledge(
            inv=inv, target_snapshot=target_snapshot, case_state=case_state,
        )
        user_prompt = self._build_user_prompt(
            inv=inv,
            branch=branch,
            case_state=case_state,
            turn=turn_number,
            pending_operator_messages=pending_operator_messages,
            **self._extra_user_prompt_kwargs(),
            target_snapshot=target_snapshot,
            tool_specs=tool_specs,
            prior_outcomes=prior_outcomes,
            sibling_context=sibling_context,
            applicable_patterns=self._applicable_patterns,
        )
        # fix §88 -- per-component prompt-size logging stays as
        # diagnostic visibility, demoted from WARNING to DEBUG. At
        # WARNING level this fired ~22k times per MASVS audit (53
        # children × 70 turns × 6 personas), flooding the worker log
        # and drowning real warnings. Operators enable
        # the researcher logger at DEBUG when they want to see the
        # bloat distribution.
        if _log.isEnabledFor(logging.DEBUG):
            sys_chars = len(system_prompt or "")
            usr_chars = len(user_prompt or "")
            tools_chars = len(json.dumps(tool_specs) if tool_specs else "")
            snap_chars = len(json.dumps(target_snapshot) if target_snapshot else "")
            cs_chars = len(json.dumps(case_state.model_dump() if hasattr(case_state, "model_dump") else {}))
            _log.debug(
                "PROMPT_SIZE_DIAG inv=%s branch=%s turn=%d persona=%s "
                "sys=%d user=%d tools=%d snap=%d case=%d TOTAL=%d (~%dK tok)",
                inv.id[:8], branch.id[:8], turn_number, branch.persona_voice,
                sys_chars, usr_chars, tools_chars, snap_chars, cs_chars,
                sys_chars + usr_chars + tools_chars,
                (sys_chars + usr_chars + tools_chars) // 4000,
            )

        # Idempotency: derive a request_key from (investigation, branch,
        # turn, prompts) and check the cache before the LLM call. If a
        # prior attempt completed the LLM call but crashed before the
        # tool result was durably saved, the retry replays the cached
        # decision instead of paying for a duplicate Claude call.
        prompt_hash = hashlib.sha256(
            (system_prompt + "\x00" + user_prompt).encode()
        ).hexdigest()
        request_key = make_request_key(
            self.investigation_id, self.branch_id, turn_number, prompt_hash,
        )
        cached_response: dict[str, Any] | None = None
        async with UnitOfWork() as cache_uow:
            cached_response = await lookup_cached_response(
                cache_uow.session, request_key,
            )
        # decision is set in exactly one of two paths: from a valid
        # cache HIT, or from the upstream LLM call. Any failure to
        # validate the cache row falls through to the API path.
        decision: ReasoningTurnDecision | None = None
        # fix §89 -- `cache_hit` flag lets the post-LLM UoW skip the
        # cache store when we already had the response. The previous
        # separate `store_uow` here is folded into the message-write
        # UoW further down so one UoW covers all post-LLM writes.
        cache_hit = False
        if cached_response is not None:
            try:
                decision = ReasoningTurnDecision.model_validate(cached_response)
                cache_hit = True
                _log.info(
                    "%s: idempotency cache HIT inv=%s branch=%s turn=%d "
                    "(skipped duplicate LLM call)",
                    self._LOG_LABEL, self.investigation_id, self.branch_id, turn_number,
                )
            except (ValueError, TypeError, KeyError, AttributeError) as exc:
                # ValidationError, KeyError, AttributeError, or any
                # other cache-shape mismatch. We fall through to the
                # API path; the bad cache row stays in DB but will be
                # overwritten by store_response on the next success.
                # fix §350 -- surface traceback so a malformed cache row's
                # actual shape failure is debuggable on first occurrence
                # instead of waiting for a second hit.
                _log.warning(
                    "%s: cache validate failed (%s: %s) -- calling LLM",
                    self._LOG_LABEL, type(exc).__name__, exc,
                    exc_info=True,
                )
                decision = None

        if decision is None:
            try:
                with correlation_scope(
                    investigation_id=self.investigation_id,
                    branch_id=self.branch_id,
                    turn_number=turn_number,
                    prompt_content_hash=system_prompt_hash,
                    prompt_version=resolved_prompt_version,
                    canary_key=loaded_prompt.canary_key,
                ):
                    decision = await self._engine.decide_next_turn(
                        task_type=task_type,
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                        run_id=self.investigation_id,
                    )
            except (OSError, RuntimeError, ValueError, TypeError, KeyError, AttributeError, LLMError) as exc:
                # Wrap every engine failure as self._error_cls so the loop's
                # researcher_error handler catches it, sets
                # exit_reason='researcher_error:<msg>', and resolve_final_status
                # leaves the investigation RUNNING while auto_continue
                # re-enqueues this branch. LLMError was previously absent from
                # this tuple: a non-retryable provider error (a 400 model
                # rejection) is a direct Exception subclass, not OSError or
                # RuntimeError, so it escaped run_turn uncaught, crashed the
                # phase state, failed the task, and flipped the whole
                # investigation to FAILED, starving every sibling branch at
                # setup STATUS_LOCKED.
                raise self._error_cls(
                    f"engine.decide_next_turn failed for investigation_id="
                    f"{self.investigation_id} branch_id={self.branch_id}: "
                    f"{type(exc).__name__}: {exc}",
                    retryable=bool(getattr(exc, "retryable", False)),
                ) from exc
            # fix §89 -- store_response moved into the post-LLM UoW at
            # the end of run_turn. Cache row + message write + branch
            # update + outcome upsert now share ONE transaction instead
            # of three. Failure to commit means the cache row is also
            # not persisted, so a retry hits the API again -- correct
            # behavior for transient failures.

        # fix §87 -- was a production `assert`; stripped under `-O` and
        # then a NoneType-has-no-attribute crashes later on the next
        # decision use. Raise explicitly so the workflow finalizer
        # marks the investigation FAILED instead of partial-completing.
        # decision must be set by now: either the cache HIT branch
        # assigned it OR the LLM call branch did. The only escape path
        # is the raise self._error_cls above which exits entirely.
        if decision is None:
            raise self._error_cls(
                f"decision unbound after cache + LLM paths "
                f"(inv={self.investigation_id} branch={self.branch_id} "
                f"turn={turn_number}) -- logic bug",
            )

        # ── variant_hunt submit gate ────────────────────────────────────
        # When the agent terminal-submits on a kind=variant_hunt
        # investigation, the dispatcher spawns ONE CHILD investigation
        # per `variant_hunt_orders` entry on the payload. After the
        # turn-budget bump (c912d5b: 25→60→70) + branch-aware auto-
        # continue (fba2a08) landed, agents started investigating
        # candidates inline for the whole 60+ turn budget and submitting
        # carrying `variant_hunt_orders=[]` AND no exhaustion declaration --
        # collapsing the variant-hunt fan-out from ~120 children/day to
        # ~2/day overnight (5-21 → 5-22). The submit was technically
        # valid but it produced ZERO downstream investigations on
        # exactly the investigation kind whose entire purpose is to
        # fan out variant probes.
        #
        # The gate intercepts that submit and forces the agent to either:
        #   (a) populate variant_hunt_orders with the candidates it
        #       investigated inline (child investigations confirm-and-
        #       extend, not duplicate work), or
        #   (b) explicitly declare exhaustion via a recognised phrase
        #       (matches outcome_dispatcher._VARIANT_EXHAUSTION_PATTERN
        #       -- NO FURTHER VARIANTS, VARIANT DEAD, etc.)
        #
        # On rejection we DON'T persist the outcome and DON'T mark the
        # branch terminal. Instead we inject a loud
        # `_directive.variant_hunt_submit_rejected` observable into
        # case_state so next turn's prompt surfaces the rejection at
        # PROMPT POSITION 2 (render_active_directives_section).
        #
        # Safety: after _VARIANT_HUNT_REJECT_CAP consecutive rejections
        # on the same branch we force the submit through with a
        # `variant_hunt_advisory: forced_through_after_N_rejects` flag
        # on the payload so the operator can audit and the agent
        # doesn't loop forever.
        # Pre-submit: every live hypothesis must be either explicitly
        # rejected (in decision.rejected[]) or folded into the answer
        # as supported evidence. Runs BEFORE the variant_hunt gate so
        # the agent fixes the hypothesis-resolution issue first; once
        # resolved cleanly, the variant_hunt gate (if applicable)
        # evaluates against the cleaned decision.
        # Pre-submit gate (NEW): if another branch in this investigation
        # has a draft outcome up for review and this branch has not yet
        # voted, refuse the submit and inject a "vote first" directive.
        # Otherwise multiple siblings race to terminal_submit before
        # anyone votes on the first draft, and the first draft sits
        # stuck in draft forever because every potential voter has
        # closed itself out. See an observed investigation (renzo's draft
        # never reached quorum because maddie/wei/yuki all submitted
        # their own before voting on it).
        if decision.action == "submit":
            decision = await self._maybe_reject_submit_when_draft_pending(
                decision=decision,
                case_state=case_state,
                turn_number=turn_number,
            )

        # Reciprocal gate (Option B follow-up): if the agent emits
        # submit_outcome_review for an outcome this branch ALREADY voted
        # on, reject and steer back to investigation work. Without this
        # gate the agent re-emits the same vote every turn (idempotent at
        # the DB level via UNIQUE (outcome_id, branch_id) -- so harmless
        # -- but burns the entire 70-turn budget on re-voting instead of
        # adding to quorum or doing useful audit work). Observed live on
        # an observed investigation and branch (yuki): turns 29-40 all
        # re-voted approve on the same outcome.
        if (
            decision.action == "submit_outcome_review"
            and decision.review_outcome_id
        ):
            decision = await self._maybe_reject_revote_when_already_voted(
                decision=decision,
                case_state=case_state,
                turn_number=turn_number,
            )

        if decision.action == "submit":
            decision = self._maybe_reject_submit_with_unresolved_hypotheses(
                decision=decision,
                case_state=case_state,
                turn_number=turn_number,
            )

        # Sibling-open-hyp gate (#4 convergence fix): block a terminal
        # no_finding / inconclusive submit while a sibling holds a live
        # hypothesis id no branch has rejected. Runs AFTER the
        # unresolved-hyp gate because that gate operates on THIS
        # branch's live hypotheses; this gate closes the cross-branch
        # loop by looking at sibling_context (already loaded above,
        # passed here without a second DB round-trip). Default hook
        # on non-panel modules is a no-op.
        if decision.action == "submit":
            decision = self._maybe_reject_no_finding_while_sibling_open_hyp(
                decision=decision,
                case_state=case_state,
                sibling_context=sibling_context,
                turn_number=turn_number,
            )

        # Gate 5 (RFC #94): defense-check gate. Reject overflow/OOB
        # findings that skip allocator verification, input-range check,
        # or callers_of reachability trace. Runs after sibling-open-hyp
        # but before fanout so the rejection doesn't hit module-specific
        # gates. Only fires on submit with finding-class outcomes.
        if decision.action == "submit":
            from aila.platform.agents.submit_gates import (
                check_defense_verification,
                classify_claim,
            )
            _ok_kind = self._terminal_outcome_kind(decision)
            _ok_payload = self._outcome_payload(decision)
            _claim_class = classify_claim(_ok_kind.value, _ok_payload)
            async with UnitOfWork() as _gate_uow:
                _ok, _reject = await check_defense_verification(
                    session=_gate_uow.session,
                    branch_id=self.branch_id,
                    claim_class=_claim_class,
                    message_table=self._message_model.__tablename__,
                )
            if not _ok:
                _log.info(
                    "defense_check_gate REJECTED inv=%s branch=%s "
                    "claim_class=%s reason=%s",
                    self.investigation_id, self.branch_id,
                    _claim_class, (_reject or "")[:80],
                )
                decision = decision.model_copy(update={
                    "action": "reasoning",
                    "reasoning": _reject,
                })
                case_state.observables["_directive.defense_check_rejected"] = _reject

        decision = self._maybe_reject_fanout_submit(
            decision=decision,
            inv=inv,
            case_state=case_state,
            turn_number=turn_number,
        )

        # FINAL GATE -- empty tool_run coerce. Runs AFTER every other
        # gate (re-vote, submit-with-unresolved-hyp, variant-hunt-submit)
        # because those gates THEMSELVES produce action=tool_run +
        # empty command as a "rejection no-op" output. Only checks
        # `command` (the field tool_executor parses).
        # Swap to "reasoning" (valid Literal; falls through to TEXT
        # payload in _decision_to_message_payload). The directive
        # observable explains what happened so the next prompt picks a
        # real action instead of looping.
        if (
            decision.action == "tool_run"
            and not (decision.command or "").strip()
        ):
            _log.info(
                "empty_tool_run COERCED→reasoning inv=%s branch=%s turn=%d",
                self.investigation_id, self.branch_id, turn_number,
            )
            case_state.observables["_directive.empty_tool_run_coerced"] = (
                self._EMPTY_TOOLRUN_DIRECTIVE
            )
            decision = decision.model_copy(update={
                "action": "reasoning",
                "command": "",
                "script_content": "",
            })

        # Recall durable-history backing. When the agent recalls a key
        # that is no longer in the live observables (evicted by the
        # storage cap), ask the module for a sync closure that reads the
        # body from the DB message history. absorb() consumes the closure
        # inside its recall branch and rehydrates the pinned observables;
        # ``None`` (the platform default) degrades to a short marker so
        # the render layer still surfaces the recall attempt. The build
        # is scoped to the exact recall_keys so the pre-load can narrow
        # its DB scan.
        recall_fetcher: Callable[[str], str | None] | None = None
        if (
            decision.action == "recall"
            and decision.recall_keys
        ):
            recall_fetcher = await self._build_recall_fetcher(
                list(decision.recall_keys),
            )

        new_case_state = self._engine.absorb(
            case_state, decision, turn_number=turn_number,
            fetch_observable_body=recall_fetcher,
        )

        # Not-ready directive stamp (#6 convergence fix): when the
        # agent records a ``not_ready`` review, expose the stated
        # blocker on the NEXT turn's prompt via
        # ``_directive.draft_not_ready_recorded`` so operators + the
        # branch itself can see why the sibling declined to approve /
        # reject yet. Stamped BEFORE the case_state UoW so it rides
        # the same commit; the vote row itself is upserted after the
        # UoW closes (see the ``submit_outcome_review`` block below).
        # A no-op on any other action + on modules whose
        # ``_review_vote_and_comment`` overrides never emit not_ready.
        if (
            decision.action == "submit_outcome_review"
            and decision.review_outcome_id
        ):
            _early_vote, _early_comment = self._review_vote_and_comment(decision)
            if _early_vote == "not_ready":
                blocker = (_early_comment or "").strip() or "(no blocker recorded)"
                new_case_state.observables[
                    "_directive.draft_not_ready_recorded"
                ] = (
                    "*** NOT_READY VOTE RECORDED ***\n"
                    f"You voted not_ready on outcome {decision.review_outcome_id} "
                    "with blocker:\n"
                    f"  {blocker[:400]}\n\n"
                    "This response counts you as having responded to the "
                    "draft but does NOT move approve or reject quorum. Revisit "
                    "the outcome once the evidence named in the blocker has "
                    "landed (upgrade to approve/reject then), or continue "
                    "investigating."
                )

        payload_kind, payload = self._decision_to_message_payload(decision)
        terminal = decision.action == "submit"
        outcome_id: str | None = None

        # fix §89 -- ONE post-LLM UoW: cache store (if we made the LLM
        # call) + message write + branch state update + outcome upsert.
        # Was three separate UoWs (sibling-directive pre-LLM, cache
        # store post-LLM, message-write post-LLM). The sibling-directive
        # UoW was eliminated entirely by §103 (directive lives in
        # in-memory case_state.observables and persists with the
        # end-of-turn case_state_json write).
        # fix §103 -- ONE branch_row.case_state_json write per turn (was
        # three). The final write happens AFTER terminal auto-resolve
        # mutates new_case_state, so the durable scratchpad reflects
        # the post-auto-resolve state in a single observable transition.
        # Concurrent readers (frontend polling, auto_steering) see only
        # the pre- and post-turn states, not three intermediate flips.
        async with UnitOfWork() as uow:
            if not cache_hit:
                # Store on success only -- failed LLM calls leave no
                # cache entry so retry hits the API again (correct for
                # transient failures).
                await store_response(
                    uow.session,
                    request_key=request_key,
                    investigation_id=self.investigation_id,
                    branch_id=self.branch_id,
                    turn_number=turn_number,
                    response=decision.model_dump(mode="json"),
                )

            msg = self._message_model(
                investigation_id=self.investigation_id,
                branch_id=self.branch_id,
                sender_kind=SenderKind.ENGINE.value,
                sender_id="engine",
                payload_kind=payload_kind.value,
                payload_json=json.dumps(payload),
                at_turn=turn_number,
                evidence_refs_json="[]",
            )
            uow.session.add(msg)

            branch_row = (await uow.session.exec(
                _select(self._branch_model).where(
                    self._branch_model.id == self.branch_id,
                )
            )).first()
            if branch_row is None:
                raise self._error_cls(
                    f"branch {self.branch_id} disappeared during turn",
                )
            branch_row.turn_count = turn_number
            branch_row.updated_at = utc_now()

            await self._post_ledger_writes(
                decision, turn_number, uow.session, case_state,
            )
            await self._post_ledger_approvals(decision, uow.session)

            if terminal:
                outcome_kind = self._terminal_outcome_kind(decision)
                new_payload = self._outcome_payload(decision)
                new_confidence = to_outcome_confidence(decision).value
                # Auto-reject any hypothesis still in `hypotheses` at
                # submit time. The agent had every prior turn to call
                # reject_hypothesis manually; whatever survives to the
                # terminal turn is "unresolved" and stays "live" in the
                # frontend forever unless we close it here. Carries an
                # explicit reason so the audit trail shows it was
                # auto-closed rather than reasoned-through.
                auto_resolve_live_on_terminal(
                    new_case_state,
                    turn=turn_number,
                    outcome_kind=outcome_kind.value,
                )
                outcome_id = await self._upsert_canonical_outcome(
                    uow=uow,
                    investigation_id=self.investigation_id,
                    branch_id=self.branch_id,
                    persona_voice=branch_row.persona_voice,
                    new_outcome_kind=outcome_kind.value,
                    new_confidence=new_confidence,
                    new_payload=new_payload,
                    at_turn=turn_number,
                    # fix §173 -- explicit terminal-submit contract marker.
                    # _upsert_canonical_outcome is the ONE canonical-outcome
                    # write path and asserts this value at function entry;
                    # any non-terminal write path would have to call this
                    # starting inside its own terminal_submit (no separate
                    # submit_canonical_addition action exists by design).
                    action="terminal_submit",
                )
                # Close the branch -- BranchStatus.COMPLETED + closed_reason
                # + closed_at -- so _maybe_trigger_synthesis can count it
                # against the "expected to submit" set and the UI shows
                # the branch as done rather than perpetually active.
                branch_row.status = BranchStatus.COMPLETED.value
                branch_row.closed_reason = (
                    f"terminal_submit:turn_{turn_number}:{outcome_kind.value}"
                )
                branch_row.closed_at = utc_now()

            # fix §103 -- single case_state_json write, performed after
            # the optional terminal auto-resolve so the persisted
            # scratchpad reflects post-resolution state.
            branch_row.case_state_json = encode_case_state(new_case_state)
            uow.session.add(branch_row)

            await uow.session.commit()
            await uow.session.refresh(msg)

        # ------- submit_outcome_review handling (draft outcome workflow) -------
        # The message was already written in the UoW above; here we
        # turn the agent's vote into a row in vr_outcome_reviews and
        # evaluate quorum. If quorum flips state to APPROVED, the
        # dispatcher fires inline so the outcome ships immediately
        # rather than waiting for the next worker poll.
        review_state: str | None = None
        if decision.action == "submit_outcome_review" and decision.review_outcome_id:
            review_vote, review_comment = self._review_vote_and_comment(decision)
            try:
                await self._upsert_review(
                    outcome_id=decision.review_outcome_id,
                    reviewer_branch_id=self.branch_id,
                    vote=review_vote,
                    comment=review_comment,
                    suggested_edits=decision.payload or {},
                )
                quorum = await self._evaluate_quorum(decision.review_outcome_id)
                review_state = quorum.new_state
                # RFC-08: a reviewer's vote that flips quorum to a terminal
                # verdict here dispatches inline and never re-transitions on
                # the emit-state DRAFT_REVIEW path, so the emit-side
                # experience write would miss it. Mirror it here. Defensive:
                # a write failure MUST NOT affect the review / dispatch below.
                if (
                    self._record_experience_on_verdict is not None
                    and quorum.transition_occurred
                ):
                    try:
                        await self._record_experience_on_verdict(
                            verdict=quorum,
                            investigation_id=self.investigation_id,
                            outcome_id=decision.review_outcome_id,
                        )
                    except (OSError, TimeoutError, RuntimeError, ValueError) as exc:
                        _log.warning(
                            "%s EXPERIENCE_WRITE FAILED outcome=%s err=%s: %s",
                            self._LOG_LABEL, decision.review_outcome_id,
                            type(exc).__name__, exc,
                        )
                _log.info(
                    "%s REVIEW inv=%s branch=%s outcome=%s "
                    "vote=%s state=%s approve=%d reject=%d k=%d",
                    self._LOG_LABEL, self.investigation_id, self.branch_id,
                    decision.review_outcome_id, decision.review_vote,
                    quorum.new_state, quorum.approve_count,
                    quorum.reject_count, quorum.quorum_k,
                )
                if quorum.new_state == self._OUTCOME_STATE_APPROVED:
                    await self._dispatch_approved_outcome(
                        decision.review_outcome_id,
                    )
            except (SQLAlchemyError, OSError, RuntimeError, ValueError, TypeError, KeyError, AttributeError, self._error_cls) as exc:
                # Was `(OSError, TimeoutError, RuntimeError, ValueError)`;
                # SQLAlchemyError, pydantic.ValidationError, KeyError,
                # AttributeError from upsert_review / evaluate_quorum /
                # dispatcher.dispatch all fell through silently as the
                # turn-loop just continued, dropping the vote. Catch
                # everything, log with the type, then re-raise the
                # subtypes that the workflow finalizer recognises as
                # retryable LLM failures so the runner can re-enqueue.
                _log.exception(
                    "%s REVIEW failed inv=%s branch=%s "
                    "outcome=%s err=%s: %s",
                    self._LOG_LABEL, self.investigation_id, self.branch_id,
                    decision.review_outcome_id,
                    type(exc).__name__, exc,
                )
                if isinstance(exc, self._error_cls):
                    raise

        edit_state = await self._handle_edit_outcome(decision)

        _log.info(
            "%s TURN inv=%s branch=%s turn=%d action=%s terminal=%s "
            "review_state=%s edit_state=%s",
            self._LOG_LABEL, self.investigation_id, self.branch_id, turn_number,
            decision.action, terminal, review_state or "-", edit_state or "-",
        )

        return self._result_cls(
            investigation_id=self.investigation_id,
            branch_id=self.branch_id,
            turn=turn_number,
            decision=decision,
            message_id=msg.id,
            outcome_id=outcome_id,
            terminal=terminal,
        )
