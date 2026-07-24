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
from dataclasses import dataclass
from typing import Any, ClassVar

from sqlalchemy.exc import SQLAlchemyError
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
from aila.platform.llm.idempotency_cache import (
    lookup_cached_response,
    make_request_key,
    store_response,
)
from aila.platform.uow import UnitOfWork

__all__ = ["AgentTurnResult", "AgentTurnRunnerBase"]

_log = logging.getLogger(__name__)


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

    def _extra_user_prompt_kwargs(self) -> dict[str, Any]:
        """Per-module extra kwargs merged into the user-prompt build.

        Default: none. VR adds ``cve_intel``.
        """
        return {}

    def _maybe_reject_fanout_submit(
        self, *, decision: Any, inv: Any, case_state: Any, turn_number: int,
    ) -> Any:
        """Gate a terminal submit on fan-out completeness. Default: allow.

        VR rejects a variant-hunt submit carrying no orders; malware runs
        its fan-out gate.
        """
        del inv, case_state, turn_number
        return decision

    def _review_vote_and_comment(self, decision: Any) -> tuple[str, str]:
        """Resolve the effective (vote, comment) for an outcome review.

        Default mirrors the raw decision fields. Malware downgrades an
        empty-rationale reject to abstain.
        """
        return (
            decision.review_vote or "abstain",
            decision.review_comment or decision.reasoning or "",
        )

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
        system_prompt = await self._load_prompt(inv.strategy_family, branch.persona_voice)
        system_prompt_hash = hashlib.sha256(
            (system_prompt or "").encode()
        ).hexdigest()
        tool_specs = await self._fetch_tool_specs(
            target_kind=(target_snapshot or {}).get("kind"),
            primary_language=(target_snapshot or {}).get("primary_language"),
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

        # v0.4 GA-52: branch persona maps to a per-role task_type
        # (researcher / implementer / critic). Falls back to the
        # investigation's strategy_family when no persona is assigned.
        task_type = self._resolve_task_type(branch.persona_voice) if branch.persona_voice else inv.strategy_family

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
                ):
                    decision = await self._engine.decide_next_turn(
                        task_type=task_type,
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                        run_id=self.investigation_id,
                    )
            except (OSError, RuntimeError, ValueError, TypeError, KeyError, AttributeError) as exc:
                # must surface as self._error_cls so the loop catches
                # it, marks exit_reason='researcher_error:<msg>', and
                # the workflow finalises with status=FAILED instead of
                # silently completing the task with no outcome and
                # status=RUNNING.
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

        new_case_state = self._engine.absorb(case_state, decision, turn_number=turn_number)

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
