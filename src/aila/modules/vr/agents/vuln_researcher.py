"""HonestVulnResearcher — single-turn reasoning agent (M3.R-2).

Per the M3.R-1 schema lesson and the no-overengineering rule: this
agent runs ONE turn against the platform's existing
``CyberReasoningEngine``. The workflow state machine (M3.R-7) drives
the loop; the agent itself owns no loop, no tool execution, no
branching. Each of those is a separate later milestone.

What this commit ships:
  1. ``HonestVulnResearcher.run_turn()`` — load branch state, build
     prompt context, call engine.decide_next_turn, absorb decision,
     persist message + updated branch state.
  2. ``run_turn`` returns a ``VulnResearcherTurnResult`` describing
     what happened (action chosen, terminal yes/no, message id).
  3. Tool calls are RECORDED as messages but NOT executed (M3.R-3 wires
     MCP adapters). Submit actions DO get persisted as VROutcome rows.

What this commit does NOT do:
  - Branching: only the primary branch is touched (M3.R-5).
  - Persona voicing: ignores branch.persona_voice (M3.R-5).
  - Cost tracking: turn count goes up but $ costs stay at 0 until the
    cost_tracker service ships (separate small commit).
  - Tool execution: tool_run decisions become tool_call messages but no
    real MCP call. M3.R-3 adapters convert the message into a real call.
  - Operator messaging interleave: operator messages stored in DB but
    agent does NOT incorporate them into context. M3.R-6 adds that.
"""
from __future__ import annotations

import functools
import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlmodel import select as _select

from aila.modules.vr.agents.mcp_adapters import (
    KNOWN_TOOLS,
    specialized_tools,
)
from aila.modules.vr.agents.persona_router import resolve_task_type
from aila.modules.vr.contracts import (
    OutcomeConfidence,
    OutcomeKind,
    PayloadKind,
    SenderKind,
)
from aila.modules.vr.contracts.branch import BranchStatus
from aila.modules.vr.contracts.investigation import InvestigationKind
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationMessageRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
)
from aila.modules.vr.tools.android_mcp_bridge import AndroidMcpBridgeTool
from aila.modules.vr.tools.audit_mcp_bridge import AuditMcpBridgeTool
from aila.modules.vr.tools.ida_bridge import IDABridgeTool
from aila.platform.contracts._common import utc_now
from aila.platform.contracts.reasoning import (
    ReasoningCaseState,
    ReasoningContract,
    ReasoningTurnDecision,
    ResolvedHypothesis,
)
from aila.platform.services.reasoning import CyberReasoningEngine
from aila.platform.uow import UnitOfWork

__all__ = [
    "HonestVulnResearcher",
    "VulnResearcherError",
    "VulnResearcherTurnResult",
]

_log = logging.getLogger(__name__)


# Variant-hunt submit gate (Option B): when the agent terminal-submits
# on a kind=variant_hunt investigation with zero variant_hunt_orders
# AND no exhaustion declaration, the gate rejects the submit and forces
# the agent to either populate orders or explicitly declare exhaustion.
# Mirrors outcome_dispatcher._VARIANT_EXHAUSTION_PATTERN so what the
# gate accepts and what the dispatcher accepts as exhaustion stay in
# lockstep. Keep the two regexes synchronised if you change either.
_VARIANT_HUNT_EXHAUSTION_PATTERN = re.compile(
    r"\b("
    r"NO\s+(?:FURTHER|NEW|ADJACENT|REMAINING|OTHER)\s+VARIANTS?"
    r"|NO\s+VARIANT\s+(?:EXISTS?|FOUND|REMAINS?|CANDIDATES?)"
    r"|VARIANT\s+(?:IS\s+)?DEAD"
    r"|DEAD\s+VARIANT"
    r"|VARIANT\s+(?:NOT\s+FOUND|ABSENT|EXHAUSTED)"
    r"|VARIANT\s+HUNT\s+(?:EXHAUSTED|COMPLETE|CONCLUDED)"
    r"|EXHAUSTIVE\s+(?:NEGATIVE|SEARCH)"
    r")\b"
)

# After this many consecutive rejected submits on the same branch, the
# gate FORCES the submit through with a `variant_hunt_advisory:
# forced_through_after_N_rejects` flag on the payload. The agent never
# loops forever; the operator gets an audit trail of the over-forced
# submissions. Configurable via env for operators tuning the trade-off
# between "more variant fan-out" and "fewer no-op forced submits".
_VARIANT_HUNT_REJECT_CAP = int(__import__("os").environ.get(
    "VR_VARIANT_HUNT_REJECT_CAP", "3",
))
# Hypothesis-settlement gate on terminal submit. Every live hypothesis
# must be either explicitly rejected (in decision.rejected[]) or folded
# into the submitted answer/provenance as supported evidence — no live
# hypotheses are permitted to survive a submit. Without this gate, agents
# accumulate live hypotheses across deep-search turns and submit while
# the case still has 5+ unresolved claims, leaving the operator to
# manually decide which ones the finding actually addresses.
#
# Cap mirrors variant_hunt: after N rejections the submit is FORCED
# through with payload.unresolved_hypotheses_at_submit_advisory stamped
# so the operator can grep the outcomes table.
_UNRESOLVED_HYP_REJECT_CAP = int(__import__("os").environ.get(
    "VR_UNRESOLVED_HYP_REJECT_CAP", "3",
))


_PROMPT_DIR = Path(__file__).parent / "prompts"


@dataclass
class VulnResearcherTurnResult:
    """What one ``run_turn`` produced.

    ``terminal`` is True when the engine chose ``submit`` — caller
    (workflow state) should stop calling run_turn for this branch.
    """

    investigation_id: str
    branch_id: str
    turn: int
    decision: ReasoningTurnDecision
    message_id: str
    outcome_id: str | None = None
    terminal: bool = False


class VulnResearcherError(Exception):
    """Raised on fatal agent failures (branch not found, prompt missing, etc.).

    ``retryable`` is True when the underlying cause was a transient LLM
    failure (rate limit, provider overload, network) — the workflow
    finalizer reads this to choose between auto-re-enqueue and
    marking the investigation FAILED.
    """

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable


class HonestVulnResearcher:
    """Single-branch reasoning agent.

    Construction takes the reasoning engine + identifiers. The engine
    can be swapped for a fake in tests (tests inject a stub with the
    same ``decide_next_turn`` + ``absorb`` shape).
    """

    def __init__(
        self,
        reasoning_engine: CyberReasoningEngine,
        investigation_id: str,
        branch_id: str,
        cve_intel: list[dict[str, Any]] | None = None,
        applicable_patterns: list[dict[str, Any]] | None = None,
    ) -> None:
        self._engine = reasoning_engine
        self.investigation_id = investigation_id
        self.branch_id = branch_id
        self._cve_intel = list(cve_intel or [])
        self._applicable_patterns = list(applicable_patterns or [])

    async def run_turn(self) -> VulnResearcherTurnResult:
        """Run one turn for this branch and write the result to the DB.

        On a ``submit`` decision, also writes a VRInvestigationOutcomeRecord
        and returns ``terminal=True`` so the workflow state knows to
        stop driving the branch.
        """
        inv, branch, target_snapshot = await self._load()

        case_state = _decode_case_state(branch.case_state_json)
        turn_number = branch.turn_count + 1

        pending_operator_messages = await self._consume_pending_operator_messages(
            turn_number,
        )

        # Re-enqueue blindness fix: on a continuation run (operator
        # re-enqueued a completed investigation), the agent has zero
        # awareness it already submitted DIRECT_FINDINGs in prior
        # passes. Without this, it re-investigates from scratch every
        # time and lands on the same root cause — 6 outcomes, 0 new
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
        # source proof (observed live on investigation 8cf6144f).
        my_live_ids = {h.id for h in case_state.hypotheses if h.id}
        if my_live_ids and sibling_context:
            sibling_rejection_count: dict[str, int] = {}
            sibling_rejection_claims: dict[str, list[str]] = {}
            for sib in sibling_context:
                for rej in sib.get("rejected", []):
                    rid = rej.get("id")
                    if not rid or rid not in my_live_ids:
                        continue
                    sibling_rejection_count[rid] = sibling_rejection_count.get(rid, 0) + 1
                    sibling_rejection_claims.setdefault(rid, []).append(
                        f"{sib.get('persona_voice','?')}: {rej.get('claim','')[:120]}"
                    )
            consensus_rejections = {
                rid: claims for rid, claims in sibling_rejection_claims.items()
                if sibling_rejection_count.get(rid, 0) >= 2
            }
            if consensus_rejections:
                directive_lines = [
                    "*** SIBLING CONSENSUS REJECTION ***",
                    f"You have {len(consensus_rejections)} hypothesis(es) still LIVE that ",
                    "2+ sibling branches have already REJECTED with source-citing evidence:",
                    "",
                ]
                for rid, claims in consensus_rejections.items():
                    directive_lines.append(f"  hypothesis id={rid}")
                    for c in claims:
                        directive_lines.append(f"    - {c}")
                directive_lines.append("")
                directive_lines.append(
                    "This turn you MUST either: (a) include these ids in your "
                    "decision.rejected[] with your own short concurring claim, "
                    "OR (b) explain in reasoning why you disagree AND cite the "
                    "verbatim source contradicting the siblings' refutation. "
                    "Passive 'keep alive without comment' is a deliberation "
                    "integrity failure."
                )
                # Inject directly into the branch's case_state observable
                # so render_active_directives_section surfaces at the top
                # of the next prompt build.
                # NOTE: do NOT add `from ... import VRInvestigationBranchRecord`
                # here. The module-level import at the top of the file
                # already binds the name. A function-local
                # `from ... import X` would shadow it for the WHOLE
                # function — including the unconditional uses ~150 lines
                # below at the message-write site — and Python's
                # function-scope rule makes those uses raise
                # UnboundLocalError on every code path where this `if
                # consensus_rejections:` block does NOT execute (which is
                # the normal case for any investigation whose siblings
                # haven't rejected anything yet, i.e. every freshly-spawned
                # investigation). This single typo crashed every primary +
                # sibling task in <3s for two days straight.
                async with UnitOfWork() as uow:
                    branch_row = (await uow.session.exec(
                        _select(VRInvestigationBranchRecord).where(
                            VRInvestigationBranchRecord.id == self.branch_id,
                        )
                    )).first()
                    if branch_row is not None:
                        try:
                            cs_obj = json.loads(branch_row.case_state_json or "{}")
                            obs = cs_obj.get("observables") or {}
                            if not isinstance(obs, dict):
                                obs = {}
                            obs["_directive.sibling_consensus_rejection"] = "\n".join(directive_lines)
                            cs_obj["observables"] = obs
                            branch_row.case_state_json = json.dumps(cs_obj)
                            uow.session.add(branch_row)
                            await uow.commit()
                            # Reload case_state into local copy so this turn
                            # also sees the directive.
                            case_state.observables["_directive.sibling_consensus_rejection"] = "\n".join(directive_lines)
                        except (json.JSONDecodeError, AttributeError):
                            pass
        system_prompt = _load_prompt(inv.strategy_family, branch.persona_voice)
        tool_specs = await _fetch_tool_specs(
            target_kind=(target_snapshot or {}).get("kind"),
            primary_language=(target_snapshot or {}).get("primary_language"),
        )
        user_prompt = self._build_user_prompt(
            inv=inv,
            branch=branch,
            case_state=case_state,
            turn=turn_number,
            pending_operator_messages=pending_operator_messages,
            cve_intel=self._cve_intel,
            target_snapshot=target_snapshot,
            tool_specs=tool_specs,
            prior_outcomes=prior_outcomes,
            sibling_context=sibling_context,
            applicable_patterns=self._applicable_patterns,
        )
        # DIAG (temporary): per-component prompt size logging so operator can
        # see what's bloating the 1M-token context limit. Remove after fix.
        import json as _json_diag  # noqa: PLC0415
        sys_chars = len(system_prompt or "")
        usr_chars = len(user_prompt or "")
        tools_chars = len(_json_diag.dumps(tool_specs) if tool_specs else "")
        snap_chars = len(_json_diag.dumps(target_snapshot) if target_snapshot else "")
        cs_chars = len(_json_diag.dumps(case_state.model_dump() if hasattr(case_state, "model_dump") else {}))
        _log.warning(
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
        task_type = resolve_task_type(branch.persona_voice) if branch.persona_voice else inv.strategy_family

        # Idempotency: derive a request_key from (investigation, branch,
        # turn, prompts) and check the cache before the LLM call. If a
        # prior attempt completed the LLM call but crashed before the
        # tool result was durably saved, the retry replays the cached
        # decision instead of paying for a duplicate Claude call.
        import hashlib as _hashlib  # noqa: PLC0415

        from aila.platform.contracts.reasoning import (  # noqa: PLC0415
            ReasoningTurnDecision,
        )
        from aila.platform.llm.idempotency_cache import (  # noqa: PLC0415
            lookup_cached_response,
            make_request_key,
            store_response,
        )

        prompt_hash = _hashlib.sha256(
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
        if cached_response is not None:
            try:
                decision = ReasoningTurnDecision.model_validate(cached_response)
                _log.info(
                    "vuln_researcher: idempotency cache HIT inv=%s branch=%s turn=%d "
                    "(skipped duplicate LLM call)",
                    self.investigation_id, self.branch_id, turn_number,
                )
            except Exception as exc:  # noqa: BLE001 — catch pydantic
                # ValidationError, KeyError, AttributeError, or any
                # other cache-shape mismatch. We fall through to the
                # API path; the bad cache row stays in DB but will be
                # overwritten by store_response on the next success.
                _log.warning(
                    "vuln_researcher: cache validate failed (%s: %s) — calling LLM",
                    type(exc).__name__, exc,
                )
                decision = None

        if decision is None:
            try:
                decision = await self._engine.decide_next_turn(
                    task_type=task_type,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                )
            except Exception as exc:  # noqa: BLE001 — any engine/LLM failure
                # must surface as VulnResearcherError so the loop catches
                # it, marks exit_reason='researcher_error:<msg>', and
                # the workflow finalises with status=FAILED instead of
                # silently completing the task with no outcome and
                # status=RUNNING.
                raise VulnResearcherError(
                    f"engine.decide_next_turn failed for investigation_id="
                    f"{self.investigation_id} branch_id={self.branch_id}: "
                    f"{type(exc).__name__}: {exc}",
                    retryable=bool(getattr(exc, "retryable", False)),
                ) from exc
            # Store on success only — failed calls leave no cache entry
            # so retry will hit the API again (correct behavior for
            # transient failures).
            async with UnitOfWork() as store_uow:
                await store_response(
                    store_uow.session,
                    request_key=request_key,
                    investigation_id=self.investigation_id,
                    branch_id=self.branch_id,
                    turn_number=turn_number,
                    response=decision.model_dump(mode="json"),
                )

        # decision must be set by now: either the cache HIT branch
        # assigned it OR the LLM call branch did. The only escape
        # path is the raise VulnResearcherError above which exits
        # the function entirely.
        assert decision is not None, "decision unbound after both paths — logic bug"

        # ── variant_hunt submit gate ────────────────────────────────────
        # When the agent terminal-submits on a kind=variant_hunt
        # investigation, the dispatcher spawns ONE CHILD investigation
        # per `variant_hunt_orders` entry on the payload. After the
        # turn-budget bump (c912d5b: 25→60→70) + branch-aware auto-
        # continue (fba2a08) landed, agents started investigating
        # candidates inline for the whole 60+ turn budget and submitting
        # with `variant_hunt_orders=[]` AND no exhaustion declaration —
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
        #       — NO FURTHER VARIANTS, VARIANT DEAD, etc.)
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
        # closed itself out. See investigation b53d3bb0 (renzo's draft
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
        # the DB level via UNIQUE (outcome_id, branch_id) — so harmless
        # — but burns the entire 70-turn budget on re-voting instead of
        # adding to quorum or doing useful audit work). Observed live on
        # investigation 30b4437c branch cee88f86 (yuki): turns 29-40 all
        # re-voted approve on the same outcome 3acc6764.
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

        if (
            decision.action == "submit"
            and inv.kind == InvestigationKind.VARIANT_HUNT.value
        ):
            decision = self._maybe_reject_variant_hunt_submit(
                decision=decision,
                case_state=case_state,
                turn_number=turn_number,
            )

        # FINAL GATE — empty tool_run coerce. Runs AFTER every other
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
                "*** EMPTY tool_run COERCED TO reasoning ***\n\n"
                "Your prior turn emitted action='tool_run' but command "
                "was empty. (Could also have come from an internal gate "
                "that rejected your submit and converted to tool_run as "
                "a no-op.) Engine treated it as action='reasoning'.\n\n"
                "Valid actions: tool_run / reasoning / submit / "
                "submit_outcome_review / script_execute. There is no "
                "'observe' action. Empty tool_run wastes a turn — pick "
                "'reasoning' to think, or check the directives in this "
                "prompt for what you actually need to do next."
            )
            decision = decision.model_copy(update={
                "action": "reasoning",
                "command": "",
                "script_content": "",
            })

        new_case_state = self._engine.absorb(case_state, decision, turn_number=turn_number)

        payload_kind, payload = _decision_to_message_payload(decision)
        terminal = decision.action == "submit"
        outcome_id: str | None = None

        async with UnitOfWork() as uow:
            msg = VRInvestigationMessageRecord(
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
                _select(VRInvestigationBranchRecord).where(
                    VRInvestigationBranchRecord.id == self.branch_id,
                )
            )).first()
            if branch_row is None:
                raise VulnResearcherError(
                    f"branch {self.branch_id} disappeared during turn",
                )
            branch_row.turn_count = turn_number
            branch_row.case_state_json = _encode_case_state(new_case_state)
            branch_row.updated_at = utc_now()
            uow.session.add(branch_row)

            if terminal:
                outcome_kind = _terminal_outcome_kind(decision)
                new_payload = _outcome_payload(decision)
                new_confidence = _to_outcome_confidence(decision).value
                # Auto-reject any hypothesis still in `hypotheses` at
                # submit time. The agent had every prior turn to call
                # reject_hypothesis manually; whatever survives to the
                # terminal turn is "unresolved" and stays "live" in the
                # frontend forever unless we close it here. Carries an
                # explicit reason so the audit trail shows it was
                # auto-closed rather than reasoned-through.
                _auto_resolve_live_on_terminal(
                    new_case_state,
                    turn=turn_number,
                    outcome_kind=outcome_kind.value,
                )
                branch_row.case_state_json = _encode_case_state(new_case_state)
                outcome_id = await _upsert_canonical_outcome(
                    uow=uow,
                    investigation_id=self.investigation_id,
                    branch_id=self.branch_id,
                    persona_voice=branch_row.persona_voice,
                    new_outcome_kind=outcome_kind.value,
                    new_confidence=new_confidence,
                    new_payload=new_payload,
                    at_turn=turn_number,
                )
                # Close the branch — BranchStatus.COMPLETED + closed_reason
                # + closed_at — so _maybe_trigger_synthesis can count it
                # against the "expected to submit" set and the UI shows
                # the branch as done rather than perpetually active.
                branch_row.status = BranchStatus.COMPLETED.value
                branch_row.closed_reason = (
                    f"terminal_submit:turn_{turn_number}:{outcome_kind.value}"
                )
                branch_row.closed_at = utc_now()

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
            from aila.modules.vr.services.outcome_review import (  # noqa: PLC0415
                OUTCOME_STATE_APPROVED,
                evaluate_quorum,
                upsert_review,
            )

            try:
                await upsert_review(
                    outcome_id=decision.review_outcome_id,
                    reviewer_branch_id=self.branch_id,
                    vote=decision.review_vote or "abstain",
                    comment=(decision.review_comment or decision.reasoning or ""),
                    suggested_edits=decision.payload or {},
                )
                quorum = await evaluate_quorum(decision.review_outcome_id)
                review_state = quorum.new_state
                _log.info(
                    "vuln_researcher REVIEW inv=%s branch=%s outcome=%s "
                    "vote=%s state=%s approve=%d reject=%d k=%d",
                    self.investigation_id, self.branch_id,
                    decision.review_outcome_id, decision.review_vote,
                    quorum.new_state, quorum.approve_count,
                    quorum.reject_count, quorum.quorum_k,
                )
                if quorum.new_state == OUTCOME_STATE_APPROVED:
                    from aila.modules.vr.agents.outcome_dispatcher import (  # noqa: PLC0415
                        OutcomeDispatcher,
                    )
                    from aila.platform.services.factory import (  # noqa: PLC0415
                        ServiceFactory,
                    )
                    dispatcher = OutcomeDispatcher(
                        knowledge=ServiceFactory().knowledge,
                    )
                    await dispatcher.dispatch(decision.review_outcome_id)
            except (OSError, TimeoutError, RuntimeError, ValueError) as exc:
                _log.warning(
                    "vuln_researcher REVIEW failed inv=%s branch=%s "
                    "outcome=%s err=%s",
                    self.investigation_id, self.branch_id,
                    decision.review_outcome_id, exc,
                )

        _log.info(
            "vuln_researcher TURN inv=%s branch=%s turn=%d action=%s terminal=%s "
            "review_state=%s",
            self.investigation_id, self.branch_id, turn_number,
            decision.action, terminal, review_state or "-",
        )

        return VulnResearcherTurnResult(
            investigation_id=self.investigation_id,
            branch_id=self.branch_id,
            turn=turn_number,
            decision=decision,
            message_id=msg.id,
            outcome_id=outcome_id,
            terminal=terminal,
        )

    async def _load(
        self,
    ) -> tuple[
        VRInvestigationRecord,
        VRInvestigationBranchRecord,
        dict[str, Any],
    ]:
        """Load investigation + branch + a snapshot of the primary target.

        Target snapshot has the fields the agent needs to pick the
        right MCP family + ground its reasoning:
          kind, display_name, primary_language, secondary_languages,
          analysis_state, descriptor (repo_url / upload_filename /
          binary_id / etc.), capability_profile.applicable_mcp_servers,
          capability_profile.applicable_fuzzing_engines,
          capability_profile.functions_of_interest (top 10),
          mcp_handles (audit_mcp_index_id / binary_id) so the agent
          knows what to pass to the bridge.
        """
        from aila.modules.vr.db_models import VRTargetRecord  # noqa: PLC0415

        async with UnitOfWork() as uow:
            inv = (await uow.session.exec(
                _select(VRInvestigationRecord).where(
                    VRInvestigationRecord.id == self.investigation_id,
                )
            )).first()
            if inv is None:
                raise VulnResearcherError(
                    f"investigation {self.investigation_id} not found",
                )
            branch = (await uow.session.exec(
                _select(VRInvestigationBranchRecord).where(
                    VRInvestigationBranchRecord.id == self.branch_id,
                )
            )).first()
            if branch is None:
                raise VulnResearcherError(
                    f"branch {self.branch_id} not found",
                )
            if branch.investigation_id != self.investigation_id:
                raise VulnResearcherError(
                    f"branch {self.branch_id} does not belong to investigation "
                    f"{self.investigation_id}",
                )
            target_snapshot: dict[str, Any] = {}
            if inv.target_id:
                target = (await uow.session.exec(
                    _select(VRTargetRecord).where(
                        VRTargetRecord.id == inv.target_id,
                    )
                )).first()
                if target is not None:
                    target_snapshot = self._snapshot_target(target)
            return inv, branch, target_snapshot

    async def _load_prior_outcomes(self) -> list[dict[str, Any]]:
        """Load every prior VRInvestigationOutcomeRecord for this investigation,
        oldest first. Used by ``_build_user_prompt`` to render a
        ``# Prior submissions`` section so the agent doesn't re-derive
        the same root cause on every re-enqueue.
        """
        async with UnitOfWork() as uow:
            rows = (await uow.session.exec(
                _select(VRInvestigationOutcomeRecord)
                .where(VRInvestigationOutcomeRecord.investigation_id == self.investigation_id)
                .order_by(VRInvestigationOutcomeRecord.created_at.asc()),
            )).all()
        out: list[dict[str, Any]] = []
        for row in rows:
            try:
                payload = json.loads(row.payload_json or "{}")
            except (ValueError, TypeError):
                payload = {}
            out.append({
                "outcome_id": row.id,
                "outcome_kind": row.outcome_kind,
                "confidence": row.confidence,
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "answer": payload.get("answer") or "",
                "variant_hunt_orders": payload.get("variant_hunt_orders") or [],
                "affected_components": payload.get("affected_components") or [],
            })
        return out

    async def _load_sibling_context(self) -> list[dict[str, Any]]:
        """Load active sibling branches' latest case_state + last outcome.

        Each entry: {branch_id, persona_voice, turn_count, hypotheses,
        rejected, key_observables, terminal_outcome}. Used by
        _build_user_prompt to inject a '# Sibling deliberations'
        section so this branch can REACT to what other personas have
        hypothesised/concluded. This is what makes adversarial
        deliberation real: HALVAR proposes -> MADDIE sees it next
        turn and counter-proposes -> HALVAR sees counter the turn
        after.
        """
        async with UnitOfWork() as uow:
            siblings = (await uow.session.exec(
                _select(VRInvestigationBranchRecord)
                .where(VRInvestigationBranchRecord.investigation_id == self.investigation_id)
                .where(VRInvestigationBranchRecord.id != self.branch_id)
                .order_by(VRInvestigationBranchRecord.created_at.asc()),
            )).all()
            out: list[dict[str, Any]] = []
            for s in siblings:
                terminal = (await uow.session.exec(
                    _select(VRInvestigationOutcomeRecord)
                    .where(VRInvestigationOutcomeRecord.investigation_id == self.investigation_id)
                    .where(VRInvestigationOutcomeRecord.branch_id == s.id)
                    .order_by(VRInvestigationOutcomeRecord.created_at.desc())
                    .limit(1),
                )).first()
                cs = _decode_case_state(s.case_state_json)
                t_payload: dict[str, Any] | None = None
                if terminal is not None:
                    try:
                        tp = json.loads(terminal.payload_json or "{}")
                    except (ValueError, TypeError):
                        tp = {}
                    t_payload = {
                        "outcome_kind": terminal.outcome_kind,
                        "confidence": terminal.confidence,
                        "answer": (tp.get("answer") or "")[:1500],
                        "variant_hunt_orders_count": len(tp.get("variant_hunt_orders") or []),
                    }
                hyps = [
                    {"id": h.id, "claim": h.claim[:240]}
                    for h in (cs.hypotheses or [])[:5]
                ]
                rej = [
                    {"id": h.id, "claim": h.claim[:160]}
                    for h in (cs.rejected or [])[:5]
                ]
                key_obs: dict[str, Any] = {}
                # Tool-prefix cache observables: surface them all so this
                # branch sees what siblings already fetched (function bodies
                # from audit_mcp:read_function.source.*, semantic_search
                # results, etc.). Each value preview-capped to 600 chars
                # so the sibling section doesn't dominate the prompt;
                # full body remains in the SIBLING's own case_state.
                tool_obs: dict[str, str] = {}
                for k, v in (cs.observables or {}).items():
                    if not isinstance(v, (str, int, float, bool)):
                        continue
                    if k.startswith("audit_mcp:") or k.startswith("audit_mcp.") \
                            or k.startswith("ida_headless:") or k.startswith("ida_headless."):
                        tool_obs[k] = str(v)[:5000]
                    elif not k.startswith("_"):
                        key_obs[k] = str(v)[:240]
                        if len(key_obs) >= 8:
                            break
                out.append({
                    "branch_id": s.id,
                    "persona_voice": s.persona_voice or "(none)",
                    "turn_count": s.turn_count,
                    "hypotheses": hyps,
                    "rejected": rej,
                    "key_observables": key_obs,
                    "tool_observables": tool_obs,
                    "terminal_outcome": t_payload,
                })
            return out


    @staticmethod
    def _snapshot_target(target: Any) -> dict[str, Any]:
        """Compact dict the prompt builder renders."""
        try:
            descriptor = json.loads(target.descriptor_json or "{}")
        except (ValueError, TypeError):
            descriptor = {}
        try:
            capability = json.loads(target.capability_profile_json or "{}")
        except (ValueError, TypeError):
            capability = {}
        try:
            handles = json.loads(target.mcp_handles_json or "{}")
        except (ValueError, TypeError):
            handles = {}
        try:
            secondary = json.loads(target.secondary_languages_json or "[]")
        except (ValueError, TypeError):
            secondary = []
        # F-4: android_apk targets carry their APK path in the
        # descriptor (set by POST /vr/targets/upload-apk). The F-2
        # RULE line and the renderer's mcp_handles loop both read
        # `handles["android_mcp_apk_path"]`, so surface it under that
        # key here. Synthesizing at snapshot-build time covers rows
        # ingested before this commit without requiring a stage
        # re-run, and keeps the on-disk handles dict as a pure record
        # of stage outputs (apk_path is a descriptor echo, not a
        # stage output).
        kind_str = str(target.kind or "").lower()
        if kind_str == "android_apk" and not handles.get("android_mcp_apk_path"):
            apk_path = descriptor.get("apk_path")
            if isinstance(apk_path, str) and apk_path:
                handles["android_mcp_apk_path"] = apk_path
        # Operator-mandated: MobSF output NEVER enters LLM prompts.
        # Even the digest form is forbidden — agents should query
        # android_mcp.mobsf_scan as a tool when they need it, not have
        # it preloaded into context. Strip the key entirely.
        if kind_str == "android_apk":
            handles.pop("android_mcp_mobsf_scan", None)
            static_full = handles.get("android_mcp_static_summary")
            if isinstance(static_full, dict) and static_full:
                digest = {}
                for k in ("package", "version_name", "version_code", "min_sdk", "target_sdk", "signing_scheme"):
                    if static_full.get(k) is not None:
                        digest[k] = static_full[k]
                for k in ("permissions", "dangerous_permissions", "exported_activities", "exported_services", "exported_receivers", "exported_providers", "native_libs", "certificates"):
                    v = static_full.get(k)
                    if isinstance(v, list):
                        digest[f"{k}_count"] = len(v)
                handles["android_mcp_static_summary"] = digest
        return {
            "id": target.id,
            "kind": target.kind,
            "display_name": target.display_name,
            "primary_language": target.primary_language or "",
            "secondary_languages": secondary,
            "analysis_state": target.analysis_state,
            "analysis_state_message": getattr(target, "analysis_state_message", None) or "",
            "descriptor": descriptor,
            "applicable_mcp_servers": list(capability.get("applicable_mcp_servers") or []),
            "applicable_fuzzing_engines": list(capability.get("applicable_fuzzing_engines") or []),
            "applicable_strategies": list(capability.get("applicable_strategies") or []),
            "functions_of_interest": list(capability.get("functions_of_interest") or [])[:10],
            "attack_surface": list(capability.get("attack_surface") or [])[:10],
            "mitigations": capability.get("mitigations") or {},
            "mcp_handles": handles,
        }

    def _build_user_prompt(
        self,
        *,
        inv: VRInvestigationRecord,
        branch: VRInvestigationBranchRecord,
        case_state: ReasoningCaseState,
        turn: int,
        pending_operator_messages: list[dict[str, Any]] | None = None,
        cve_intel: list[dict[str, Any]] | None = None,
        target_snapshot: dict[str, Any] | None = None,
        tool_specs: dict[str, list[dict[str, Any]]] | None = None,
        prior_outcomes: list[dict[str, Any]] | None = None,
        sibling_context: list[dict[str, Any]] | None = None,
        applicable_patterns: list[dict[str, Any]] | None = None,
    ) -> str:
        """Render the per-turn user prompt.

        Compact + structured. Includes the investigation question,
        a target-snapshot block (kind, language, descriptor,
        applicable MCP servers, ranked candidates), the current case
        state model, turn counter, any pending operator messages
        (M3.R-6), an External-CVE-intel block, and a target-kind-
        filtered tool catalog. Render order is deliberate — target
        first so the agent grounds on what's actually being audited
        before it picks tools.
        """
        case_model = self._engine.render_case_model(case_state)
        secondary_refs = json.loads(inv.secondary_target_refs_json or "[]")
        secondary_str = (
            ", ".join(str(r) for r in secondary_refs) if secondary_refs else "(none)"
        )

        operator_section = _render_operator_messages_section(
            pending_operator_messages or [],
        )
        directive_section = _render_active_directives_section(case_state)
        cve_intel_section = _render_cve_intel_section(cve_intel or [])
        target_section = _render_target_snapshot_section(target_snapshot or {})
        prior_submissions_section = _render_prior_submissions_section(
            prior_outcomes or [], inv.kind,
        )
        sibling_section = _render_sibling_context_section(
            sibling_context or [],
            this_persona=branch.persona_voice,
        )
        pattern_section = _render_pattern_section(applicable_patterns or [])
        target_kind = (target_snapshot or {}).get("kind")
        primary_language = (target_snapshot or {}).get("primary_language")
        return (
            f"{operator_section}"
            f"{directive_section}"
            f"# Investigation\n\n"
            f"Title: {inv.title}\n"
            f"Kind: {inv.kind}\n"
            f"Question: {inv.initial_question}\n"
            f"Primary target: {inv.target_id}\n"
            f"Secondary targets: {secondary_str}\n"
            f"Strategy: {inv.strategy_family}\n"
            f"Turn: {turn}\n"
            f"Branch: {branch.id} (persona: {branch.persona_voice or 'none'})\n"
            f"\n"
            f"{target_section}"
            f"{cve_intel_section}"
            f"{pattern_section}"
            f"# Current case state\n\n"
            f"{case_model}\n"
            f"\n"
            f"{prior_submissions_section}"
            f"{sibling_section}"
            f"{_render_available_tools_section(target_kind, tool_specs, primary_language)}"
            f"# Instruction\n\n"
            f"Produce the next reasoning turn as a JSON object per the "
            f"system prompt schema."
        )

    # Wall-clock TTL for operator messages. Previously computed as
    # _OPERATOR_MESSAGE_TTL_TURNS * 240s assuming each turn ≈ 4min —
    # wrong for variant_hunt runs that span hours of slow Claude
    # calls. A steering message posted at hour 1 would silently drop
    # by hour 1.5 even though the agent was only on turn 4. 24h
    # covers any realistic single-session run; operator can delete
    # stale messages via UI / DB if needed.
    _OPERATOR_MESSAGE_TTL_SECONDS: int = 24 * 3600

    async def _consume_pending_operator_messages(
        self,
        turn_number: int,
    ) -> list[dict[str, Any]]:
        """Load recent operator messages for this investigation.

        Returns newest-first so the agent reads the most recent
        steering directive first.

        Filters out:
          - empty text bodies
          - case-insensitive whitespace-normalised duplicate texts
          - messages whose wall-clock age exceeds the TTL window
          - messages addressed to a non-primary sibling branch (so
            "talk to Maddie specifically" doesn't leak to Halvar /
            Renzo). Primary-branch addressing is treated as broadcast.

        `at_turn` is still stamped on first read (the UI's "delivered
        at turn N" badge), but ages are computed from wall-clock so
        the value is consistent across siblings that read the same
        row at different turn numbers.
        """
        async with UnitOfWork() as uow:
            rows = (await uow.session.exec(
                _select(VRInvestigationMessageRecord)
                .where(
                    VRInvestigationMessageRecord.investigation_id == self.investigation_id,
                    VRInvestigationMessageRecord.sender_kind == SenderKind.OPERATOR.value,
                )
                .order_by(VRInvestigationMessageRecord.created_at.desc())
                .limit(20)
            )).all()

            if not rows:
                return []

            # Resolve primary branch id once for the visibility filter.
            primary_id = (await uow.session.exec(
                _select(VRInvestigationBranchRecord.id)
                .where(
                    VRInvestigationBranchRecord.investigation_id == self.investigation_id,
                    VRInvestigationBranchRecord.parent_branch_id.is_(None),
                )
                .limit(1)
            )).first()

            # ACK filter: drop operator messages whose row id is listed
            # in this branch's case_state._acked_operator_messages
            # observable. Agent sets that observable in its decision to
            # mark steering as understood; without it, every operator
            # message re-fires on every turn within the wall-clock TTL
            # even after the agent has already acted on it.
            acked_ids: set[str] = set()
            try:
                branch_row = (await uow.session.exec(
                    _select(VRInvestigationBranchRecord).where(
                        VRInvestigationBranchRecord.id == self.branch_id,
                    )
                )).first()
                if branch_row is not None:
                    cs = json.loads(branch_row.case_state_json or "{}")
                    acked_raw = (cs.get("observables") or {}).get("_acked_operator_messages")
                    if isinstance(acked_raw, str) and acked_raw:
                        acked_ids = {x.strip() for x in acked_raw.split(",") if x.strip()}
                    elif isinstance(acked_raw, list):
                        acked_ids = {str(x).strip() for x in acked_raw if x}
            except (json.JSONDecodeError, AttributeError):
                pass

            messages: list[dict[str, Any]] = []
            seen_texts: set[str] = set()
            stamped = False
            now = utc_now()
            ttl_seconds = self._OPERATOR_MESSAGE_TTL_SECONDS
            for row in rows:
                try:
                    payload = json.loads(row.payload_json or "{}")
                except json.JSONDecodeError:
                    payload = {}
                text = str(payload.get("text", "")).strip()
                if not text:
                    continue
                # ACK filter — drop message entirely if agent has marked it
                # via _acked_operator_messages.
                if row.id in acked_ids:
                    continue
                # Branch-addressed visibility: messages addressed to
                # a specific sibling (not this branch, not the primary)
                # are suppressed for everyone else. Primary-branch
                # addressing acts as broadcast.
                if (
                    row.branch_id
                    and row.branch_id != self.branch_id
                    and row.branch_id != primary_id
                ):
                    continue
                # Stamp first-seen turn for UI badge.
                if row.at_turn is None:
                    row.at_turn = turn_number
                    uow.session.add(row)
                    stamped = True
                # Wall-clock age — branch-independent.
                age_seconds = (now - row.created_at).total_seconds()
                if age_seconds > ttl_seconds:
                    continue
                # De-dup case-insensitive + whitespace-normalised.
                norm = " ".join(text.split()).lower()
                if norm in seen_texts:
                    continue
                seen_texts.add(norm)
                messages.append({
                    "id": row.id,
                    "text": text,
                    "intent": row.operator_intent or "unclassified",
                    "sender_id": row.sender_id,
                    "delivered_at_turn": row.at_turn,
                    "branch_addressed": row.branch_id,
                    "age_seconds": int(age_seconds),
                })
            if stamped:
                await uow.commit()
            return messages[:10]

    # --- variant_hunt submit gate helpers ----------------------------

    def _maybe_reject_variant_hunt_submit(
        self,
        *,
        decision: ReasoningTurnDecision,
        case_state: ReasoningCaseState,
        turn_number: int,
    ) -> ReasoningTurnDecision:
        """Intercept a kind=variant_hunt terminal_submit that emits zero
        ``variant_hunt_orders`` AND fails to declare exhaustion.

        Returns either:
          - the ORIGINAL decision (passed the gate, or forced-through
            after _VARIANT_HUNT_REJECT_CAP rejections)
          - a REPLACEMENT decision with ``action='tool_run'``,
            ``command=''``, and a synthetic answer body explaining the
            rejection. The replacement is non-terminal so the loop
            continues; the agent sees the
            ``_directive.variant_hunt_submit_rejected`` observable on
            the next turn's prompt and re-decides.

        Side effect: writes the rejection directive + counter into
        ``case_state.observables`` IN PLACE. The caller passes the
        pre-absorb case_state; absorb() runs afterwards in
        ``run_turn`` so the observable persists onto the branch's
        case_state_json.
        """
        payload = decision.payload or {}
        raw_orders = payload.get("variant_hunt_orders")
        orders_count = len(raw_orders) if isinstance(raw_orders, list) else 0
        answer_text = (payload.get("answer") or "")[:400].upper()
        declares_exhaustion = bool(
            _VARIANT_HUNT_EXHAUSTION_PATTERN.search(answer_text),
        )

        if orders_count > 0 or declares_exhaustion:
            # Passes the gate. Clear any prior rejection counter so a
            # later regression on the same branch starts fresh.
            if "_variant_hunt_submit_rejected_count" in case_state.observables:
                case_state.observables.pop(
                    "_variant_hunt_submit_rejected_count", None,
                )
            case_state.observables.pop(
                "_directive.variant_hunt_submit_rejected", None,
            )
            return decision

        prior_rejects = int(
            case_state.observables.get("_variant_hunt_submit_rejected_count", 0) or 0,
        )
        new_reject_count = prior_rejects + 1

        if new_reject_count > _VARIANT_HUNT_REJECT_CAP:
            # Force through after N rejections so the agent doesn't loop
            # forever. Stamp the payload with an audit flag so the
            # operator can find these in the outcomes table.
            _log.warning(
                "variant_hunt submit FORCED THROUGH after %d rejections "
                "inv=%s branch=%s turn=%d — payload had zero "
                "variant_hunt_orders AND no exhaustion declaration",
                prior_rejects, self.investigation_id, self.branch_id,
                turn_number,
            )
            new_payload = dict(payload)
            new_payload["variant_hunt_advisory"] = (
                f"forced_through_after_{prior_rejects}_rejects"
            )
            case_state.observables.pop(
                "_directive.variant_hunt_submit_rejected", None,
            )
            case_state.observables.pop(
                "_variant_hunt_submit_rejected_count", None,
            )
            return decision.model_copy(update={"payload": new_payload})

        _log.info(
            "variant_hunt submit REJECTED inv=%s branch=%s turn=%d "
            "rejects=%d/%d — orders=0, no exhaustion phrase",
            self.investigation_id, self.branch_id, turn_number,
            new_reject_count, _VARIANT_HUNT_REJECT_CAP,
        )

        case_state.observables["_variant_hunt_submit_rejected_count"] = new_reject_count
        case_state.observables["_directive.variant_hunt_submit_rejected"] = (
            "*** VARIANT_HUNT SUBMIT REJECTED ***\n"
            f"Rejection {new_reject_count}/{_VARIANT_HUNT_REJECT_CAP} on this branch.\n"
            "\n"
            "You attempted to terminal_submit a kind=variant_hunt investigation\n"
            "with EMPTY variant_hunt_orders AND no exhaustion declaration. The\n"
            "dispatcher spawns ONE CHILD INVESTIGATION per variant_hunt_orders\n"
            "entry; with zero entries, this investigation produces no fan-out.\n"
            "That defeats the entire purpose of a variant_hunt run.\n"
            "\n"
            "REQUIRED for your next decision: choose EXACTLY ONE of:\n"
            "\n"
            "  (a) Re-submit with variant_hunt_orders populated. Each entry MUST\n"
            "      cite a SPECIFIC (file, function) you read during this audit.\n"
            "      Re-list candidates you investigated inline too — child\n"
            "      investigations confirm-and-extend, they do not duplicate\n"
            "      already-done work. The schema is:\n"
            "          {\"title\": \"...\", \"hypothesis\": \"...\",\n"
            "           \"target_descriptor\": {...}, \"file\": \"...\",\n"
            "           \"function\": \"...\"}\n"
            "      Five well-cited variants are infinitely better than a\n"
            "      single confident-feeling root cause with zero downstream\n"
            "      probes.\n"
            "\n"
            "  (b) Re-submit with answer starting with one of:\n"
            "          NO FURTHER VARIANTS\n"
            "          VARIANT DEAD\n"
            "          NO VARIANT EXISTS / NO VARIANT FOUND\n"
            "          VARIANT EXHAUSTED\n"
            "          EXHAUSTIVE NEGATIVE\n"
            "      Use this ONLY after you have audited every plausible call\n"
            "      site of the shared machinery and found no new candidates.\n"
            "      Cite which call sites you reviewed in the answer body.\n"
            "\n"
            f"After {_VARIANT_HUNT_REJECT_CAP} rejections on this branch the\n"
            "submit is FORCED THROUGH with variant_hunt_advisory:\n"
            f"forced_through_after_{_VARIANT_HUNT_REJECT_CAP}_rejects stamped on\n"
            "the payload. Don't burn through your safety budget — pick (a)\n"
            "or (b) cleanly."
        )

        # Convert the submit into a non-terminal placeholder. The
        # message persisted to vr_investigation_messages still records
        # the agent's submit attempt (audit trail), but the workflow
        # treats this turn as non-terminal: branch stays ACTIVE,
        # turn_count still increments, loop continues to next turn.
        rejected_command_text = (
            "[VARIANT_HUNT GATE: submit rejected — see "
            "_directive.variant_hunt_submit_rejected]\n"
            "Original submit attempt:\n"
            + (payload.get("answer") or "(no answer)")[:1000]
        )
        return decision.model_copy(update={
            "action": "tool_run",
            "command": "",
            "answer": rejected_command_text,
            "payload": {
                **payload,
                "_variant_hunt_gate_rejected": True,
                "_variant_hunt_gate_reject_count": new_reject_count,
            },
        })

    def _maybe_reject_submit_with_unresolved_hypotheses(
        self,
        *,
        decision: ReasoningTurnDecision,
        case_state: ReasoningCaseState,
        turn_number: int,
    ) -> ReasoningTurnDecision:
        """Intercept any terminal_submit emitted while live hypotheses
        remain unresolved.

        A hypothesis is "resolved" by this turn when it appears in
        ``decision.rejected[]`` with the same id. Anything in
        ``case_state.hypotheses`` whose id isn't in that set is an
        unresolved live hypothesis. Submitting with unresolved
        hypotheses leaves the operator (or a downstream reviewer) to
        guess which claims the finding actually addresses — that's the
        same trap the closure-discipline section of system_audit.md
        warns against, made into a hard structural gate.

        Same shape as ``_maybe_reject_variant_hunt_submit``:
          - Pass: clear directive + counter, return original decision.
          - Reject (under cap): convert to non-terminal placeholder,
            inject directive into case_state.observables.
          - Force-through (over cap): stamp payload with audit advisory
            and return the submit.
        """
        live_ids = [h.id for h in case_state.hypotheses if h.id]
        newly_rejected_ids = {r.id for r in decision.rejected if r.id}
        unresolved = [hid for hid in live_ids if hid not in newly_rejected_ids]

        if not unresolved:
            # Passes the gate. Clear any prior rejection counter so a
            # later regression on the same branch starts fresh.
            case_state.observables.pop(
                "_unresolved_hyp_submit_rejected_count", None,
            )
            case_state.observables.pop(
                "_directive.unresolved_hyp_submit_rejected", None,
            )
            return decision

        prior_rejects = int(
            case_state.observables.get("_unresolved_hyp_submit_rejected_count", 0) or 0,
        )
        new_reject_count = prior_rejects + 1

        # Compact hypothesis listing for the directive (cap at 10 to
        # keep the prompt section bounded; agent can see the rest in
        # the regular case_model rendering).
        hyp_by_id = {h.id: h for h in case_state.hypotheses if h.id}
        unresolved_lines: list[str] = []
        for hid in unresolved[:10]:
            h = hyp_by_id.get(hid)
            claim = (h.claim if h else "")[:140]
            unresolved_lines.append(f"  - {hid}: {claim}")
        if len(unresolved) > 10:
            unresolved_lines.append(f"  ... and {len(unresolved) - 10} more")
        unresolved_block = "\n".join(unresolved_lines)

        if new_reject_count > _UNRESOLVED_HYP_REJECT_CAP:
            _log.warning(
                "unresolved_hyp submit FORCED THROUGH after %d rejections "
                "inv=%s branch=%s turn=%d — payload retained %d unresolved "
                "hypothesis ids: %s",
                prior_rejects, self.investigation_id, self.branch_id,
                turn_number, len(unresolved), ",".join(unresolved[:20]),
            )
            payload = decision.payload or {}
            new_payload = dict(payload)
            new_payload["unresolved_hypotheses_at_submit_advisory"] = {
                "count": len(unresolved),
                "ids": unresolved[:50],
                "forced_through_after_rejects": prior_rejects,
            }
            case_state.observables.pop(
                "_directive.unresolved_hyp_submit_rejected", None,
            )
            case_state.observables.pop(
                "_unresolved_hyp_submit_rejected_count", None,
            )
            return decision.model_copy(update={"payload": new_payload})

        _log.info(
            "unresolved_hyp submit REJECTED inv=%s branch=%s turn=%d "
            "rejects=%d/%d — %d live hypotheses unresolved",
            self.investigation_id, self.branch_id, turn_number,
            new_reject_count, _UNRESOLVED_HYP_REJECT_CAP, len(unresolved),
        )

        case_state.observables["_unresolved_hyp_submit_rejected_count"] = new_reject_count
        case_state.observables["_directive.unresolved_hyp_submit_rejected"] = (
            "*** SUBMIT REJECTED - UNRESOLVED LIVE HYPOTHESES ***\n"
            f"Rejection {new_reject_count}/{_UNRESOLVED_HYP_REJECT_CAP} on this branch.\n"
            "\n"
            f"You attempted action: submit while {len(unresolved)} live "
            "hypotheses are unresolved. Submitting now leaves the operator "
            "unable to tell which hypotheses your finding actually settles.\n"
            "\n"
            "UNRESOLVED LIVE HYPOTHESES:\n"
            f"{unresolved_block}\n"
            "\n"
            "REQUIRED for your next decision: for EACH unresolved id above,\n"
            "EITHER\n"
            "  (a) add it to `decision.rejected[]` with a `reason` that cites\n"
            "      the concrete evidence (file:line, tool output, or another\n"
            "      hypothesis's rejection) that disproves it. The standard\n"
            "      'rejected' schema is {id, claim, reason}.\n"
            "  (b) fold it into your submission's `answer` + `provenance` as\n"
            "      supporting evidence (the finding IS this hypothesis,\n"
            "      confirmed). Cite the hypothesis id verbatim in your answer\n"
            "      so the reader can trace what your finding claims to settle.\n"
            "\n"
            "Then re-emit `action: submit` with the cleaned state. ALL live\n"
            "hypotheses must be reachable from (a) OR (b) on the same turn as\n"
            "the submit.\n"
            "\n"
            f"After {_UNRESOLVED_HYP_REJECT_CAP} rejections on this branch the\n"
            "submit is FORCED THROUGH with unresolved_hypotheses_at_submit_\n"
            "advisory stamped on the payload listing the surviving ids. The\n"
            "operator will audit those entries. Don't burn through your\n"
            "safety budget when the fix is mechanical."
        )

        payload = decision.payload or {}
        rejected_command_text = (
            "[HYPOTHESIS GATE: submit rejected - see "
            "_directive.unresolved_hyp_submit_rejected]\n"
            "Original submit attempt:\n"
            + (payload.get("answer") or "(no answer)")[:1000]
        )
        return decision.model_copy(update={
            "action": "tool_run",
            "command": "",
            "answer": rejected_command_text,
            "payload": {
                **payload,
                "_unresolved_hyp_gate_rejected": True,
                "_unresolved_hyp_gate_reject_count": new_reject_count,
            },
        })

    async def _maybe_reject_submit_when_draft_pending(
        self,
        *,
        decision: ReasoningTurnDecision,
        case_state: ReasoningCaseState,
        turn_number: int,
    ) -> ReasoningTurnDecision:
        """Intercept a terminal_submit when another sibling already has
        a draft outcome up for review on this investigation, and this
        branch has not yet voted on that draft.

        Returns a non-terminal observe with a directive injected at
        operator-priority. Original submit payload is preserved on the
        observables under ``_pending_draft_blocked_submit`` so the agent
        can re-submit once it has voted on every open draft.

        Without this gate, multiple siblings race each other to
        terminal_submit, each one closes itself out, and the first
        draft's quorum never assembles — every potential voter has
        already submitted its own and gone to status=completed (which
        cannot vote, see ``vr_investigation_branches.status``).
        """
        from sqlmodel import select as _select_local  # noqa: PLC0415

        from aila.modules.vr.db_models.outcome import (  # noqa: PLC0415
            VRInvestigationOutcomeRecord,
        )
        from aila.modules.vr.db_models.outcome_review import (  # noqa: PLC0415
            VRInvestigationOutcomeReviewRecord,
        )
        from aila.modules.vr.services.outcome_review import (  # noqa: PLC0415
            OUTCOME_STATE_DRAFT,
        )

        async with UnitOfWork() as uow:
            drafts = (await uow.session.exec(
                _select_local(VRInvestigationOutcomeRecord)
                .where(
                    VRInvestigationOutcomeRecord.investigation_id
                    == self.investigation_id,
                )
                .where(
                    VRInvestigationOutcomeRecord.state
                    == OUTCOME_STATE_DRAFT,
                ),
            )).all()
            if not drafts:
                return decision

            # Exclude drafts proposed by this branch — the proposer
            # doesn't vote on its own outcome.
            other_drafts = [
                d for d in drafts if d.branch_id != self.branch_id
            ]
            if not other_drafts:
                return decision

            voted_on: set[str] = set()
            for d in other_drafts:
                review = (await uow.session.exec(
                    _select_local(VRInvestigationOutcomeReviewRecord)
                    .where(
                        VRInvestigationOutcomeReviewRecord.outcome_id
                        == d.id,
                    )
                    .where(
                        VRInvestigationOutcomeReviewRecord.reviewer_branch_id
                        == self.branch_id,
                    )
                    .limit(1),
                )).first()
                if review is not None:
                    voted_on.add(d.id)

            pending = [d for d in other_drafts if d.id not in voted_on]
            if not pending:
                return decision

        _log.info(
            "draft_pending submit REJECTED inv=%s branch=%s turn=%d — "
            "%d unvoted draft outcomes: %s",
            self.investigation_id, self.branch_id, turn_number,
            len(pending), [d.id[:8] for d in pending],
        )

        directive_lines = [
            "*** SUBMIT BLOCKED - UNVOTED DRAFT OUTCOMES IN THIS INVESTIGATION ***",
            "",
            "Another sibling branch submitted a terminal outcome that is now in",
            "DRAFT state and waiting for quorum. You MUST vote on it before",
            "submitting your own outcome. The dispatcher will not ship any",
            "outcome until existing drafts reach quorum.",
            "",
            "Unvoted drafts on this investigation:",
        ]
        for d in pending[:10]:
            directive_lines.append(
                f"  - outcome_id={d.id} kind={d.outcome_kind} "
                f"confidence={d.confidence}",
            )
        directive_lines.extend([
            "",
            "Your next turn MUST be a submit_outcome_review action with one",
            "of: approve | reject | request_edit | abstain. Re-read the",
            "submit_outcome_review block in your prompt for the exact shape.",
            "",
            "Once all drafts on this investigation have your vote, you may",
            "submit your own outcome.",
        ])
        directive = "\n".join(directive_lines)

        case_state.observables["_directive.draft_pending_submit_blocked"] = (
            directive
        )
        case_state.observables["_pending_draft_blocked_submit"] = {
            "answer": decision.answer or "",
            "payload": decision.payload or {},
            "blocked_at_turn": turn_number,
            "unvoted_draft_ids": [d.id for d in pending[:10]],
        }

        rejected_command_text = (
            "[DRAFT PENDING GATE: submit blocked - see "
            "_directive.draft_pending_submit_blocked]\n"
            "Vote on the listed drafts via submit_outcome_review first."
        )
        return decision.model_copy(update={
            "action": "tool_run",
            "command": "",
            "answer": rejected_command_text,
            "payload": {
                **(decision.payload or {}),
                "_draft_pending_gate_rejected": True,
                "_draft_pending_unvoted_count": len(pending),
            },
        })

    async def _maybe_reject_revote_when_already_voted(
        self,
        *,
        decision: Any,
        case_state: Any,
        turn_number: int,
    ) -> Any:
        """Reject submit_outcome_review when the branch already voted on this outcome.

        Quorum is computed by counting DISTINCT branches that voted approve
        on an outcome (vr_outcome_reviews has UNIQUE(outcome_id, branch_id)).
        A branch's 2nd, 3rd, 4th vote on the same outcome is upserted into
        the same row — they do NOT add to the approve count. Yet the agent
        keeps emitting submit_outcome_review every turn it sees the draft
        directive, burning the whole 70-turn budget on idempotent
        re-votes. Observed on inv=30b4437c branch=cee88f86 (yuki): turns
        29-40 all re-voted approve on outcome=3acc6764 while the draft
        still needed one more approver to reach quorum_k=3.

        Behavior: when a re-vote is detected, swap the action to tool_run
        with an answer that explicitly tells the agent to stop reviewing
        and resume audit work (or submit its own outcome if it has enough
        independent evidence). Includes a directive observable so the next
        prompt makes the same instruction visible to the agent.
        """
        from sqlmodel import select as _select_local  # noqa: PLC0415

        from aila.modules.vr.db_models.outcome_review import (  # noqa: PLC0415
            VRInvestigationOutcomeReviewRecord,
        )

        outcome_id = decision.review_outcome_id
        async with UnitOfWork() as uow:
            existing = (await uow.session.exec(
                _select_local(VRInvestigationOutcomeReviewRecord)
                .where(
                    VRInvestigationOutcomeReviewRecord.outcome_id == outcome_id,
                )
                .where(
                    VRInvestigationOutcomeReviewRecord.reviewer_branch_id
                    == self.branch_id,
                )
                .limit(1),
            )).first()

        if existing is None:
            # First vote — let it through.
            return decision

        _log.info(
            "draft_revote REJECTED inv=%s branch=%s turn=%d outcome=%s "
            "(prior vote=%s)",
            self.investigation_id, self.branch_id, turn_number,
            outcome_id, existing.vote,
        )

        directive = (
            "*** ALREADY VOTED — STOP RE-EMITTING THE SAME REVIEW ***\n\n"
            f"You already voted '{existing.vote}' on outcome {outcome_id} "
            "on a prior turn. Re-emitting submit_outcome_review is a no-op "
            "(unique constraint on outcome_id, branch_id — your vote is "
            "already counted toward quorum).\n\n"
            "Your next turn MUST be one of:\n"
            "  - tool_run: continue investigating the MASVS control with "
            "audit_mcp / android_mcp tools to gather additional evidence.\n"
            "  - submit: if you have independent terminal evidence (a "
            "finding the proposing branch missed, or a refutation), submit "
            "your own outcome.\n\n"
            "Do NOT re-emit submit_outcome_review for outcomes you have "
            "already voted on. The quorum waits on UNVOTED siblings, "
            "not on louder voices."
        )
        case_state.observables["_directive.already_voted_stop_reviewing"] = (
            directive
        )
        rejected_text = (
            "[ALREADY VOTED GATE: re-vote on outcome "
            f"{outcome_id} blocked - see "
            "_directive.already_voted_stop_reviewing]\n"
            "Continue investigating with tools or submit your own outcome."
        )
        return decision.model_copy(update={
            "action": "tool_run",
            "command": "",
            "answer": rejected_text,
            "payload": {
                **(decision.payload or {}),
                "_already_voted_gate_rejected": True,
                "_already_voted_outcome_id": outcome_id,
            },
        })


def _render_target_snapshot_section(snapshot: dict[str, Any]) -> str:
    """Render the primary-target snapshot so the agent grounds on
    concrete artifact metadata instead of treating the target id as
    an opaque UUID.

    Without this block the agent saw only ``Primary target: <uuid>``
    and defaulted to ``ida_headless.list_binaries`` even when the
    target was a source repo already cloned + indexed by audit-mcp.
    The block surfaces:
      - kind + language
      - descriptor (repo_url / upload_filename / binary_id)
      - resolved MCP handles (audit_mcp_index_id / binary_id) so the
        agent passes the right id to the bridge
      - which MCP servers + fuzzing engines + strategies are
        APPLICABLE to this target kind
      - the top 5 ranked candidate functions, when capability_profile
        carries them
      - a hard rule that tells the agent which MCP family to use

    Returns "" when snapshot is empty so the caller concatenates
    unconditionally.
    """
    if not snapshot:
        return ""
    lines: list[str] = ["# Primary target snapshot\n"]
    kind = snapshot.get("kind") or "?"
    name = snapshot.get("display_name") or "?"
    lang = snapshot.get("primary_language") or ""
    sec_lang = snapshot.get("secondary_languages") or []
    state = snapshot.get("analysis_state") or "?"
    handles = snapshot.get("mcp_handles") or {}
    descriptor = snapshot.get("descriptor") or {}
    applicable_mcp = snapshot.get("applicable_mcp_servers") or []
    applicable_engines = snapshot.get("applicable_fuzzing_engines") or []
    applicable_strategies = snapshot.get("applicable_strategies") or []
    ranked = snapshot.get("functions_of_interest") or []
    attack_surface = snapshot.get("attack_surface") or []

    lines.append(f"kind: {kind}")
    lines.append(f"display_name: {name}")
    if lang:
        sec_str = (
            f" (secondary: {', '.join(sec_lang)})" if sec_lang else ""
        )
        lines.append(f"language: {lang}{sec_str}")
    lines.append(f"analysis_state: {state}")

    descriptor_keys = ("repo_url", "vulnerable_ref", "patched_ref",
                       "upload_filename", "binary_id", "download_url")
    descriptor_pairs = [
        f"{k}={descriptor[k]}" for k in descriptor_keys
        if descriptor.get(k)
    ]
    if descriptor_pairs:
        lines.append("descriptor: " + " · ".join(descriptor_pairs))

    if handles:
        handle_pairs = [f"{k}={v}" for k, v in handles.items() if v]
        if handle_pairs:
            lines.append("mcp_handles: " + " · ".join(handle_pairs))

    # Hard rule on which MCP family to use. This is the most
    # important line in the section — without it the LLM defaults
    # to whichever tool name catches its eye.
    rule = _mcp_family_rule_for_kind(kind, handles)
    if rule:
        lines.append("")
        lines.append(rule)

    if applicable_mcp:
        lines.append(f"applicable_mcp_servers: {', '.join(applicable_mcp)}")
    if applicable_engines:
        lines.append(f"applicable_fuzzing_engines: {', '.join(applicable_engines)}")
    if applicable_strategies:
        lines.append(f"applicable_strategies: {', '.join(applicable_strategies)}")

    if ranked:
        lines.append("")
        lines.append("ranked candidate functions (top 5 by composite score):")
        for entry in ranked[:5]:
            entry_name = (
                entry.get("name") or entry.get("function_name") or "?"
            )
            score = entry.get("score")
            score_str = f"score={score:.2f}" if isinstance(score, (int, float)) else ""
            reasons = entry.get("reasons") or []
            reason_str = "; ".join(str(r) for r in reasons[:2])
            lines.append(
                f"  - {entry_name}"
                + (f" ({score_str})" if score_str else "")
                + (f" — {reason_str}" if reason_str else "")
            )

    if attack_surface:
        lines.append("")
        lines.append("attack_surface entries (top 5):")
        for entry in attack_surface[:5]:
            ek = entry.get("kind") or "?"
            en = entry.get("name") or "?"
            loc = entry.get("location") or ""
            sev = entry.get("severity_hint") or ""
            extras = []
            if loc:
                extras.append(f"@{loc}")
            if sev:
                extras.append(f"sev={sev}")
            lines.append(
                f"  - [{ek}] {en}"
                + (" " + " ".join(extras) if extras else "")
            )

    lines.append("")
    return "\n".join(lines) + "\n"


def _mcp_family_rule_for_kind(
    kind: str | None, handles: dict[str, Any],
) -> str:
    """Emit a one-line rule telling the agent which MCP server to use.

    Picks the right family based on target kind + the handles that
    actually exist. This is what stops the agent from drifting to the
    wrong tool family. By construction we ONLY mention the applicable
    server — never name the one we want the agent to avoid, because
    LLMs latch on to negated mentions ("Do NOT call ida_headless"
    keeps ida_headless in their attention budget).
    """
    k = (kind or "").lower()
    if k == "source_repo":
        idx = handles.get("audit_mcp_index_id")
        if idx:
            return (
                f"!!! INDEX_ID FOR THIS INVESTIGATION: `{idx}` !!!\n"
                f"RULE: source repo. EVERY audit_mcp tool call MUST pass "
                f"`index_id=\"{idx}\"`. Do NOT pass the branch name "
                f"(\"main\", \"master\", \"HEAD\", \"trunk\", \"current\", "
                f"\"latest\", \"default\") — those are placeholders the "
                f"agent commonly hallucinates and they all bounce back as "
                f"`Unknown index`, costing a 30s LLM retry. Copy the "
                f"index_id verbatim from the line above, every call, no "
                f"variation. The bridge auto-corrects placeholders to the "
                f"right id but each correction still rounds-trips a turn."
            )
        return (
            "RULE: source repo. Use **audit_mcp** tools. If you need an "
            "index_id, the target's ingestion may not be complete "
            "(check analysis_state)."
        )
    if k == "android_apk":
        idx = handles.get("audit_mcp_decompiled_index_id")
        apk_path = handles.get("android_mcp_apk_path")
        parts: list[str] = []
        if idx:
            parts.append(
                "For source-graph queries against the jadx-decompiled "
                f"Java tree, use **audit_mcp** with `index_id=\"{idx}\"`."
            )
        else:
            parts.append(
                "For source-graph queries against the jadx-decompiled "
                "Java tree, use **audit_mcp**. If you need an index_id, "
                "the target's decompiled-index stage may still be "
                "running (check analysis_state)."
            )
        if apk_path:
            parts.append(
                "For APK-specific facts — manifest, permissions, "
                "signing certificates, behaviour classification, "
                "MobSF / drozer / LIEF / YARA — "
                f"use **android_mcp** with `apk_path=\"{apk_path}\"`."
            )
        else:
            parts.append(
                "For APK-specific facts — manifest, permissions, "
                "signing certificates, behaviour classification, "
                "MobSF / drozer / LIEF / YARA — "
                "use **android_mcp**. The bridge resolves the APK "
                "path from the target descriptor automatically."
            )
        parts.append(
            "For NATIVE LIBRARY analysis (lib/arm64-v8a/*.so, "
            "lib/armeabi-v7a/*.so — e.g. libucs-credential.so, "
            "anti-tamper .so, JNI crypto .so) use **ida_headless** "
            "tools. Start with `ida_headless.open_binary(path=\"<absolute "
            "path to .so>\")` to register the library, then "
            "`ida_headless.decompile(binary_id=..., address_or_name=...)`, "
            "`ida_headless.imports`, `ida_headless.exports`, "
            "`ida_headless.search_pattern`, etc. NEVER try to "
            "analyze native .so files via audit_mcp (source-graph "
            "indexer is Java/Kotlin only) or via android_mcp "
            "(APK-level facets only, no instruction-level "
            "decompilation). .so files in lib/<abi>/ are ELF "
            "binaries — ida_headless is the only correct tool."
        )
        return "RULE: " + " ".join(parts)
    if k in {
        "native_binary", "ipa", "jar", "dotnet_assembly",
        "kernel_image", "kernel_module", "hypervisor_image",
    }:
        bid = handles.get("binary_id")
        if bid:
            return (
                f"RULE: binary target. Use **ida_headless** tools with "
                f"`binary_id=\"{bid}\"`."
            )
        return "RULE: binary target. Use **ida_headless** tools."
    return ""



def _render_prior_submissions_section(
    outcomes: list[dict[str, Any]],
    investigation_kind: str,
) -> str:
    """Render prior submissions as a markdown block for the prompt.

    Tells the agent what it already concluded on prior runs so it
    doesn't re-derive the same root cause on every re-enqueue.
    Returns "" when no prior outcomes — caller concatenates
    unconditionally.
    """
    if not outcomes:
        return ""
    lines: list[str] = [
        "# Prior submissions (you have run this investigation before)",
        "",
        f"You previously submitted **{len(outcomes)}** terminal outcome(s) "
        f"for this investigation. The platform has those answers on file. "
        f"Your job on this run is NOT to re-derive the same root cause "
        f"and re-submit it.",
        "",
    ]
    for i, o in enumerate(outcomes, 1):
        ts = (o.get("created_at") or "")[:19].replace("T", " ")
        kind = o.get("outcome_kind") or "?"
        conf = o.get("confidence") or "?"
        ans = (o.get("answer") or "").strip()
        excerpt = ans[:600] + ("..." if len(ans) > 600 else "")
        orders = o.get("variant_hunt_orders") or []
        comp = o.get("affected_components") or []
        lines.append(f"## Prior submission {i}/{len(outcomes)} - {ts} ({kind}, conf={conf})")
        lines.append(f"variant_hunt_orders emitted: {len(orders)}")
        lines.append(f"affected_components emitted: {len(comp)}")
        lines.append("")
        lines.append(excerpt or "(empty)")
        lines.append("")
    lines.append("# What this run must do")
    lines.append("")
    if investigation_kind == "variant_hunt":
        lines.append(
            "This is a `variant_hunt` investigation. You have already "
            "established the root cause above. Re-submitting another "
            "DIRECT_FINDING with the same root cause is WASTE - it "
            "produces a duplicate outcome row and contributes nothing. "
            "Two acceptable actions:",
        )
        lines.append("")
        lines.append(
            "1. **Emit `variant_hunt_orders`** for SPECIFIC NEW call sites "
            "you identified that share the bug class but were NOT in any "
            "prior submission's `variant_hunt_orders`. Each entry must "
            "cite a concrete `{file, function}` you read via audit-mcp "
            "during the audit. Cross-reference the prior submissions' "
            "`affected_components` and `variant_hunt_orders` so you don't "
            "re-list known sites.",
        )
        lines.append(
            "2. **Declare exhaustion**: submit a final DIRECT_FINDING "
            "whose `answer` starts with `NO FURTHER VARIANTS` and whose "
            "`variant_hunt_orders` is `[]`. Use this only after you have "
            "audited every plausible call site of the shared machinery "
            "and found no new candidates. Cite which call sites you "
            "reviewed in the answer body.",
        )
        lines.append("")
        lines.append(
            "Do NOT re-submit a third option (re-state the root cause). "
            "The dispatcher records every submission; duplicate answers "
            "are visible to the operator and reflect badly on the audit.",
        )
    else:
        lines.append(
            "You have already submitted a terminal outcome for this "
            "investigation. Either (a) explicitly EXTEND the prior "
            "analysis with new evidence the prior runs did not have, "
            "or (b) explicitly state in `answer` why a re-submission is "
            "warranted (e.g. operator-supplied new context, refined "
            "scope). Do NOT re-derive the same conclusion in different "
            "wording - that produces duplicate outcomes.",
        )
    lines.append("")
    return "\n".join(lines) + "\n"


def _render_sibling_context_section(
    siblings: list[dict[str, Any]],
    this_persona: str | None,
) -> str:
    """Render sibling branches' current state so this branch can react.

    Empty string when no siblings exist (single-branch fallback mode).
    Otherwise produces a '# Sibling deliberations (other personas)'
    block listing each sibling's persona, turn count, top hypotheses,
    rejected hypotheses, key observables, and latest terminal outcome.
    The agent is then told explicitly: REACT to these — challenge,
    refine, or build on them.
    """
    if not siblings:
        return ""
    lines: list[str] = [
        "# Sibling deliberations (other personas reasoning in parallel)",
        "",
        f"You are the **{this_persona or 'primary'}** voice. Other "
        f"persona branches are reasoning about this SAME investigation in "
        f"parallel, each driven by a different LLM routing. Their latest "
        f"state is below. Your turn MUST react: agree with evidence, "
        f"counter with new evidence, or escalate by spawning a tool call "
        f"that settles a disagreement. Silently ignoring sibling "
        f"hypotheses defeats the deliberation.",
        "",
        f"**IMPORTANT: speak ONLY as {this_persona or 'yourself'}. "
        f"Do NOT write text as other personas. Do NOT prefix your output "
        f"with role headers like 'RESEARCHER (name):' or 'CRITIC (name):'. "
        f"Your output is YOUR voice alone — reference siblings by name "
        f"('Maddie argues...', 'Halvar claims...') but do not simulate them.**",
        "",
    ]
    for s in siblings:
        persona = s.get("persona_voice") or "(no persona)"
        turn = s.get("turn_count") or 0
        lines.append(f"## Sibling: **{persona}** (turn {turn})")
        hyps = s.get("hypotheses") or []
        if hyps:
            lines.append("Active hypotheses:")
            for h in hyps:
                lines.append(f"  - [{h.get('id','?')}] {h.get('claim','')}")
        rej = s.get("rejected") or []
        if rej:
            lines.append("Rejected hypotheses:")
            for h in rej:
                lines.append(f"  - [{h.get('id','?')}] {h.get('claim','')}")
        key_obs = s.get("key_observables") or {}
        if key_obs:
            lines.append("Key observables:")
            # Cap to 10 entries x 300 chars per value to avoid prompt bloat
            # (6 siblings x N key_obs each was producing multi-KB sections).
            for k, v in list(key_obs.items())[:10]:
                v_str = str(v)[:300]
                lines.append(f"  - {k}: {v_str}")
        tool_obs = s.get("tool_observables") or {}
        if tool_obs:
            lines.append(
                "Tool readings sibling has CACHED (you can SKIP re-fetching "
                "these — reference the sibling's data instead):"
            )
            # Cap to 5 entries x 500 chars per value. Each tool reading was
            # already truncated to 5000 chars upstream; with 6 branches x
            # 20 readings that was ~600KB of context per turn.
            for k, v in list(tool_obs.items())[:5]:
                v_str = str(v)[:500]
                lines.append(f"  - {k}: {v_str}")
        term = s.get("terminal_outcome")
        if term:
            lines.append(
                f"**Submitted**: {term.get('outcome_kind','?')} "
                f"(confidence {term.get('confidence','?')}, "
                f"variant_hunt_orders={term.get('variant_hunt_orders_count',0)})",
            )
            ans = term.get("answer") or ""
            if ans:
                lines.append(f"Their answer (excerpt): {ans[:600]}")
        else:
            lines.append("(no terminal outcome yet — still reasoning)")
        lines.append("")
    lines.append("# Your reaction is mandatory")
    lines.append("")
    lines.append(
        "Before choosing this turn's action you MUST address at least one "
        "of the sibling hypotheses or outcomes above in your reasoning. "
        "If a sibling has submitted a verdict you disagree with, name "
        "the disagreement explicitly and either (a) emit a tool call "
        "that produces evidence to settle it, or (b) refine your own "
        "hypothesis to incorporate their finding. If you agree with a "
        "sibling's verdict, say so explicitly — but only after the "
        "critic-voice in your reasoning has tried to falsify it.",
    )
    lines.append("")
    return "\n".join(lines) + "\n"


_PATTERN_SECTION_BUDGET = 3000


def _render_pattern_section(patterns: list[dict[str, Any]]) -> str:
    """Render reusable patterns from prior investigations (Knowledge
    Transfer plan GA-41).

    Patterns are extracted from completed investigations and surface
    proven exploitation techniques, fuzzing strategies, search
    heuristics, tool recipes, and triage rules. Without injecting them
    into the per-turn prompt, every new investigation starts from zero
    and the 1.7k+ patterns sitting in vr_patterns deliver no value.

    Hard-caps the section at ``_PATTERN_SECTION_BUDGET`` chars so a
    workspace with hundreds of relevant patterns doesn't blow the
    prompt budget. Patterns are assumed to be pre-ranked by
    ``PatternStore.applicable()`` so truncation drops the
    lowest-relevance entries first.
    """
    if not patterns:
        return ""
    header = (
        "# Applicable patterns from prior investigations\n\n"
        "These patterns were extracted from successful prior investigations on\n"
        "similar targets. Use them to guide your hypothesis formation and tool\n"
        "selection — they represent proven techniques.\n\n"
    )
    lines: list[str] = []
    used = len(header)
    for p in patterns:
        title = str(p.get("summary") or "(untitled pattern)").strip()
        kind = str(p.get("kind") or "unknown").strip()
        body = str(p.get("body") or "").strip()
        block = f"## Pattern: {title}\nKind: {kind}\n"
        if body:
            block += f"{body}\n"
        block += "\n"
        if used + len(block) > _PATTERN_SECTION_BUDGET:
            # Truncate the last block to fit the remaining budget rather
            # than dropping it entirely, so the agent at least sees the
            # title + kind of the next-most-relevant pattern.
            remaining = _PATTERN_SECTION_BUDGET - used
            if remaining > 80:
                lines.append(block[: remaining - 4] + "...\n")
            break
        lines.append(block)
        used += len(block)
    if not lines:
        return ""
    return header + "".join(lines)


def _render_cve_intel_section(entries: list[dict[str, Any]]) -> str:
    """Render every CVE id mentioned in the operator's question with
    its resolved intel status (08_FRONTEND_UX.md §2.4).

    The reasoning agent uses this to distinguish:
      - ``status=found``     → real NVD/EPSS/KEV data — consume it
      - ``status=not_found`` → no aggregator has the CVE — do NOT
                                invent details; surface and ask
      - ``status=error``     → transport failure — treat as unknown

    Returns "" when no entries — caller concatenates unconditionally.
    """
    if not entries:
        return ""
    lines: list[str] = ["# External CVE intel\n"]
    for entry in entries:
        cve_id = entry.get("cve_id", "?")
        status = entry.get("status", "unknown")
        lines.append(f"## {cve_id} — status: {status}")
        if status == "found":
            desc = (entry.get("description") or "").strip()
            if desc:
                # Trim long descriptions; the agent needs the gist,
                # not the full advisory body.
                if len(desc) > 800:
                    desc = desc[:797] + "..."
                lines.append(f"description: {desc}")
            cwe_ids = entry.get("cwe_ids") or []
            if cwe_ids:
                lines.append(f"cwe_ids: {', '.join(cwe_ids)}")
            cvss = entry.get("cvss_score")
            sev = entry.get("base_severity")
            if cvss is not None or sev:
                lines.append(
                    f"cvss: {cvss if cvss is not None else 'n/a'} "
                    f"({sev or 'unrated'})",
                )
            if entry.get("kev_listed"):
                kev_date = entry.get("kev_date_added") or ""
                lines.append(
                    "**kev_listed: yes** — CISA flagged as actively "
                    "exploited in the wild"
                    + (f" (added {kev_date})" if kev_date else "")
                )
            epss_pct = entry.get("epss_percentile")
            epss = entry.get("epss_score")
            if epss_pct is not None or epss is not None:
                lines.append(
                    f"epss: score={epss if epss is not None else 'n/a'} "
                    f"percentile={epss_pct if epss_pct is not None else 'n/a'}",
                )
            affected = entry.get("affected_products") or []
            if affected:
                preview = affected[:6]
                more = f" (+{len(affected) - 6} more)" if len(affected) > 6 else ""
                lines.append(f"affected: {', '.join(preview)}{more}")
            notes = entry.get("notes") or []
            for note in notes[:4]:
                lines.append(f"note: {note}")
        else:
            err = (entry.get("error") or "").strip()
            if err:
                lines.append(f"reason: {err}")
            lines.append(
                "RULE: do not invent details for this CVE. Cite the "
                "missing intel in your rationale and ask the operator "
                "(via an AssessmentReport outcome) if the id is "
                "load-bearing for the investigation.",
            )
        lines.append("")
    return "\n".join(lines) + "\n"



def _render_operator_messages_section(messages: list[dict[str, Any]]) -> str:
    """Render pending operator messages as a markdown block for the prompt.

    Empty when no messages — caller concatenates unconditionally.
    Framing is intentionally LOUD because this block ends up at the TOP
    of the user prompt and overrides everything below it. Operator
    steering is a hard override, not advisory; the agent treating it as
    a suggestion is the bug the loud framing exists to prevent.
    """
    if not messages:
        return ""
    lines: list[str] = [
        "# *** OPERATOR STEERING — MANDATORY OVERRIDE ***",
        "",
        "The human operator sent these messages. They override the",
        "default strategy, override your current hypothesis, and override",
        "any prior tool-selection plan. Read each one, decide what action",
        "it dictates, and make that your next move. Ignoring a steering",
        "message is a contract violation.",
        "",
        "ACK CONTRACT: after you actually act on a steering message,",
        "include its id in your decision's observables under the",
        "reserved key `_acked_operator_messages` (comma-separated when",
        "multiple). Acknowledged messages stop appearing on subsequent",
        "turns. ONLY ACK after acting — premature ACK loses the steering",
        "forever. Example: observables: {\"_acked_operator_messages\":",
        "\"<id1>,<id2>\"}",
        "",
    ]
    for entry in messages:
        intent = entry.get("intent") or "unclassified"
        text = entry.get("text") or ""
        msg_id = entry.get("id") or "?"
        lines.append(f"- [id={msg_id} intent={intent}] {text}")
    lines.append("")
    lines.append("*** END OPERATOR STEERING ***")
    lines.append("")
    return "\n".join(lines) + "\n"


def _render_active_directives_section(case_state: ReasoningCaseState) -> str:
    """Render any ``_directive.*`` observables as a top-level prompt
    section. Surfaces at PROMPT POSITION 2 (right under operator
    steering, above # Investigation). Lifting these OUT of case_model
    means the agent doesn't have to wade through target snapshot + CVE
    intel + observables to find them — they're attention-anchored at
    the top.

    Source of truth: ``case_state.observables`` keys starting with
    ``_directive.``. Empty-string values are skipped (the clear path
    set by tool_executor when the agent satisfies the directive).
    Multiple directives can co-exist (e.g. ``_directive.pivot``,
    ``_directive.cost_cap``); each renders as its own labelled block.
    """
    directives = {
        k: v for k, v in case_state.observables.items()
        if k.startswith("_directive.") and isinstance(v, str) and v.strip()
    }
    if not directives:
        return ""
    lines: list[str] = [
        "# *** ACTIVE DIRECTIVES (MANDATORY — act on these THIS TURN) ***",
        "",
    ]
    for key, value in directives.items():
        label = key[len("_directive."):]
        lines.append(f"## directive: {label}")
        lines.append(value.rstrip())
        lines.append("")
    lines.append("*** END DIRECTIVES ***")
    lines.append("")
    return "\n".join(lines) + "\n"


_SOURCE_REPO_KINDS = frozenset({"source_repo"})
_BINARY_KINDS = frozenset({
    "native_binary", "ipa", "jar", "dotnet_assembly",
    "kernel_image", "kernel_module", "hypervisor_image",
})
# F-2: android_apk targets need BOTH bridges — android_mcp for the
# APK-specific surface (manifest, permissions, signing, behaviour
# classification, MobSF, drozer, etc.) AND audit_mcp for source-graph
# queries against the jadx-decompiled Java tree (the index_id lands in
# mcp_handles_json.audit_mcp_decompiled_index_id from F-3).
_ANDROID_KINDS = frozenset({"android_apk"})


def _applicable_servers_for_kind(target_kind: str | None) -> set[str]:
    """Return the MCP server ids the agent should consider given the
    target's kind. Source repos resolve via audit-mcp; classic binary
    kinds via ida_headless; android_apk gets the android_mcp bridge
    PLUS audit_mcp (source-graph over the decompiled Java tree).
    Unknown / mixed kinds default to every known bridge so the agent
    isn't locked out of any path.
    """
    k = (target_kind or "").lower()
    if k in _SOURCE_REPO_KINDS:
        return {"audit_mcp"}
    if k in _ANDROID_KINDS:
        # APKs ship Java/Kotlin source (audit_mcp via jadx index) AND
        # APK-specific facets (android_mcp: manifest / permissions /
        # signing / MobSF / etc.) AND native libraries in lib/<abi>/
        # (ida_headless: the Huawei UCS credential .so, anti-tamper
        # .so, Frida-resistant crypto .so etc.). Excluding ida_
        # headless previously forced agents to either skip native
        # analysis entirely or hallucinate calls to whichever
        # android_mcp tool LOOKED native-adjacent (frida_*) which
        # then errored every call. Including all
        # three gives the agent the actual right tool for every
        # facet of an APK target.
        return {"android_mcp", "audit_mcp", "ida_headless"}
    if k in _BINARY_KINDS:
        return {"ida_headless"}
    return set(KNOWN_TOOLS.keys())


async def _fetch_tool_specs(
    target_kind: str | None = None,
    primary_language: str | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Fetch JSON-Schema-derived tool specs from the MCP bridges.

    Returns ``{server_id: [spec, ...]}`` only for servers applicable
    to ``target_kind`` so we don't pay the catalog fetch for a server
    the agent isn't allowed to call. This helper itself does no
    caching; the bridges back each call with a class-level cache so
    the second invocation is a dict lookup, not an HTTP round-trip.

    When ``primary_language`` indicates a language with known
    static-call-graph blind spots (cpp, java, kotlin, csharp, swift,
    objc, scala — see ``LANGUAGE_UNRELIABLE_TOOLS``), the
    corresponding tools (e.g. ``dead_code``, ``unreachable_from_
    entrypoints``) are dropped from the returned spec list. They lie
    systematically on those languages — every virtual override,
    template instantiation, and callback registration looks "dead" in
    the trailmark graph even though the runtime calls them via
    vtable / monomorphization / dynamic dispatch.
    """
    from aila.modules.vr.agents.mcp_adapters.known_tools import (  # noqa: PLC0415
        tools_for_language,
    )

    applicable = _applicable_servers_for_kind(target_kind)
    out: dict[str, list[dict[str, Any]]] = {}
    if "audit_mcp" in applicable:
        specs = await AuditMcpBridgeTool().list_tool_specs()
        allowed = tools_for_language("audit_mcp", primary_language)
        out["audit_mcp"] = [s for s in specs if s.get("name", "") in allowed]
    if "ida_headless" in applicable:
        specs = await IDABridgeTool().list_tool_specs()
        allowed = tools_for_language("ida_headless", primary_language)
        out["ida_headless"] = [s for s in specs if s.get("name", "") in allowed]
    if "android_mcp" in applicable:
        specs = await AndroidMcpBridgeTool().list_tool_specs()
        allowed = tools_for_language("android_mcp", primary_language)
        out["android_mcp"] = [s for s in specs if s.get("name", "") in allowed]
    return out


def _format_param(param: dict[str, Any]) -> str:
    """Render one parameter as ``name: type [required]`` or
    ``name: type = <default>`` so the agent sees exact call shape.
    """
    name = param.get("name", "?")
    ptype = param.get("type", "any")
    if param.get("required"):
        return f"{name}: {ptype} [required]"
    if "default" in param:
        default = param["default"]
        # json.dumps handles strings/numbers/bools/null + escapes;
        # truncate over-long defaults so a paragraph-sized default
        # doesn't wreck the signature.
        rendered = json.dumps(default)
        if len(rendered) > 60:
            rendered = rendered[:57] + "..."
        return f"{name}: {ptype} = {rendered}"
    return f"{name}: {ptype}"


def _render_available_tools_section(
    target_kind: str | None = None,
    tool_specs: dict[str, list[dict[str, Any]]] | None = None,
    primary_language: str | None = None,
) -> str:
    """Render the catalog of MCP tools the engine may invoke this turn.

    When ``tool_specs`` carries per-server schemas (fetched live from
    each MCP server's ``GET /tools``), every applicable tool renders
    as ``server.name(p1: type [required], p2: type = default)`` so
    the agent sees the exact parameter names + types it must use.
    When schemas are missing (catalog fetch failed), falls back to a
    name-only listing from ``KNOWN_TOOLS`` so the prompt still works.

    Servers irrelevant to the target's kind are SUPPRESSED with a
    short note instead of listed — the agent kept choosing
    ida_headless.list_binaries for a source_repo target because the
    catalog showed every server unconditionally. Filtering at render
    time prevents the wrong tool family from ever being the obvious
    pick.
    """
    specialized = set(specialized_tools())
    applicable = _applicable_servers_for_kind(target_kind)
    specs_by_server = tool_specs or {}
    parts: list[str] = ["# Available tools\n"]
    if target_kind:
        parts.append(
            f"\nTarget kind: `{target_kind}` — only servers applicable "
            f"to this kind are listed below. Use the **exact** "
            f"parameter names shown in each signature; the bridge "
            f"rejects unknown kwargs.\n",
        )
    for server in sorted(KNOWN_TOOLS):
        if server not in applicable:
            # Silently skip — listing "NOT APPLICABLE: ida_headless"
            # for a source_repo target just gives the agent a hook to
            # think about IDA tools it shouldn't be considering at all.
            # Operator was rightly furious when source-repo prompts
            # surfaced ida_headless as a sibling section.
            continue

        live_specs = specs_by_server.get(server) or []
        if live_specs:
            parts.append(
                f"\n## {server} ({len(live_specs)} tools — live schema)\n\n",
            )
            for spec in sorted(live_specs, key=lambda s: s.get("name", "")):
                tool_name = spec.get("name", "?")
                full = f"{server}.{tool_name}"
                marker = " [structured]" if full in specialized else ""
                params = spec.get("params") or []
                signature = ", ".join(_format_param(p) for p in params)
                parts.append(f"- `{full}({signature})`{marker}\n")
            parts.append("\n")
        else:
            # Catalog fetch failed — fall back to a name-only listing
            # using the static KNOWN_TOOLS registry filtered by
            # primary_language (drops tools known-broken on this
            # target's language, e.g. dead_code on C++). Agent will
            # know which tools exist; it just won't see signatures.
            from aila.modules.vr.agents.mcp_adapters.known_tools import (  # noqa: PLC0415
                tools_for_language,
            )
            tool_names = sorted(tools_for_language(server, primary_language))
            parts.append(
                f"\n## {server} ({len(tool_names)} tools — "
                f"schema unavailable)\n\n",
            )
            for name in tool_names:
                full = f"{server}.{name}"
                marker = " [structured]" if full in specialized else ""
                parts.append(f"- `{full}`{marker}\n")
            parts.append("\n")
    return "".join(parts)



def _decode_case_state(raw_json: str | None) -> ReasoningCaseState:
    if not raw_json:
        return ReasoningCaseState()
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        return ReasoningCaseState()
    try:
        return ReasoningCaseState.model_validate(data)
    except (ValueError, TypeError):
        return ReasoningCaseState()


def _encode_case_state(state: ReasoningCaseState) -> str:
    return json.dumps(state.model_dump(mode="json"))


def _auto_resolve_live_on_terminal(
    state: ReasoningCaseState,
    *,
    turn: int,
    outcome_kind: str,
) -> None:
    """Move every still-live hypothesis to ``state.resolved`` in place.

    Called from ``run_turn`` immediately before the case_state is
    serialised for a terminal submission. A hypothesis sitting in
    ``state.hypotheses`` at submit time can be in three states the
    agent never explicitly labels:
      - CONFIRMED: agent relied on it as the basis of the finding
      - REJECTED: agent ran out of turns / refuted but forgot to move
      - SUPERSEDED: subsumed by a finer hypothesis but never killed

    Without auto-bucketing, these hypotheses stay "live" in the rail
    forever even though the investigation has concluded. The previous
    implementation moved them to ``state.rejected`` — but that's
    actively misleading for confirmed claims (e.g. the agent's
    'predicate symmetry holds' claim that grounds a 'VARIANT DEAD'
    finding shouldn't be labeled 'rejected' in red).

    New behavior: move to ``state.resolved`` with a neutral note that
    points the reader at the terminal outcome for the actual
    classification. The frontend renders ``resolved`` with a yellow
    badge — neither red (rejected) nor green (confirmed) — so readers
    know to consult the canonical outcome.
    """
    if not state.hypotheses:
        return
    note = (
        f"auto-resolved at turn {turn}: branch submitted terminal "
        f"{outcome_kind} — see canonical outcome for whether this "
        f"claim was confirmed (basis of finding) or refuted "
        f"(unaddressed alternative)"
    )
    seen_resolved = {r.id for r in state.resolved}
    seen_rejected = {r.id for r in state.rejected}
    for h in state.hypotheses:
        if h.id in seen_resolved or h.id in seen_rejected:
            continue
        state.resolved.append(
            ResolvedHypothesis(
                id=h.id,
                claim=h.claim,
                resolved_at_turn=turn,
                terminal_outcome_kind=outcome_kind,
                note=note,
            ),
        )
    state.hypotheses = []


def _decision_to_message_payload(
    decision: ReasoningTurnDecision,
) -> tuple[PayloadKind, dict[str, Any]]:
    """Map a ReasoningTurnDecision into a typed message payload.

    The mapping is intentionally narrow for v0.3 v1:
      - tool_run    → TOOL_CALL payload with command/script_content
      - submit      → OUTCOME_PENDING payload with answer + confidence
      - everything else → TEXT payload with reasoning + expected_observation
    Richer payload kinds (graph_view, taint_flow, etc.) land in M3.R-3
    when MCP adapters produce them.
    """
    if decision.action == "tool_run":
        return PayloadKind.TOOL_CALL, {
            "command": decision.command or "",
            "script_content": decision.script_content or "",
            "reasoning": decision.reasoning,
            "expected_observation": decision.expected_observation,
        }
    if decision.action == "submit":
        return PayloadKind.OUTCOME_PENDING, {
            "answer": decision.answer or "",
            "confidence": (
                decision.confidence if decision.confidence else "unknown"
            ),
            "reasoning": decision.reasoning,
            "provenance": decision.provenance.model_dump(mode="json"),
        }
    if decision.action == "submit_outcome_review":
        return PayloadKind.OUTCOME_REVIEW, {
            "outcome_id": decision.review_outcome_id or "",
            "vote": decision.review_vote or "abstain",
            "comment": (
                decision.review_comment
                or decision.reasoning
                or ""
            ),
            "suggested_edits": decision.payload or {},
            "reasoning": decision.reasoning,
        }
    return PayloadKind.TEXT, {
        "text": decision.reasoning,
        "expected_observation": decision.expected_observation,
    }


def _terminal_outcome_kind(decision: ReasoningTurnDecision) -> OutcomeKind:
    """Pick a terminal outcome kind from a submit decision.

    v0.3 v1 has a tiny dispatch: confidence >= strong + contract suggests
    DirectFinding -> DirectFinding; otherwise AssessmentReport. Real
    routing logic lands in M3.R-4 outcome_router.
    """
    if decision.confidence in {"strong", "exact"}:
        return OutcomeKind.DIRECT_FINDING
    return OutcomeKind.ASSESSMENT_REPORT


def _to_outcome_confidence(decision: ReasoningTurnDecision) -> OutcomeConfidence:
    if decision.confidence:
        return OutcomeConfidence(decision.confidence)
    return OutcomeConfidence.UNKNOWN


def _outcome_payload(decision: ReasoningTurnDecision) -> dict[str, Any]:
    """Build the outcome row payload from the decision.

    Merges the agent's structured ``decision.payload`` dict (which
    carries affected_components, variant_hunt_orders, crash_type,
    poc_code, etc. per the system_audit.md submission schema) with
    the top-level answer / reasoning / provenance / contract fields.

    The structured payload keys win on conflict so the agent's intent
    is preserved.
    """
    base: dict[str, Any] = {
        "answer": decision.answer or "",
        "reasoning": decision.reasoning,
        "provenance": decision.provenance.model_dump(mode="json"),
        "contract": (
            decision.contract.model_dump(mode="json") if decision.contract else None
        ),
    }
    # Promote everything the agent supplied under `payload` to the
    # top level so the dispatcher's payload.get('variant_hunt_orders')
    # etc. lookups resolve.
    structured = decision.payload or {}
    for k, v in structured.items():
        base[k] = v
    return base


_OUTCOME_KIND_RANK = {
    "direct_finding": 0,
    "patch_assessment_report": 1,
    "variant_hunt_order": 2,
    "assessment_report": 3,
    "audit_memo": 4,
}
_CONFIDENCE_RANK = {
    "exact": 0, "strong": 1, "medium": 2,
    "caveated": 3, "weak": 4, "unknown": 5,
}


async def _upsert_canonical_outcome(
    *,
    uow: Any,
    investigation_id: str,
    branch_id: str,
    persona_voice: str | None,
    new_outcome_kind: str,
    new_confidence: str,
    new_payload: dict[str, Any],
    at_turn: int,
) -> str:
    """Merge a branch's terminal submission into the single canonical
    outcome row, creating it on first submission.

    At most ONE canonical outcome row per investigation. Subsequent
    submissions (from any persona) merge in additively:
      - affected_components: union dedupe by (file, function)
      - variant_hunt_orders: union dedupe by title
      - poc_code: take new if existing is empty
      - outcome_kind: prefer more-specific via _OUTCOME_KIND_RANK
      - confidence: keep highest via _CONFIDENCE_RANK
      - answer: replace if new is ≥20% longer OR comes from a more-
        specific outcome_kind
      - panel_contributions: append every submission as
        {persona, branch_id, at_turn, submitted_at, outcome_kind,
         confidence, answer_brief} — full audit trail

    inv.primary_outcome_id always points at the canonical row.
    """
    # fix §168 — race-fix: serialize canonical-outcome writes per
    # investigation by taking a row lock on the parent investigation
    # row BEFORE the existence check. Concurrent terminal_submits
    # queue at this lock; the second arrival sees the row created by
    # the first and falls through to the merge path instead of
    # INSERTing a duplicate canonical. Chose SELECT FOR UPDATE over
    # an alembic UNIQUE-index + ON CONFLICT migration because no
    # schema change is required (vr_investigations row always exists
    # by FK) and the lock scope is exactly the per-investigation
    # critical section.
    await uow.session.exec(
        _select(VRInvestigationRecord)
        .where(VRInvestigationRecord.id == investigation_id)
        .with_for_update(),
    )
    existing = (await uow.session.exec(
        _select(VRInvestigationOutcomeRecord)
        .where(VRInvestigationOutcomeRecord.investigation_id == investigation_id)
        # fix §169 — read NEWEST canonical (was OLDEST). After §168 the
        # race that could create two canonicals is gone, but if any
        # legacy duplicate pair exists in older data, merging into the
        # newer row keeps fresh contributions visible to downstream
        # readers instead of stranding them on a row nothing else reads.
        .order_by(VRInvestigationOutcomeRecord.created_at.desc())
        .limit(1),
    )).first()

    persona = (persona_voice or "primary").lower()
    now = utc_now()
    contribution = {
        "persona": persona,
        "branch_id": branch_id,
        "at_turn": at_turn,
        "submitted_at": now.isoformat(),
        "outcome_kind": new_outcome_kind,
        "confidence": new_confidence,
        # fix §171 — keep the full answer text (was [:4000]). The
        # per-contribution snapshot is the load-bearing audit record
        # for per-persona analyses; truncating dropped the tail of
        # any answer >4000 chars, which was recoverable only if the
        # canonical payload['answer'] still carried the full text —
        # and §166 explicitly stops overwriting that field on merge,
        # so a per-persona answer truncated here used to be lost.
        "answer_brief": new_payload.get("answer") or "",
        # fix §175 — preserve per-persona evidence at contribution time.
        # Previously these fields were merged into the canonical payload
        # only (affected_components/variant_hunt_orders union-dedupe,
        # poc_code first-write-wins), so readers could no longer tell
        # which persona cited which file/component/variant/PoC. Storing
        # the per-persona view alongside the merged view preserves
        # attribution without affecting the merged readers.
        "evidence_refs": list(new_payload.get("evidence_refs") or []),
        "poc_code": new_payload.get("poc_code") or "",
        "poc_language": new_payload.get("poc_language") or "",
        "affected_components": list(new_payload.get("affected_components") or []),
        "variant_hunt_orders": list(new_payload.get("variant_hunt_orders") or []),
    }

    if existing is None:
        seed_payload = dict(new_payload)
        seed_payload["panel_contributions"] = [contribution]
        seed_payload["canonical"] = True
        row = VRInvestigationOutcomeRecord(
            investigation_id=investigation_id,
            branch_id=branch_id,
            outcome_kind=new_outcome_kind,
            confidence=new_confidence,
            payload_json=json.dumps(seed_payload),
            evidence_refs_json="[]",
        )
        uow.session.add(row)
        await uow.session.flush()
        inv = (await uow.session.exec(
            _select(VRInvestigationRecord).where(
                VRInvestigationRecord.id == investigation_id,
            )
        )).first()
        if inv is not None:
            inv.primary_outcome_id = row.id
            inv.updated_at = now
            uow.session.add(inv)
        return row.id

    try:
        old_payload = json.loads(existing.payload_json or "{}")
    except (ValueError, TypeError):
        old_payload = {}

    changed = False

    old_components = old_payload.get("affected_components") or []
    seen_components: set[tuple[str, str]] = {
        (c.get("file") or "", c.get("function") or "")
        for c in old_components if isinstance(c, dict)
    }
    for c in new_payload.get("affected_components") or []:
        if not isinstance(c, dict):
            continue
        key = (c.get("file") or "", c.get("function") or "")
        if key not in seen_components:
            seen_components.add(key)
            old_components.append(c)
            changed = True
    old_payload["affected_components"] = old_components

    old_orders = old_payload.get("variant_hunt_orders") or []
    seen_titles: set[str] = {
        (o.get("title") or "") for o in old_orders if isinstance(o, dict)
    }
    for o in new_payload.get("variant_hunt_orders") or []:
        if not isinstance(o, dict):
            continue
        title = (o.get("title") or "").strip()
        if title and title not in seen_titles:
            seen_titles.add(title)
            old_orders.append(o)
            changed = True
    old_payload["variant_hunt_orders"] = old_orders

    # fix §167 — capture every poc_code submission. Previously the new
    # poc was taken ONLY when the old slot was empty, so a second
    # branch's more complete or correct PoC was silently dropped (not
    # even in panel_contributions before §175). Each submission is now
    # appended to payload['poc_code_versions'] as a persona-attributed
    # entry. The legacy single payload['poc_code'] field is still
    # populated on first write for backward compatibility with readers
    # that haven't migrated to the list shape.
    if new_payload.get("poc_code"):
        poc_versions = old_payload.get("poc_code_versions") or []
        already_recorded = any(
            isinstance(v, dict)
            and v.get("branch_id") == branch_id
            and v.get("at_turn") == at_turn
            for v in poc_versions
        )
        if not already_recorded:
            poc_versions.append({
                "persona": persona,
                "branch_id": branch_id,
                "at_turn": at_turn,
                "submitted_at": now.isoformat(),
                "poc_code": new_payload["poc_code"],
                "poc_language": new_payload.get("poc_language", "text"),
            })
            old_payload["poc_code_versions"] = poc_versions
            changed = True
        if not old_payload.get("poc_code"):
            old_payload["poc_code"] = new_payload["poc_code"]
            old_payload["poc_language"] = new_payload.get("poc_language", "text")

    new_kind_rank = _OUTCOME_KIND_RANK.get(new_outcome_kind, 99)
    old_kind_rank = _OUTCOME_KIND_RANK.get(existing.outcome_kind, 99)
    if new_kind_rank < old_kind_rank:
        existing.outcome_kind = new_outcome_kind
        changed = True

    new_conf_rank = _CONFIDENCE_RANK.get(new_confidence, 9)
    old_conf_rank = _CONFIDENCE_RANK.get(existing.confidence, 9)
    if new_conf_rank < old_conf_rank:
        existing.confidence = new_confidence
        changed = True

    # fix §166 — stop overwriting payload['answer'] on merge. Every
    # submission's full answer goes into payload['merge_log'] as a
    # versioned, persona-attributed entry. The canonical
    # payload['answer'] is seeded on first submission and never
    # replaced thereafter, so the original answer survives forever
    # and the report/frontend has a stable text field to render.
    # Operator can read merge_log to see every persona's full answer
    # with provenance (and panel_contributions[i].answer_brief still
    # carries each per-persona text per §171).
    old_answer = old_payload.get("answer") or ""
    new_answer = new_payload.get("answer") or ""
    if new_answer and new_answer != old_answer:
        merge_log = old_payload.get("merge_log") or []
        merge_log.append({
            "persona": persona,
            "branch_id": branch_id,
            "at_turn": at_turn,
            "submitted_at": now.isoformat(),
            "outcome_kind": new_outcome_kind,
            "confidence": new_confidence,
            "answer": new_answer,
        })
        old_payload["merge_log"] = merge_log
        # Seed canonical answer if absent; never overwrite once set.
        if not old_answer:
            old_payload["answer"] = new_answer
        changed = True

    # fix §172 — dedupe panel_contributions by (branch_id, at_turn).
    # Re-enqueues of the same terminal_submit (operator re-runs an
    # investigation, worker retry, etc.) used to append a duplicate
    # entry every time, inflating len(panel_contributions) and
    # breaking quorum thresholds that read it (see
    # investigation_emit._maybe_trigger_synthesis line 712).
    contributions = old_payload.get("panel_contributions") or []
    contrib_key = (branch_id, at_turn)
    already_recorded = any(
        isinstance(c, dict)
        and (c.get("branch_id"), c.get("at_turn")) == contrib_key
        for c in contributions
    )
    if not already_recorded:
        contributions.append(contribution)
        old_payload["panel_contributions"] = contributions

    existing.payload_json = json.dumps(old_payload)
    uow.session.add(existing)

    inv = (await uow.session.exec(
        _select(VRInvestigationRecord).where(
            VRInvestigationRecord.id == investigation_id,
        )
    )).first()
    if inv is not None and inv.primary_outcome_id != existing.id:
        inv.primary_outcome_id = existing.id
        inv.updated_at = now
        uow.session.add(inv)

    _ = changed  # tracked for log later; same row id either way
    return existing.id


@functools.lru_cache(maxsize=16)
def _cached_read_prompt(path_str: str) -> str:
    """Read a prompt file from disk with content cached by path.

    Prompts are static files baked into the repo; reading the same
    48KB system_audit.md hundreds of times per investigation is pure
    overhead. ``maxsize=16`` comfortably covers base prompts +
    per-persona variants.
    """
    return Path(path_str).read_text(encoding="utf-8")


def _load_prompt(strategy_family: str, persona_voice: str | None = None) -> str:
    """Load the system prompt for a strategy family + optional persona.

    When ``persona_voice`` is supplied AND a per-persona prompt file
    exists at ``prompts/persona_<voice>.md``, that file's content is
    prepended to the base audit prompt as a role-specific opening
    section. The persona file should focus on ROLE BEHAVIOUR (what
    this voice's job is in the deliberation), not repeat the common
    audit rules — those come from the base prompt below.

    Falls through to base ``system_<strategy>.md`` (or
    ``system_audit.md``) when no persona is set or no persona file
    exists.
    """
    base_candidate = _PROMPT_DIR / f"system_{strategy_family.rsplit('.', 1)[-1]}.md"
    if not base_candidate.exists():
        base_candidate = _PROMPT_DIR / "system_audit.md"
    if not base_candidate.exists():
        raise VulnResearcherError(f"prompt file missing: {base_candidate}")
    base = _cached_read_prompt(str(base_candidate))

    if persona_voice:
        persona_candidate = _PROMPT_DIR / f"persona_{persona_voice.lower()}.md"
        if persona_candidate.exists():
            persona_prefix = _cached_read_prompt(str(persona_candidate))
            return f"{persona_prefix}\n\n---\n\n{base}"
    return base


# Resolves Pydantic forward refs when this module is imported standalone.
ReasoningContract.model_rebuild()
