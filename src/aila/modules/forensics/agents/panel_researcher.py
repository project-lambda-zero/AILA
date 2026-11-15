"""Forensics panel researcher: one persona branch on the shared agent substrate.

:class:`ForensicsPanelResearcher` subclasses
:class:`aila.platform.agents.turn_runner.AgentTurnRunnerBase`, which owns the
turn: idempotent LLM call, decision absorb, message and branch persistence,
the canonical outcome on submit, and the sibling-review quorum on
``submit_outcome_review``. This module supplies the forensics residue:

* loading the investigation, its project, the evidence listing, the
  artefact snapshot, analyst steering, and this branch's recent analyzer
  results before each turn;
* the per-persona system prompt (:mod:`.panel_prompts`);
* the user prompt: the free-flow forensic layout from
  :meth:`CyberReasoningEngine.domain_prompt_sections` plus panel sections
  (role, operator messages, drafts awaiting this branch's vote, sibling
  state, prior outcomes, applicable patterns);
* the canonical-outcome upsert and the approved-outcome dispatch
  (:func:`aila.modules.forensics.services.panel_outcome.dispatch_panel_outcome`);
* the submit gates that make a branch vote on an open draft before it
  submits, and stop it re-voting.

Analyzer actions themselves run in the loop's action dispatcher
(:class:`aila.modules.forensics.agents.panel_actions.PanelActionDispatcher`),
which records each result as a branch message this researcher reads back.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from sqlmodel import select

from aila.modules.forensics.agents.panel_actions import PANEL_ACTION_SENDER_ID
from aila.modules.forensics.agents.panel_prompts import resolve_panel_prompt
from aila.modules.forensics.config_schema import FORENSICS_DEFAULTS, FORENSICS_HARD_TURN_CAP
from aila.modules.forensics.contracts.outcome import ForensicsOutcomeKind
from aila.modules.forensics.db_models import (
    ForensicsInvestigationBranchRecord,
    ForensicsInvestigationMessageRecord,
    ForensicsInvestigationOutcomeRecord,
    ForensicsInvestigationOutcomeReviewRecord,
    ForensicsProjectRecord,
    InvestigationRunRecord,
)
from aila.modules.forensics.services import analyzer_actions, cost_ceiling
from aila.modules.forensics.services.outcome_review import (
    OUTCOME_STATE_APPROVED,
    OUTCOME_STATE_DRAFT,
    OUTCOME_STATE_REJECTED,
    evaluate_quorum,
    summarize_outcome_for_review,
    upsert_review,
)
from aila.modules.forensics.services.panel_outcome import dispatch_panel_outcome
from aila.platform.agents.prompt_sections import outcome_payload
from aila.platform.agents.turn_helpers import decode_case_state
from aila.platform.agents.turn_runner import AgentTurnResult, AgentTurnRunnerBase
from aila.platform.config_base import ModuleConfigReader
from aila.platform.contracts import utc_now
from aila.platform.contracts.enums import SenderKind
from aila.platform.contracts.mcp_payload import PayloadKind
from aila.platform.contracts.reasoning import (
    ReasoningCaseState,
    ReasoningOperatorSteering,
    ReasoningPromptContext,
    ReasoningTurnDecision,
)
from aila.platform.exceptions import AILAError
from aila.platform.prompts import LoadedPrompt, PromptNotFoundError
from aila.platform.services.context_assembler import ContextSection, ContextTier
from aila.platform.services.reasoning import CyberReasoningEngine
from aila.platform.uow import UnitOfWork

__all__ = [
    "COST_CEILING_ERROR_PREFIX",
    "ForensicsPanelResearcher",
    "ForensicsPanelResearcherError",
    "ForensicsPanelTurnResult",
    "read_panel_max_turns",
]

_log = logging.getLogger(__name__)
_cfg = ModuleConfigReader("forensics")

# Prefix of the researcher error raised when the investigation's LLM spend
# reached ``forensics.freeflow_max_cost_usd``. The loop exits with
# ``researcher_error:<message>``; finalize reads the spend itself.
COST_CEILING_ERROR_PREFIX = "cost_ceiling_reached"

# How many of this branch's recent analyzer results the prompt renders.
_RECENT_RESULTS = 10
# Operator and system messages shown per turn, newest first.
_OPERATOR_MESSAGES = 10
# Applicable prior patterns shown per turn.
_PATTERN_LIMIT = 10
_SUPPORTED_ACTIONS = (
    "script_execute / tool_run / artifact_query / reasoning / submit / submit_outcome_review"
)


async def read_panel_max_turns() -> int:
    """Per-branch turn budget: ``forensics.max_turns_per_task`` clamped to the hard cap."""
    try:
        configured = await _cfg.get_int("max_turns_per_task")
    except (KeyError, ValueError, TypeError, OSError, RuntimeError, AILAError) as exc:
        _log.warning(
            "forensics.max_turns_per_task registry read failed (%s); using schema default", exc,
        )
        configured = FORENSICS_DEFAULTS.max_turns_per_task
    return min(max(configured, 1), FORENSICS_HARD_TURN_CAP)


@dataclass
class ForensicsPanelTurnResult(AgentTurnResult):
    """Result of one panel branch turn. Same shape as the base."""


class ForensicsPanelResearcherError(Exception):
    """Fatal panel turn failure; ``retryable`` marks transient LLM faults."""

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable


@dataclass(frozen=True)
class _TurnContext:
    """Everything the synchronous prompt builder needs, loaded per turn."""

    project_id: str
    analyzer_os: str
    evidence_dir: str
    evidence_listing: str
    project_kind: str
    artifacts_snapshot: str
    steering: ReasoningOperatorSteering
    recent_results: str


class ForensicsPanelResearcher(AgentTurnRunnerBase):
    """Per-branch forensic examiner on the panel (HALVAR, MADDIE, or RENZO)."""

    _LOG_LABEL = "forensics_panel_researcher"
    _error_cls = ForensicsPanelResearcherError
    _result_cls = ForensicsPanelTurnResult
    _message_model = ForensicsInvestigationMessageRecord
    _branch_model = ForensicsInvestigationBranchRecord
    _OUTCOME_STATE_APPROVED = OUTCOME_STATE_APPROVED
    _MODULE_ID = "forensics"

    def __init__(
        self,
        reasoning_engine: CyberReasoningEngine,
        investigation_id: str,
        branch_id: str,
        applicable_patterns: list[dict[str, Any]] | None = None,
        retrieved_knowledge: list[dict[str, Any]] | None = None,
    ) -> None:
        del retrieved_knowledge  # forensics binds no knowledge corpus
        self._engine = reasoning_engine
        self.investigation_id = investigation_id
        self.branch_id = branch_id
        self._applicable_patterns = list(applicable_patterns or [])
        self._turn_ctx: _TurnContext | None = None
        self._max_turns = FORENSICS_DEFAULTS.max_turns_per_task

    # ------------------------------------------------------------ loading

    async def _load(
        self,
    ) -> tuple[InvestigationRunRecord, ForensicsInvestigationBranchRecord, dict[str, Any]]:
        async with UnitOfWork() as uow:
            inv = (await uow.session.exec(
                select(InvestigationRunRecord).where(
                    InvestigationRunRecord.id == self.investigation_id,
                ),
            )).first()
            if inv is None:
                raise ForensicsPanelResearcherError(
                    f"investigation {self.investigation_id} not found",
                )
            branch = (await uow.session.exec(
                select(ForensicsInvestigationBranchRecord).where(
                    ForensicsInvestigationBranchRecord.id == self.branch_id,
                ),
            )).first()
            if branch is None or branch.investigation_id != self.investigation_id:
                raise ForensicsPanelResearcherError(
                    f"branch {self.branch_id} does not belong to investigation "
                    f"{self.investigation_id}",
                )
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(
                    ForensicsProjectRecord.id == inv.project_id,
                ),
            )).first()
            if project is None:
                raise ForensicsPanelResearcherError(
                    f"project {inv.project_id} of investigation {self.investigation_id} not found",
                )
            result_rows = (await uow.session.exec(
                select(ForensicsInvestigationMessageRecord)
                .where(
                    ForensicsInvestigationMessageRecord.branch_id == self.branch_id,
                    ForensicsInvestigationMessageRecord.sender_id == PANEL_ACTION_SENDER_ID,
                )
                .order_by(ForensicsInvestigationMessageRecord.created_at.desc())
                .limit(_RECENT_RESULTS),
            )).all()
        evidence_listing, evidence_dir, project_kind, _team_id = (
            await analyzer_actions.load_project_context(project_id=project.id)
        )
        self._turn_ctx = _TurnContext(
            project_id=project.id,
            analyzer_os=project.analyzer_os,
            evidence_dir=evidence_dir,
            evidence_listing=evidence_listing,
            project_kind=project_kind,
            artifacts_snapshot=await analyzer_actions.snapshot_artifacts(project_id=project.id),
            steering=await analyzer_actions.load_operator_steering(
                project_id=project.id, investigation_id=self.investigation_id,
            ),
            recent_results=analyzer_actions.render_previous(
                [_decode(row.payload_json) for row in reversed(result_rows)],
            ),
        )
        snapshot = {
            "kind": "forensics_project",
            "project_id": project.id,
            "project_kind": project_kind,
            "analyzer_os": project.analyzer_os,
        }
        return inv, branch, snapshot

    async def _load_turn_config(self) -> None:
        """Read the turn budget and stop the turn once the cost ceiling is reached."""
        self._max_turns = await read_panel_max_turns()
        cap = await cost_ceiling.read_cost_cap_usd()
        spent = await cost_ceiling.actual_cost_usd(self.investigation_id)
        if cost_ceiling.cost_ceiling_exceeded(spent, cap):
            raise ForensicsPanelResearcherError(
                f"{COST_CEILING_ERROR_PREFIX}: ${spent:.2f} of ${cap:.2f}",
            )

    async def _consume_pending_operator_messages(
        self, turn_number: int,
    ) -> list[dict[str, Any]]:
        """Newest operator and system messages on the investigation, stamped on first read."""
        async with UnitOfWork() as uow:
            rows = (await uow.session.exec(
                select(ForensicsInvestigationMessageRecord)
                .where(
                    ForensicsInvestigationMessageRecord.investigation_id == self.investigation_id,
                    ForensicsInvestigationMessageRecord.sender_kind.in_([
                        SenderKind.OPERATOR.value, SenderKind.SYSTEM.value,
                    ]),
                    ForensicsInvestigationMessageRecord.superseded_at.is_(None),
                )
                .order_by(ForensicsInvestigationMessageRecord.created_at.desc())
                .limit(_OPERATOR_MESSAGES),
            )).all()
            out: list[dict[str, Any]] = []
            stamped = False
            for row in rows:
                text = str(_decode(row.payload_json).get("text") or "").strip()
                if not text:
                    continue
                if row.at_turn is None:
                    row.at_turn = turn_number
                    uow.session.add(row)
                    stamped = True
                out.append({
                    "id": row.id,
                    "text": text,
                    "intent": row.operator_intent or "unclassified",
                    "sender_id": row.sender_id,
                    "delivered_at_turn": row.at_turn,
                })
            if stamped:
                await uow.commit()
        return out

    async def _load_prior_outcomes(self) -> list[dict[str, Any]]:
        """Every outcome on the investigation with its votes and this branch's vote."""
        async with UnitOfWork() as uow:
            outcomes = (await uow.session.exec(
                select(ForensicsInvestigationOutcomeRecord)
                .where(ForensicsInvestigationOutcomeRecord.investigation_id == self.investigation_id)
                .order_by(ForensicsInvestigationOutcomeRecord.created_at.asc()),
            )).all()
            reviews = (await uow.session.exec(
                select(ForensicsInvestigationOutcomeReviewRecord).where(
                    ForensicsInvestigationOutcomeReviewRecord.outcome_id.in_(
                        [o.id for o in outcomes],
                    ),
                ),
            )).all() if outcomes else []
        votes_by_outcome: dict[str, list[Any]] = {}
        for review in reviews:
            votes_by_outcome.setdefault(review.outcome_id, []).append(review)
        out: list[dict[str, Any]] = []
        for row in outcomes:
            row_votes = votes_by_outcome.get(row.id, [])
            mine = next((v.vote for v in row_votes if v.reviewer_branch_id == self.branch_id), None)
            out.append({
                "outcome_id": row.id,
                "proposer_branch_id": row.branch_id,
                "state": row.state,
                "confidence": row.confidence,
                "summary": summarize_outcome_for_review(row.payload_json),
                "votes": [
                    {
                        "persona": v.reviewer_persona or "?",
                        "vote": v.vote,
                        "comment": (v.comment or "")[:400],
                    }
                    for v in row_votes
                ],
                "my_vote": mine,
            })
        return out

    async def _load_sibling_context(self) -> list[dict[str, Any]]:
        """Each other branch's status, live hypotheses, and rejected hypotheses."""
        async with UnitOfWork() as uow:
            siblings = (await uow.session.exec(
                select(ForensicsInvestigationBranchRecord)
                .where(
                    ForensicsInvestigationBranchRecord.investigation_id == self.investigation_id,
                    ForensicsInvestigationBranchRecord.id != self.branch_id,
                )
                .order_by(ForensicsInvestigationBranchRecord.created_at.asc()),
            )).all()
        out: list[dict[str, Any]] = []
        for sibling in siblings:
            state = decode_case_state(sibling.case_state_json)
            out.append({
                "branch_id": sibling.id,
                "persona_voice": sibling.persona_voice or "(none)",
                "status": sibling.status,
                "turn_count": int(sibling.turn_count),
                "hypotheses": [h.model_dump(mode="json") for h in state.hypotheses],
                "rejected": [r.model_dump(mode="json") for r in state.rejected],
            })
        return out

    # ------------------------------------------------------------ prompts

    def _resolve_task_type(self, persona_voice: str | None) -> str:
        """Every persona runs on the forensics domain route, the one free-flow uses."""
        del persona_voice
        return self._engine.resolve_domain_profile("forensics").task_type

    async def _load_prompt(
        self,
        strategy_family: str,
        persona_voice: str | None = None,
        *,
        investigation_id: str | None = None,
        model_family: str | None = None,
    ) -> LoadedPrompt:
        del strategy_family  # the panel prompt is keyed by analyzer OS and persona
        if self._turn_ctx is None:
            raise ForensicsPanelResearcherError("panel prompt requested before the turn loaded")
        try:
            return await resolve_panel_prompt(
                self._turn_ctx.analyzer_os,
                persona_voice,
                investigation_id=investigation_id,
                model_family=model_family,
            )
        except PromptNotFoundError as exc:
            raise ForensicsPanelResearcherError(str(exc)) from exc

    async def _fetch_tool_specs(
        self, *, target_kind: str | None = None, primary_language: str | None = None,
    ) -> dict[str, list[dict[str, Any]]]:
        """No MCP servers: the analyzer actions are specified in the system prompt."""
        del target_kind, primary_language
        return {}

    def _build_user_prompt(
        self,
        *,
        inv: InvestigationRunRecord,
        branch: ForensicsInvestigationBranchRecord,
        case_state: ReasoningCaseState,
        turn: int,
        pending_operator_messages: list[dict[str, Any]] | None = None,
        target_snapshot: dict[str, Any] | None = None,
        tool_specs: dict[str, list[dict[str, Any]]] | None = None,
        prior_outcomes: list[dict[str, Any]] | None = None,
        sibling_context: list[dict[str, Any]] | None = None,
        applicable_patterns: list[dict[str, Any]] | None = None,
    ) -> str:
        del target_snapshot, tool_specs
        ctx = self._turn_ctx
        if ctx is None:
            raise ForensicsPanelResearcherError("user prompt requested before the turn loaded")
        domain_profile = self._engine.resolve_domain_profile("forensics")
        strategy_family = self._engine.select_strategy_family(
            question=inv.question,
            case_state=case_state,
            evidence_listing=ctx.evidence_listing,
            project_kind=ctx.project_kind,
            steering=ctx.steering,
        )
        base_context = ReasoningPromptContext(
            turn=turn,
            max_turns=self._max_turns,
            question=inv.question,
            evidence_dir=ctx.evidence_dir,
            evidence_listing=ctx.evidence_listing,
            project_kind=ctx.project_kind,
            case_model=self._engine.render_case_model(case_state),
            artifacts=ctx.artifacts_snapshot,
            previous=ctx.recent_results,
            domain_profile=domain_profile.domain_id,
            operator_steering=ctx.steering,
            strategy_family=strategy_family,
        )
        sections = self._engine.domain_prompt_sections(base_context)
        panel_sections = _panel_sections(
            branch=branch,
            pending_operator_messages=pending_operator_messages or [],
            prior_outcomes=prior_outcomes or [],
            sibling_context=sibling_context or [],
            applicable_patterns=applicable_patterns or [],
        )
        # The domain layout ends with the pinned response-contract line; the
        # panel sections go in front of it.
        sections[-1:-1] = panel_sections
        return self._engine.build_user_prompt(ReasoningPromptContext(
            turn=turn,
            max_turns=self._max_turns,
            question=inv.question,
            prebuilt_sections=sections,
            context_budget_tokens=self._engine.resolve_context_budget_tokens(),
        ))

    # ------------------------------------------------------------ gates

    def _maybe_reject_unsupported_action(
        self, *, decision: Any, case_state: Any, turn_number: int,
    ) -> Any:
        """``recall`` and ``edit_outcome`` have no panel handler; turn them into reasoning."""
        del turn_number
        if decision.action not in ("recall", "edit_outcome"):
            return decision
        case_state.observables["_directive.unsupported_action_rejected"] = (
            f"[UNSUPPORTED ACTION: {decision.action}]\n"
            f"{decision.action} is not available on the forensics panel. Nothing "
            "was recalled or edited.\n\n"
            f"Valid actions: {_SUPPORTED_ACTIONS}."
        )
        return decision.model_copy(update={"action": "reasoning"})

    async def _maybe_reject_submit_when_draft_pending(
        self, *, decision: Any, case_state: Any, turn_number: int,
    ) -> Any:
        """Require draft votes first and allow only one proposal per examiner.

        A rejected draft may be followed by a different examiner's proposal.
        Reopening that proposer would otherwise let draft/reject cycles burn
        the cost ceiling without converging, so an examiner whose earlier
        proposal was rejected reviews later drafts instead of proposing again.
        """
        async with UnitOfWork() as uow:
            drafts = (await uow.session.exec(
                select(ForensicsInvestigationOutcomeRecord).where(
                    ForensicsInvestigationOutcomeRecord.investigation_id == self.investigation_id,
                    ForensicsInvestigationOutcomeRecord.state == OUTCOME_STATE_DRAFT,
                    ForensicsInvestigationOutcomeRecord.branch_id != self.branch_id,
                ),
            )).all()
            voted = set((await uow.session.exec(
                select(ForensicsInvestigationOutcomeReviewRecord.outcome_id).where(
                    ForensicsInvestigationOutcomeReviewRecord.reviewer_branch_id == self.branch_id,
                    ForensicsInvestigationOutcomeReviewRecord.outcome_id.in_([d.id for d in drafts]),
                ),
            )).all()) if drafts else set()
            latest = (await uow.session.exec(
                select(ForensicsInvestigationOutcomeRecord)
                .where(ForensicsInvestigationOutcomeRecord.investigation_id == self.investigation_id)
                .order_by(ForensicsInvestigationOutcomeRecord.created_at.desc())
                .limit(1),
            )).first()
            prior_proposal = None
            if latest is not None and latest.state == OUTCOME_STATE_REJECTED:
                prior_proposal = (await uow.session.exec(
                    select(ForensicsInvestigationOutcomeRecord.id).where(
                        ForensicsInvestigationOutcomeRecord.investigation_id == self.investigation_id,
                        ForensicsInvestigationOutcomeRecord.branch_id == self.branch_id,
                    ).limit(1),
                )).first()
        pending = [d for d in drafts if d.id not in voted]
        if pending:
            _log.info(
                "%s submit blocked inv=%s branch=%s turn=%d unvoted_drafts=%d",
                self._LOG_LABEL, self.investigation_id, self.branch_id, turn_number, len(pending),
            )
            lines = [
                "*** SUBMIT BLOCKED: A DRAFT ANSWER IS WAITING FOR YOUR VOTE ***",
                "",
                "Vote on each draft below with submit_outcome_review before you submit",
                "an answer of your own. Your answer was not recorded.",
                "",
            ]
            for draft in pending:
                lines.append(f"- outcome_id={draft.id} confidence={draft.confidence}")
                lines.extend(
                    f"    {line}" for line in summarize_outcome_for_review(draft.payload_json).splitlines()
                )
            case_state.observables["_directive.draft_pending_submit_blocked"] = "\n".join(lines)
            return decision.model_copy(update={"action": "reasoning"})
        if prior_proposal is not None:
            _log.info(
                "%s repeat proposal blocked inv=%s branch=%s turn=%d",
                self._LOG_LABEL, self.investigation_id, self.branch_id, turn_number,
            )
            case_state.observables["_directive.repeat_proposal_blocked"] = (
                "Your earlier answer was reviewed and rejected. Each examiner may "
                "propose once per panel. Review the latest draft with "
                "submit_outcome_review, or continue examining evidence with "
                "reasoning and analyzer actions. Your repeat proposal was not recorded."
            )
            return decision.model_copy(update={"action": "reasoning"})
        return decision

    async def _maybe_reject_revote_when_already_voted(
        self, *, decision: Any, case_state: Any, turn_number: int,
    ) -> Any:
        """Turn a second vote on the same outcome into reasoning with a directive."""
        async with UnitOfWork() as uow:
            existing = (await uow.session.exec(
                select(ForensicsInvestigationOutcomeReviewRecord).where(
                    ForensicsInvestigationOutcomeReviewRecord.outcome_id == decision.review_outcome_id,
                    ForensicsInvestigationOutcomeReviewRecord.reviewer_branch_id == self.branch_id,
                ),
            )).first()
        if existing is None:
            return decision
        _log.info(
            "%s re-vote blocked inv=%s branch=%s turn=%d outcome=%s",
            self._LOG_LABEL, self.investigation_id, self.branch_id, turn_number,
            decision.review_outcome_id,
        )
        case_state.observables["_directive.already_voted_stop_reviewing"] = (
            f"You already voted '{existing.vote}' on outcome {decision.review_outcome_id}. "
            "A second vote changes nothing. Continue examining the evidence, or submit "
            "your own answer if you hold independent evidence for it."
        )
        return decision.model_copy(update={"action": "reasoning"})

    # ------------------------------------------------------------ outcome

    async def _dispatch_approved_outcome(self, outcome_id: str) -> None:
        await dispatch_panel_outcome(outcome_id)


def _decode(raw: str | None) -> dict[str, Any]:
    value = json.loads(raw or "{}")
    return value if isinstance(value, dict) else {}


def _panel_sections(
    *,
    branch: ForensicsInvestigationBranchRecord,
    pending_operator_messages: list[dict[str, Any]],
    prior_outcomes: list[dict[str, Any]],
    sibling_context: list[dict[str, Any]],
    applicable_patterns: list[dict[str, Any]],
) -> list[ContextSection]:
    persona = (branch.persona_voice or "primary").upper()
    sections = [
        ContextSection(
            tier=ContextTier.PINNED,
            label="panel_role",
            body=(
                f"You are {persona} on the forensics panel (branch {branch.id[:8]}, "
                f"turn {branch.turn_count + 1})."
            ),
            droppable=False,
        ),
    ]
    if pending_operator_messages:
        sections.append(ContextSection(
            tier=ContextTier.PINNED,
            label="operator_messages",
            body="Operator messages:\n" + "\n".join(f"- {m['text']}" for m in pending_operator_messages),
            droppable=False,
        ))
    awaiting = [
        o for o in prior_outcomes
        if o["state"] == OUTCOME_STATE_DRAFT
        and o["proposer_branch_id"] != branch.id
        and o["my_vote"] is None
    ]
    if awaiting:
        lines = ["Draft answers awaiting your vote (use submit_outcome_review):"]
        for o in awaiting:
            lines.append(f"- outcome_id={o['outcome_id']} confidence={o['confidence']}")
            lines.extend(f"    {line}" for line in str(o["summary"]).splitlines())
        sections.append(ContextSection(
            tier=ContextTier.PINNED,
            label="draft_reviews",
            body="\n".join(lines),
            droppable=False,
        ))
    if sibling_context:
        lines = ["Panel siblings:"]
        for s in sibling_context:
            lines.append(
                f"- {str(s['persona_voice']).upper()} (branch {str(s['branch_id'])[:8]}, "
                f"{s['status']}, {s['turn_count']} turns)",
            )
            for h in s["hypotheses"]:
                lines.append(f"    live {h.get('id')}: {h.get('claim')}")
            for r in s["rejected"]:
                lines.append(f"    rejected {r.get('id')}: {r.get('claim')} -- {r.get('reason')}")
        sections.append(ContextSection(
            tier=ContextTier.LIVE,
            label="panel_siblings",
            body="\n".join(lines),
            summary=f"Panel siblings: {len(sibling_context)} (detail elided for budget)",
        ))
    if prior_outcomes:
        lines = ["Panel outcomes so far:"]
        for o in prior_outcomes:
            votes = ", ".join(f"{v['persona']}={v['vote']}" for v in o["votes"]) or "no votes"
            lines.append(
                f"- outcome_id={o['outcome_id']} state={o['state']} "
                f"confidence={o['confidence']} votes: {votes}",
            )
            if o["state"] == OUTCOME_STATE_REJECTED:
                for v in o["votes"]:
                    if v["vote"] == "reject":
                        lines.append(f"    reject reason ({v['persona']}): {v['comment']}")
        sections.append(ContextSection(
            tier=ContextTier.RECENT,
            label="panel_outcomes",
            body="\n".join(lines),
            summary=f"Panel outcomes: {len(prior_outcomes)} (detail elided for budget)",
        ))
    patterns = [p for p in applicable_patterns if isinstance(p, dict)][:_PATTERN_LIMIT]
    if patterns:
        sections.append(ContextSection(
            tier=ContextTier.RECENT,
            label="applicable_patterns",
            body="Applicable prior patterns:\n" + "\n".join(
                f"- [{p.get('kind') or 'unspecified'}] {p.get('summary') or '(no summary)'}"
                for p in patterns
            ),
            summary=f"Applicable prior patterns: {len(patterns)} (elided for budget)",
        ))
    return sections


# --------------------------------------------------------------------- #
#  Module-level helpers bound as staticmethods, the same shape the other #
#  AgentTurnRunnerBase subclasses use.                                   #
# --------------------------------------------------------------------- #


def _decision_to_message_payload(
    decision: ReasoningTurnDecision,
) -> tuple[PayloadKind, dict[str, Any]]:
    if decision.action in ("tool_run", "script_execute", "artifact_query"):
        return PayloadKind.TOOL_CALL, {
            "action": decision.action,
            "command": decision.command or "",
            "script_content": decision.script_content or "",
            "reasoning": decision.reasoning,
            "expected_observation": decision.expected_observation,
        }
    if decision.action == "submit":
        return PayloadKind.OUTCOME_PENDING, {
            "answer": decision.answer or "",
            "confidence": decision.confidence or "unknown",
            "reasoning": decision.reasoning,
            "provenance": decision.provenance.model_dump(mode="json"),
        }
    if decision.action == "submit_outcome_review":
        return PayloadKind.OUTCOME_REVIEW, {
            "outcome_id": decision.review_outcome_id or "",
            "vote": decision.review_vote or "abstain",
            "comment": decision.review_comment or decision.reasoning or "",
            "suggested_edits": decision.payload or {},
            "reasoning": decision.reasoning,
        }
    return PayloadKind.TEXT, {
        "text": decision.reasoning,
        "expected_observation": decision.expected_observation,
    }


def _terminal_outcome_kind(decision: ReasoningTurnDecision) -> ForensicsOutcomeKind:
    del decision
    return ForensicsOutcomeKind.FORENSIC_ANSWER


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
    action: str,
) -> str:
    """Fold a branch's submit into the panel's canonical outcome.

    The newest outcome is canonical. A draft, approved, or dispatched one
    absorbs the submit as a ``panel_contributions`` entry; the proposer's
    answer stands. With no outcome yet, or when the newest one was rejected,
    the submit opens a new draft that siblings review.
    """
    if action != "terminal_submit":
        raise ValueError(f"_upsert_canonical_outcome accepts only action='terminal_submit'; got {action!r}")
    # Lock the investigation row so simultaneous submits serialize: the
    # first creates the canonical draft, the second folds into it.
    await uow.session.exec(
        select(InvestigationRunRecord)
        .where(InvestigationRunRecord.id == investigation_id)
        .with_for_update(),
    )
    latest = (await uow.session.exec(
        select(ForensicsInvestigationOutcomeRecord)
        .where(ForensicsInvestigationOutcomeRecord.investigation_id == investigation_id)
        .order_by(ForensicsInvestigationOutcomeRecord.created_at.desc())
        .limit(1),
    )).first()
    contribution = {
        "persona": (persona_voice or "primary").lower(),
        "branch_id": branch_id,
        "at_turn": at_turn,
        "submitted_at": utc_now().isoformat(),
        "outcome_kind": new_outcome_kind,
        "confidence": new_confidence,
        "answer_brief": str(new_payload.get("answer") or "")[:400],
    }
    if latest is None or latest.state == OUTCOME_STATE_REJECTED:
        payload = dict(new_payload)
        payload["panel_contributions"] = [contribution]
        row = ForensicsInvestigationOutcomeRecord(
            investigation_id=investigation_id,
            branch_id=branch_id,
            outcome_kind=new_outcome_kind,
            confidence=new_confidence,
            payload_json=json.dumps(payload, default=str),
            evidence_refs_json="[]",
        )
        uow.session.add(row)
        await uow.session.flush()
        return row.id
    payload = _decode(latest.payload_json)
    contributions = payload.get("panel_contributions")
    if not isinstance(contributions, list):
        contributions = []
    if not any(
        isinstance(c, dict) and (c.get("branch_id"), c.get("at_turn")) == (branch_id, at_turn)
        for c in contributions
    ):
        contributions.append(contribution)
        payload["panel_contributions"] = contributions
        latest.payload_json = json.dumps(payload, default=str)
        uow.session.add(latest)
    return latest.id


ForensicsPanelResearcher._decision_to_message_payload = staticmethod(_decision_to_message_payload)
ForensicsPanelResearcher._terminal_outcome_kind = staticmethod(_terminal_outcome_kind)
ForensicsPanelResearcher._outcome_payload = staticmethod(outcome_payload)
ForensicsPanelResearcher._upsert_canonical_outcome = staticmethod(_upsert_canonical_outcome)
ForensicsPanelResearcher._evaluate_quorum = staticmethod(evaluate_quorum)
ForensicsPanelResearcher._upsert_review = staticmethod(upsert_review)
