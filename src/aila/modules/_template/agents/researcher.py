"""Template reasoning researcher -- thin subclass of AgentTurnRunnerBase.

The full per-turn engine (load state, build prompt, call LLM through the
idempotency cache, absorb decision, persist message + branch + outcome,
handle draft-review workflow, three pre-submit gates) lives on
:class:`aila.platform.agents.turn_runner.AgentTurnRunnerBase`. This
module supplies the template-specific residue every subclass has to
provide: class attributes, module-level staticmethods bound at import
time, and the small set of instance methods the runner calls on
``self`` (``_load`` / ``_build_user_prompt`` /
``_consume_pending_operator_messages`` / ``_load_prior_outcomes`` /
``_load_sibling_context``). Every gate defaults to allow -- the
scaffold shows the shape, not vr's domain-specific rejection logic.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlmodel import select as _select

from aila.modules._template._task_queue import default_task_queue
from aila.modules._template.agents.persona_router import resolve_task_type
from aila.modules._template.contracts.outcome import TemplateOutcomeKind
from aila.modules._template.db_models import (
    TemplateInvestigationBranchRecord,
    TemplateInvestigationMessageRecord,
    TemplateInvestigationOutcomeRecord,
    TemplateInvestigationRecord,
    TemplateTargetRecord,
)
from aila.modules._template.services.outcome_review import (
    OUTCOME_STATE_APPROVED,
    evaluate_quorum,
    upsert_review,
)
from aila.platform.agents.turn_runner import (
    AgentTurnResult,
    AgentTurnRunnerBase,
)
from aila.platform.contracts import utc_now
from aila.platform.contracts.enums import SenderKind
from aila.platform.contracts.mcp_payload import PayloadKind
from aila.platform.contracts.reasoning import (
    ReasoningCaseState,
    ReasoningContract,
    ReasoningPromptContext,
    ReasoningTurnDecision,
)
from aila.platform.prompts import LoadedPrompt, PromptNotFoundError, PromptRegistry
from aila.platform.services.context_assembler import ContextSection, ContextTier
from aila.platform.services.reasoning import CyberReasoningEngine
from aila.platform.uow import UnitOfWork

__all__ = [
    "TemplateResearcher",
    "TemplateResearcherError",
    "TemplateResearcherTurnResult",
]

_log = logging.getLogger(__name__)

_PROMPT_DIR = Path(__file__).parent / "prompts"


@dataclass
class TemplateResearcherTurnResult(AgentTurnResult):
    """Result of one template researcher turn. Same shape as the base."""


class TemplateResearcherError(Exception):
    """Fatal template researcher failure.

    ``retryable=True`` marks transient LLM / transport failures so the
    workflow finalizer can auto-re-enqueue instead of marking the
    investigation FAILED.
    """

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable


class TemplateResearcher(AgentTurnRunnerBase):
    """Template-scoped per-branch reasoning agent."""

    _LOG_LABEL = "template_researcher"
    _error_cls = TemplateResearcherError
    _result_cls = TemplateResearcherTurnResult
    _message_model = TemplateInvestigationMessageRecord
    _branch_model = TemplateInvestigationBranchRecord
    _OUTCOME_STATE_APPROVED = OUTCOME_STATE_APPROVED
    # RFC-24 step 3 -- scopes the RETRIEVED-tier populator to this
    # module's observation namespace when the flag is on.
    _MODULE_ID = "_template"

    def __init__(
        self,
        reasoning_engine: CyberReasoningEngine,
        investigation_id: str,
        branch_id: str,
        applicable_patterns: list[dict[str, Any]] | None = None,
        retrieved_knowledge: list[dict[str, Any]] | None = None,
    ) -> None:
        self._engine = reasoning_engine
        self.investigation_id = investigation_id
        self.branch_id = branch_id
        self._applicable_patterns = list(applicable_patterns or [])
        self._retrieved_knowledge = list(retrieved_knowledge or [])

    async def _dispatch_approved_outcome(self, outcome_id: str) -> None:
        """Enqueue the template outcome dispatcher task for an approved row."""
        # Deferred import: workflow.task imports back into this module
        # through the researcher factory, so a module-level import here
        # forms an import cycle at worker bootstrap.
        from aila.modules._template.workflow.task import (
            run_template_outcome_dispatch,
        )
        await default_task_queue().submit(
            track="template",
            fn=run_template_outcome_dispatch,
            kwargs={"outcome_id": outcome_id},
            user_id="system",
            group_id="template_dispatcher",
        )

    async def _load(
        self,
    ) -> tuple[
        TemplateInvestigationRecord,
        TemplateInvestigationBranchRecord,
        dict[str, Any],
    ]:
        """Load investigation + branch + a compact target snapshot.

        The snapshot is the minimal shape ``_build_user_prompt`` renders
        into the header + target section; a copier expands it with the
        module-specific fields the agent needs (descriptor, capability
        profile, MCP handles).
        """
        async with UnitOfWork() as uow:
            inv = (await uow.session.exec(
                _select(TemplateInvestigationRecord).where(
                    TemplateInvestigationRecord.id == self.investigation_id,
                ),
            )).first()
            if inv is None:
                raise TemplateResearcherError(
                    f"investigation {self.investigation_id} not found",
                )
            branch = (await uow.session.exec(
                _select(TemplateInvestigationBranchRecord).where(
                    TemplateInvestigationBranchRecord.id == self.branch_id,
                ),
            )).first()
            if branch is None:
                raise TemplateResearcherError(
                    f"branch {self.branch_id} not found",
                )
            if branch.investigation_id != self.investigation_id:
                raise TemplateResearcherError(
                    f"branch {self.branch_id} does not belong to "
                    f"investigation {self.investigation_id}",
                )
            target_snapshot: dict[str, Any] = {}
            if inv.target_id:
                target = (await uow.session.exec(
                    _select(TemplateTargetRecord).where(
                        TemplateTargetRecord.id == inv.target_id,
                    ),
                )).first()
                if target is not None:
                    target_snapshot = _snapshot_target(target)
            return inv, branch, target_snapshot

    async def _load_prior_outcomes(self) -> list[dict[str, Any]]:
        """Return the compact prior-outcome list the prompt renders.

        The runner uses this to surface prior submissions from earlier
        turns / re-enqueues so the agent extends past work instead of
        repeating it. Minimal shape: id, kind, confidence, answer.
        """
        async with UnitOfWork() as uow:
            rows = (await uow.session.exec(
                _select(TemplateInvestigationOutcomeRecord)
                .where(
                    TemplateInvestigationOutcomeRecord.investigation_id
                    == self.investigation_id,
                )
                .order_by(TemplateInvestigationOutcomeRecord.created_at.asc()),
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
                "answer": payload.get("answer") or "",
            })
        return out

    async def _load_sibling_context(self) -> list[dict[str, Any]]:
        """Return one entry per active sibling branch on this investigation.

        Minimal shape: branch_id, persona_voice, turn_count. Sufficient
        to prove the sibling-context slot is wired without dragging
        in vr's live-hypothesis / rejected / observable projections
        (which the template agent has no domain gate that consumes).
        """
        async with UnitOfWork() as uow:
            siblings = (await uow.session.exec(
                _select(TemplateInvestigationBranchRecord)
                .where(
                    TemplateInvestigationBranchRecord.investigation_id
                    == self.investigation_id,
                )
                .where(
                    TemplateInvestigationBranchRecord.id != self.branch_id,
                )
                .order_by(TemplateInvestigationBranchRecord.created_at.asc()),
            )).all()
        return [
            {
                "branch_id": s.id,
                "persona_voice": s.persona_voice or "(none)",
                "turn_count": int(s.turn_count),
            }
            for s in siblings
        ]

    async def _consume_pending_operator_messages(
        self,
        turn_number: int,
    ) -> list[dict[str, Any]]:
        """Load recent operator/system messages for this investigation.

        Newest-first, capped to 10. Stamps ``at_turn`` on first read so
        the UI's "delivered at turn N" badge is populated. A copier
        extends this with the vr shape (TTL, ACK dedup, per-branch
        addressed filtering) once the module has an operator UI that
        drives them.
        """
        cutoff = 10
        async with UnitOfWork() as uow:
            rows = (await uow.session.exec(
                _select(TemplateInvestigationMessageRecord)
                .where(
                    TemplateInvestigationMessageRecord.investigation_id
                    == self.investigation_id,
                    TemplateInvestigationMessageRecord.sender_kind.in_([
                        SenderKind.OPERATOR.value,
                        SenderKind.SYSTEM.value,
                    ]),
                )
                .order_by(TemplateInvestigationMessageRecord.created_at.desc())
                .limit(cutoff),
            )).all()
            if not rows:
                return []
            stamped = False
            out: list[dict[str, Any]] = []
            for row in rows:
                try:
                    payload = json.loads(row.payload_json or "{}")
                except json.JSONDecodeError:
                    payload = {}
                text = str(payload.get("text", "")).strip()
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

    def _build_user_prompt(
        self,
        *,
        inv: TemplateInvestigationRecord,
        branch: TemplateInvestigationBranchRecord,
        case_state: ReasoningCaseState,
        turn: int,
        pending_operator_messages: list[dict[str, Any]] | None = None,
        target_snapshot: dict[str, Any] | None = None,
        tool_specs: dict[str, list[dict[str, Any]]] | None = None,
        prior_outcomes: list[dict[str, Any]] | None = None,
        sibling_context: list[dict[str, Any]] | None = None,
        applicable_patterns: list[dict[str, Any]] | None = None,
    ) -> str:
        """Assemble a minimal user prompt for the reasoning engine.

        Uses ``engine.build_user_prompt`` with a plain
        ``ReasoningPromptContext``. Copiers switch to the tiered
        :class:`ContextSection` shape (see vr's ``_build_user_prompt``)
        once the branch case state grows past a comfortable size and
        needs budget-aware trimming.
        """
        parts: list[str] = []
        if pending_operator_messages:
            parts.append("# Operator messages")
            for m in pending_operator_messages:
                parts.append(f"- {m['text']}")
            parts.append("")
        parts.append(
            "# Investigation\n"
            f"Title: {inv.title}\n"
            f"Kind: {inv.kind}\n"
            f"Question: {inv.initial_question}\n"
            f"Turn: {turn}\n"
            f"Branch: {branch.id} (persona: {branch.persona_voice or 'none'})",
        )
        if target_snapshot:
            parts.append(
                "# Target\n"
                f"Kind: {target_snapshot.get('kind') or '(unknown)'}\n"
                f"Name: {target_snapshot.get('display_name') or '(unknown)'}\n"
                f"Primary language: "
                f"{target_snapshot.get('primary_language') or '(unknown)'}",
            )
        if applicable_patterns:
            parts.append(
                f"# Applicable patterns: {len(applicable_patterns)} entries",
            )
        if prior_outcomes:
            parts.append(
                f"# Prior submissions on this investigation: "
                f"{len(prior_outcomes)}",
            )
        if sibling_context:
            parts.append(
                f"# Sibling branches active: {len(sibling_context)}",
            )
        parts.append("# Current case state")
        parts.append(self._engine.render_case_model(case_state))
        if tool_specs:
            parts.append("# Available tools")
            for server, specs in sorted(tool_specs.items()):
                parts.append(f"## {server} ({len(specs)} tools)")
                for spec in specs:
                    parts.append(f"- {server}.{spec.get('name', '?')}")
        parts.append(
            "# Instruction\n"
            "Produce the next reasoning turn as a JSON object per the "
            "system prompt schema.",
        )
        body = "\n\n".join(parts)
        # Wrap the concatenated body in a single LIVE-tier section and
        # hand it to the engine's tiered assembler through
        # ``prebuilt_sections``. Callers extend this with the multi-tier
        # shape once they need PINNED/RECENT/RETRIEVED separation (see
        # vr's ``_build_user_prompt`` for the mature layout).
        sections = [
            ContextSection(
                tier=ContextTier.LIVE,
                label="template_prompt",
                body=body,
                droppable=False,
            ),
        ]
        context = ReasoningPromptContext(
            turn=turn,
            max_turns=turn,
            question=inv.initial_question,
            prebuilt_sections=sections,
            context_budget_tokens=self._engine.resolve_context_budget_tokens(),
        )
        return self._engine.build_user_prompt(context)


def _snapshot_target(target: Any) -> dict[str, Any]:
    """Minimal target-snapshot projection used by ``_build_user_prompt``.

    A copier expands this with the descriptor / capability_profile /
    mcp_handles / functions_of_interest projections the module needs.
    """
    return {
        "id": target.id,
        "kind": target.kind,
        "display_name": target.display_name,
        "primary_language": target.primary_language or "",
        "analysis_state": target.analysis_state,
    }


# --------------------------------------------------------------------- #
#  Module-level helpers bound as staticmethods on TemplateResearcher.   #
#  Mirrors the vr shape: helpers live below the class so the runner    #
#  resolves them off ``self`` via the staticmethod bindings at the     #
#  bottom of this file.                                                #
# --------------------------------------------------------------------- #


async def _fetch_tool_specs(
    target_kind: str | None = None,
    primary_language: str | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Return the per-server tool spec map the prompt renders.

    The template scaffold ships ZERO MCP bridges so the map is always
    empty. A copier adds one entry per applicable bridge here.
    """
    del target_kind, primary_language
    return {}


def _decision_to_message_payload(
    decision: ReasoningTurnDecision,
) -> tuple[PayloadKind, dict[str, Any]]:
    """Map a ``ReasoningTurnDecision`` into a typed message payload.

    Same shape as the vr binding: tool_run -> TOOL_CALL, submit ->
    OUTCOME_PENDING, submit_outcome_review -> OUTCOME_REVIEW, anything
    else -> TEXT.
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


def _terminal_outcome_kind(
    decision: ReasoningTurnDecision,
) -> TemplateOutcomeKind:
    """Pick a terminal outcome kind for a submit decision.

    Template ships one kind; copiers grow the mapping.
    """
    del decision
    return TemplateOutcomeKind.ASSESSMENT_REPORT


def _outcome_payload(decision: ReasoningTurnDecision) -> dict[str, Any]:
    """Build the outcome payload dict written to the outcome row."""
    base: dict[str, Any] = {
        "answer": decision.answer or "",
        "reasoning": decision.reasoning,
        "provenance": decision.provenance.model_dump(mode="json"),
        "contract": (
            decision.contract.model_dump(mode="json")
            if decision.contract else None
        ),
    }
    for k, v in (decision.payload or {}).items():
        base[k] = v
    return base


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
    """Merge the branch's terminal submission into the canonical row.

    Minimal single-row shape: create-if-absent, then append this
    branch's ``panel_contributions`` entry so multi-persona
    deliberation still shows every branch's contribution. Copiers
    extend with the vr-style union-dedupe of affected_components /
    variant_hunt_orders / poc_code once those fields land on the
    outcome payload.
    """
    if action != "terminal_submit":
        raise ValueError(
            f"_upsert_canonical_outcome accepts only "
            f"action='terminal_submit'; got action={action!r}",
        )
    # Row-lock the investigation to serialise concurrent submits so
    # the first arrival creates the canonical row and the second folds
    # into it -- mirrors the vr fix that eliminated duplicate
    # canonicals under simultaneous terminal_submits.
    await uow.session.exec(
        _select(TemplateInvestigationRecord)
        .where(TemplateInvestigationRecord.id == investigation_id)
        .with_for_update(),
    )
    existing = (await uow.session.exec(
        _select(TemplateInvestigationOutcomeRecord)
        .where(
            TemplateInvestigationOutcomeRecord.investigation_id
            == investigation_id,
        )
        .order_by(TemplateInvestigationOutcomeRecord.created_at.desc())
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
        "answer_brief": new_payload.get("answer") or "",
    }

    if existing is None:
        seed_payload = dict(new_payload)
        seed_payload["panel_contributions"] = [contribution]
        seed_payload["canonical"] = True
        row = TemplateInvestigationOutcomeRecord(
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
            _select(TemplateInvestigationRecord).where(
                TemplateInvestigationRecord.id == investigation_id,
            ),
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
    contributions = old_payload.get("panel_contributions") or []
    contrib_key = (branch_id, at_turn)
    already = any(
        isinstance(c, dict)
        and (c.get("branch_id"), c.get("at_turn")) == contrib_key
        for c in contributions
    )
    if not already:
        contributions.append(contribution)
        old_payload["panel_contributions"] = contributions
        existing.payload_json = json.dumps(old_payload)
        uow.session.add(existing)
    inv = (await uow.session.exec(
        _select(TemplateInvestigationRecord).where(
            TemplateInvestigationRecord.id == investigation_id,
        ),
    )).first()
    if inv is not None and inv.primary_outcome_id != existing.id:
        inv.primary_outcome_id = existing.id
        inv.updated_at = now
        uow.session.add(inv)
    return existing.id


_PROMPT_REGISTRY = PromptRegistry(_PROMPT_DIR, fallback_base="system_audit.md")


async def _load_prompt(
    strategy_family: str,
    persona_voice: str | None = None,
    *,
    investigation_id: str | None = None,
    model_family: str | None = None,
) -> LoadedPrompt:
    """Load the system prompt for a strategy + optional persona.

    Scaffold: file-only load (no RFC-09 version store binding yet).
    Copiers wire the platform ``PromptVersionStore`` +
    ``resolve_pinned_prompt`` here once the module has a live prompt
    lifecycle to manage (see vr's ``_load_prompt`` for the shape).
    """
    del investigation_id
    try:
        body = _PROMPT_REGISTRY.load(
            strategy_family, persona_voice, model_family=model_family,
        )
    except PromptNotFoundError as exc:
        raise TemplateResearcherError(str(exc)) from exc
    return LoadedPrompt(body=body, version=None)


# Resolves forward refs when this module is imported standalone.
ReasoningContract.model_rebuild()


# Bind the per-module module-level helpers as staticmethods so the
# shared AgentTurnRunnerBase.run_turn resolves them via ``self``. They
# are defined below the class, hence bound here at module import time.
TemplateResearcher._fetch_tool_specs = staticmethod(_fetch_tool_specs)
TemplateResearcher._load_prompt = staticmethod(_load_prompt)
TemplateResearcher._decision_to_message_payload = staticmethod(
    _decision_to_message_payload,
)
TemplateResearcher._terminal_outcome_kind = staticmethod(_terminal_outcome_kind)
TemplateResearcher._outcome_payload = staticmethod(_outcome_payload)
TemplateResearcher._upsert_canonical_outcome = staticmethod(
    _upsert_canonical_outcome,
)
TemplateResearcher._resolve_task_type = staticmethod(resolve_task_type)
TemplateResearcher._evaluate_quorum = staticmethod(evaluate_quorum)
TemplateResearcher._upsert_review = staticmethod(upsert_review)
