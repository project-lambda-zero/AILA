"""SynthesisAgent -- consolidates persona-panel outcomes into one verdict.

Triggered by ``investigation_emit._maybe_trigger_synthesis`` once every
persona branch in the multi-deliberation panel has produced a terminal
outcome. Reads every branch's last terminal outcome (researcher /
critic / implementer), feeds them to an LLM that synthesises a single
final answer with explicit agreement/disagreement structure, and
writes the synthesis as a new outcome on the primary branch -- then
sets ``inv.primary_outcome_id`` so the investigation surfaces one
authoritative verdict in the UI + report.

Idempotency: exits with ``{"status": "skipped", "reason": ...}`` when
``inv.primary_outcome_id`` is already a synthesis-kind outcome.
"""
from __future__ import annotations

import json
import logging
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field
from sqlmodel import select as _select

from aila.modules.vr.contracts import (
    OutcomeConfidence,
)
from aila.modules.vr.contracts.investigation import InvestigationStatus
from aila.modules.vr.db_models import (
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
)
from aila.platform.contracts._common import utc_now
from aila.platform.llm.errors import BudgetExceededError, LLMError
from aila.platform.llm.sanitize import sanitize_input
from aila.platform.services.factory import ServiceFactory
from aila.platform.uow import UnitOfWork

__all__ = ["SynthesisAgent", "SynthesisResponse"]

_log = logging.getLogger(__name__)

# Investigation statuses that mean "still alive -- synthesis may write".
# Anything outside this set (PAUSED / COMPLETED / FAILED / ABANDONED) means
# the operator or another agent closed the investigation while the LLM
# call was in flight; UoW 2 aborts in that case (fix §160).
_ALIVE_STATUSES: frozenset[str] = frozenset({
    InvestigationStatus.CREATED.value,
    InvestigationStatus.RUNNING.value,
})


class SynthesisResponse(BaseModel):
    """Structured output schema for the persona-deliberation synthesiser.

    Enforced by :meth:`AilaLLMClient.chat_structured` (fix §159) so the
    synthesiser never receives free-text markdown that the renderer
    cannot validate. Each field renders into one labelled section of the
    final markdown narrative via :meth:`to_markdown`.
    """

    model_config = ConfigDict(extra="forbid")

    headline_verdict: str = Field(
        min_length=1,
        max_length=600,
        description=(
            "One sentence: did the panel find a bug, find a patch in "
            "place, or fail to establish either."
        ),
    )
    points_of_agreement: list[str] = Field(
        default_factory=list,
        max_length=20,
        description="What every persona converged on, with source citations.",
    )
    points_of_disagreement: list[str] = Field(
        default_factory=list,
        max_length=20,
        description=(
            "Where personas reached different conclusions; name each "
            "side and which has stronger evidence."
        ),
    )
    unresolved_questions: list[str] = Field(
        default_factory=list,
        max_length=20,
        description="What the panel could not settle.",
    )
    recommended_next_actions: list[str] = Field(
        default_factory=list,
        max_length=20,
        description="Variant hunts to spawn, refs to audit, operator questions.",
    )

    def to_markdown(self) -> str:
        """Render the structured response back into the markdown shape
        consumers (PDF renderer, UI) already know how to display.
        """
        def _bulleted(items: list[str]) -> str:
            if not items:
                return "_(none)_"
            return "\n".join(f"- {item}" for item in items)

        return (
            f"**Headline verdict.** {self.headline_verdict.strip()}\n\n"
            f"### Points of agreement\n{_bulleted(self.points_of_agreement)}\n\n"
            f"### Points of disagreement\n"
            f"{_bulleted(self.points_of_disagreement)}\n\n"
            f"### Unresolved questions\n{_bulleted(self.unresolved_questions)}\n\n"
            f"### Recommended next actions\n"
            f"{_bulleted(self.recommended_next_actions)}\n"
        )


class SynthesisAgent:
    """LLM-backed consolidator for the persona deliberation panel."""

    _TASK_TYPE = "vulnerability_research.synthesizer"

    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id

    async def run(self) -> dict[str, Any]:
        """Consolidate panel persona submissions into a synthesis verdict.

        D-101 architecture: ONE canonical outcome row per investigation
        holds every persona's submission inside ``payload.panel_contributions``.
        Synthesis reads that array (NOT per-branch outcome rows -- there
        is only one row), produces a consolidated narrative via LLM,
        writes ``panel_summary`` into the canonical row's payload, and
        flips ``inv.status`` to COMPLETED + ``stopped_at``.

        Idempotency: skips if the canonical row's payload already has
        ``panel_summary`` (real synthesis output marker).
        """
        async with UnitOfWork() as uow:
            inv = (await uow.session.exec(
                _select(VRInvestigationRecord).where(
                    VRInvestigationRecord.id == self.investigation_id,
                )
            )).first()
            if inv is None:
                return {"status": "skipped", "reason": "investigation_not_found"}

            canonical = (await uow.session.exec(
                _select(VRInvestigationOutcomeRecord)
                .where(VRInvestigationOutcomeRecord.investigation_id == self.investigation_id)
                .order_by(VRInvestigationOutcomeRecord.created_at.asc())
                .limit(1)
            )).first()
            if canonical is None:
                return {"status": "skipped", "reason": "no_canonical_outcome"}

            try:
                canonical_payload = json.loads(canonical.payload_json or "{}")
            except (ValueError, TypeError):
                canonical_payload = {}
            if "panel_summary" in canonical_payload:
                return {
                    "status": "skipped",
                    "reason": "already_synthesized",
                    "canonical_outcome_id": canonical.id,
                }

            contributions = canonical_payload.get("panel_contributions") or []
            if not contributions:
                return {"status": "skipped", "reason": "no_panel_contributions"}

            # Build the per-persona panel from contributions. answer_brief
            # carries up to 4000 chars of each persona's submission --
            # enough for the synthesiser without extra DB round-trips.
            panel: list[dict[str, Any]] = []
            for c in contributions:
                if not isinstance(c, dict):
                    continue
                panel.append({
                    "branch_id": c.get("branch_id") or "",
                    "persona_voice": c.get("persona") or "(none)",
                    "turn_count": c.get("at_turn") or 0,
                    "outcome_kind": c.get("outcome_kind") or "",
                    "confidence": c.get("confidence") or "unknown",
                    "answer": c.get("answer_brief") or "",
                    "reasoning": "",
                    "affected_components": canonical_payload.get("affected_components") or [],
                    "variant_hunt_orders": canonical_payload.get("variant_hunt_orders") or [],
                })
            if not panel:
                return {"status": "skipped", "reason": "no_valid_contributions"}

        # fix §159 -- switch to chat_structured so the response is
        # schema-validated; the renderer never has to parse free-text
        # markdown that might drift.
        # fix §158 -- broaden the narrow ``except RuntimeError`` so
        # systemic LLM failures (TimeoutError, httpx errors, validation
        # failures, etc.) are visible instead of crashing the worker.
        # BudgetExceededError is reraised so the caller sees the budget
        # halt for what it is (NOT an LLM failure).
        services = ServiceFactory()
        try:
            response = await services.llm_client.chat_structured(
                task_type=self._TASK_TYPE,
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": _render_panel(panel)},
                ],
                model_class=SynthesisResponse,
            )
        except BudgetExceededError:
            raise
        except (httpx.HTTPError, LLMError, OSError, RuntimeError, ValueError, TypeError) as exc:
            # Catch systemic LLM failure shapes (TimeoutError is a subclass
            # of OSError; httpx transport errors, LLM client errors, JSON
            # decode errors via ValueError, schema validation failures).
            # fix §350 -- traceback now reaches operator log so transient
            # LLM transport failures vs. permanent schema/auth failures
            # are distinguishable from the warning alone.
            _log.warning(
                "synthesis LLM call failed for inv=%s err=%s",
                self.investigation_id, exc,
                exc_info=True,
            )
            return {"status": "failed", "reason": f"llm_error:{type(exc).__name__}"}
        if response.disabled:
            return {"status": "skipped", "reason": "llm_kill_switch_active"}
        # chat_structured guarantees ``response.content`` is JSON matching
        # the schema. LLMResponse does NOT carry a ``.parsed`` field, so
        # validate explicitly here.
        try:
            parsed = SynthesisResponse.model_validate_json(response.content)
        except ValueError as exc:
            _log.warning(
                "synthesis chat_structured content failed schema validation "
                "inv=%s err=%s",
                self.investigation_id, exc,
            )
            return {"status": "failed", "reason": "structured_parse_failed"}
        synthesis_text = parsed.to_markdown().strip()
        if not synthesis_text:
            return {"status": "failed", "reason": "empty_llm_response"}

        # Update the canonical row's payload in-place. Don't create a
        # new outcome row -- D-101 mandates exactly one canonical row per
        # investigation.
        async with UnitOfWork() as uow:
            # fix §160 -- SELECT FOR UPDATE on the investigation row so
            # we hold a row-lock for the full UoW; if the operator
            # paused the investigation between UoW 1 and UoW 2, the
            # status re-check below sees the PAUSED state and aborts.
            # Without the lock, two synthesis triggers could fire in
            # parallel (or pause+synthesis could interleave) and the
            # later writer would clobber the operator's pause.
            inv_row = (await uow.session.exec(
                _select(VRInvestigationRecord)
                .where(VRInvestigationRecord.id == self.investigation_id)
                .with_for_update()
            )).first()
            if inv_row is None:
                return {"status": "skipped", "reason": "investigation_disappeared"}
            # fix §160 -- re-check status under lock. If the operator
            # paused (or another path closed) the investigation while
            # the LLM call was in flight, abort cleanly without
            # overwriting the operator's terminal state.
            if inv_row.status not in _ALIVE_STATUSES:
                _log.info(
                    "synthesis aborted inv=%s -- status=%s no longer alive "
                    "(paused or closed mid-synthesis)",
                    self.investigation_id, inv_row.status,
                )
                return {
                    "status": "skipped",
                    "reason": f"investigation_not_alive:{inv_row.status}",
                }

            canonical_row = (await uow.session.exec(
                _select(VRInvestigationOutcomeRecord)
                .where(VRInvestigationOutcomeRecord.id == canonical.id)
                .with_for_update()
            )).first()
            if canonical_row is None:
                return {"status": "skipped", "reason": "canonical_disappeared"}
            try:
                payload = json.loads(canonical_row.payload_json or "{}")
            except (ValueError, TypeError):
                payload = {}
            if "panel_summary" in payload:
                return {
                    "status": "skipped",
                    "reason": "already_synthesized_under_lock",
                    "canonical_outcome_id": canonical_row.id,
                }
            payload["panel_summary"] = {
                "narrative": synthesis_text,
                "personas": [
                    {
                        "persona": p["persona_voice"],
                        "branch_id": p["branch_id"],
                        "kind": p["outcome_kind"],
                        "confidence": p["confidence"],
                    }
                    for p in panel
                ],
                "synthesized_at": utc_now().isoformat(),
            }
            canonical_row.payload_json = json.dumps(payload)
            canonical_row.confidence = _synthesis_confidence(panel).value
            uow.session.add(canonical_row)

            # Flip investigation status to COMPLETED + record stopped_at
            # via the shared helper (fix §162).
            _mark_investigation_completed(inv_row)
            uow.session.add(inv_row)
            # Phase C surgical (BLOCK fix): close orphan active branches
            # so the projection stays in lockstep with inv.status. See
            # services/branch_cleanup.py for the rationale.
            from aila.modules.vr.services.branch_cleanup import (
                close_orphan_branches_on_terminal,
            )
            await close_orphan_branches_on_terminal(
                uow, self.investigation_id,
                reason="investigation_completed",
                now=inv_row.updated_at,
            )
            await uow.commit()

        _log.info(
            "synthesis DONE inv=%s canonical_outcome_id=%s panel=%d",
            self.investigation_id, canonical.id, len(panel),
        )
        return {
            "status": "ok",
            "canonical_outcome_id": canonical.id,
            "panel_size": len(panel),
        }


def _synthesis_confidence(panel: list[dict[str, Any]]) -> OutcomeConfidence:
    """Heuristic: take the median of the panel's confidences, downgrade
    one notch if any panel member disagrees with the majority on
    outcome_kind (CRITIC says PATCH_PRESENT, RESEARCHER says
    DIRECT_FINDING -- that's real disagreement).
    """
    # fix §326 -- rank 0 ('exact' confidence) must round-trip to
    # OutcomeConfidence.EXACT, not STRONG. The reverse map was lossy.
    rank_to_conf = {
        0: OutcomeConfidence.EXACT,
        1: OutcomeConfidence.STRONG,
        2: OutcomeConfidence.MEDIUM,
        3: OutcomeConfidence.CAVEATED,
        4: OutcomeConfidence.UNKNOWN,
    }
    # fix §161 -- 'weak' is NOT in OutcomeConfidence; drop the alias.
    # Personas that emit 'weak' fall through to the .get(default=4)
    # ('unknown') rank, which is the same end-state CAVEATED would
    # have produced via the disagreement penalty.
    conf_rank = {"exact": 0, "strong": 1, "medium": 2, "caveated": 3, "unknown": 4}
    ranks = sorted(conf_rank.get(p.get("confidence", "unknown"), 4) for p in panel)
    median = ranks[len(ranks) // 2]
    # fix §327 -- graduated disagreement penalty: the notch downgrade
    # scales with the number of distinct outcome_kinds in the panel.
    # Unanimous (1 kind): no penalty. 2-way split (e.g. critic disagrees
    # against researcher on PATCH_PRESENT vs DIRECT_FINDING): one notch --
    # the prior flat penalty. 3-way split (one persona finds a bug, one
    # sees a patch, one writes an audit-memo): two notches because a
    # panel that cannot even agree on whether anything was found is
    # fundamentally less confident than a panel arguing degree. For a
    # 3-persona panel this matches round(Shannon entropy in bits) of
    # the kind distribution.
    kinds = {p.get("outcome_kind") for p in panel}
    disagreement = max(len(kinds) - 1, 0)
    if disagreement:
        median = min(median + disagreement, 4)
    return rank_to_conf.get(median, OutcomeConfidence.MEDIUM)


def _mark_investigation_completed(inv_row: VRInvestigationRecord) -> None:
    """Set ``inv`` to COMPLETED + stopped_at/updated_at in a single helper
    so every synthesis writer flips the same three fields the same way.

    fix §162 -- replaces inline ``inv.status = COMPLETED.value`` writes
    with a shared helper. When E1 ships its sibling ``_mark_investigation_completed``
    at the outcome_dispatcher layer (§22), this local helper can be
    swapped out for the shared one without touching call sites.
    """
    now = utc_now()
    inv_row.status = InvestigationStatus.COMPLETED.value
    inv_row.stopped_at = now
    inv_row.updated_at = now


def _render_panel(panel: list[dict[str, Any]]) -> str:
    # fix §165 -- panel content (answer / reasoning / persona_voice) is
    # derived from upstream tool results and arbitrary LLM outputs. Pass
    # every dynamic string through ``sanitize_input`` before splicing it
    # into the synthesiser's prompt so a persona that pasted an
    # ``Ignore previous instructions``-style payload from a tool result
    # can't override the synthesis system prompt.
    lines: list[str] = [
        "# Persona deliberation panel",
        "",
        f"Investigation produced {len(panel)} terminal outcomes -- one per "
        f"persona branch. Each branch reasoned independently against its "
        f"own LLM routing. Your job is to read all three and produce ONE "
        f"consolidated verdict.",
        "",
    ]
    for p in panel:
        persona = sanitize_input(str(p["persona_voice"])).upper()
        outcome_kind = sanitize_input(str(p["outcome_kind"]))
        confidence = sanitize_input(str(p["confidence"]))
        lines.append(f"## {persona} (turn {p['turn_count']})")
        lines.append(f"outcome_kind: {outcome_kind}")
        lines.append(f"confidence: {confidence}")
        lines.append(f"affected_components: {len(p['affected_components'])} entries")
        lines.append(f"variant_hunt_orders: {len(p['variant_hunt_orders'])} entries")
        lines.append("")
        lines.append("### answer")
        lines.append(sanitize_input(p["answer"]) if p["answer"] else "(empty)")
        lines.append("")
        if p.get("reasoning"):
            lines.append("### reasoning")
            lines.append(sanitize_input(p["reasoning"]))
            lines.append("")
    lines.append(
        "# Synthesis instruction\n\n"
        "Produce ONE consolidated verdict in markdown. Structure:\n"
        "1. **Headline verdict** -- single sentence stating whether the "
        "investigation found a bug, found a patch in place, or could not "
        "establish either.\n"
        "2. **Points of agreement** -- what all personas agreed on, with "
        "specific source citations.\n"
        "3. **Points of disagreement** -- where personas reached different "
        "conclusions, what each claimed, and which has the stronger evidence.\n"
        "4. **Unresolved questions** -- what the panel collectively could not "
        "settle and what would be needed to resolve.\n"
        "5. **Recommended next actions** -- variant hunts to spawn, operator "
        "questions to answer, refs to audit instead.\n\n"
        "Be honest about disagreement. A synthesis that erases dissent is "
        "worse than a synthesis that names it explicitly."
    )
    return "\n".join(lines)


_SYSTEM_PROMPT = (
    "You are the synthesiser for a vulnerability-research deliberation "
    "panel. Three persona branches (researcher / critic / implementer) "
    "have each reasoned independently about the same investigation using "
    "different LLM routings and produced one terminal outcome each. Your "
    "job is to read all three and produce ONE consolidated verdict.\n\n"
    "Rules:\n"
    "- Be honest about disagreement. If the critic dissents from the "
    "researcher's hypothesis, name the dissent explicitly. Do not "
    "average the answers -- pick the verdict with the strongest "
    "source-level evidence and explain why.\n"
    "- Quote specific file:line citations from the panel members' "
    "answers when describing the verdict. Do not invent new citations.\n"
    "- If the panel collectively could not establish a verdict, say so "
    "and list the open questions. 'Inconclusive' is an honest outcome.\n"
    "- Variant_hunt_orders the panel produced are aggregated by the "
    "dispatcher automatically. You do not need to repeat them -- just "
    "reference the count and the most important ones in your "
    "recommended next actions.\n"
    "- The synthesis lands as the investigation's primary outcome, "
    "rendered in the PDF report as the headline finding. Write for the "
    "audit-committee reader, not for another LLM."
)
