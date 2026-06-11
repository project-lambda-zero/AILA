"""SynthesisAgent — consolidates persona-panel outcomes into one verdict.

Triggered by ``investigation_emit._maybe_trigger_synthesis`` once every
persona branch in the multi-deliberation panel has produced a terminal
outcome. Reads every branch's last terminal outcome (researcher /
critic / implementer), feeds them to an LLM that synthesises a single
final answer with explicit agreement/disagreement structure, and
writes the synthesis as a new outcome on the primary branch — then
sets ``inv.primary_outcome_id`` so the investigation surfaces one
authoritative verdict in the UI + report.

Idempotency: exits with ``{"status": "skipped", "reason": ...}`` when
``inv.primary_outcome_id`` is already a synthesis-kind outcome.
"""
from __future__ import annotations

import json
import logging
from typing import Any

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
from aila.platform.services.factory import ServiceFactory
from aila.platform.uow import UnitOfWork

__all__ = ["SynthesisAgent"]

_log = logging.getLogger(__name__)


class SynthesisAgent:
    """LLM-backed consolidator for the persona deliberation panel."""

    _TASK_TYPE = "vulnerability_research.synthesizer"

    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id

    async def run(self) -> dict[str, Any]:
        """Consolidate panel persona submissions into a synthesis verdict.

        D-101 architecture: ONE canonical outcome row per investigation
        holds every persona's submission inside ``payload.panel_contributions``.
        Synthesis reads that array (NOT per-branch outcome rows — there
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
            # carries up to 4000 chars of each persona's submission —
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

        # Synthesise via LLM.
        services = ServiceFactory()
        try:
            response = await services.llm_client.chat(
                task_type=self._TASK_TYPE,
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": _render_panel(panel)},
                ],
            )
        except RuntimeError as exc:
            _log.warning(
                "synthesis LLM call failed for inv=%s err=%s",
                self.investigation_id, exc,
            )
            return {"status": "failed", "reason": f"llm_error:{exc}"}
        if response.disabled:
            return {"status": "skipped", "reason": "llm_kill_switch_active"}
        synthesis_text = (response.content or "").strip()
        if not synthesis_text:
            return {"status": "failed", "reason": "empty_llm_response"}

        # Update the canonical row's payload in-place. Don't create a
        # new outcome row — D-101 mandates exactly one canonical row per
        # investigation.
        async with UnitOfWork() as uow:
            canonical_row = (await uow.session.exec(
                _select(VRInvestigationOutcomeRecord).where(
                    VRInvestigationOutcomeRecord.id == canonical.id,
                )
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

            # Flip investigation status to COMPLETED + record stopped_at.
            inv_row = (await uow.session.exec(
                _select(VRInvestigationRecord).where(
                    VRInvestigationRecord.id == self.investigation_id,
                )
            )).first()
            if inv_row is not None:
                inv_row.status = InvestigationStatus.COMPLETED.value
                inv_row.stopped_at = utc_now()
                inv_row.updated_at = utc_now()
                uow.session.add(inv_row)
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
    DIRECT_FINDING — that's real disagreement).
    """
    # fix §326 — rank 0 ('exact' confidence) must round-trip to
    # OutcomeConfidence.EXACT, not STRONG. The reverse map was lossy.
    rank_to_conf = {
        0: OutcomeConfidence.EXACT,
        1: OutcomeConfidence.STRONG,
        2: OutcomeConfidence.MEDIUM,
        3: OutcomeConfidence.CAVEATED,
        4: OutcomeConfidence.UNKNOWN,
    }
    conf_rank = {"strong": 1, "exact": 0, "medium": 2, "caveated": 3, "weak": 3, "unknown": 4}
    ranks = sorted(conf_rank.get(p.get("confidence", "unknown"), 4) for p in panel)
    median = ranks[len(ranks) // 2]
    # Disagreement penalty: any kind mismatch downgrades by 1.
    kinds = {p.get("outcome_kind") for p in panel}
    if len(kinds) > 1:
        median = min(median + 1, 4)
    return rank_to_conf.get(median, OutcomeConfidence.MEDIUM)


def _render_panel(panel: list[dict[str, Any]]) -> str:
    lines: list[str] = [
        "# Persona deliberation panel",
        "",
        f"Investigation produced {len(panel)} terminal outcomes — one per "
        f"persona branch. Each branch reasoned independently against its "
        f"own LLM routing. Your job is to read all three and produce ONE "
        f"consolidated verdict.",
        "",
    ]
    for p in panel:
        lines.append(f"## {p['persona_voice'].upper()} (turn {p['turn_count']})")
        lines.append(f"outcome_kind: {p['outcome_kind']}")
        lines.append(f"confidence: {p['confidence']}")
        lines.append(f"affected_components: {len(p['affected_components'])} entries")
        lines.append(f"variant_hunt_orders: {len(p['variant_hunt_orders'])} entries")
        lines.append("")
        lines.append("### answer")
        lines.append(p["answer"] or "(empty)")
        lines.append("")
        if p.get("reasoning"):
            lines.append("### reasoning")
            lines.append(p["reasoning"])
            lines.append("")
    lines.append(
        "# Synthesis instruction\n\n"
        "Produce ONE consolidated verdict in markdown. Structure:\n"
        "1. **Headline verdict** — single sentence stating whether the "
        "investigation found a bug, found a patch in place, or could not "
        "establish either.\n"
        "2. **Points of agreement** — what all personas agreed on, with "
        "specific source citations.\n"
        "3. **Points of disagreement** — where personas reached different "
        "conclusions, what each claimed, and which has the stronger evidence.\n"
        "4. **Unresolved questions** — what the panel collectively could not "
        "settle and what would be needed to resolve.\n"
        "5. **Recommended next actions** — variant hunts to spawn, operator "
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
    "average the answers — pick the verdict with the strongest "
    "source-level evidence and explain why.\n"
    "- Quote specific file:line citations from the panel members' "
    "answers when describing the verdict. Do not invent new citations.\n"
    "- If the panel collectively could not establish a verdict, say so "
    "and list the open questions. 'Inconclusive' is an honest outcome.\n"
    "- Variant_hunt_orders the panel produced are aggregated by the "
    "dispatcher automatically. You do not need to repeat them — just "
    "reference the count and the most important ones in your "
    "recommended next actions.\n"
    "- The synthesis lands as the investigation's primary outcome, "
    "rendered in the PDF report as the headline finding. Write for the "
    "audit-committee reader, not for another LLM."
)
