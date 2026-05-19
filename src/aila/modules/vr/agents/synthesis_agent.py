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
    OutcomeKind,
    SenderKind,
)
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
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
        # Load investigation + every branch's latest terminal outcome.
        async with UnitOfWork() as uow:
            inv = (await uow.session.exec(
                _select(VRInvestigationRecord).where(
                    VRInvestigationRecord.id == self.investigation_id,
                )
            )).first()
            if inv is None:
                return {"status": "skipped", "reason": "investigation_not_found"}
            if inv.primary_outcome_id:
                return {
                    "status": "skipped",
                    "reason": "primary_outcome_already_set",
                    "primary_outcome_id": inv.primary_outcome_id,
                }

            branches = (await uow.session.exec(
                _select(VRInvestigationBranchRecord).where(
                    VRInvestigationBranchRecord.investigation_id == self.investigation_id,
                )
            )).all()

            panel: list[dict[str, Any]] = []
            primary_branch: VRInvestigationBranchRecord | None = None
            for b in branches:
                if b.parent_branch_id is None:
                    primary_branch = b
                latest = (await uow.session.exec(
                    _select(VRInvestigationOutcomeRecord)
                    .where(VRInvestigationOutcomeRecord.investigation_id == self.investigation_id)
                    .where(VRInvestigationOutcomeRecord.branch_id == b.id)
                    .order_by(VRInvestigationOutcomeRecord.created_at.desc())
                    .limit(1),
                )).first()
                if latest is None:
                    return {
                        "status": "skipped",
                        "reason": f"branch_{b.persona_voice or b.id[:8]}_has_no_terminal",
                    }
                try:
                    payload = json.loads(latest.payload_json or "{}")
                except (ValueError, TypeError):
                    payload = {}
                panel.append({
                    "branch_id": b.id,
                    "persona_voice": b.persona_voice or "(none)",
                    "turn_count": b.turn_count,
                    "outcome_id": latest.id,
                    "outcome_kind": latest.outcome_kind,
                    "confidence": latest.confidence,
                    "answer": (payload.get("answer") or "")[:6000],
                    "reasoning": (payload.get("reasoning") or "")[:6000],
                    "affected_components": payload.get("affected_components") or [],
                    "variant_hunt_orders": payload.get("variant_hunt_orders") or [],
                })

        if primary_branch is None:
            return {"status": "skipped", "reason": "no_primary_branch"}

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

        # Aggregate variant_hunt_orders across all branches (dedupe by title).
        seen_titles: set[str] = set()
        aggregated_orders: list[dict[str, Any]] = []
        for p in panel:
            for o in p.get("variant_hunt_orders") or []:
                if not isinstance(o, dict):
                    continue
                title = (o.get("title") or "").strip()
                if title and title in seen_titles:
                    continue
                seen_titles.add(title)
                aggregated_orders.append(o)

        # Pick the highest-confidence individual outcome's components as the
        # baseline affected_components; aggregate any others on top.
        _conf_rank = {"strong": 0, "exact": 0, "medium": 1, "caveated": 2, "weak": 3, "unknown": 4}
        panel_sorted = sorted(panel, key=lambda p: _conf_rank.get(p.get("confidence", "unknown"), 9))
        baseline_components: list[dict[str, Any]] = []
        seen_components: set[tuple[str, str]] = set()
        for p in panel_sorted:
            for c in p.get("affected_components") or []:
                if not isinstance(c, dict):
                    continue
                key = (c.get("file") or "", c.get("function") or "")
                if key in seen_components:
                    continue
                seen_components.add(key)
                baseline_components.append(c)

        synthesis_payload = {
            "answer": synthesis_text,
            "panel_summary": [
                {
                    "persona": p["persona_voice"],
                    "kind": p["outcome_kind"],
                    "confidence": p["confidence"],
                    "outcome_id": p["outcome_id"],
                }
                for p in panel
            ],
            "affected_components": baseline_components,
            "variant_hunt_orders": aggregated_orders,
            "source_outcome_ids": [p["outcome_id"] for p in panel],
        }

        async with UnitOfWork() as uow:
            inv_row = (await uow.session.exec(
                _select(VRInvestigationRecord).where(
                    VRInvestigationRecord.id == self.investigation_id,
                )
            )).first()
            if inv_row is None:
                return {"status": "skipped", "reason": "investigation_not_found"}
            # Re-check idempotency under the write lock.
            if inv_row.primary_outcome_id:
                return {
                    "status": "skipped",
                    "reason": "primary_outcome_already_set",
                    "primary_outcome_id": inv_row.primary_outcome_id,
                }

            synthesis_outcome = VRInvestigationOutcomeRecord(
                investigation_id=self.investigation_id,
                branch_id=primary_branch.id,
                outcome_kind=OutcomeKind.ASSESSMENT_REPORT.value,
                confidence=_synthesis_confidence(panel).value,
                payload_json=json.dumps(synthesis_payload),
                dispatch_status="pending",
                sender_kind=SenderKind.ENGINE.value,
            )
            uow.session.add(synthesis_outcome)
            await uow.session.flush()
            await uow.session.refresh(synthesis_outcome)

            inv_row.primary_outcome_id = synthesis_outcome.id
            inv_row.updated_at = utc_now()
            uow.session.add(inv_row)
            await uow.commit()
            synthesis_outcome_id = synthesis_outcome.id

        _log.info(
            "synthesis DONE inv=%s outcome_id=%s panel=%d",
            self.investigation_id, synthesis_outcome_id, len(panel),
        )
        return {
            "status": "ok",
            "synthesis_outcome_id": synthesis_outcome_id,
            "panel_size": len(panel),
            "aggregated_variant_orders": len(aggregated_orders),
        }


def _synthesis_confidence(panel: list[dict[str, Any]]) -> OutcomeConfidence:
    """Heuristic: take the median of the panel's confidences, downgrade
    one notch if any panel member disagrees with the majority on
    outcome_kind (CRITIC says PATCH_PRESENT, RESEARCHER says
    DIRECT_FINDING — that's real disagreement).
    """
    rank_to_conf = {
        0: OutcomeConfidence.STRONG,
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
