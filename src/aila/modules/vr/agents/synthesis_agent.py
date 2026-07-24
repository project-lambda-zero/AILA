"""VR-side thin binding for the platform SynthesisRunner (RFC-03 Phase 5).

The synthesis pipeline (load canonical outcome, gate on
already-synthesized, build panel, call schema-validated LLM, commit
panel_summary + status flip under a row lock) lives on
:class:`aila.platform.agents.synthesis_runner.SynthesisRunnerBase`.
This file binds the vr-specific record models, the ``SynthesisResponse``
schema, the ``_SYSTEM_PROMPT`` text, the ``_render_user_prompt`` panel
rendering, and the panel-entry extras vr needs for its prompt.

Every module aggregator + caller keeps using the ``SynthesisAgent``
class name imported from this path; the constructor sig
(``SynthesisAgent(investigation_id)``) is unchanged.

Triggered by ``investigation_emit._maybe_trigger_synthesis`` once every
persona branch in the multi-deliberation panel has produced a terminal
outcome. Idempotency: exits with ``{"status": "skipped", "reason":
"already_synthesized"}`` when the canonical outcome payload already
carries a ``panel_summary``.
"""
from __future__ import annotations

from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field

from aila.modules.vr.db_models import (
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
)
from aila.platform.agents.synthesis_runner import SynthesisRunnerBase
from aila.platform.llm.sanitize import sanitize_input

__all__ = ["SynthesisAgent", "SynthesisResponse"]


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


def _render_panel(panel: list[dict[str, Any]]) -> str:
    """Render the vr persona panel into the LLM user-side prompt.

    fix §165 -- panel content (answer / reasoning / persona_voice) is
    derived from upstream tool results and arbitrary LLM outputs. Pass
    every dynamic string through :func:`sanitize_input` before splicing
    it into the synthesiser's prompt so a persona that pasted an
    ``Ignore previous instructions``-style payload from a tool result
    can't override the synthesis system prompt.
    """
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


class SynthesisAgent(SynthesisRunnerBase):
    """VR-side persona-panel synthesis agent (RFC-03 Phase 5 subclass).

    Every method + attribute is inherited from
    :class:`SynthesisRunnerBase`; this class only supplies the vr
    record models, the ``SynthesisResponse`` schema, the system prompt,
    the task-type key, the branch table name for orphan-branch cleanup,
    and the two overrides vr needs on top of the shared skeleton:

    - ``_build_panel_entry`` adds ``affected_components`` +
      ``variant_hunt_orders`` derived from the canonical payload so
      ``_render_user_prompt`` can surface their counts.
    - ``_render_user_prompt`` produces the vr persona-panel rendering
      with the "points of agreement / disagreement" instruction block.
    """

    _LOG_LABEL: ClassVar[str] = "synthesis"
    _TASK_TYPE: ClassVar[str] = "vulnerability_research.synthesizer"
    _SYSTEM_PROMPT: ClassVar[str] = _SYSTEM_PROMPT
    _investigation_model: ClassVar[type[VRInvestigationRecord]] = (
        VRInvestigationRecord
    )
    _outcome_model: ClassVar[type[VRInvestigationOutcomeRecord]] = (
        VRInvestigationOutcomeRecord
    )
    _response_model: ClassVar[type[SynthesisResponse]] = SynthesisResponse
    _branch_table: ClassVar[str] = "vr_investigation_branches"

    def _build_panel_entry(
        self,
        contribution: dict[str, Any],
        canonical_payload: dict[str, Any],
    ) -> dict[str, Any]:
        """vr adds ``affected_components`` + ``variant_hunt_orders`` counts.

        The base builds the 7 core keys; vr overlays the two extra
        canonical-payload-derived lists so :func:`_render_panel` can
        surface their counts in each persona block.
        """
        entry = super()._build_panel_entry(contribution, canonical_payload)
        entry["affected_components"] = (
            canonical_payload.get("affected_components") or []
        )
        entry["variant_hunt_orders"] = (
            canonical_payload.get("variant_hunt_orders") or []
        )
        return entry

    def _render_user_prompt(self, panel: list[dict[str, Any]]) -> str:
        return _render_panel(panel)
