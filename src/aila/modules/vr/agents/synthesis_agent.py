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

import json
from pathlib import Path
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field

from aila.modules.vr.db_models import (
    VRInvestigationOutcomeRecord,
    VRInvestigationOutcomeReviewRecord,
    VRInvestigationRecord,
)
from aila.platform.agents.synthesis_runner import SynthesisRunnerBase
from aila.platform.llm.sanitize import sanitize_input
from aila.platform.prompts import PromptRegistry

__all__ = ["SynthesisAgent", "SynthesisResponse"]

_PROMPT_DIR = Path(__file__).parent / "prompts"
_PROMPT_REGISTRY = PromptRegistry(
    _PROMPT_DIR,
    module="vr",
    fallback_base="system_synthesis.md",
)


def _load_system_prompt() -> str:
    """Return the VR synthesis system prompt from the registry.

    RFC-09 criterion 1: body lives in ``prompts/system_synthesis.md``
    resolved via :class:`PromptRegistry`. Called at class-body import
    time to populate the ``_SYSTEM_PROMPT`` ClassVar the shared
    :class:`SynthesisRunnerBase.run` reads.
    """
    return _PROMPT_REGISTRY.load("synthesis")


class SynthesisResponse(BaseModel):
    """Structured output schema for the persona-deliberation synthesiser.

    Enforced by :meth:`AilaLLMClient.chat_structured` (fix §159) so the
    synthesiser never receives free-text markdown that the renderer
    cannot validate. Each field renders into one labelled section of the
    final markdown narrative via :meth:`to_markdown`.
    """

    model_config = ConfigDict(extra="forbid")

    scope: str = Field(
        min_length=1,
        max_length=1000,
        description=(
            "What the panel examined before the verdict: the control/"
            "check under audit, the code surface inspected (files/"
            "functions/manifest/resources), and the evidence base. "
            "Written so a reader knows the audit's coverage without "
            "opening the child investigation."
        ),
    )
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
            f"### Scope\n{self.scope.strip()}\n\n"
            f"**Headline verdict.** {self.headline_verdict.strip()}\n\n"
            f"### Points of agreement\n{_bulleted(self.points_of_agreement)}\n\n"
            f"### Points of disagreement\n"
            f"{_bulleted(self.points_of_disagreement)}\n\n"
            f"### Unresolved questions\n{_bulleted(self.unresolved_questions)}\n\n"
            f"### Recommended next actions\n"
            f"{_bulleted(self.recommended_next_actions)}\n"
        )


def _render_reviews(lines: list[str], reviews: list[dict[str, Any]]) -> None:
    """Append the sibling-review section so the synthesiser honors edits.

    fix §170 -- the request_edit vote's suggested_edits + the reviewer
    comment were previously written to the review row and never read.
    Surfacing them here is the consumer that folds the requested
    corrections + dissent into the consolidated verdict.
    """
    if not reviews:
        return
    lines.append("# Sibling reviews of the panel drafts")
    lines.append("")
    lines.append(
        "Each persona reviewed the drafts. Fold the substance of these "
        "reviews into the verdict: honor a requested confidence change, "
        "correct any claim a reviewer flagged as wrong, and name a dissent "
        "instead of dropping it. A reviewer's suggested_edits and comment "
        "are corrections to apply, not optional notes."
    )
    lines.append("")
    for rv in reviews:
        persona = sanitize_input(str(rv.get("persona") or "(none)")).upper()
        vote = sanitize_input(str(rv.get("vote") or ""))
        lines.append(f"## {persona} voted {vote}")
        comment = rv.get("comment") or ""
        if comment:
            lines.append(f"comment: {sanitize_input(comment)}")
        edits = rv.get("suggested_edits") or {}
        if edits:
            lines.append(f"suggested_edits: {sanitize_input(json.dumps(edits))}")
        lines.append("")


def _render_panel(
    panel: list[dict[str, Any]],
    reviews: list[dict[str, Any]] | None = None,
) -> str:
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
    _render_reviews(lines, reviews or [])
    lines.append(
        "# Synthesis instruction\n\n"
        "Produce ONE consolidated verdict in markdown. Structure:\n"
        "0. **Scope** -- one short paragraph naming the control/check "
        "under audit, the surface inspected (files/functions/manifest "
        "entries/resources), and the evidence base (tool queries, "
        "decompiler reads, config snippets). The reader must know the "
        "audit's coverage before reading the verdict.\n"
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
    _SYSTEM_PROMPT: ClassVar[str] = _load_system_prompt()
    _investigation_model: ClassVar[type[VRInvestigationRecord]] = (
        VRInvestigationRecord
    )
    _outcome_model: ClassVar[type[VRInvestigationOutcomeRecord]] = (
        VRInvestigationOutcomeRecord
    )
    _response_model: ClassVar[type[SynthesisResponse]] = SynthesisResponse
    _branch_table: ClassVar[str] = "vr_investigation_branches"
    _review_model: ClassVar[type[VRInvestigationOutcomeReviewRecord]] = (
        VRInvestigationOutcomeReviewRecord
    )

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

    def _render_user_prompt(
        self,
        panel: list[dict[str, Any]],
        reviews: list[dict[str, Any]],
    ) -> str:
        return _render_panel(panel, reviews)

    def _update_payload_extras(
        self,
        payload: dict[str, Any],
        parsed: BaseModel,
    ) -> None:
        """Promote the structured synthesis fields onto ``panel_summary``.

        The base ``_commit_synthesis`` writes ``panel_summary`` with
        ``narrative`` + ``personas`` + ``synthesized_at``. The parsed
        LLM response also carries the schema fields that per-control
        aggregate rows (MASVS, apk_static) need without re-parsing the
        markdown narrative: ``scope``, ``headline_verdict``,
        ``points_of_agreement``, ``points_of_disagreement``,
        ``unresolved_questions``, ``recommended_next_actions``. Promote
        each onto ``panel_summary`` so a downstream projector can read
        ``payload['panel_summary'][<field>]`` directly.

        ``recommended_next_actions`` also feeds the follow-up-discovery
        take-over service which spawns child investigations from the
        panel's structured hand-off.

        Runtime type of ``parsed`` is :class:`SynthesisResponse`; the
        abstract base annotates it as ``BaseModel`` to keep the hook
        schema-agnostic. Attribute reads go through :func:`getattr`
        with safe defaults so a payload that arrives with a partial
        response (schema evolution, tests) still commits.
        """
        panel_summary = payload.get("panel_summary")
        if not isinstance(panel_summary, dict):
            return
        scope = getattr(parsed, "scope", None)
        if isinstance(scope, str) and scope.strip():
            panel_summary["scope"] = scope.strip()
        headline = getattr(parsed, "headline_verdict", None)
        if isinstance(headline, str) and headline.strip():
            panel_summary["headline_verdict"] = headline.strip()
        for field in (
            "points_of_agreement",
            "points_of_disagreement",
            "unresolved_questions",
            "recommended_next_actions",
        ):
            items = getattr(parsed, field, None) or []
            if items:
                panel_summary[field] = [str(item) for item in items]
