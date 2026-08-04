"""Template synthesis agent -- thin subclass of the platform base.

The synthesis pipeline (load canonical outcome, gate on already-
synthesized, build panel, call schema-validated LLM, commit
``panel_summary`` under a row lock) lives on
:class:`aila.platform.agents.synthesis_runner.SynthesisRunnerBase`.
This module binds the template-specific record models, the
``SynthesisResponse`` schema, the (inline for now, RFC-09 later)
system prompt, and a minimal ``_render_user_prompt`` panel renderer.
"""
from __future__ import annotations

from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field

from aila.modules._template.db_models import (
    TemplateInvestigationOutcomeRecord,
    TemplateInvestigationOutcomeReviewRecord,
    TemplateInvestigationRecord,
)
from aila.platform.agents.synthesis_runner import SynthesisRunnerBase

__all__ = ["SynthesisAgent", "SynthesisResponse"]


class SynthesisResponse(BaseModel):
    """Structured output schema for the template panel synthesiser.

    Minimal contract -- a copier expands the schema with module-
    specific fields (``family_attribution`` / ``variant_hunt_orders``
    / etc.) once the module's outcome payload shape stabilises.
    """

    model_config = ConfigDict(extra="forbid")

    consolidated_answer: str = Field(
        default="", description="One-paragraph consolidated verdict.",
    )
    points_of_agreement: list[str] = Field(default_factory=list)
    points_of_disagreement: list[str] = Field(default_factory=list)


_SYSTEM_PROMPT = (
    "You synthesise a panel of persona reasoning contributions into one "
    "consolidated verdict for the template investigation engine. Return "
    "JSON matching the SynthesisResponse schema. Preserve every point of "
    "disagreement; do not silently reconcile them."
)


class SynthesisAgent(SynthesisRunnerBase):
    """Template-side persona-panel synthesis agent scaffold."""

    _TASK_TYPE: ClassVar[str] = "template.synthesis"
    _SYSTEM_PROMPT: ClassVar[str] = _SYSTEM_PROMPT
    _investigation_model: ClassVar[type[Any]] = TemplateInvestigationRecord
    _outcome_model: ClassVar[type[Any]] = TemplateInvestigationOutcomeRecord
    _response_model: ClassVar[type[BaseModel]] = SynthesisResponse
    _branch_table: ClassVar[str] = "template_investigation_branches"
    _review_model: ClassVar[type[Any] | None] = (
        TemplateInvestigationOutcomeReviewRecord
    )

    def _render_user_prompt(
        self,
        panel: list[dict[str, Any]],
        reviews: list[dict[str, Any]],
    ) -> str:
        """Render a minimal panel + reviews block for the synthesis LLM."""
        lines: list[str] = ["# Panel contributions", ""]
        for i, entry in enumerate(panel, start=1):
            persona = entry.get("persona_voice") or "(none)"
            confidence = entry.get("confidence") or "unknown"
            answer = (entry.get("answer") or "").strip()
            lines.append(
                f"## contribution {i} -- persona={persona} confidence={confidence}",
            )
            lines.append(answer or "(no answer text)")
            lines.append("")
        if reviews:
            lines.append("# Sibling reviews")
            lines.append("")
            for review in reviews:
                lines.append(
                    f"- persona={review.get('persona') or '(none)'} "
                    f"vote={review.get('vote') or 'abstain'}: "
                    f"{(review.get('comment') or '').strip()}",
                )
            lines.append("")
        lines.append("# Instruction")
        lines.append("")
        lines.append(
            "Return JSON matching the SynthesisResponse schema. Fold every "
            "review vote into the consolidated verdict.",
        )
        return "\n".join(lines)
