"""Template pattern extractor -- thin binding of the platform base.

The extraction body (load outcome + investigation + target, render the
transcript, prompt the LLM through the idempotency cache, validate,
persist via :class:`PatternStore`) lives on
:class:`aila.platform.agents.pattern_extractor.PatternExtractorBase`.
This module binds the template-specific record models, enums,
``PatternCreate`` contract, task-type key, extractable outcome kinds,
and prompt template path.
"""
from __future__ import annotations

from typing import ClassVar

from aila.modules._template.contracts.outcome import TemplateOutcomeKind
from aila.modules._template.contracts.pattern import (
    PatternConfidence,
    PatternScope,
    TemplatePatternCreate,
    TemplatePatternKind,
)
from aila.modules._template.db_models import (
    TemplateInvestigationBranchRecord,
    TemplateInvestigationMessageRecord,
    TemplateInvestigationOutcomeRecord,
    TemplateInvestigationRecord,
    TemplateTargetRecord,
)
from aila.platform.agents.pattern_extractor import (
    PatternExtractionResult,
    PatternExtractorBase,
    PatternExtractorError,
)
from aila.platform.prompts.seeds import TEMPLATE_PATTERN_EXTRACTION_TEXT

__all__ = [
    "PatternExtractionResult",
    "PatternExtractor",
    "PatternExtractorError",
]

# The template's single outcome kind is extractable; a real module
# extends the enum and this frozenset in lockstep.
_EXTRACTION_OUTCOME_KINDS: frozenset[TemplateOutcomeKind] = frozenset({
    TemplateOutcomeKind.ASSESSMENT_REPORT,
})


class PatternExtractor(PatternExtractorBase):
    """Template-side pattern extractor scaffold subclass."""

    _task_type: ClassVar[str] = "template.pattern_extraction"
    _extraction_outcome_kinds: ClassVar[frozenset[TemplateOutcomeKind]] = (
        _EXTRACTION_OUTCOME_KINDS
    )
    _outcome_kind_enum: ClassVar[type[TemplateOutcomeKind]] = TemplateOutcomeKind
    _pattern_kind_enum: ClassVar[type[TemplatePatternKind]] = TemplatePatternKind
    _pattern_confidence_enum: ClassVar[type[PatternConfidence]] = PatternConfidence
    _pattern_scope_enum: ClassVar[type[PatternScope]] = PatternScope
    _pattern_create_cls: ClassVar[type[TemplatePatternCreate]] = TemplatePatternCreate
    _outcome_model: ClassVar[type[TemplateInvestigationOutcomeRecord]] = (
        TemplateInvestigationOutcomeRecord
    )
    _investigation_model: ClassVar[type[TemplateInvestigationRecord]] = (
        TemplateInvestigationRecord
    )
    _target_model: ClassVar[type[TemplateTargetRecord]] = TemplateTargetRecord
    _message_model: ClassVar[type[TemplateInvestigationMessageRecord]] = (
        TemplateInvestigationMessageRecord
    )
    _branch_model: ClassVar[type[TemplateInvestigationBranchRecord]] = (
        TemplateInvestigationBranchRecord
    )
    _prompt_template: ClassVar[str] = TEMPLATE_PATTERN_EXTRACTION_TEXT
