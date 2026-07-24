"""VR-side thin binding for the platform PatternExtractor (RFC-03 Phase 5).

The extraction body lives on ``aila.platform.agents.pattern_extractor.
PatternExtractorBase``; this file binds the vr-specific record models,
enums, ``PatternCreate`` contract, task-type key, extractable outcome
kinds, and prompt template path. Every module aggregator + caller keeps
using the ``PatternExtractor`` class name imported from this path.

Design contract -- DO NOT relax these without updating the prompt:
  - Returns an empty list when nothing reusable was learned. Empty is OK.
  - Each pattern's ``evidence_refs`` must point at real message/outcome
    ids from the transcript.
  - Patterns persist immediately as ``draft`` so operator review is
    mandatory before any cross-investigation reuse.
"""
from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from aila.modules.vr.contracts.outcome import OutcomeKind
from aila.modules.vr.contracts.pattern import (
    PatternConfidence,
    PatternKind,
    PatternScope,
    VRPatternCreate,
)
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationMessageRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
    VRTargetRecord,
)
from aila.platform.agents.pattern_extractor import (
    PatternExtractionResult,
    PatternExtractorBase,
    PatternExtractorError,
)

__all__ = [
    "PatternExtractionResult",
    "PatternExtractor",
    "PatternExtractorError",
]

# Outcome kinds where pattern extraction is meaningful. AUDIT_MEMO is
# explicitly INCLUDED -- negative audits still encode reusable search
# heuristics + triage rules. ASSESSMENT_REPORT is excluded (low-signal
# self-aborts). VARIANT_HUNT_ORDER is excluded (the child investigation
# is what produces patterns, not the spawning order).
_EXTRACTION_OUTCOME_KINDS: frozenset[OutcomeKind] = frozenset({
    OutcomeKind.DIRECT_FINDING,
    OutcomeKind.AUDIT_MEMO,
    OutcomeKind.CRASH_TRIAGE_REPORT,
    OutcomeKind.PROFILE_SPEC_DRAFT,
    OutcomeKind.STRATEGY_DESCRIPTOR,
    OutcomeKind.PATCH_ASSESSMENT_REPORT,
})


class PatternExtractor(PatternExtractorBase):
    """VR-side pattern extractor (RFC-03 Phase 5 subclass).

    Every method + attribute is inherited from
    :class:`PatternExtractorBase`; this class only supplies the vr
    record models, enums, prompt path, task-type key, and the set of
    extractable outcome kinds.
    """

    _task_type: ClassVar[str] = "vulnerability_research.pattern_extraction"
    _extraction_outcome_kinds: ClassVar[frozenset[OutcomeKind]] = _EXTRACTION_OUTCOME_KINDS
    _outcome_kind_enum: ClassVar[type[OutcomeKind]] = OutcomeKind
    _pattern_kind_enum: ClassVar[type[PatternKind]] = PatternKind
    _pattern_confidence_enum: ClassVar[type[PatternConfidence]] = PatternConfidence
    _pattern_scope_enum: ClassVar[type[PatternScope]] = PatternScope
    _pattern_create_cls: ClassVar[type[VRPatternCreate]] = VRPatternCreate
    _outcome_model: ClassVar[type[VRInvestigationOutcomeRecord]] = VRInvestigationOutcomeRecord
    _investigation_model: ClassVar[type[VRInvestigationRecord]] = VRInvestigationRecord
    _target_model: ClassVar[type[VRTargetRecord]] = VRTargetRecord
    _message_model: ClassVar[type[VRInvestigationMessageRecord]] = VRInvestigationMessageRecord
    _branch_model: ClassVar[type[VRInvestigationBranchRecord]] = VRInvestigationBranchRecord
    _prompt_path: ClassVar[Path] = (
        Path(__file__).parent / "prompts" / "pattern_extraction.md"
    )
