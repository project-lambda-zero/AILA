"""Platform agent runtime primitives (RFC-03).

Per-turn reasoning primitives shared by every module's investigation
engine. Modules supply their record types, prompts, tool specs, and
submit gates; the platform owns the turn mechanics. Phase 1 lands the
two zero-drift lifts: the operator-intent classifier and the automatic
operator-steering injector.
"""
from __future__ import annotations

from aila.platform.agents.auto_steering import maybe_post_auto_steering
from aila.platform.agents.branch_pool import (
    BranchManagerError,
    BranchOpResult,
    BranchPool,
)
from aila.platform.agents.claim_verifier import (
    ClaimVerifierAgentBase,
    is_negative_finding_claim,
)
from aila.platform.agents.idempotent_llm import idempotent_llm_call
from aila.platform.agents.intent_classifier import classify_intent
from aila.platform.agents.observation import (
    ObservationKind,
    ObservationPolarity,
    PlatformObservation,
    observation_dedup_key,
    observation_namespace,
    record_observation,
)
from aila.platform.agents.outcome_dispatcher import (
    OutcomeDispatcherBase,
    OutcomeDispatcherError,
    OutcomeDispatchResult,
)
from aila.platform.agents.pattern_extractor import (
    PatternExtractionResult,
    PatternExtractorBase,
    PatternExtractorError,
)
from aila.platform.agents.persona_router import (
    PersonaRole,
    PersonaRouter,
)
from aila.platform.agents.sibling_consensus import inject_sibling_consensus
from aila.platform.agents.synthesis_runner import (
    SynthesisRunnerBase,
    synthesis_confidence,
)
from aila.platform.agents.tool_execution import (
    ToolExecutionResult,
    classify_contract_error,
    parse_command,
)

__all__ = [
    "BranchManagerError",
    "BranchOpResult",
    "BranchPool",
    "ClaimVerifierAgentBase",
    "ObservationKind",
    "ObservationPolarity",
    "OutcomeDispatchResult",
    "OutcomeDispatcherBase",
    "OutcomeDispatcherError",
    "PatternExtractionResult",
    "PatternExtractorBase",
    "PatternExtractorError",
    "PersonaRole",
    "PersonaRouter",
    "PlatformObservation",
    "SynthesisRunnerBase",
    "ToolExecutionResult",
    "classify_contract_error",
    "classify_intent",
    "idempotent_llm_call",
    "inject_sibling_consensus",
    "is_negative_finding_claim",
    "maybe_post_auto_steering",
    "observation_dedup_key",
    "observation_namespace",
    "parse_command",
    "record_observation",
    "synthesis_confidence",
]
