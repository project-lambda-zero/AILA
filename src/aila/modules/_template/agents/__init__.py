"""Template reasoning agents -- copy-me subclasses of the platform bases.

Every primitive lives on ``aila.platform.agents.*``; each module below
is a thin subclass binding the template record models, contracts, and
configuration namespace. Public exports mirror the vr surface so
downstream operator dashboards and reports keep the same identifier
shapes across modules.
"""
from __future__ import annotations

from .branch_manager import BranchManager, BranchManagerError, BranchOpResult
from .claim_verifier import ClaimVerifierAgent
from .outcome_dispatcher import (
    OutcomeDispatcher,
    OutcomeDispatcherError,
    OutcomeDispatchResult,
)
from .pattern_extractor import (
    PatternExtractionResult,
    PatternExtractor,
    PatternExtractorError,
)
from .persona_router import PersonaRouter, resolve_task_type
from .researcher import (
    TemplateResearcher,
    TemplateResearcherError,
    TemplateResearcherTurnResult,
)
from .synthesis_agent import SynthesisAgent, SynthesisResponse
from .tool_executor import ToolExecutionResult, ToolExecutor

__all__ = [
    "BranchManager",
    "BranchManagerError",
    "BranchOpResult",
    "ClaimVerifierAgent",
    "OutcomeDispatchResult",
    "OutcomeDispatcher",
    "OutcomeDispatcherError",
    "PatternExtractionResult",
    "PatternExtractor",
    "PatternExtractorError",
    "PersonaRouter",
    "SynthesisAgent",
    "SynthesisResponse",
    "TemplateResearcher",
    "TemplateResearcherError",
    "TemplateResearcherTurnResult",
    "ToolExecutionResult",
    "ToolExecutor",
    "resolve_task_type",
]
