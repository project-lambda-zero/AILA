"""Async LLM client for the AILA platform.

Provides a minimal async-first client built on AsyncOpenAI + OpenRouter.
Config-based model routing, retry with backoff, Pydantic fallback validation,
truncation detection, and operator kill switch.

Usage::

    from aila.platform.llm import AilaLLMClient, RunMemory

    client = AilaLLMClient(registry=registry, secret_store=secret_store)
    response = await client.chat("scoring", messages=[...])
"""

from .classify import (
    ClassificationLevel,
    ClassificationResult,
    classify_messages,
    make_classify_step,
    register_pattern,
)
from .client import AilaLLMClient, LLMResponse
from .config import LLMConfigProvider, LLMRouting
from .cost import CostTracker
from .errors import BudgetExceededError, ClassificationBlockedError, ConfidenceRejectedError, LLMDisabledError, LLMError
from .gate import extract_confidence, make_gate_step
from .health_router import (
    EndpointHealth,
    ModelHealthRouter,
    get_default_health_router,
    reset_default_health_router,
)
from .pipeline import PipelineRunner
from .run_memory import RunMemory
from .sanitize import register_injection_pattern, sanitize_input, sanitize_output
from .seal import compute_seal, make_seal_step
from .untrusted import BEGIN_FENCE_PREFIX, END_FENCE, sanitize_untrusted
from .validate import (
    CitationResult,
    EvidenceValidationReport,
    EvidenceValidator,
    ValidationResult,
    make_validate_step,
)
from .verify import make_verify_step

# Backwards-compatible alias -- platform code uses "LLMClient" in
# TYPE_CHECKING blocks.  Points to AilaLLMClient (the only client).
LLMClient = AilaLLMClient

__all__ = [
    "AilaLLMClient",
    "BEGIN_FENCE_PREFIX",
    "BudgetExceededError",
    "END_FENCE",
    "CitationResult",
    "ClassificationBlockedError",
    "CostTracker",
    "ClassificationLevel",
    "ClassificationResult",
    "ConfidenceRejectedError",
    "EndpointHealth",
    "EvidenceValidationReport",
    "EvidenceValidator",
    "LLMClient",
    "ModelHealthRouter",
    "LLMConfigProvider",
    "LLMDisabledError",
    "LLMError",
    "LLMResponse",
    "LLMRouting",
    "PipelineRunner",
    "RunMemory",
    "ValidationResult",
    "classify_messages",
    "compute_seal",
    "extract_confidence",
    "get_default_health_router",
    "make_classify_step",
    "make_gate_step",
    "make_seal_step",
    "make_validate_step",
    "make_verify_step",
    "register_injection_pattern",
    "register_pattern",
    "reset_default_health_router",
    "sanitize_input",
    "sanitize_output",
    "sanitize_untrusted",
]
