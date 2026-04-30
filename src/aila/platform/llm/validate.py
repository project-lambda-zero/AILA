"""Evidence validation pipeline step for LLM responses.

Validates LLM-cited evidence (CVE IDs, EPSS scores, KEV status) against
stored enrichment data. Hallucinated citations -- CVE IDs invented by the
LLM that have no backing data -- are caught and reported in response
metadata and audit events.

Runs as a post-call step in the pipeline (after the API call returns).

Architecture:
  - EvidenceValidator Protocol: module-pluggable interface
  - make_validate_step factory: creates the StepFn closure
  - _merge_results: aggregates multiple validator outputs
  - _emit_validation_event: audit event emission
"""

from __future__ import annotations

import logging
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol, runtime_checkable, TYPE_CHECKING

if TYPE_CHECKING:
    from .config import LLMRouting
    from ..events.emitter import EventEmitter

logger = logging.getLogger(__name__)

# CVE pattern -- duplicated from classify.py intentionally to avoid
# cross-concern coupling (per RESEARCH anti-patterns).
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b")


# ---------------------------------------------------------------------------
# Data types (frozen, slots)
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class CitationResult:
    """Result of validating a single citation in an LLM response.

    Attributes:
        citation_id: The cited identifier (e.g. "CVE-2024-1234").
        citation_type: One of "cve_id", "epss_score", "kev_status".
        status: One of "valid", "invalid", "hallucinated".
        detail: Human-readable explanation (empty if valid).
    """

    citation_id: str
    citation_type: str
    status: str
    detail: str = ""


@dataclass(frozen=True, slots=True)
class ValidationResult:
    """Output of a single EvidenceValidator.validate() call.

    Attributes:
        validator_name: Name of the validator that produced this result.
        citations: Individual citation validation results.
        hallucination_count: Number of hallucinated citations found.
        overall_pass: True if no hallucinated citations were found.
    """

    validator_name: str
    citations: list[CitationResult] = field(default_factory=list)
    hallucination_count: int = 0
    overall_pass: bool = True


@dataclass(frozen=True, slots=True)
class EvidenceValidationReport:
    """Aggregated report across all validators for one LLM response.

    Attributes:
        citations_found: Total unique CVE IDs found (cve_id type only).
        citations_valid: Count of citations with status="valid".
        citations_hallucinated: Count of citations with status="hallucinated".
        hallucinated_ids: Deduplicated list of hallucinated citation IDs.
        overall_pass: True if all validators passed.
        results: Individual ValidationResult objects.
    """

    citations_found: int = 0
    citations_valid: int = 0
    citations_hallucinated: int = 0
    hallucinated_ids: list[str] = field(default_factory=list)
    overall_pass: bool = True
    results: list[ValidationResult] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Protocol (runtime_checkable per D-01)
# ---------------------------------------------------------------------------

@runtime_checkable
class EvidenceValidator(Protocol):
    """Module-pluggable evidence validation interface.

    Each module (e.g. vulnerability) implements its own validator that
    cross-references LLM-cited evidence against its enrichment store.
    """

    async def validate(self, content: str, ctx: dict[str, Any]) -> ValidationResult: ...


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def _merge_results(results: list[ValidationResult]) -> EvidenceValidationReport:
    """Aggregate multiple ValidationResults into a single report.

    - citations_found counts unique CVE IDs (cve_id type only -- EPSS/KEV
      are sub-assertions on the same CVE, not separate citations).
    - hallucinated_ids are deduplicated.
    - overall_pass is False if any result has overall_pass=False.
    """
    all_citations: list[CitationResult] = []
    for r in results:
        all_citations.extend(r.citations)

    # Count by status
    valid_count = sum(1 for c in all_citations if c.status == "valid")
    hallucinated_count = sum(1 for c in all_citations if c.status == "hallucinated")

    # Unique CVE IDs found (cve_id type only)
    cve_ids_found: set[str] = set()
    for c in all_citations:
        if c.citation_type == "cve_id":
            cve_ids_found.add(c.citation_id)

    # Deduplicated hallucinated IDs
    seen: set[str] = set()
    hallucinated_ids: list[str] = []
    for c in all_citations:
        if c.status == "hallucinated" and c.citation_id not in seen:
            hallucinated_ids.append(c.citation_id)
            seen.add(c.citation_id)

    overall_pass = all(r.overall_pass for r in results) if results else True

    return EvidenceValidationReport(
        citations_found=len(cve_ids_found),
        citations_valid=valid_count,
        citations_hallucinated=hallucinated_count,
        hallucinated_ids=hallucinated_ids,
        overall_pass=overall_pass,
        results=list(results),
    )


# ---------------------------------------------------------------------------
# Audit event emission (per D-14, D-15)
# ---------------------------------------------------------------------------

def _emit_validation_event(
    ctx: dict[str, Any],
    routing: LLMRouting,
    report: EvidenceValidationReport,
    emitter: EventEmitter | None,
) -> None:
    """Emit audit event for evidence validation. Handles emitter=None gracefully."""
    if emitter is None:
        return

    from ..events.event import PlatformEvent

    emitter.emit(
        PlatformEvent(
            stage="llm_evidence_validation",
            action="validate",
            key=f"llm.validate.{ctx['task_type']}",
            message=(
                f"Evidence validation: {report.citations_found} citations, "
                f"{report.citations_hallucinated} hallucinated"
            ),
            details={
                "task_type": ctx["task_type"],
                "model_id": routing.model_id,
                "citations_found": report.citations_found,
                "citations_valid": report.citations_valid,
                "citations_hallucinated": report.citations_hallucinated,
                "hallucinated_ids": report.hallucinated_ids,
                "overall_pass": report.overall_pass,
            },
        )
    )


# ---------------------------------------------------------------------------
# Pipeline step factory (per D-02)
# ---------------------------------------------------------------------------

def make_validate_step(
    validators: list[EvidenceValidator],
    emitter: EventEmitter | None = None,
) -> Any:
    """Create the validate pipeline step closure.

    The returned async callable matches the StepFn protocol:
    ``async def step(ctx, messages, routing) -> None``.

    Args:
        validators: List of EvidenceValidator implementations to run.
        emitter: Optional EventEmitter for audit logging.

    Returns:
        Async step function for pipeline registration.
    """

    async def _validate_step(
        ctx: dict[str, Any],
        messages: list[dict[str, Any]],
        routing: LLMRouting,
    ) -> None:
        # `messages` is required by the StepFn protocol but the validate step
        # only inspects ctx['response'] -- the LLM input is not consulted.
        del messages
        # Guard: no response to validate
        response = ctx.get("response")
        if response is None:
            return

        content = response.content if response.content else ""

        # Guard: empty content -> write passing report
        if not content.strip():
            report = EvidenceValidationReport()
            ctx["evidence_validation"] = asdict(report)
            _emit_validation_event(ctx, routing, report, emitter)
            return

        # Run all validators (per D-03)
        results: list[ValidationResult] = []
        for v in validators:
            results.append(await v.validate(content, ctx))

        # Merge and write to ctx
        report = _merge_results(results)
        ctx["evidence_validation"] = asdict(report)
        _emit_validation_event(ctx, routing, report, emitter)

    return _validate_step
