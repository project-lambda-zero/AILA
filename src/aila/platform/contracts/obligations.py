"""Evidence obligation system for deterministic claim adjudication.

Platform-level contracts any module (vr, forensics, ...) can use to enforce
evidence requirements on LLM-generated claims. The adjudicator is a pure
function that runs after the LLM produces text and returns one of three
verdicts: accepted, downgraded, blocked. No DB, no IO, no module imports.
"""
from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

__all__ = [
    "AdjudicationResult",
    "CONTRADICTION_SIGNALS",
    "EvidenceObligation",
    "ObligationSet",
    "ObligationSeverity",
    "adjudicate",
]


CONTRADICTION_SIGNALS: tuple[str, ...] = (
    "might be possible",
    "could potentially",
    "theoretically",
    "in some configurations",
    "under certain conditions",
    "if ASLR is disabled",
    "assuming no mitigations",
)
"""Hedge phrases that flag a claim as speculative; case-insensitive substrings."""


class ObligationSeverity(StrEnum):
    """CRITICAL blocks submission; REQUIRED blocks advisory; RECOMMENDED logged."""

    CRITICAL = "critical"
    REQUIRED = "required"
    RECOMMENDED = "recommended"


class EvidenceObligation(BaseModel):
    """A single claim that must be backed by named evidence before yielding."""

    id: str
    claim: str
    required_evidence: str
    severity: ObligationSeverity
    satisfied: bool = False
    evidence_ref: str | None = None
    waived: bool = False
    waiver_reason: str | None = None
    waiver_source: str | None = None

    @property
    def outstanding(self) -> bool:
        return not (self.satisfied or self.waived)

    @property
    def blocking(self) -> bool:
        return self.outstanding and self.severity in (
            ObligationSeverity.CRITICAL, ObligationSeverity.REQUIRED,
        )


class ObligationSet(BaseModel):
    """Mutable collection of evidence obligations with adjudication helpers."""

    obligations: list[EvidenceObligation] = Field(default_factory=list)

    def _index(self, obligation_id: str) -> int:
        for idx, ob in enumerate(self.obligations):
            if ob.id == obligation_id:
                return idx
        return -1

    def add(self, obligation: EvidenceObligation) -> None:
        """Append obligation. Re-adding the same id is a no-op (first wins)."""
        if self._index(obligation.id) >= 0:
            return
        self.obligations.append(obligation)

    def satisfy(self, obligation_id: str, evidence_ref: str) -> bool:
        """Mark obligation satisfied. Returns False for unknown ids."""
        idx = self._index(obligation_id)
        if idx < 0:
            return False
        target = self.obligations[idx]
        target.satisfied = True
        target.evidence_ref = evidence_ref
        return True

    def waive(
        self,
        obligation_id: str,
        reason: str,
        source: str = "operator",
    ) -> bool:
        """Mark obligation waived. Returns False for unknown ids."""
        idx = self._index(obligation_id)
        if idx < 0:
            return False
        target = self.obligations[idx]
        target.waived = True
        target.waiver_reason = reason
        target.waiver_source = source
        return True

    @property
    def blocking(self) -> list[EvidenceObligation]:
        """Outstanding obligations whose severity blocks output."""
        return [ob for ob in self.obligations if ob.blocking]

    @property
    def all_critical_met(self) -> bool:
        return all(
            ob.satisfied or ob.waived for ob in self.obligations
            if ob.severity is ObligationSeverity.CRITICAL
        )

    @property
    def all_required_met(self) -> bool:
        return all(
            ob.satisfied or ob.waived for ob in self.obligations
            if ob.severity in (ObligationSeverity.CRITICAL, ObligationSeverity.REQUIRED)
        )

    def summary_for_prompt(self) -> str:
        """Render the obligation state as a system-prompt fragment for the LLM."""
        if not self.obligations:
            return "No evidence obligations registered."
        buckets: dict[ObligationSeverity, list[EvidenceObligation]] = {
            ObligationSeverity.CRITICAL: [],
            ObligationSeverity.REQUIRED: [],
            ObligationSeverity.RECOMMENDED: [],
        }
        for ob in self.obligations:
            buckets[ob.severity].append(ob)
        lines: list[str] = []
        for severity in (
            ObligationSeverity.CRITICAL,
            ObligationSeverity.REQUIRED,
            ObligationSeverity.RECOMMENDED,
        ):
            bucket = buckets[severity]
            if not bucket:
                continue
            lines.append(f"[{severity.value.upper()}]")
            for ob in bucket:
                if ob.satisfied:
                    state = f"SATISFIED via {ob.evidence_ref or 'evidence'}"
                elif ob.waived:
                    state = f"WAIVED ({ob.waiver_reason or 'no reason'})"
                else:
                    state = "OUTSTANDING"
                lines.append(
                    f"  - {ob.id}: {ob.claim} "
                    f"| needs {ob.required_evidence} | {state}"
                )
        return "\n".join(lines)


class AdjudicationResult(BaseModel):
    """Outcome of `adjudicate()`. The function never raises -- it returns this."""

    verdict: str
    original_claim: str
    adjusted_claim: str | None = None
    reason: str
    unmet_obligations: list[str] = Field(default_factory=list)
    contradiction_signals: list[str] = Field(default_factory=list)


_NEGATIVE_PRIORS: frozenset[str] = frozenset({"blocked", "invalid", "downgraded"})


def _detect_signals(text: str) -> list[str]:
    haystack = text.lower()
    return [signal for signal in CONTRADICTION_SIGNALS if signal in haystack]


def adjudicate(
    claim: str,
    reasoning_text: str,
    obligations: ObligationSet,
    previous_verdict: str | None = None,
) -> AdjudicationResult:
    """Order: unmet CRITICAL -> blocked, unmet REQUIRED -> downgraded,
    hedge signals -> downgraded, neg-prior with required unmet -> blocked.
    Empty set + no signals -> accepted.
    """
    unmet_critical = [
        ob.id for ob in obligations.obligations
        if ob.severity is ObligationSeverity.CRITICAL and ob.outstanding
    ]
    unmet_required = [
        ob.id for ob in obligations.obligations
        if ob.severity is ObligationSeverity.REQUIRED and ob.outstanding
    ]
    signals = _detect_signals(reasoning_text)

    if unmet_critical:
        return AdjudicationResult(
            verdict="blocked",
            original_claim=claim,
            reason=f"Critical obligations unmet: {', '.join(unmet_critical)}.",
            unmet_obligations=unmet_critical + unmet_required,
            contradiction_signals=signals,
        )
    if unmet_required:
        return AdjudicationResult(
            verdict="downgraded",
            original_claim=claim,
            adjusted_claim=f"[advisory withheld] {claim}",
            reason=f"Required obligations unmet: {', '.join(unmet_required)}.",
            unmet_obligations=unmet_required,
            contradiction_signals=signals,
        )
    if signals:
        return AdjudicationResult(
            verdict="downgraded",
            original_claim=claim,
            adjusted_claim=f"[hedged] {claim}",
            reason=f"Reasoning contains hedge phrases: {', '.join(signals)}.",
            contradiction_signals=signals,
        )
    if previous_verdict in _NEGATIVE_PRIORS and not obligations.all_required_met:
        return AdjudicationResult(
            verdict="blocked",
            original_claim=claim,
            reason=(
                f"Previous verdict was {previous_verdict!r} and required "
                "obligations not all satisfied. Cannot upgrade without new evidence."
            ),
            unmet_obligations=[ob.id for ob in obligations.blocking],
        )
    return AdjudicationResult(
        verdict="accepted",
        original_claim=claim,
        adjusted_claim=claim,
        reason="All obligations met or waived; no contradiction signals.",
    )
