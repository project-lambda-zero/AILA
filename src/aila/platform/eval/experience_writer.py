"""RFC-08 step 1: turn a reviewed outcome into a signed pattern.

The outcome-review quorum (``platform/services/outcome_review.py``) writes
one of three terminal verdicts onto a draft outcome: ``approved`` (siblings
reached the approve quorum), ``rejected`` (reject-quorum veto), or the row
stays ``draft`` (undecided). ``ExperienceWriter`` consumes an already-
evaluated ``QuorumOutcome`` and writes a matching signed row into the
module's ``PatternStore`` -- a positive pattern on approve, a NEGATIVE
pattern on reject. Draft / abstain / no-transition results write nothing.

Negative signing carries three signals so a retrieval that ranks patterns
purely on similarity still sees the down-weight:

* ``applicability["polarity"] = "negative"`` -- structured filter available
  to any caller that wants to skip or discount negatives (RFC-08 says the
  negative "lowers a prior, does not hard-block").
* ``confidence = PatternConfidence.CAVEATED`` -- the lowest confidence in
  the platform enum (``EXACT``, ``STRONG``, ``MEDIUM``, ``CAVEATED``,
  ``UNKNOWN``); the mirrored KnowledgeEntry's metadata carries the same
  caveated confidence so the pgvector rank sees a down-weight signal.
* summary prefix ``[NEGATIVE] `` so an operator inspecting the pattern
  catalog sees the polarity without opening the JSON.

Generic over the module: the writer takes the module's ``PatternStore`` and
its ``PatternCreate`` class as constructor deps; the platform never names a
specific module. The ``pattern_kind`` (module's ``PatternKind`` enum value)
is passed by the caller because platform code cannot enumerate module
vocabulary (honesty rule 48).

The writer never touches the eval gate or the promotion path. Recording a
pattern is an OBSERVATION of the review verdict; whether that pattern
influences future prompts is decided later by the retriever + relevance
floor + the eval harness, per the propose-and-gate contract.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from aila.platform.contracts.enums import PatternConfidence, PatternScope

if TYPE_CHECKING:
    from aila.platform.services.outcome_review import QuorumOutcome
    from aila.platform.services.pattern_store import PatternStoreBase

# Module-scope import of ``aila.platform.services.pattern_store`` would
# pull ``services/__init__ -> audit -> journal -> db_models`` at import
# time, which is precisely the load-order that ``db_models`` itself is in
# the middle of when it eager-registers eval.models. Same cycle the
# outcome_review constants comment covers. ``PatternStoreBase`` is a
# duck-typed constructor argument here (the writer only calls ``.create``
# on it) so the runtime class is never dereferenced, and
# ``from __future__ import annotations`` keeps the constructor annotation
# as a string that gets resolved on demand.

# Outcome-state string literals held here as SINGLE SOURCE for the eval
# module. The canonical declaration lives in
# ``aila.platform.services.outcome_review`` (``OUTCOME_STATE_APPROVED`` /
# ``OUTCOME_STATE_REJECTED``); importing that module at module scope
# creates a load-time cycle through ``services/__init__ -> audit ->
# journal -> db_models -> eval.models`` (``db_models`` is the eager
# registrar for eval tables). Duplicating two three-letter strings costs
# nothing and honesty rule 2 explicitly permits it when the alternative
# is a cycle -- a single-line divergence between the two files would be
# caught by ``tests/platform/eval/test_rfc08_self_improvement`` which
# feeds real ``QuorumOutcome`` instances built with the outcome_review
# helpers into ``record`` and asserts the two branches fire.
_OUTCOME_STATE_APPROVED: str = "approved"
_OUTCOME_STATE_REJECTED: str = "rejected"

__all__ = [
    "EXPERIENCE_POLARITY_KEY",
    "EXPERIENCE_POLARITY_NEGATIVE",
    "EXPERIENCE_POLARITY_POSITIVE",
    "ExperienceWriter",
    "ExperienceWriteResult",
    "NEGATIVE_SUMMARY_PREFIX",
]

_log = logging.getLogger(__name__)


# Applicability key + values used to sign the polarity of a review-derived
# pattern. Retrievers can filter on this key to either skip negatives or
# down-weight them beyond the confidence signal alone. Kept as module
# constants so callers and tests share one string.
EXPERIENCE_POLARITY_KEY: str = "polarity"
EXPERIENCE_POLARITY_POSITIVE: str = "positive"
EXPERIENCE_POLARITY_NEGATIVE: str = "negative"

# Prefix stamped on rejected-outcome pattern summaries so a human reading
# the catalog sees the polarity without opening the JSON blob. Applies only
# to the negative branch; approved outcomes keep the caller's raw summary.
NEGATIVE_SUMMARY_PREFIX: str = "[NEGATIVE] "


@dataclass(frozen=True, slots=True)
class ExperienceWriteResult:
    """Outcome of one :meth:`ExperienceWriter.record` call.

    ``pattern_id`` is ``None`` when the verdict was neither approved nor
    rejected (draft outcomes and no-transition tallies never generate a
    pattern). ``polarity`` echoes which branch fired -- callers use this to
    audit which review verdicts produced which side of the catalog.
    """

    outcome_id: str
    pattern_id: str | None
    polarity: str
    skipped_reason: str = ""


class ExperienceWriter:
    """Write signed patterns into a PatternStore from review verdicts."""

    def __init__(
        self,
        *,
        pattern_store: PatternStoreBase,
        pattern_create_cls: type[Any],
        pattern_kind: Any,
    ) -> None:
        """Bind to one module's pattern store + pattern shape.

        Args:
            pattern_store: A concrete :class:`PatternStoreBase` subclass
                instance (e.g. the module's ``PatternStore``). The writer
                delegates every insert through ``pattern_store.create`` so
                the pair-write (module patterns table + KnowledgeEntryRecord
                mirror) stays the single write path.
            pattern_create_cls: The module's ``PatternCreate`` Pydantic
                class (subclass of ``PatternCreateBase``). Instantiated with
                the review-derived fields and handed to ``create``.
            pattern_kind: The module's ``PatternKind`` enum value to stamp
                on every review-derived pattern. Platform code cannot pick
                a module-specific kind, so the caller supplies it. A common
                choice is a general kind like ``TRIAGE_RULE`` for the vr
                module or ``TRIAGE_RULE``'s malware analogue.
        """
        self._store = pattern_store
        self._create_cls = pattern_create_cls
        self._kind = pattern_kind

    async def record(
        self,
        *,
        workspace_id: str,
        investigation_id: str | None,
        verdict: QuorumOutcome,
        summary: str,
        body: str,
        team_id: str | None = None,
        evidence_refs: list[str] | None = None,
        applicability: dict[str, Any] | None = None,
        scope: PatternScope = PatternScope.LOCAL,
    ) -> ExperienceWriteResult:
        """Persist a signed pattern from one review verdict.

        Approved verdicts write a positive pattern with the caller's summary
        + body verbatim and ``PatternConfidence.MEDIUM``. Rejected verdicts
        write a negative pattern with the summary prefixed by
        :data:`NEGATIVE_SUMMARY_PREFIX`, the ``polarity`` marker in
        applicability, and ``PatternConfidence.LOW``. Every other verdict
        state (draft, no-transition tally, unrecognized value) skips.
        """
        # Extract state before branching so the skip result can name it.
        state = verdict.new_state
        if state == _OUTCOME_STATE_APPROVED:
            polarity = EXPERIENCE_POLARITY_POSITIVE
        elif state == _OUTCOME_STATE_REJECTED:
            polarity = EXPERIENCE_POLARITY_NEGATIVE
        else:
            _log.debug(
                "experience_writer: skip outcome_id=%s state=%s (not terminal)",
                verdict.outcome_id, state,
            )
            return ExperienceWriteResult(
                outcome_id=verdict.outcome_id,
                pattern_id=None,
                polarity="",
                skipped_reason=f"non_terminal_state:{state}",
            )

        clean_summary = summary.strip()
        clean_body = body.strip()
        if not clean_summary or not clean_body:
            return ExperienceWriteResult(
                outcome_id=verdict.outcome_id,
                pattern_id=None,
                polarity=polarity,
                skipped_reason="empty_summary_or_body",
            )

        signed_summary, signed_confidence = self._sign(clean_summary, polarity)
        signed_applicability = self._merge_polarity(applicability, polarity)
        signed_refs = list(evidence_refs) if evidence_refs else []

        create_body = self._create_cls(
            workspace_id=workspace_id,
            investigation_id=investigation_id,
            kind=self._kind,
            summary=signed_summary[:512],
            body=clean_body,
            applicability=signed_applicability,
            confidence=signed_confidence,
            evidence_refs=signed_refs,
            scope=scope,
        )
        row = await self._store.create(create_body, team_id=team_id)
        _log.info(
            "experience_writer: wrote pattern_id=%s polarity=%s outcome_id=%s",
            row.id, polarity, verdict.outcome_id,
        )
        return ExperienceWriteResult(
            outcome_id=verdict.outcome_id,
            pattern_id=row.id,
            polarity=polarity,
        )

    @staticmethod
    def _sign(
        summary: str, polarity: str,
    ) -> tuple[str, PatternConfidence]:
        """Return the polarity-adjusted summary + confidence pair.

        The negative branch signals the polarity three ways (prefix,
        applicability marker, low confidence) so callers ranking on any of
        the three signals see the down-weight. The positive branch leaves
        the summary untouched -- polarity marker still lands in
        applicability for symmetry with the retriever's structured filter.
        """
        if polarity == EXPERIENCE_POLARITY_NEGATIVE:
            return NEGATIVE_SUMMARY_PREFIX + summary, PatternConfidence.CAVEATED
        return summary, PatternConfidence.MEDIUM

    @staticmethod
    def _merge_polarity(
        applicability: dict[str, Any] | None, polarity: str,
    ) -> dict[str, Any]:
        """Return applicability with the polarity marker set.

        The marker is always written by this writer even when the caller
        supplied one: the polarity is derived from the verdict, not the
        caller's guess.
        """
        merged: dict[str, Any] = dict(applicability) if applicability else {}
        merged[EXPERIENCE_POLARITY_KEY] = polarity
        return merged
