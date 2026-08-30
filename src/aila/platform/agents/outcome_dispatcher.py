"""Shared OutcomeDispatcher skeleton (RFC-03 Phase 6).

Both the vr and malware modules ship a dispatcher that:

1. Atomically claims an accepted outcome for dispatch via the platform
   service ``claim_outcome_for_dispatch`` (closes the TOCTOU that would
   otherwise let two workers double-dispatch the same outcome).
2. Routes the winning claim to a per-kind handler that materialises the
   downstream artifact (child investigation, finding row, knowledge
   entry, YARA rule row, ...).
3. Persists the terminal ``dispatch_status`` (+ optional
   ``dispatch_target``) on the outcome row.

Everything OUTSIDE the per-kind body is the same skeleton. This module
owns that skeleton; each module subclasses with its own per-kind body.

Subclass contract (see :class:`OutcomeDispatcherBase`):

* Class attributes
    ``_outcome_model``           the module's SQLModel outcome record class.
    ``_outcome_kind_cls``        the module's ``OutcomeKind`` StrEnum type.
    ``_default_error_kind``      the kind stamped into the SKIPPED result
                                 returned for ``outcome_not_found`` and for
                                 not-won claims whose ``claim.outcome_kind``
                                 does not parse as ``_outcome_kind_cls``.
    ``_catch_handler_errors``    ``True`` folds handler exceptions into a
                                 FAILED result; ``False`` re-raises so the
                                 caller records the failure and retries.
    ``_log_label``               log-line prefix used for RESULT / FAILED
                                 lines.

* Overridable hooks
    ``_dispatch_state_guard(row)``    optional pre-claim guard passed to
                                      ``claim_outcome_for_dispatch``; return
                                      a skip reason to refuse the claim, or
                                      ``None`` to allow it. Default: allow.
    ``_load_outcome_row(outcome_id)`` optional post-claim reload of the
                                      outcome row; returned value is passed
                                      to ``_handle_kind`` as ``outcome_row``.
                                      Default: ``None`` (skip the reload
                                      and route from the claim snapshot).
    ``_handle_kind(...)``             REQUIRED. Route to the per-kind
                                      handler. Receives the claim snapshot
                                      (kind, payload, investigation_id) plus
                                      the reloaded ``outcome_row``.
    ``_persist_dispatch_status(...)`` write the terminal status onto the
                                      outcome row. Default: minimal write
                                      of ``dispatch_status`` +
                                      ``dispatch_target``. Modules override
                                      to add cross-row side effects (halt
                                      sibling branches, flip the parent
                                      investigation to COMPLETED, purge
                                      ARQ jobs).

The dispatch skeleton also folds two invariants shared by both modules:

* A missing outcome (``claim.found=False``) returns SKIPPED with reason
  ``"outcome_not_found"`` rather than raising, so the ARQ worker that
  runs the dispatch does not retry a permanently-missing row. Both
  callsites (vr and malware) already wrap dispatch in a broad
  try/except that catches this shape, so returning the SKIPPED result
  is a defensive normalisation.
* Not-won claims where the guard returned ``unknown_outcome_kind:<x>``
  land as FAILED (data-shape bug the operator must see) while every
  other not-won reason lands as SKIPPED (the row is fine, just not
  dispatchable by this caller).
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, ClassVar

from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import select

from aila.platform.contracts import utc_now
from aila.platform.contracts.enums import OutcomeConfidence, OutcomeDispatchStatus
from aila.platform.services.ledger import ADJUDICATION_KIND, LedgerService
from aila.platform.services.outcome_dispatch import (
    OutcomeClaim,
    claim_outcome_for_dispatch,
)
from aila.platform.uow import UnitOfWork

__all__ = [
    "FinalizeAggregateResult",
    "OutcomeDispatchResult",
    "OutcomeDispatcherBase",
    "OutcomeDispatcherError",
    "PromotedFinding",
    "finalize_investigation_aggregate",
    "handle_adjudication_refuted",
]

# Author markers stamped on ledger rows the finalize spine writes so a
# reader can distinguish aggregation-time writes from live-agent ones.
_FINALIZE_AUTHOR: str = "__finalize__"

# Ledger kind used to mark a claim as settled at finalize so a re-enqueue
# fork does not re-propose it in the fresh case_state. Consumed by the
# turn-runner's re-enqueue reader (owned by the LedgerKnowledge sibling
# widening episodic kinds); until that lands the marker is still a
# durable ledger fact so the invariant harness can observe it.
_SETTLED_CLAIM_KIND: str = "settled_claim"

# States the aggregator considers when deciding what to merge / promote.
# ``draft`` is excluded (still under sibling review) and ``rejected`` is
# excluded (already refused). ``approved`` + ``dispatched`` are the two
# surviving states after outcome_review evaluates quorum.
_AGGREGATABLE_STATES: frozenset[str] = frozenset({"approved", "dispatched"})

# Confidence order used to pick the strongest positive when multiple
# outcomes tie on kind + target signature. Higher is stronger. Kept
# local to the aggregator so a module tweaking its enum labels does not
# accidentally reorder the promotion race.
_CONFIDENCE_RANK: dict[str, int] = {
    OutcomeConfidence.EXACT.value: 4,
    OutcomeConfidence.STRONG.value: 3,
    OutcomeConfidence.MEDIUM.value: 2,
    OutcomeConfidence.CAVEATED.value: 1,
    OutcomeConfidence.UNKNOWN.value: 0,
}

_log = logging.getLogger(__name__)


class OutcomeDispatcherError(Exception):
    """Fatal dispatcher failure -- bad state, corrupt payload, missing FK.

    Raised inside a per-kind handler when the outcome cannot be
    dispatched even though the claim was won. The base skeleton either
    catches this and records a FAILED result (when
    ``_catch_handler_errors=True``) or re-raises so the caller marks the
    outcome FAILED and retries (when ``_catch_handler_errors=False``).
    """


@dataclass(slots=True)
class OutcomeDispatchResult:
    """Result of dispatching one outcome to its downstream artifact.

    ``outcome_kind`` carries an instance of the caller module's
    ``OutcomeKind`` StrEnum. The base skeleton stamps
    ``_default_error_kind`` when the outcome disappeared before the
    claim could observe it (``outcome_not_found``) or when
    ``claim.outcome_kind`` does not parse against the module enum.
    """

    outcome_id: str
    outcome_kind: StrEnum
    dispatch_status: OutcomeDispatchStatus
    dispatch_target: str | None
    reason: str = ""


class OutcomeDispatcherBase:
    """Shared dispatch skeleton for module outcome dispatchers.

    Subclass contract is documented at module top. The base owns the
    atomic claim, the not-found / not-won skip paths, the per-kind
    routing entry point, the handler-exception policy, and the terminal
    status-write.
    """

    # Subclass required -- declared here so readers see the full contract.
    _outcome_model: ClassVar[type]
    _outcome_kind_cls: ClassVar[type[StrEnum]]
    _default_error_kind: ClassVar[StrEnum]

    # Subclass optional -- defaults documented above.
    _catch_handler_errors: ClassVar[bool] = False
    _log_label: ClassVar[str] = "outcome_dispatcher"

    def _dispatch_state_guard(self, row: Any) -> str | None:
        """Optional pre-claim guard. Default: allow every found row.

        Subclass returns a short skip reason to refuse the claim (the
        row stays PENDING and no handler runs) or raises to signal a
        corrupt row. Runs inside the claim's FOR UPDATE transaction.
        """
        del row
        return None

    async def _load_outcome_row(self, outcome_id: str) -> Any | None:
        """Optional post-claim reload of the outcome row. Default: None.

        Subclass overrides when a per-kind handler needs a live row
        (VR passes ``outcome`` into three handlers for
        ``outcome.confidence``). The base uses ``claim.payload_json``
        + ``claim.investigation_id`` for the routing values themselves,
        so returning ``None`` is safe when no handler needs the row.
        """
        del outcome_id
        return None

    async def _verify_before_dispatch(
        self,
        *,
        outcome_kind: StrEnum,
        outcome_id: str,
        investigation_id: str,
        payload: dict[str, Any],
        outcome_row: Any | None,
    ) -> OutcomeDispatchResult | None:
        """Inline verifier gate for approved positive outcomes (issue #13/#14/#249 W13).

        Returns ``None`` to allow dispatch, or an ``OutcomeDispatchResult``
        (SKIPPED / FAILED) to block. Default implementation asks the VR
        module's polarity helper whether the outcome kind is
        ``"positive"``; for positive kinds it lazily imports the VR
        claim verifier's ``verify_evidence`` and refuses dispatch when
        the verdict is not ``confirmed``. Non-VR modules -- where
        neither import resolves -- fall through to the caller (fail
        safe to the prior behaviour). Any verifier error is logged and
        treated as a fail-safe allow so a broken adversarial pass does
        not permanently block a module dispatch.
        """
        polarity_fn = _load_outcome_polarity_fn()
        if polarity_fn is None:
            return None
        try:
            polarity = polarity_fn(outcome_kind)
        except (RuntimeError, ValueError, TypeError, LookupError):
            polarity = None
        if polarity != "positive":
            return None
        verify_fn = _load_verify_evidence_fn()
        if verify_fn is None:
            return None
        packet = self._build_evidence_packet(
            outcome_kind=outcome_kind,
            outcome_id=outcome_id,
            investigation_id=investigation_id,
            payload=payload,
            outcome_row=outcome_row,
        )
        try:
            verdict = await verify_fn(packet)
        except (RuntimeError, ValueError, TypeError, OSError,
                LookupError, AttributeError, ImportError) as exc:
            _log.warning(
                "%s verifier gate raised outcome_id=%s: %s (fail-safe allow)",
                self._log_label, outcome_id, exc,
            )
            return None
        if not isinstance(verdict, dict):
            return None
        raw_verdict = str(verdict.get("verdict") or "").strip().lower()
        if raw_verdict == "confirmed":
            return None
        reason = f"verifier_blocked:{raw_verdict or 'no_verdict'}"
        summary = str(verdict.get("summary") or "").strip()
        if summary:
            reason = f"{reason} ({summary[:120]})"
        return OutcomeDispatchResult(
            outcome_id=outcome_id,
            outcome_kind=outcome_kind,
            dispatch_status=OutcomeDispatchStatus.SKIPPED,
            dispatch_target=None,
            reason=reason,
        )

    def _build_evidence_packet(
        self,
        *,
        outcome_kind: StrEnum,
        outcome_id: str,
        investigation_id: str,
        payload: dict[str, Any],
        outcome_row: Any | None,
    ) -> dict[str, Any]:
        """Default evidence-packet shape passed to the verifier.

        Modules may override to add per-kind ``case_state`` / tool-call
        provenance. The shape is the one the sibling Verifier task
        publishes: ``{case_state, citations, tool_calls}``.
        """
        citations = list(payload.get("evidence_refs") or [])
        if not citations and outcome_row is not None:
            raw_refs = getattr(outcome_row, "evidence_refs_json", None)
            if raw_refs:
                try:
                    citations = list(json.loads(raw_refs))
                except (ValueError, TypeError):
                    citations = []
        return {
            "case_state": {
                "outcome_id": outcome_id,
                "investigation_id": investigation_id,
                "outcome_kind": outcome_kind.value,
                "payload": payload,
            },
            "citations": [str(c) for c in citations],
            "tool_calls": [],
        }

    async def _handle_kind(
        self,
        *,
        outcome_kind: StrEnum,
        outcome_id: str,
        investigation_id: str,
        payload: dict[str, Any],
        outcome_row: Any | None,
    ) -> OutcomeDispatchResult:
        """Route the winning claim to a per-kind handler. REQUIRED override.

        Return an ``OutcomeDispatchResult`` (any dispatch_status). Raise
        ``OutcomeDispatcherError`` on a fatal per-kind failure; the
        base's handler-exception policy decides whether to re-raise or
        fold into a FAILED result.
        """
        del outcome_kind, outcome_id, investigation_id, payload, outcome_row
        raise NotImplementedError

    async def _persist_dispatch_status(
        self,
        *,
        outcome_id: str,
        result: OutcomeDispatchResult,
    ) -> None:
        """Write the terminal dispatch_status + target on the outcome row.

        Default performs the minimal write. Modules override to add the
        cross-row cascade (halt sibling branches, flip investigation
        to COMPLETED, purge ARQ jobs) that fires only for VR today.
        """
        async with UnitOfWork() as uow:
            row = await uow.session.get(self._outcome_model, outcome_id)
            if row is None:
                return
            row.dispatch_status = result.dispatch_status.value
            row.dispatch_target = result.dispatch_target
            await uow.commit()

    async def dispatch(self, outcome_id: str) -> OutcomeDispatchResult:
        """Dispatch one outcome and return the terminal result.

        The claim is atomic (FOR UPDATE inside the platform service).
        Missing outcomes and refused claims return SKIPPED so an ARQ
        retry does not fire on a permanently-lost row. Handler
        exceptions follow the module's ``_catch_handler_errors`` policy.
        """
        claim = await claim_outcome_for_dispatch(
            self._outcome_model,
            outcome_id,
            guard=self._dispatch_state_guard,
        )
        if not claim.found:
            return OutcomeDispatchResult(
                outcome_id=outcome_id,
                outcome_kind=self._default_error_kind,
                dispatch_status=OutcomeDispatchStatus.SKIPPED,
                dispatch_target=None,
                reason="outcome_not_found",
            )
        resolved_kind = self._resolve_kind(claim)
        if not claim.won:
            return self._make_not_won_result(outcome_id, resolved_kind, claim)

        payload = self._decode_payload(claim.payload_json)
        investigation_id = claim.investigation_id or ""
        outcome_row = await self._load_outcome_row(outcome_id)

        # Issue #13 (success contrast) + #14 (adjudication source).
        # Positive-polarity outcomes gate on the VR claim verifier
        # before the module handler ships them downstream. A verdict
        # other than ``confirmed`` blocks the dispatch as SKIPPED with
        # ``verifier_blocked:<verdict>`` so a refuted-but-approved
        # finding never leaves the platform boundary. Non-VR modules
        # (malware / forensics) have no verifier import and skip the
        # gate silently.
        gate_result = await self._verify_before_dispatch(
            outcome_kind=resolved_kind,
            outcome_id=outcome_id,
            investigation_id=investigation_id,
            payload=payload,
            outcome_row=outcome_row,
        )
        if gate_result is not None:
            await self._persist_dispatch_status(
                outcome_id=outcome_id, result=gate_result,
            )
            _log.info(
                "%s VERIFIER_GATE outcome_id=%s kind=%s status=%s reason=%s",
                self._log_label, outcome_id, resolved_kind.value,
                gate_result.dispatch_status.value, gate_result.reason,
            )
            return gate_result

        try:
            result = await self._handle_kind(
                outcome_kind=resolved_kind,
                outcome_id=outcome_id,
                investigation_id=investigation_id,
                payload=payload,
                outcome_row=outcome_row,
            )
        except OutcomeDispatcherError as exc:
            if not self._catch_handler_errors:
                _log.exception(
                    "%s FAILED outcome_id=%s kind=%s",
                    self._log_label, outcome_id, resolved_kind.value,
                )
                raise
            result = OutcomeDispatchResult(
                outcome_id=outcome_id,
                outcome_kind=resolved_kind,
                dispatch_status=OutcomeDispatchStatus.FAILED,
                dispatch_target=None,
                reason=str(exc),
            )
        except (SQLAlchemyError, RuntimeError, OSError, ValueError,
                TypeError, AttributeError, LookupError, ImportError) as exc:
            if not self._catch_handler_errors:
                _log.exception(
                    "%s FAILED outcome_id=%s kind=%s",
                    self._log_label, outcome_id, resolved_kind.value,
                )
                raise
            _log.exception(
                "%s: handler crashed for %s",
                self._log_label, outcome_id,
            )
            result = OutcomeDispatchResult(
                outcome_id=outcome_id,
                outcome_kind=resolved_kind,
                dispatch_status=OutcomeDispatchStatus.FAILED,
                dispatch_target=None,
                reason=f"handler_crash:{type(exc).__name__}",
            )

        await self._persist_dispatch_status(
            outcome_id=outcome_id, result=result,
        )
        _log.info(
            "%s RESULT outcome_id=%s kind=%s status=%s target=%s reason=%s",
            self._log_label,
            result.outcome_id, result.outcome_kind.value,
            result.dispatch_status.value,
            result.dispatch_target, result.reason,
        )
        return result

    def _resolve_kind(self, claim: OutcomeClaim) -> StrEnum:
        """Parse ``claim.outcome_kind`` against the module enum.

        Unknown values fall back to ``_default_error_kind`` so the
        SKIPPED/FAILED result the base emits still stamps a valid enum
        member. The unknown-kind case is stamped as FAILED further down.
        """
        raw = claim.outcome_kind or ""
        try:
            return self._outcome_kind_cls(raw)
        except ValueError:
            return self._default_error_kind

    def _make_not_won_result(
        self,
        outcome_id: str,
        outcome_kind: StrEnum,
        claim: OutcomeClaim,
    ) -> OutcomeDispatchResult:
        """Build the result for a found-but-not-won claim.

        ``unknown_outcome_kind:<x>`` is a data-shape bug the operator
        must see, so it maps to FAILED. Every other skip reason maps
        to SKIPPED (the row is fine, just not this caller's to dispatch).
        """
        reason = claim.skip_reason or "already_claimed_or_dispatched"
        unknown_kind = reason.startswith("unknown_outcome_kind")
        status = (
            OutcomeDispatchStatus.FAILED if unknown_kind
            else OutcomeDispatchStatus.SKIPPED
        )
        _log.info(
            "%s SKIP outcome_id=%s kind=%s reason=%s",
            self._log_label, outcome_id, outcome_kind.value, reason,
        )
        return OutcomeDispatchResult(
            outcome_id=outcome_id,
            outcome_kind=outcome_kind,
            dispatch_status=status,
            dispatch_target=None,
            reason=reason,
        )

    @staticmethod
    def _decode_payload(payload_json: str | None) -> dict[str, Any]:
        """Decode ``claim.payload_json`` into a dict.

        A corrupted payload string produces an empty dict rather than
        raising -- the handler owns the missing-required-field check
        and produces a clean FAILED result with a specific reason.
        """
        try:
            return json.loads(payload_json or "{}")
        except (ValueError, TypeError) as exc:
            _log.debug(
                "outcome payload_json parse failed (%s: %s); "
                "using empty dict, handler will surface missing fields",
                type(exc).__name__, exc,
            )
            return {}


# --------------------------------------------------------------------
# Finalize / aggregate spine (issue #19 -- aggregation_spine, #13, #14).
# --------------------------------------------------------------------

def _load_outcome_polarity_fn() -> Any | None:
    """Lazy import of the VR polarity helper (platform -> module cycle safe).

    Contract locked with sibling Main: ``outcome_polarity(kind)`` returns
    ``"positive" | "negative" | "inconclusive"``. Non-VR modules that
    have no ``vr.contracts.outcome`` on the path silently disable the
    verifier gate here (returning ``None``); the caller falls through.
    """
    try:
        from aila.modules.vr.contracts.outcome import (  # noqa: PLC0415
            outcome_polarity as _fn,
        )
    except (ImportError, AttributeError):
        return None
    return _fn


def _load_verify_evidence_fn() -> Any | None:
    """Lazy import of the VR claim verifier's ``verify_evidence``.

    Sibling Verifier task owns the concrete implementation on
    ``aila.modules.vr.agents.claim_verifier``. Absence disables the
    gate silently -- the caller retains prior behaviour.
    """
    try:
        from aila.modules.vr.agents.claim_verifier import (  # noqa: PLC0415
            verify_evidence as _fn,
        )
    except (ImportError, AttributeError):
        return None
    return _fn


def _confidence_rank(value: str | None) -> int:
    return _CONFIDENCE_RANK.get(str(value or "").lower(), 0)


def _claim_signature(outcome_kind: str, payload: dict[str, Any]) -> str:
    """Stable key for grouping outcomes that assert the same claim.

    The signature intentionally uses the coarse fields the module
    payloads all carry (kind + target id + function/file locus) so a
    positive-finding row and a duplicate positive-finding row on the
    same locus land in the same aggregation bucket even when their
    prose differs.
    """
    parts: list[str] = [str(outcome_kind or "")]
    for key in (
        "target_signature", "target_id", "target",
        "function_name", "sink_function", "sink",
        "cwe", "cwe_id", "capability_id",
    ):
        value = payload.get(key)
        if value:
            parts.append(f"{key}={value}")
    file_locus = payload.get("file") or payload.get("path")
    if file_locus:
        parts.append(f"file={file_locus}")
    return "|".join(parts)


@dataclass(slots=True, frozen=True)
class PromotedFinding:
    """One promoted positive outcome selected by :func:`finalize_investigation_aggregate`."""

    outcome_id: str
    branch_id: str
    outcome_kind: str
    confidence: str
    signature: str
    supporting_outcome_ids: tuple[str, ...]


@dataclass(slots=True)
class FinalizeAggregateResult:
    """Terminal result of one finalize pass over an investigation."""

    investigation_id: str
    scanned_outcomes: int = 0
    merged_branch_pairs: list[tuple[str, str, str]] = field(default_factory=list)
    promoted: PromotedFinding | None = None
    settled_claim_ids: list[int] = field(default_factory=list)
    refuted_by_falsifier: list[str] = field(default_factory=list)
    downgraded_outcome_ids: list[str] = field(default_factory=list)


async def finalize_investigation_aggregate(
    investigation_id: str,
    *,
    outcome_model: type,
    branch_pool: Any | None = None,
    falsifier: Any | None = None,
    ledger: LedgerService | None = None,
    polarity_fn: Any | None = None,
    session: Any = None,
) -> FinalizeAggregateResult:
    """Aggregate an investigation's outcomes at finalize (issue #19).

    Doc ``.run/vr_truth_aggregation_spine.md`` \u00a72 established that
    ``BranchPool.merge()`` and ``BranchPool.promote()`` are complete
    and correct but were never invoked by any automatic caller: 0 of
    1755 branches were merged, 0 were promoted. This spine is that
    caller. Steps:

    1. Load every non-superseded, aggregatable outcome for the
       investigation (states ``approved`` / ``dispatched``).
    2. Group by claim signature (kind + target locus). Within each
       group carrying \u2265 2 outcomes, if a ``branch_pool`` is
       supplied and both branches are still ACTIVE, invoke
       :meth:`BranchPool.merge` on the two source branches -- the
       existing correct merge union (``_merge_case_states``,
       ``merge_hypotheses``) is invoked, not reimplemented.
    3. Select the strongest positive-polarity outcome across the
       investigation (highest confidence rank, ties broken by the
       larger supporting-outcome group). Optionally run
       :meth:`FalsifierAgent.try_refute` against it; a refuted verdict
       stamps ``superseded_at`` + ``state='rejected'`` on the outcome
       (issue #06 -- refuted outcomes are retracted, not dispatched).
    4. When the strongest positive survives, promote its branch via
       :meth:`BranchPool.promote` (when a pool is supplied) and record
       a ``settled_claim`` ledger entry so a subsequent re-enqueue
       fork does not re-propose the same claim (issue #08 -- stop
       re-proposing settled claims).
    5. Also write ``settled_claim`` markers for every outcome the
       aggregator considered settled (approved with a verdict).

    Every branch_pool / falsifier call is guarded: a failure on one
    branch pair or one adversarial pass does not abort the whole
    finalize. Returns a :class:`FinalizeAggregateResult` summarising
    the changes so the caller can log / audit.
    """
    ledger_svc = ledger if ledger is not None else LedgerService()
    result = FinalizeAggregateResult(investigation_id=investigation_id)

    outcomes = await _load_aggregatable_outcomes(
        outcome_model, investigation_id, session=session,
    )
    result.scanned_outcomes = len(outcomes)
    if not outcomes:
        return result

    # Group by signature.
    groups: dict[str, list[Any]] = {}
    for row in outcomes:
        payload = _decode_payload_json(row.payload_json)
        sig = _claim_signature(row.outcome_kind, payload)
        groups.setdefault(sig, []).append(row)

    # 1. Merge duplicate-signature branch pairs.
    if branch_pool is not None:
        for sig, rows in groups.items():
            if len(rows) < 2:
                continue
            branch_pairs = _distinct_branch_pairs(rows)
            for a_id, b_id in branch_pairs:
                try:
                    op = await branch_pool.merge(
                        a_id, b_id,
                        merge_reason=f"finalize_aggregate:{sig[:80]}",
                    )
                except (RuntimeError, ValueError, TypeError,
                        SQLAlchemyError) as exc:
                    _log.warning(
                        "finalize merge(%s, %s) failed inv=%s: %s",
                        a_id, b_id, investigation_id, exc,
                    )
                    continue
                result.merged_branch_pairs.append(
                    (a_id, b_id, getattr(op, "new_branch_id", "") or "")
                )

    # 2. Pick the strongest positive.
    resolved_polarity_fn = polarity_fn or _load_outcome_polarity_fn()
    strongest, supporting = _select_strongest_positive(
        groups, resolved_polarity_fn,
    )

    # 3. Falsifier pass.
    if strongest is not None and falsifier is not None:
        prior_adjudications = await _read_outcome_adjudications(
            ledger_svc, investigation_id, strongest.id, session=session,
        )
        packet = _build_falsifier_packet(strongest, prior_adjudications)
        try:
            verdict = await falsifier.try_refute(packet)
        except (RuntimeError, ValueError, TypeError,
                LookupError, AttributeError) as exc:
            _log.warning(
                "finalize falsifier raised inv=%s outcome=%s: %s",
                investigation_id, strongest.id, exc,
            )
            verdict = None
        if verdict is not None and getattr(verdict, "refuted", False):
            await handle_adjudication_refuted(
                investigation_id,
                outcome_id=strongest.id,
                outcome_model=outcome_model,
                reason=getattr(verdict, "reason", "falsifier_refuted"),
                session=session,
            )
            result.refuted_by_falsifier.append(strongest.id)
            result.downgraded_outcome_ids.append(strongest.id)
            strongest = None

    # 4. Promote surviving strongest.
    if strongest is not None:
        result.promoted = PromotedFinding(
            outcome_id=strongest.id,
            branch_id=strongest.branch_id,
            outcome_kind=strongest.outcome_kind,
            confidence=strongest.confidence,
            signature=_claim_signature(
                strongest.outcome_kind,
                _decode_payload_json(strongest.payload_json),
            ),
            supporting_outcome_ids=tuple(o.id for o in supporting),
        )
        if branch_pool is not None:
            try:
                await branch_pool.promote(
                    strongest.branch_id,
                    reason="finalize_aggregate_promotion",
                )
            except (RuntimeError, ValueError, TypeError,
                    SQLAlchemyError) as exc:
                _log.warning(
                    "finalize promote(%s) failed inv=%s: %s",
                    strongest.branch_id, investigation_id, exc,
                )

    # 5. Settle claims so a re-enqueue does not re-propose them.
    for row in outcomes:
        try:
            entry_id = await ledger_svc.append_general(
                investigation_id,
                _FINALIZE_AUTHOR,
                _SETTLED_CLAIM_KIND,
                {
                    "outcome_id": row.id,
                    "outcome_kind": row.outcome_kind,
                    "confidence": row.confidence,
                    "signature": _claim_signature(
                        row.outcome_kind,
                        _decode_payload_json(row.payload_json),
                    ),
                    "settled_at": utc_now().isoformat(),
                    "promoted": bool(
                        result.promoted
                        and result.promoted.outcome_id == row.id
                    ),
                },
                idempotency_key=f"settled:{row.id}",
                session=session,
            )
        except (RuntimeError, ValueError, TypeError) as exc:
            _log.warning(
                "finalize settled_claim write failed inv=%s outcome=%s: %s",
                investigation_id, row.id, exc,
            )
            continue
        result.settled_claim_ids.append(int(entry_id))

    _log.info(
        "finalize_aggregate inv=%s scanned=%d merged=%d promoted=%s "
        "refuted=%d settled=%d",
        investigation_id, result.scanned_outcomes,
        len(result.merged_branch_pairs),
        result.promoted.outcome_id if result.promoted else None,
        len(result.refuted_by_falsifier), len(result.settled_claim_ids),
    )
    return result


async def handle_adjudication_refuted(
    investigation_id: str,
    *,
    outcome_id: str,
    outcome_model: type,
    reason: str = "adjudication_refuted",
    session: Any = None,
) -> bool:
    """Retract a refuted outcome (issue #06 / #259).

    Doc ``.run/vr_truth_success_contrast.md`` \u00a73 traced the
    ``mov_read_senc`` finding on investigation ``609c8e3e`` where the
    verifier refuted the outcome, the investigation polarity flipped
    to ``no_finding``, but the outcome row stayed
    ``dispatch_status=pending`` and ``confidence=strong`` -- the
    refutation never reached the row so a downstream dispatcher could
    still ship a claim its own adjudicator killed. This helper closes
    that desync: on a refuted verdict it stamps ``superseded_at`` +
    ``state='rejected'`` on the outcome row so no future dispatch
    claim ever wins.

    Idempotent: an already-superseded or already-rejected row returns
    ``False`` without a write. Session-optional so a caller inside an
    existing UnitOfWork can pass its session.
    """
    del session  # UnitOfWork below owns its own session
    async with UnitOfWork() as uow:
        row = await uow.session.get(outcome_model, outcome_id)
        if row is None:
            _log.info(
                "handle_adjudication_refuted: outcome %s not found inv=%s",
                outcome_id, investigation_id,
            )
            return False
        if getattr(row, "superseded_at", None) is not None:
            return False
        if getattr(row, "state", None) == "rejected":
            return False
        row.superseded_at = utc_now()
        row.state = "rejected"
        row.dispatch_status = OutcomeDispatchStatus.SKIPPED.value
        row.dispatch_target = None
        uow.session.add(row)
        await uow.commit()
    _log.info(
        "handle_adjudication_refuted inv=%s outcome=%s reason=%s",
        investigation_id, outcome_id, reason,
    )
    return True


async def _load_aggregatable_outcomes(
    outcome_model: type, investigation_id: str, *, session: Any,
) -> list[Any]:
    """Return non-superseded outcomes in an aggregatable state."""
    del session
    async with UnitOfWork() as uow:
        rows = list((await uow.session.exec(
            select(outcome_model).where(
                outcome_model.investigation_id == investigation_id,
                outcome_model.superseded_at.is_(None),
                outcome_model.state.in_(list(_AGGREGATABLE_STATES)),
            )
        )).all())
    return rows


def _decode_payload_json(raw: str | None) -> dict[str, Any]:
    try:
        return json.loads(raw or "{}")
    except (ValueError, TypeError):
        return {}


def _distinct_branch_pairs(rows: list[Any]) -> list[tuple[str, str]]:
    seen: set[str] = set()
    branches: list[str] = []
    for row in rows:
        bid = str(row.branch_id or "")
        if not bid or bid in seen:
            continue
        seen.add(bid)
        branches.append(bid)
    pairs: list[tuple[str, str]] = []
    for idx in range(0, len(branches) - 1, 2):
        pairs.append((branches[idx], branches[idx + 1]))
    return pairs


def _select_strongest_positive(
    groups: dict[str, list[Any]],
    polarity_fn: Any | None,
) -> tuple[Any | None, list[Any]]:
    """Pick the strongest positive outcome across all groups.

    Returns ``(strongest_row, supporting_rows)`` where supporting rows
    are the same-signature outcomes that back the promoted one.
    Without a polarity function every outcome is treated as
    inconclusive -- the aggregator declines to promote to avoid
    shipping a non-VR module claim as a positive.
    """
    if polarity_fn is None:
        return None, []
    best_row: Any | None = None
    best_supporting: list[Any] = []
    best_key: tuple[int, int] = (-1, -1)
    for _sig, rows in groups.items():
        positive_rows = []
        for row in rows:
            try:
                if polarity_fn(row.outcome_kind) == "positive":
                    positive_rows.append(row)
            except (RuntimeError, ValueError, TypeError, LookupError):
                continue
        if not positive_rows:
            continue
        positive_rows.sort(
            key=lambda r: _confidence_rank(r.confidence), reverse=True,
        )
        candidate = positive_rows[0]
        key = (_confidence_rank(candidate.confidence), len(positive_rows))
        if key > best_key:
            best_key = key
            best_row = candidate
            best_supporting = positive_rows[1:]
    return best_row, best_supporting


async def _read_outcome_adjudications(
    ledger: LedgerService,
    investigation_id: str,
    outcome_id: str,
    *,
    session: Any,
) -> list[dict[str, Any]]:
    rows = await ledger.read_general(
        investigation_id, kinds=[ADJUDICATION_KIND],
        limit=100, session=session,
    )
    out: list[dict[str, Any]] = []
    for row in rows:
        payload = row.get("payload") or {}
        if str(payload.get("target_outcome_id") or "") == str(outcome_id):
            out.append(payload)
    return out


def _build_falsifier_packet(
    outcome_row: Any, prior_adjudications: list[dict[str, Any]],
) -> Any:
    """Construct the :class:`RefutationPacket` fed to the falsifier.

    Imported lazily so the aggregation spine does not pay the falsifier
    module's import cost on every finalize call. Modules with no
    falsifier deployed skip this path entirely (``falsifier is None``
    in :func:`finalize_investigation_aggregate`).
    """
    from aila.platform.agents.falsifier import RefutationPacket  # noqa: PLC0415

    payload = _decode_payload_json(outcome_row.payload_json)
    claim_text = (
        payload.get("answer")
        or payload.get("summary")
        or payload.get("headline_verdict")
        or ""
    )
    try:
        evidence = list(json.loads(outcome_row.evidence_refs_json or "[]"))
    except (ValueError, TypeError):
        evidence = []
    return RefutationPacket(
        investigation_id=outcome_row.investigation_id,
        outcome_id=outcome_row.id,
        outcome_kind=outcome_row.outcome_kind,
        claim_text=str(claim_text),
        evidence_refs=[str(e) for e in evidence],
        payload=payload,
        prior_adjudications=prior_adjudications,
    )
