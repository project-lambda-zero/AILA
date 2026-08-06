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
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, ClassVar

from sqlalchemy.exc import SQLAlchemyError

from aila.platform.contracts.enums import OutcomeDispatchStatus
from aila.platform.services.outcome_dispatch import (
    OutcomeClaim,
    claim_outcome_for_dispatch,
)
from aila.platform.uow import UnitOfWork

__all__ = [
    "OutcomeDispatchResult",
    "OutcomeDispatcherBase",
    "OutcomeDispatcherError",
]

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
