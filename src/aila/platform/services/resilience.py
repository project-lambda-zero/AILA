"""RFC-07 ResilienceLayer -- single facade over the platform recovery
primitives.

Premise verification (2026-07-24). The RFC-07 acceptance bullet 2 asked
for "a single platform ResilienceLayer replaces the five duplicated
recovery services; no recovery service exists in two module copies." The
duplication half of that claim was already satisfied by RFC-04: the
recovery services (investigation reaper, investigation finalizers, stall
recovery, branch reaper, auto-steering) live once under
``aila.platform.services`` / ``aila.platform.agents``; the files at
``aila.modules.<mod>.services.*`` are thin ``functools.partial``
bindings that inject the module record models and config. The genuinely
missing half was the coherent policy facade -- each fail-open site
carried its own conservative-default value AND its own metric bump AND
its own log line, so a fix to the pattern touched five files. This
module is that facade: one place that answers

* does this exception class look like infrastructure death,
* what is the conservative default for a given operation,
* which failure signal metric fires and with what labels.

The facade is intentionally thin. It does NOT re-implement the pure
:class:`InfraDeathClassifier`, does NOT re-implement the reaper /
finalizer / stall sweeps, and does NOT change the observable
fail-closed behaviour shipped in RFC-07 step 0. Every call site keeps
its existing default value and existing raise / return semantics. What
changes: the value + metric bump route through the same helper so the
umbrella :data:`aila_resilience_signals_total` counter fires from one
place, and adding a new fail-closed site is one call rather than three
copy-paste lines.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal, TypeVar

from sqlalchemy.exc import SQLAlchemyError

__all__ = [
    "RETRYABLE_INFRA_CLASSES",
    "FailureVerdict",
    "InfraDeathClassifier",
    "InfraDeathVerdict",
    "RecoveryPolicy",
    "ResilienceLayer",
    "get_default_resilience_layer",
]


# ---------------------------------------------------------------------------
# Infra-death classifier (issue #146 item 2: inlined from the standalone
# ``aila.platform.services.infra_death`` module).
#
# Kept next to the ResilienceLayer facade because it is a pure classifier
# already wrapped by the layer (the layer exposes it via
# ``ResilienceLayer.classifier`` and no other consumer instantiates it
# directly). Behaviour identical to the removed module; the only external
# consumer (investigation_finalizers) reaches the classifier through the
# layer's ``.classifier`` handle, which still works.
#
# Return contract for ``classify()``:
#   "infra_death" -- caller must NOT synthesize a clean no-finding
#                    outcome; instead mark the investigation FAILED
#                    (retryable) with a distinct closed_reason so the
#                    operator can reopen / re-enqueue.
#   "terminal"    -- caller may proceed with the existing no-finding
#                    synthesis path.
# ---------------------------------------------------------------------------


# Error-class strings the classifier treats as infra failures. Sources:
#   * openai / provider client exception names surfaced through
#     WorkflowStateTransition.error_class ("APIConnectionError",
#     "APITimeoutError", "RateLimitError"). Provider-network transports
#     the aila LLM retry loop already treats as retryable per
#     aila.platform.llm.client._is_retryable.
#   * "LLMError" -- the platform wrapper raised with retryable=True
#     after the in-call retry budget is exhausted.
#   * "TimeoutError", "OSError", "ConnectionError" -- generic transport
#     and socket failures that surface identically for a wedged Redis
#     or Postgres session as for the LLM endpoint.
#   * "WorkflowConflictError" -- optimistic-lock loss during a turn is
#     the cursor engine's retryable signal (the whole task retries).
#   * "stale_no_progress" -- pseudo-class the finalizer feeds when a
#     branch's closed_reason starts with "stale_no_progress_"; the
#     stale-branch abandonment fires when a branch went dark, which
#     in practice means an LLM outage or a dispatcher failure earlier
#     in the run.
#
# The set is frozen at module load so callers cannot silently widen it.
RETRYABLE_INFRA_CLASSES: frozenset[str] = frozenset(
    {
        "APIConnectionError",
        "APITimeoutError",
        "ConnectionError",
        "LLMError",
        "OSError",
        "RateLimitError",
        "TimeoutError",
        "WorkflowConflictError",
        "stale_no_progress",
    }
)


InfraDeathVerdict = Literal["infra_death", "terminal"]


class InfraDeathClassifier:
    """Pure classifier: turn signals into a finalizer verdict.

    Constructed once per finalizer sweep tick; classify() is called per
    orphan-candidate investigation. Holds no state -- kept as a class
    so callers pin a stable object identity through their DI wiring
    and so a future increment (per-module tuning of the infra class
    set) has an obvious extension point.
    """

    def classify(
        self,
        *,
        branch_turn_count: int,
        recent_turn_errors: Sequence[str],
        llm_unhealthy_at_close: bool,
    ) -> InfraDeathVerdict:
        """Return "infra_death" when the tail of the run died to infra.

        branch_turn_count:
            Total reasoning turns the investigation actually completed
            (summed across its branches). The zero-turn case is owned
            by the finalizer's existing zero-turn guard -- treat 0 as
            "terminal" here so a caller that forgets the outer guard
            still degrades to the pre-classifier behaviour rather than
            silently masking every zero-turn run as infra_death.
        recent_turn_errors:
            Small ordered sequence of error-class strings observed on
            the tail turns / branch closed_reasons. Any string that
            appears in RETRYABLE_INFRA_CLASSES flips the verdict to
            infra_death.
        llm_unhealthy_at_close:
            The is_llm_recently_unhealthy() snapshot at the moment the
            finalizer is about to synthesize this specific outcome. The
            outer sweep also gates on this, so it is typically False by
            the time we reach here; when True (per-id path, race, or
            future callers that bypass the sweep gate) it is a hard
            infra_death signal.
        """
        # Zero-turn: the finalizer's existing zero-turn guard handles
        # this via a distinct FAILED close reason; if we somehow reach
        # here for a zero-turn candidate the safe default is to let the
        # caller's outer branch decide, not to relabel it infra_death.
        if branch_turn_count <= 0:
            return "terminal"

        if llm_unhealthy_at_close:
            return "infra_death"

        for err_class in recent_turn_errors:
            if err_class and err_class in RETRYABLE_INFRA_CLASSES:
                return "infra_death"

        return "terminal"

_log = logging.getLogger(__name__)

T = TypeVar("T")

# Ledger author for a heal record. A recovery event is operational, not a
# persona contribution, so it carries a distinct system author and a
# distinct kind the agent-prompt board filters out (see turn_runner
# _load_ledger_board).
_RECOVERY_ACTOR = "__resilience__"
_RECOVERY_KIND = "recovery"


# Operation names that ALSO bump SSE_WRITE_FAILURES_TOTAL for dashboard
# compatibility. The umbrella RESILIENCE_SIGNALS_TOTAL fires for every
# recorded signal regardless of this set; membership only decides
# whether the legacy SSE counter also ticks so existing operator
# dashboards built on ``aila_sse_write_failures_total`` keep reading
# the same series after this consolidation.
_SSE_MIRRORED_OPS: frozenset[str] = frozenset(
    {"sse_write", "workflow_log_emit"},
)


@dataclass(frozen=True, slots=True)
class RecoveryPolicy:
    """Fail-mode policy carried by a :class:`ResilienceLayer` instance.

    ``fail_mode="closed"`` is the production posture and the constructed
    default. Every conservative-default helper still bumps the failure
    signal metric under either mode -- the mode governs the return
    value, not the observability, so an operator can flip a diagnostic
    layer to ``"open"`` without losing the counter.
    """

    fail_mode: Literal["closed", "open"] = "closed"


@dataclass(frozen=True, slots=True)
class FailureVerdict:
    """Structured verdict returned by :meth:`ResilienceLayer.classify_failure`.

    ``kind`` is the raw :type:`InfraDeathVerdict` for callers that only
    branch on infra-death vs terminal. ``retryable`` is a convenience
    for the retry / defer sites -- true when any recorded error class
    is in :data:`RETRYABLE_INFRA_CLASSES` or the LLM was unhealthy at
    the moment of classification. ``reason`` mirrors ``kind`` as a
    stable label suitable for a metric or a log line.
    """

    kind: InfraDeathVerdict
    retryable: bool
    reason: str


class ResilienceLayer:
    """Single facade over the RFC-07 recovery primitives.

    Composes :class:`InfraDeathClassifier` + the umbrella failure-signal
    metric behind three call shapes:

    * :meth:`classify_failure` -- turn signals into a
      :class:`FailureVerdict` (infra_death vs terminal + retryable).
    * :meth:`should_retry` -- boolean shortcut over the canonical
      :data:`RETRYABLE_INFRA_CLASSES` set.
    * :meth:`conservative_default` -- return the fail-closed fallback
      AND bump the failure signal in one call, so the pattern lives in
      exactly one place.

    Modules that need a custom fail-mode instantiate their own layer;
    every platform hot path that doesn't inject one reaches
    :func:`get_default_resilience_layer`.
    """

    def __init__(self, *, policy: RecoveryPolicy | None = None) -> None:
        self._policy = policy if policy is not None else RecoveryPolicy()
        self._classifier = InfraDeathClassifier()

    @property
    def policy(self) -> RecoveryPolicy:
        """Return the immutable :class:`RecoveryPolicy` this layer carries."""
        return self._policy

    @property
    def classifier(self) -> InfraDeathClassifier:
        """Expose the underlying classifier for legacy singletons.

        The RFC-07 finalizer wires its module-level classifier singleton
        through this property so a future policy tweak (e.g. widening
        the retryable-infra set) only needs to be reflected inside the
        layer -- every consumer picks it up automatically.
        """
        return self._classifier

    def should_retry(self, error_class: str | None) -> bool:
        """Return True when ``error_class`` names a retryable infra failure.

        Wraps membership in :data:`RETRYABLE_INFRA_CLASSES` so callers
        don't reach around the facade to import the frozenset. An empty
        or ``None`` class name is not retryable -- an unknown failure
        is treated as terminal per fail-closed posture.
        """
        if not error_class:
            return False
        return error_class in RETRYABLE_INFRA_CLASSES

    def classify_failure(
        self,
        *,
        error_class: str | None = None,
        branch_turn_count: int = 1,
        recent_turn_errors: Sequence[str] = (),
        llm_unhealthy_at_close: bool = False,
    ) -> FailureVerdict:
        """Classify a failure signal into infra_death vs terminal.

        Wraps :meth:`InfraDeathClassifier.classify` and additionally
        lets a caller supply a single exception-class string
        (e.g. ``"APITimeoutError"``). The single class is appended to
        ``recent_turn_errors`` before classification, so the common
        per-exception call site does not have to build a list.

        The returned :class:`FailureVerdict` carries the raw classifier
        verdict, a boolean retryable flag (any retryable-infra class in
        the merged tail or LLM unhealthy at close), and a stable reason
        label usable for a metric or log line.
        """
        merged: list[str] = [cls for cls in recent_turn_errors if cls]
        if error_class:
            merged.append(error_class)
        verdict: InfraDeathVerdict = self._classifier.classify(
            branch_turn_count=branch_turn_count,
            recent_turn_errors=merged,
            llm_unhealthy_at_close=llm_unhealthy_at_close,
        )
        retryable = (
            llm_unhealthy_at_close
            or any(cls in RETRYABLE_INFRA_CLASSES for cls in merged)
        )
        return FailureVerdict(
            kind=verdict,
            retryable=retryable,
            reason=verdict,
        )

    def record_signal(
        self,
        *,
        op: str,
        source: str,
        exc: BaseException | None = None,
    ) -> None:
        """Bump the umbrella failure signal metric in exactly one place.

        Every fail-open / fail-closed site that used to log-then-bump
        funnels here. Guarantees:

        * Metric imports are deferred so this module stays importable
          from tests and CLI paths where prometheus_client is absent.
        * Metric bump failures are logged at DEBUG only, never raised
          -- an observability increment MUST NEVER kill the caller.
        * When ``op`` names an SSE / progress-stream path
          (see :data:`_SSE_MIRRORED_OPS`) the legacy
          ``SSE_WRITE_FAILURES_TOTAL`` also ticks so existing operator
          dashboards keep reading from the counter they were built on.
        """
        exc_class = type(exc).__name__ if exc is not None else ""
        _log.warning(
            "resilience signal op=%s source=%s exc=%s",
            op,
            source,
            exc_class or "n/a",
        )
        try:
            from aila.api.metrics import RESILIENCE_SIGNALS_TOTAL

            RESILIENCE_SIGNALS_TOTAL.labels(op=op, source=source).inc()
        except (
            ImportError,
            AttributeError,
            RuntimeError,
            ValueError,
        ) as bump_exc:
            _log.debug(
                "RESILIENCE_SIGNALS_TOTAL bump skipped: %s", bump_exc,
            )
        if op in _SSE_MIRRORED_OPS:
            try:
                from aila.api.metrics import SSE_WRITE_FAILURES_TOTAL

                SSE_WRITE_FAILURES_TOTAL.labels(source=source).inc()
            except (
                ImportError,
                AttributeError,
                RuntimeError,
                ValueError,
            ) as bump_exc:
                _log.debug(
                    "SSE_WRITE_FAILURES_TOTAL bump skipped: %s", bump_exc,
                )

    def conservative_default(
        self,
        value: T,
        *,
        op: str,
        source: str,
        exc: BaseException | None = None,
    ) -> T:
        """Return ``value`` after bumping the failure signal for ``op``.

        Callers that hit a fail-closed branch use this in place of the
        historical three-line pattern (log warning; bump metric; return
        conservative default) so the pattern lives in exactly one place.
        The return value is passed through untouched: the layer never
        second-guesses the caller's choice of fallback -- it only
        guarantees the signal fires.
        """
        self.record_signal(op=op, source=source, exc=exc)
        return value

    async def emit_recovery_event(
        self,
        *,
        investigation_id: str | None,
        action: str,
        detail: dict[str, Any] | None = None,
        source: str = "resilience",
    ) -> None:
        """Record a heal as a durable, replayable event so recovery is
        itself auditable (RFC-07 #31).

        A heal (reconcile, re-enqueue, reroute, model downgrade, infra
        close) calls this so the run RECORDS the repair instead of only
        logging it. The umbrella signal always fires; when an
        ``investigation_id`` is resolvable, a durable ``kind='recovery'``
        entry is appended to the shared investigation ledger through
        :class:`LedgerService` (the sole ledger writer, so honesty rule 51
        holds). ``_load_ledger_board`` filters ``kind='recovery'`` out of
        the agent prompt, so a recovery event is an operator / audit trail,
        never an agent-facing observable.

        Best-effort on the durable write: a journal failure logs and the
        signal remains the record; the heal must never fail because its
        audit row could not be written. With no resolvable
        ``investigation_id`` (a task-level heal that cannot map to a run)
        the umbrella signal is the record.
        """
        self.record_signal(op="recovery", source=f"{source}:{action}")
        if not investigation_id:
            return
        try:
            # Lazy import: resilience is imported before db_models finishes
            # loading (tasks -> services -> resilience); deferring to call
            # time breaks the cycle (same pattern as phase_graph).
            from aila.platform.services.ledger import LedgerService

            payload: dict[str, Any] = {"action": action, "source": source}
            if detail:
                payload["detail"] = detail
            await LedgerService().append_general(
                str(investigation_id), _RECOVERY_ACTOR, _RECOVERY_KIND, payload,
            )
        except (SQLAlchemyError, OSError, RuntimeError, ValueError, TypeError) as exc:
            _log.warning(
                "emit_recovery_event durable write failed (best-effort) "
                "inv=%s action=%s: %s",
                investigation_id, action, exc,
            )


_DEFAULT_LAYER: ResilienceLayer = ResilienceLayer()


def get_default_resilience_layer() -> ResilienceLayer:
    """Return the module-level default :class:`ResilienceLayer`.

    Every platform hot path that doesn't inject its own layer reaches
    this one. The default policy is fail-closed by construction; a
    module that needs a different policy builds its own layer instance
    and injects it through the same shape.
    """
    return _DEFAULT_LAYER
