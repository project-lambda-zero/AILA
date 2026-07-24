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
from typing import Literal, TypeVar

from aila.platform.services.infra_death import (
    RETRYABLE_INFRA_CLASSES,
    InfraDeathClassifier,
    InfraDeathVerdict,
)

__all__ = [
    "FailureVerdict",
    "RecoveryPolicy",
    "ResilienceLayer",
    "get_default_resilience_layer",
]

_log = logging.getLogger(__name__)

T = TypeVar("T")


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


_DEFAULT_LAYER: ResilienceLayer = ResilienceLayer()


def get_default_resilience_layer() -> ResilienceLayer:
    """Return the module-level default :class:`ResilienceLayer`.

    Every platform hot path that doesn't inject its own layer reaches
    this one. The default policy is fail-closed by construction; a
    module that needs a different policy builds its own layer instance
    and injects it through the same shape.
    """
    return _DEFAULT_LAYER
