"""Unit tests for the RFC-07 ResilienceLayer facade.

Covers the three call shapes the fail-open sites route through
(``classify_failure``, ``conservative_default``, ``should_retry``) and
the umbrella + SSE-mirrored signal contract of ``record_signal``. Pure
in-process -- no DB, no Redis, no ARQ; the facade is deliberately thin
so this suite runs in a few milliseconds.
"""

from __future__ import annotations

import pytest

from aila.platform.services.infra_death import (
    RETRYABLE_INFRA_CLASSES,
    InfraDeathClassifier,
)
from aila.platform.services.resilience import (
    FailureVerdict,
    RecoveryPolicy,
    ResilienceLayer,
    get_default_resilience_layer,
)


@pytest.fixture
def layer() -> ResilienceLayer:
    """Fresh fail-closed layer per test; the class holds no shared state."""
    return ResilienceLayer()


# ---------------------------------------------------------------------------
# Policy + composition contract
# ---------------------------------------------------------------------------


class TestPolicyAndComposition:
    """The layer wires the pieces the RFC-07 acceptance bullet 2 consolidates."""

    def test_default_policy_is_fail_closed(self, layer: ResilienceLayer) -> None:
        """Default construction MUST land on the production fail-closed posture."""
        assert layer.policy == RecoveryPolicy()
        assert layer.policy.fail_mode == "closed"

    def test_custom_policy_is_carried_verbatim(self) -> None:
        """A caller that hands in a diagnostic ``open`` policy keeps it."""
        policy = RecoveryPolicy(fail_mode="open")
        layer = ResilienceLayer(policy=policy)
        assert layer.policy is policy
        assert layer.policy.fail_mode == "open"

    def test_classifier_property_returns_underlying_classifier(
        self, layer: ResilienceLayer,
    ) -> None:
        """Finalizer wires its module-level singleton off this property."""
        assert isinstance(layer.classifier, InfraDeathClassifier)

    def test_default_layer_is_singleton(self) -> None:
        """Every hot path reaches the same shared instance."""
        assert get_default_resilience_layer() is get_default_resilience_layer()


# ---------------------------------------------------------------------------
# should_retry
# ---------------------------------------------------------------------------


class TestShouldRetry:
    """Boolean shortcut over the canonical RETRYABLE_INFRA_CLASSES frozenset."""

    def test_none_error_class_is_not_retryable(
        self, layer: ResilienceLayer,
    ) -> None:
        """Missing error class name defaults to terminal -- fail-closed posture."""
        assert layer.should_retry(None) is False

    def test_empty_error_class_is_not_retryable(
        self, layer: ResilienceLayer,
    ) -> None:
        """Empty string is treated as missing."""
        assert layer.should_retry("") is False

    def test_unknown_error_class_is_not_retryable(
        self, layer: ResilienceLayer,
    ) -> None:
        """An unknown class name is terminal, not retryable."""
        assert layer.should_retry("ValueError") is False
        assert layer.should_retry("KeyError") is False

    @pytest.mark.parametrize("cls", sorted(RETRYABLE_INFRA_CLASSES))
    def test_every_retryable_infra_class_is_retryable(
        self, layer: ResilienceLayer, cls: str,
    ) -> None:
        """Contract with :data:`RETRYABLE_INFRA_CLASSES`: every entry retries."""
        assert layer.should_retry(cls) is True


# ---------------------------------------------------------------------------
# classify_failure
# ---------------------------------------------------------------------------


class TestClassifyFailureInfraDeath:
    """Cases that MUST resolve to infra_death + retryable."""

    def test_single_error_class_kwarg_flips_verdict(
        self, layer: ResilienceLayer,
    ) -> None:
        """The per-exception convenience shape (one error_class kwarg)."""
        v = layer.classify_failure(
            error_class="APITimeoutError", branch_turn_count=5,
        )
        assert v.kind == "infra_death"
        assert v.retryable is True
        assert v.reason == "infra_death"

    def test_llm_unhealthy_at_close_is_hard_infra_death(
        self, layer: ResilienceLayer,
    ) -> None:
        """Live LLM outage at classification time is a hard signal."""
        v = layer.classify_failure(
            branch_turn_count=42, llm_unhealthy_at_close=True,
        )
        assert v.kind == "infra_death"
        assert v.retryable is True

    def test_error_class_in_recent_turn_errors_flips_verdict(
        self, layer: ResilienceLayer,
    ) -> None:
        """The classic sequence-tail signal shape still works."""
        v = layer.classify_failure(
            recent_turn_errors=("stale_no_progress",),
            branch_turn_count=7,
        )
        assert v.kind == "infra_death"
        assert v.retryable is True

    def test_error_class_kwarg_merges_with_recent_turn_errors(
        self, layer: ResilienceLayer,
    ) -> None:
        """Convenience kwarg is appended to the sequence before classifying."""
        v = layer.classify_failure(
            recent_turn_errors=("SomeOtherError",),
            error_class="LLMError",
            branch_turn_count=3,
        )
        assert v.kind == "infra_death"
        assert v.retryable is True


class TestClassifyFailureTerminal:
    """Cases that MUST resolve to terminal + not retryable."""

    def test_unknown_error_class_is_terminal(
        self, layer: ResilienceLayer,
    ) -> None:
        """An unknown exception class name reads as terminal (fail-closed)."""
        v = layer.classify_failure(
            error_class="ValueError", branch_turn_count=5,
        )
        assert v.kind == "terminal"
        assert v.retryable is False
        assert v.reason == "terminal"

    def test_zero_turn_returns_terminal(self, layer: ResilienceLayer) -> None:
        """Zero-turn owner is the finalizer's outer guard; layer defers."""
        v = layer.classify_failure(
            error_class="APITimeoutError", branch_turn_count=0,
        )
        # Zero-turn defers to the outer FAILED-close path; classifier
        # returns terminal so a caller that forgot the outer guard
        # degrades to pre-classifier behaviour rather than masking every
        # zero-turn run as infra_death.
        assert v.kind == "terminal"

    def test_empty_signals_are_terminal(
        self, layer: ResilienceLayer,
    ) -> None:
        """No error class, no recent turn errors, healthy LLM -> terminal."""
        v = layer.classify_failure(branch_turn_count=5)
        assert v.kind == "terminal"
        assert v.retryable is False

    def test_empty_string_error_classes_are_ignored(
        self, layer: ResilienceLayer,
    ) -> None:
        """Empty-string entries in the tail don't spuriously flip the verdict."""
        v = layer.classify_failure(
            recent_turn_errors=("", ""),
            branch_turn_count=5,
        )
        assert v.kind == "terminal"


# ---------------------------------------------------------------------------
# conservative_default + record_signal
# ---------------------------------------------------------------------------


class TestConservativeDefault:
    """The one-line replacement for log-then-bump-then-return sites."""

    def test_returns_the_fallback_verbatim(
        self, layer: ResilienceLayer,
    ) -> None:
        """The layer NEVER second-guesses the caller's fallback value."""
        sentinel: dict[str, int] = {"defer_seconds": 30}
        got = layer.conservative_default(
            sentinel, op="queue_investigation_defer", source="db_error",
        )
        assert got is sentinel

    def test_returns_scalar_fallback_unchanged(
        self, layer: ResilienceLayer,
    ) -> None:
        """Works for scalar defaults too (float / int / None)."""
        assert layer.conservative_default(
            30.0, op="queue_investigation_defer", source="db_error",
        ) == 30.0

    def test_carries_exception_metadata_to_the_signal(
        self, layer: ResilienceLayer,
    ) -> None:
        """An exc kwarg is accepted and does not blow up in record_signal."""
        exc = RuntimeError("db locked")
        got = layer.conservative_default(
            42, op="queue_investigation_defer",
            source="db_error", exc=exc,
        )
        assert got == 42


class TestRecordSignal:
    """The single failure-signal metric bump lives here.

    Metric absence is a supported condition (tests, CLI paths) -- the
    layer MUST NOT raise on a missing counter. Presence tests use
    prometheus_client's snapshot API since the counters are process-
    global.
    """

    def test_record_signal_never_raises(
        self, layer: ResilienceLayer,
    ) -> None:
        """A signal bump never blows up the caller, even without exc."""
        layer.record_signal(op="anything", source="anywhere")

    def test_record_signal_with_exc_never_raises(
        self, layer: ResilienceLayer,
    ) -> None:
        """The exception-carrying shape is equally safe."""
        layer.record_signal(
            op="queue_investigation_defer",
            source="db_error",
            exc=RuntimeError("db locked"),
        )

    def test_record_signal_bumps_umbrella_counter(
        self, layer: ResilienceLayer,
    ) -> None:
        """RESILIENCE_SIGNALS_TOTAL{op, source} increments on every call."""
        pytest.importorskip("prometheus_client")
        from aila.api.metrics import RESILIENCE_SIGNALS_TOTAL

        op, source = "test_umbrella_bump", "test_source_umbrella"
        before = RESILIENCE_SIGNALS_TOTAL.labels(
            op=op, source=source,
        )._value.get()
        layer.record_signal(op=op, source=source)
        after = RESILIENCE_SIGNALS_TOTAL.labels(
            op=op, source=source,
        )._value.get()
        assert after == before + 1.0

    def test_sse_write_op_also_bumps_legacy_sse_counter(
        self, layer: ResilienceLayer,
    ) -> None:
        """SSE-mirrored ops keep bumping SSE_WRITE_FAILURES_TOTAL for dashboards."""
        pytest.importorskip("prometheus_client")
        from aila.api.metrics import (
            RESILIENCE_SIGNALS_TOTAL,
            SSE_WRITE_FAILURES_TOTAL,
        )

        source = "test_sse_mirror_source"
        umbrella_before = RESILIENCE_SIGNALS_TOTAL.labels(
            op="sse_write", source=source,
        )._value.get()
        sse_before = SSE_WRITE_FAILURES_TOTAL.labels(
            source=source,
        )._value.get()

        layer.record_signal(op="sse_write", source=source)

        umbrella_after = RESILIENCE_SIGNALS_TOTAL.labels(
            op="sse_write", source=source,
        )._value.get()
        sse_after = SSE_WRITE_FAILURES_TOTAL.labels(
            source=source,
        )._value.get()

        assert umbrella_after == umbrella_before + 1.0
        assert sse_after == sse_before + 1.0

    def test_non_sse_op_does_not_bump_legacy_sse_counter(
        self, layer: ResilienceLayer,
    ) -> None:
        """Umbrella-only ops MUST NOT tick SSE_WRITE_FAILURES_TOTAL."""
        pytest.importorskip("prometheus_client")
        from aila.api.metrics import SSE_WRITE_FAILURES_TOTAL

        source = "test_non_sse_source"
        before = SSE_WRITE_FAILURES_TOTAL.labels(source=source)._value.get()
        layer.record_signal(op="queue_investigation_defer", source=source)
        after = SSE_WRITE_FAILURES_TOTAL.labels(source=source)._value.get()
        assert after == before

    def test_workflow_log_emit_mirrors_to_sse_counter(
        self, layer: ResilienceLayer,
    ) -> None:
        """workflow_log_emit is in the SSE-mirrored set too."""
        pytest.importorskip("prometheus_client")
        from aila.api.metrics import SSE_WRITE_FAILURES_TOTAL

        source = "workflow_log"
        before = SSE_WRITE_FAILURES_TOTAL.labels(source=source)._value.get()
        layer.record_signal(op="workflow_log_emit", source=source)
        after = SSE_WRITE_FAILURES_TOTAL.labels(source=source)._value.get()
        assert after == before + 1.0


# ---------------------------------------------------------------------------
# FailureVerdict contract
# ---------------------------------------------------------------------------


class TestFailureVerdictShape:
    """Structural contract tests on the returned dataclass."""

    def test_is_frozen(self) -> None:
        """FailureVerdict is immutable so callers may safely cache it."""
        v = FailureVerdict(kind="terminal", retryable=False, reason="terminal")
        with pytest.raises((AttributeError, TypeError)):
            v.kind = "infra_death"  # type: ignore[misc]

    def test_reason_matches_kind_by_default(
        self, layer: ResilienceLayer,
    ) -> None:
        """The reason label mirrors the kind for a stable metric label."""
        v = layer.classify_failure(branch_turn_count=5)
        assert v.reason == v.kind
