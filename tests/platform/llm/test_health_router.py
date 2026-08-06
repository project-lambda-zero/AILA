"""RFC-07 phase 5 -- unit tests for
:class:`aila.platform.llm.health_router.ModelHealthRouter`.

Every test injects a deterministic monotonic clock so cooldown /
recovery windows do not depend on wall time. The router is a pure
in-memory tracker; no I/O.

Coverage:

* Happy path (nothing unhealthy) -- ``pick`` is deterministic and
  behaviour-preserving: it always returns the first candidate. This
  is the invariant that makes the router inert on the primary /
  single-URL config today.
* Failure path -- ``record_infra_failure`` flips a URL unhealthy;
  ``pick`` skips it for the cooldown; a subsequent ``record_success``
  restores it.
* Fallback path -- when every candidate is unhealthy, ``pick``
  returns the caller's supplied ``default`` so the call is never
  routed to nowhere.
* Cooldown expiry -- an unhealthy URL is lazily marked healthy again
  once the deadline slides into the past.
* Snapshot -- diagnostic view sorts URLs and reports counters.
"""
from __future__ import annotations

import pytest

from aila.platform.llm.health_router import (
    ENDPOINT_STATUS_HEALTHY,
    ENDPOINT_STATUS_UNHEALTHY,
    ModelHealthRouter,
    get_default_health_router,
    reset_default_health_router,
)


class _FakeClock:
    """A monotonic clock the test controls."""

    def __init__(self) -> None:
        self._now: float = 1000.0

    def __call__(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


class TestHappyPath:
    """No unhealthy URLs -- picks are deterministic and identity-shaped."""

    def test_empty_state_picks_first_candidate(self) -> None:
        router = ModelHealthRouter()
        picked = router.pick(
            ["http://primary", "http://fallback"],
            default="http://primary",
        )
        assert picked == "http://primary"

    def test_single_candidate_returned(self) -> None:
        router = ModelHealthRouter()
        picked = router.pick(["http://only"], default="http://only")
        assert picked == "http://only"

    def test_empty_candidates_returns_default(self) -> None:
        router = ModelHealthRouter()
        picked = router.pick([], default="http://default")
        assert picked == "http://default"

    def test_never_observed_url_is_healthy(self) -> None:
        router = ModelHealthRouter()
        assert router.is_healthy("http://x") is True

    def test_snapshot_is_empty_until_events(self) -> None:
        router = ModelHealthRouter()
        assert router.snapshot() == ()


class TestFailureAndRecovery:
    """Failures flip URLs unhealthy; successes and cooldown expiry restore."""

    def test_failure_flips_status(self) -> None:
        clock = _FakeClock()
        router = ModelHealthRouter(
            cooldown_s=10.0, monotonic_clock=clock,
        )
        router.record_infra_failure("http://primary", "timeout")
        assert router.is_healthy("http://primary") is False

    def test_pick_skips_unhealthy(self) -> None:
        clock = _FakeClock()
        router = ModelHealthRouter(
            cooldown_s=30.0, monotonic_clock=clock,
        )
        router.record_infra_failure("http://primary", "connect_refused")
        picked = router.pick(
            ["http://primary", "http://fallback"],
            default="http://primary",
        )
        assert picked == "http://fallback"

    def test_all_unhealthy_falls_back_to_default(self) -> None:
        clock = _FakeClock()
        router = ModelHealthRouter(
            cooldown_s=30.0, monotonic_clock=clock,
        )
        router.record_infra_failure("http://a", "http_5xx")
        router.record_infra_failure("http://b", "http_5xx")
        picked = router.pick(
            ["http://a", "http://b"], default="http://default",
        )
        # Default is returned even though it is not in the candidate list
        # -- routing to a known-bad URL surfaces the outage to the operator;
        # silently dropping the call would be worse.
        assert picked == "http://default"

    def test_success_clears_unhealthy(self) -> None:
        clock = _FakeClock()
        router = ModelHealthRouter(
            cooldown_s=60.0, monotonic_clock=clock,
        )
        router.record_infra_failure("http://x", "timeout")
        assert router.is_healthy("http://x") is False
        router.record_success("http://x")
        assert router.is_healthy("http://x") is True

    def test_cooldown_expiry_restores_health(self) -> None:
        clock = _FakeClock()
        router = ModelHealthRouter(
            cooldown_s=10.0, monotonic_clock=clock,
        )
        router.record_infra_failure("http://x", "timeout")
        assert router.is_healthy("http://x") is False
        clock.advance(11.0)
        # Lazy recovery: the next is_healthy check observes the elapsed
        # cooldown and marks the URL healthy again.
        assert router.is_healthy("http://x") is True

    def test_repeated_failures_extend_cooldown(self) -> None:
        clock = _FakeClock()
        router = ModelHealthRouter(
            cooldown_s=10.0, monotonic_clock=clock,
        )
        router.record_infra_failure("http://x", "timeout")
        clock.advance(5.0)
        # Second failure rolls the cooldown forward.
        router.record_infra_failure("http://x", "timeout")
        clock.advance(6.0)
        # 5 + 6 = 11 seconds since FIRST failure; without the roll-forward
        # the URL would be healthy again. With the roll-forward, only 6
        # seconds elapsed since the second failure, so still unhealthy.
        assert router.is_healthy("http://x") is False
        clock.advance(5.0)
        assert router.is_healthy("http://x") is True


class TestSnapshot:
    """Diagnostic snapshot -- sorted, immutable, per-URL counters."""

    def test_snapshot_reports_status_and_counters(self) -> None:
        clock = _FakeClock()
        router = ModelHealthRouter(
            cooldown_s=10.0, monotonic_clock=clock,
        )
        router.record_infra_failure("http://a", "timeout")
        router.record_infra_failure("http://a", "http_5xx")
        router.record_success("http://b")
        snap = router.snapshot()
        assert [s.url for s in snap] == ["http://a", "http://b"]
        a = snap[0]
        assert a.status == ENDPOINT_STATUS_UNHEALTHY
        assert a.consecutive_failures == 2
        assert a.total_failures == 2
        assert a.last_failure_kind == "http_5xx"
        b = snap[1]
        assert b.status == ENDPOINT_STATUS_HEALTHY
        assert b.total_successes == 1

    def test_snapshot_is_a_tuple(self) -> None:
        router = ModelHealthRouter()
        router.record_success("http://x")
        snap = router.snapshot()
        assert isinstance(snap, tuple)


class TestConstructorValidation:
    """Boundary conditions the constructor rejects."""

    def test_zero_cooldown_rejected(self) -> None:
        with pytest.raises(ValueError, match="cooldown_s"):
            ModelHealthRouter(cooldown_s=0.0)

    def test_negative_cooldown_rejected(self) -> None:
        with pytest.raises(ValueError, match="cooldown_s"):
            ModelHealthRouter(cooldown_s=-1.0)


class TestDefaultSingleton:
    """The process-wide default router is lazily constructed + resettable."""

    def test_default_singleton_is_stable(self) -> None:
        reset_default_health_router()
        r1 = get_default_health_router()
        r2 = get_default_health_router()
        assert r1 is r2

    def test_reset_drops_state(self) -> None:
        reset_default_health_router()
        r1 = get_default_health_router()
        r1.record_infra_failure("http://x", "timeout")
        assert r1.is_healthy("http://x") is False
        reset_default_health_router()
        r2 = get_default_health_router()
        # New router: no accumulated state, x is healthy again.
        assert r1 is not r2
        assert r2.is_healthy("http://x") is True
        reset_default_health_router()
