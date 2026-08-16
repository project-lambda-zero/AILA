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


@pytest.fixture(autouse=True)
def _disable_l2_shared_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    """ENHANCEMENT #142 -- pin the router's L2 path OFF for the classic
    unit tests.

    The pre-#142 tests below construct ``ModelHealthRouter()`` with no
    Redis wiring and assert against the L1 (process-local) state
    exclusively. In an env that pre-sets ``AILA_PLATFORM_REDIS_URL``
    (CI does), the new shared-cache path would otherwise reach out to
    a live Redis and let state bleed across tests. Clearing the env
    var guarantees ``_resolve_sync_redis_client`` returns None so
    every L2 helper becomes a no-op -- the router behaves identically
    to the pre-#142 code path these tests were written against.
    Dedicated L2 coverage lives in :class:`TestRedisSharedL2` below
    with an injected in-memory fake.
    """
    monkeypatch.delenv("AILA_PLATFORM_REDIS_URL", raising=False)


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


class _FakeSyncRedis:
    """In-memory sync Redis surface.

    Enough of the ``redis.Redis`` API for the L2 helpers:
    ``get``/``set(ex=...)``/``delete``. TTLs are stored as absolute
    monotonic deadlines and enforced on read so the tests can assert
    L2-side expiry without leaning on wall-clock sleeps.
    """

    def __init__(self, clock: _FakeClock) -> None:
        self._clock = clock
        self._store: dict[str, tuple[str, float]] = {}
        # Tunables tests flip to simulate an outage in the middle of a
        # run without swapping the whole client instance.
        self.raise_on_get: BaseException | None = None
        self.raise_on_set: BaseException | None = None
        self.raise_on_delete: BaseException | None = None

    def get(self, key: str) -> str | None:
        if self.raise_on_get is not None:
            raise self.raise_on_get
        entry = self._store.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if self._clock() >= expires_at:
            self._store.pop(key, None)
            return None
        return value

    def set(self, key: str, value: str, ex: int | None = None) -> bool:
        if self.raise_on_set is not None:
            raise self.raise_on_set
        ttl_s = float(ex) if ex is not None else 3600.0
        self._store[key] = (value, self._clock() + ttl_s)
        return True

    def delete(self, *keys: str) -> int:
        if self.raise_on_delete is not None:
            raise self.raise_on_delete
        removed = 0
        for k in keys:
            if self._store.pop(k, None) is not None:
                removed += 1
        return removed


class TestRedisSharedL2:
    """ENHANCEMENT #142 -- cross-worker sharing via Redis L2 cache."""

    def _router(
        self,
        clock: _FakeClock,
        fake: _FakeSyncRedis,
        *,
        gate: bool = True,
        cooldown_s: float = 30.0,
    ) -> ModelHealthRouter:
        return ModelHealthRouter(
            cooldown_s=cooldown_s,
            monotonic_clock=clock,
            wall_clock=clock,
            redis_sync_client_factory=lambda: fake,
            gate_resolver=lambda: gate,
        )

    def test_failure_writes_shared_marker(self) -> None:
        clock = _FakeClock()
        fake = _FakeSyncRedis(clock)
        router = self._router(clock, fake)
        router.record_infra_failure("http://primary", "http_5xx")
        # Marker present under the documented namespace.
        assert list(fake._store.keys()) == [
            "aila:llm_health_router:endpoint:http://primary",
        ]

    def test_peer_worker_sees_failure(self) -> None:
        # Two routers share the same fake Redis -> different processes.
        clock = _FakeClock()
        fake = _FakeSyncRedis(clock)
        worker_a = self._router(clock, fake)
        worker_b = self._router(clock, fake)
        worker_a.record_infra_failure("http://primary", "timeout")
        # Worker B has never seen this URL locally; the shared marker
        # is the only signal available. It MUST honour it.
        assert worker_b.is_healthy("http://primary") is False

    def test_success_clears_shared_marker(self) -> None:
        clock = _FakeClock()
        fake = _FakeSyncRedis(clock)
        worker_a = self._router(clock, fake)
        worker_a.record_infra_failure("http://primary", "timeout")
        # Peer marker is present.
        assert fake.get(
            "aila:llm_health_router:endpoint:http://primary",
        ) is not None
        worker_a.record_success("http://primary")
        # DEL cleared the shared marker so a fresh worker (worker_c
        # here -- distinct instance, no local L1 pollution) that spins
        # up AFTER the recovery sees the URL healthy immediately.
        # Note: a worker that already promoted the marker into its
        # own L1 does not see the DEL until its L1 cooldown lapses
        # -- that is the "L1 in front of L2" contract; recovery is
        # eventually consistent, failure is instant.
        assert fake.get(
            "aila:llm_health_router:endpoint:http://primary",
        ) is None
        worker_c = self._router(clock, fake)
        assert worker_c.is_healthy("http://primary") is True

    def test_redis_get_outage_is_fail_open(self) -> None:
        import socket

        clock = _FakeClock()
        fake = _FakeSyncRedis(clock)
        worker_a = self._router(clock, fake)
        worker_b = self._router(clock, fake)
        worker_a.record_infra_failure("http://primary", "timeout")
        # Redis GET now blows up -> peer worker MUST fail open, no exc.
        fake.raise_on_get = socket.timeout("simulated outage")
        assert worker_b.is_healthy("http://primary") is True

    def test_redis_set_outage_does_not_break_local_state(self) -> None:
        import socket

        clock = _FakeClock()
        fake = _FakeSyncRedis(clock)
        router = self._router(clock, fake)
        fake.raise_on_set = socket.timeout("simulated outage")
        # SET raises inside record_infra_failure -> MUST be swallowed;
        # L1 mutation MUST still apply so the local retry loop skips
        # the endpoint identically to the pre-#142 behaviour.
        router.record_infra_failure("http://primary", "timeout")
        assert router.is_healthy("http://primary") is False

    def test_redis_delete_outage_does_not_raise(self) -> None:
        import socket

        clock = _FakeClock()
        fake = _FakeSyncRedis(clock)
        router = self._router(clock, fake)
        router.record_infra_failure("http://primary", "timeout")
        fake.raise_on_delete = socket.timeout("simulated outage")
        # record_success MUST NOT raise even when the shared DEL fails;
        # the local L1 mutation still applies. The stale L2 marker
        # will be self-cleaned by its TTL. This is the acceptance
        # contract: no exception escapes on any Redis outage.
        router.record_success("http://primary")
        # L1 was updated: consecutive_failures reset, total_successes bumped.
        snap = router.snapshot()
        assert snap[0].url == "http://primary"
        assert snap[0].status == ENDPOINT_STATUS_HEALTHY
        assert snap[0].consecutive_failures == 0
        assert snap[0].total_successes == 1

    def test_gate_off_disables_shared_writes(self) -> None:
        clock = _FakeClock()
        fake = _FakeSyncRedis(clock)
        router = self._router(clock, fake, gate=False)
        router.record_infra_failure("http://primary", "timeout")
        # Gate off -> NO writes to Redis, purely L1.
        assert fake._store == {}
        assert router.is_healthy("http://primary") is False

    def test_l1_warm_unhealthy_short_circuits_redis(self) -> None:
        # Once a router has an active L1 unhealthy entry the hot-path
        # read MUST NOT query Redis (that is the whole "L1 in front of
        # L2" contract). We prove it by pointing the client at a fake
        # that would raise on any GET; is_healthy must still return
        # False without touching the client.
        import socket

        clock = _FakeClock()
        fake = _FakeSyncRedis(clock)
        router = self._router(clock, fake)
        router.record_infra_failure("http://primary", "timeout")
        fake.raise_on_get = socket.timeout(
            "MUST not be reached on warm-unhealthy L1",
        )
        assert router.is_healthy("http://primary") is False

    def test_shared_ttl_expiry_reeligibilizes_endpoint(self) -> None:
        clock = _FakeClock()
        fake = _FakeSyncRedis(clock)
        worker_a = self._router(clock, fake, cooldown_s=10.0)
        worker_b = self._router(clock, fake, cooldown_s=10.0)
        worker_a.record_infra_failure("http://primary", "timeout")
        assert worker_b.is_healthy("http://primary") is False
        # Advance beyond the cooldown -> both TTL and monotonic deadline
        # elapse; the peer worker now considers the URL healthy again
        # even without a fresh success signal.
        clock.advance(15.0)
        assert worker_b.is_healthy("http://primary") is True
