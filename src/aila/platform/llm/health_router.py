"""RFC-07 phase 5 -- per-endpoint infra-health tracker + drift bias for LLM gateways.

The problem this router solves is narrow. AILA routes every LLM call
through ONE operator-configured gateway URL today (:meth:`aila.platform.llm.config.LLMConfigProvider.resolve_base_url`);
the operator can point that URL at OmniRoute, direct OpenRouter, or any
compatible provider. When the operator lists more than one URL (a
primary + fallback), the current wiring picks the primary and stays on
it, even when the primary is refusing connections; the reactive half
of self-healing is missing.

The :class:`ModelHealthRouter` provides that reactive half and *only*
that reactive half:

* it tracks per-URL infra health (timeout / 5xx / connection refused =
  unhealthy for a bounded cooldown; a subsequent success clears it);
* :meth:`pick` receives an ordered list of candidate URLs plus the
  operator-configured default and returns the first *healthy*
  candidate, or the default when every candidate is unhealthy so the
  call is never routed to nowhere;
* it does NOT reconfigure the gateway, rewrite model aliases, or touch
  the model selection logic in :class:`~aila.platform.llm.config.LLMConfigProvider`.
  The router is inert on the happy path -- with an empty unhealthy set
  it always picks the caller's first candidate, which today is the
  only candidate the config resolves.

The router is process-local and thread-safe under the GIL for the
dict-mutating happy paths (one insertion / one deletion per event).
State that must survive a worker restart lives in the operator's
config surface, not here -- an unhealthy URL clears itself on restart,
which is intentional: a restart is exactly the moment the operator's
new gateway config re-becomes the source of truth.

Wired at :func:`aila.platform.llm.client._record_llm_error` /
:func:`aila.platform.llm.client._record_llm_ok` via
:func:`get_default_health_router`, so every LLM retry loop feeds the
router without the call sites knowing the router exists.

ENHANCEMENT #142 -- cross-worker sharing of endpoint health state.
The process-local ``_state`` dict is now the L1 cache in front of a
Redis-backed L2 keyed by endpoint URL with TTL == the current
``cooldown_s``. Reads consult L1 first; a warm-unhealthy L1 entry
short-circuits without a round-trip. On an L1 miss / L1-healthy read
the router asks Redis whether a peer worker has already flagged the
endpoint. Redis MISS is treated as HEALTHY (fail-open) so a Redis
outage silently degrades to the pre-#142 per-process behaviour rather
than blackholing every endpoint. Writes update both L1 and Redis; a
Redis outage on the write path is logged and swallowed so an outage
in the shared cache never turns into an LLM-call failure. The whole
mechanism is gated by ``PlatformConfigSchema.llm_health_router_redis_shared``
plus the presence of ``AILA_PLATFORM_REDIS_URL`` -- when either is
false the router falls back to L1-only exactly as before #142.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal, Protocol

__all__ = [
    "DRIFT_STATUS_DEGRADED",
    "DRIFT_STATUS_STABLE",
    "DRIFT_STATUS_VOLATILE",
    "ENDPOINT_STATUS_HEALTHY",
    "ENDPOINT_STATUS_UNHEALTHY",
    "EndpointHealth",
    "InfraFailureKind",
    "ModelDrift",
    "ModelHealthRouter",
    "get_default_health_router",
    "reset_default_health_router",
]

# Redis client errors + socket failures the L2 helpers degrade on. Mirrors
# the tuple :mod:`aila.storage.registry` uses so both sync-Redis touchpoints
# swallow the same exception family. ``redis`` is an optional dependency;
# folding its base class in only when importable keeps a redis-less install
# working (the sync client factory returns None; every L2 call becomes a
# no-op fail-open).
try:  # pragma: no cover - optional dependency probe
    from redis.exceptions import RedisError as _RedisError

    _REDIS_ERRORS: tuple[type[BaseException], ...] = (OSError, _RedisError)
except ImportError:  # pragma: no cover
    _REDIS_ERRORS = (OSError,)


class _SyncRedisLike(Protocol):
    """Minimal sync Redis surface used by the L2 cache.

    Both ``redis.Redis`` and lightweight test fakes satisfy it. Kept narrow
    so a test can inject an in-memory client via
    :class:`ModelHealthRouter`'s ``redis_sync_client_factory`` without
    pulling redis-py.
    """

    def get(self, key: str) -> Any: ...
    def set(self, key: str, value: Any, ex: int | None = None) -> Any: ...
    def delete(self, *keys: str) -> Any: ...


class _Missing:
    """Sentinel distinguishing "sync-redis client never resolved" from
    "resolved to None"."""

    __slots__ = ()


_MISSING = _Missing()

# Redis key namespace for per-endpoint health entries. Grep-friendly:
# ``KEYS aila:llm_health_router:endpoint:*`` lists every shared marker.
_REDIS_KEY_PREFIX: str = "aila:llm_health_router:endpoint:"

# ConfigRegistry key gating the Redis-shared path. Mirrors
# ``PlatformConfigSchema.llm_health_router_redis_shared`` (default True) so
# an operator can flip the flag via PUT /config or the env override
# ``AILA_PLATFORM_LLM_HEALTH_ROUTER_REDIS_SHARED`` without a worker restart.
_REDIS_SHARED_CONFIG_NS: str = "platform"
_REDIS_SHARED_CONFIG_KEY: str = "llm_health_router_redis_shared"

# Cache the gate value inside the router instance to keep the hot path off
# ``ConfigRegistry.get_sync`` on every ``pick``. 30s is short enough that a
# ``PUT /config`` toggle propagates within an ARQ retry window; the registry
# itself carries a 60s TTL + cross-process invalidation on top of this so
# the effective staleness window is at most both combined.
_GATE_CACHE_TTL_S: float = 30.0

_log = logging.getLogger(__name__)

# Compact status labels used by :class:`EndpointHealth` and the router's
# public snapshot. Kept as module-level strings so the operator log
# lines and any future diagnostic dashboard consume ONE spelling.
ENDPOINT_STATUS_HEALTHY: str = "healthy"
ENDPOINT_STATUS_UNHEALTHY: str = "unhealthy"

# Kinds of infra failure the router recognises. All are recorded as a
# uniform ``unhealthy`` signal; the label is retained so a diagnostic
# read can distinguish (e.g.) a chronic ``connect_refused`` from a
# once-off ``timeout`` when triaging an outage.
InfraFailureKind = Literal[
    "timeout",
    "connect_refused",
    "http_5xx",
    "unknown",
]

# Default cooldown: an unhealthy URL is skipped for this many seconds
# before the router considers it again. 60s matches the ARQ health
# check interval + is short enough that a transient gateway restart
# recovers on the next attempt. Overridable per-instance so an
# operator with a fast-cycling load balancer can shorten it.
_DEFAULT_COOLDOWN_S: float = 60.0

# Drift status labels mirror ConfidenceDriftTracker's status vocabulary
# (aila.platform.llm.drift). Kept as module-level strings so seal.py,
# tests, and the operator dashboard consume ONE spelling.
DRIFT_STATUS_STABLE: str = "stable"
DRIFT_STATUS_DEGRADED: str = "degrading"
DRIFT_STATUS_VOLATILE: str = "volatile"

# Drift-driven cooldown for (model_id, task_type). Much longer than the
# infra cooldown because drift is a slow-moving quality signal, not a
# transient outage: a volatile / degrading model stays biased against
# the pick until a fresh stable sample lands OR the cooldown lapses.
# 900s (15 min) keeps a drifting model biased through a typical
# investigation turn window without pinning the router permanently on a
# one-off spike.
_DEFAULT_DRIFT_COOLDOWN_S: float = 900.0

# Drift statuses that count as "degraded" for pick bias. Kept as a set
# so a caller inspecting slots via ``is_drift_degraded`` gets the same
# classification the pick path uses.
_DEGRADED_DRIFT_STATUSES: frozenset[str] = frozenset(
    {DRIFT_STATUS_DEGRADED, DRIFT_STATUS_VOLATILE},
)


@dataclass(frozen=True, slots=True)
class ModelDrift:
    """Snapshot of one (model_id, task_type) drift slot.

    Immutable snapshot returned by :meth:`ModelHealthRouter.snapshot_drift`;
    the router's internal dicts stay live and privately mutable. ``status``
    is one of :data:`DRIFT_STATUS_STABLE`, :data:`DRIFT_STATUS_DEGRADED`,
    :data:`DRIFT_STATUS_VOLATILE`. ``degraded_until_monotonic`` is 0.0 when
    the last observation was stable (no bias active).
    """

    model_id: str
    task_type: str
    status: str
    degraded_until_monotonic: float
    last_recorded_at_monotonic: float
    total_stable: int
    total_degraded: int


@dataclass(frozen=True, slots=True)
class EndpointHealth:
    """Snapshot of one URL's tracked state.

    Immutable snapshot returned by :meth:`ModelHealthRouter.snapshot`;
    the router's internal dicts stay live and privately mutable.

    ``status`` is one of :data:`ENDPOINT_STATUS_HEALTHY` /
    :data:`ENDPOINT_STATUS_UNHEALTHY`. A URL never observed either
    way (i.e. absent from :meth:`ModelHealthRouter.snapshot`) is
    treated as healthy by :meth:`ModelHealthRouter.pick`.

    ``last_failure_kind`` is None when the URL has never been marked
    unhealthy since process start; the router's per-URL counter
    accumulates monotonically for the operator dashboard.
    """

    url: str
    status: str
    unhealthy_until_monotonic: float
    consecutive_failures: int
    total_failures: int
    total_successes: int
    last_failure_kind: str | None


class ModelHealthRouter:
    """Skip infra-unhealthy LLM endpoints when routing.

    The router carries no notion of "which model" or "which task type"
    -- those decisions live in :class:`~aila.platform.llm.config.LLMConfigProvider`
    and MUST stay there. The router only sees URLs, marks them
    unhealthy on infra failure, and skips them for a bounded cooldown.
    When every candidate is unhealthy it falls back to the caller's
    supplied default -- routing the call anywhere is better than
    silently dropping it, and the default's own failure is what
    surfaces the outage to the operator.

    ``pick(candidates, default)`` is deterministic: with no unhealthy
    URLs it always returns ``candidates[0]`` (or ``default`` when
    ``candidates`` is empty). That determinism is what makes the
    router behaviour-preserving when everything is healthy.

    Parameters
    ----------
    cooldown_s:
        Seconds an unhealthy URL is skipped before the router
        reconsiders it. Defaults to :data:`_DEFAULT_COOLDOWN_S`.
        Must be strictly positive; the router rejects a zero /
        negative value at construction so a misconfiguration is
        caught at startup, not at the first outage.
    monotonic_clock:
        Callable returning a monotonic reading in seconds. Defaults
        to :func:`time.monotonic`; test paths override to advance
        time deterministically without sleeping.
    """

    def __init__(
        self,
        *,
        cooldown_s: float = _DEFAULT_COOLDOWN_S,
        drift_cooldown_s: float = _DEFAULT_DRIFT_COOLDOWN_S,
        monotonic_clock: Callable[[], float] | None = None,
        wall_clock: Callable[[], float] | None = None,
        redis_sync_client_factory: Callable[[], _SyncRedisLike | None] | None = None,
        gate_resolver: Callable[[], bool] | None = None,
    ) -> None:
        if cooldown_s <= 0:
            raise ValueError(
                "ModelHealthRouter: cooldown_s must be > 0, "
                f"got {cooldown_s!r}",
            )
        if drift_cooldown_s <= 0:
            raise ValueError(
                "ModelHealthRouter: drift_cooldown_s must be > 0, "
                f"got {drift_cooldown_s!r}",
            )
        self._cooldown_s = cooldown_s
        self._drift_cooldown_s = drift_cooldown_s
        self._clock = monotonic_clock or time.monotonic
        # Wall-clock used for the Redis L2 payload deadlines. Cross-process
        # coordination needs an epoch reading -- ``time.monotonic`` is a
        # process-local anchor and MUST NOT leak into the shared value.
        # Injectable so a test can advance wall time deterministically in
        # lockstep with ``monotonic_clock``.
        self._wall_clock = wall_clock or time.time
        # url -> per-URL bookkeeping. Values are plain dicts (not a
        # dataclass) so a single mutation on the happy path is one
        # attribute write and stays inside the GIL; the snapshot
        # method builds :class:`EndpointHealth` from the dict when
        # a diagnostic caller asks.
        self._state: dict[str, dict[str, object]] = {}
        # (model_id, task_type) -> per-slot drift bookkeeping. Populated
        # by :meth:`record_drift` from the seal step's drift tracker;
        # consumed by :meth:`pick` / :meth:`pick_model` to bias against
        # a persistently degrading or volatile model when a fallback
        # candidate is available.
        self._drift: dict[tuple[str, str], dict[str, object]] = {}
        self._lock = threading.Lock()
        # ENHANCEMENT #142 -- Redis L2 wiring. Both factories are lazy:
        # the sync-redis client is built on first L2 access via
        # ``AILA_PLATFORM_REDIS_URL`` (mirrors ConfigRegistry's sync-redis
        # factory precedent); the gate is resolved via
        # ``ConfigRegistry.get_sync`` with a short TTL cache so ``pick``
        # doesn't pay a DB round-trip per candidate URL. Tests inject
        # deterministic overrides.
        self._redis_sync_client_factory = redis_sync_client_factory
        self._sync_redis_client: _SyncRedisLike | None | _Missing = _MISSING
        self._sync_redis_lock = threading.Lock()
        self._gate_resolver = gate_resolver
        self._gate_cached_value: bool | None = None
        self._gate_cached_at_monotonic: float = -1.0

    # ------------------------------------------------------------------
    # #142 -- Redis L2 helpers. Every method here MUST swallow
    # ``_REDIS_ERRORS`` and return a safe fallback (None on read, silent
    # no-op on write). A Redis outage MUST NEVER escape into the LLM
    # retry loop -- fail-open is the whole point of the design.
    # ------------------------------------------------------------------

    def _resolve_sync_redis_client(self) -> _SyncRedisLike | None:
        """Return a sync Redis client, or None if unavailable. Cached per
        router instance.

        Preference: constructor-injected factory > ``redis.Redis.from_url``
        on ``AILA_PLATFORM_REDIS_URL``. A resolved None is cached so the
        second call doesn't re-attempt the import + env read on every
        LLM call. Mirrors :meth:`aila.storage.registry.ConfigRegistry._resolve_sync_redis_client`
        so both sync-Redis touchpoints degrade identically when the URL is
        unset or the socket can't build.
        """
        if self._redis_sync_client_factory is not None:
            try:
                return self._redis_sync_client_factory()
            except _REDIS_ERRORS:
                _log.debug(
                    "model_health_router: injected sync redis factory raised",
                    exc_info=True,
                )
                return None
        with self._sync_redis_lock:
            if not isinstance(self._sync_redis_client, _Missing):
                return self._sync_redis_client
            url = os.environ.get("AILA_PLATFORM_REDIS_URL", "").strip()
            if not url:
                self._sync_redis_client = None
                return None
            try:
                import redis

                client = redis.Redis.from_url(
                    url,
                    socket_connect_timeout=2.0,
                    socket_timeout=2.0,
                    decode_responses=True,
                )
            except (ImportError, OSError, RuntimeError, ValueError):
                _log.debug(
                    "model_health_router: sync redis client build failed",
                    exc_info=True,
                )
                self._sync_redis_client = None
                return None
            self._sync_redis_client = client
            return client

    def _redis_shared_enabled(self) -> bool:
        """Return True iff the L2 path should run for this call.

        Both the config gate AND a resolvable sync-Redis client are
        required. Cached for :data:`_GATE_CACHE_TTL_S` so the hot path
        doesn't pay ``ConfigRegistry.get_sync`` (with its own 60s cache
        plus cross-process invalidation) on every LLM call. Any failure
        resolving the gate defaults to True (fail-safe -- if a Redis URL
        is configured and the operator hasn't explicitly disabled the
        shared cache, use it) but a client factory that returns None
        still short-circuits every L2 call.
        """
        now = self._clock()
        if (
            self._gate_cached_value is not None
            and now - self._gate_cached_at_monotonic < _GATE_CACHE_TTL_S
        ):
            return self._gate_cached_value
        gate_value: bool
        if self._gate_resolver is not None:
            try:
                gate_value = bool(self._gate_resolver())
            except (OSError, RuntimeError, ValueError):
                _log.debug(
                    "model_health_router: injected gate resolver raised",
                    exc_info=True,
                )
                gate_value = True
        else:
            gate_value = _resolve_redis_shared_gate_default()
        self._gate_cached_value = gate_value
        self._gate_cached_at_monotonic = now
        return gate_value

    def _redis_key(self, url: str) -> str:
        return f"{_REDIS_KEY_PREFIX}{url}"

    def _write_redis_unhealthy(
        self,
        url: str,
        *,
        kind: str,
        consecutive_failures: int,
        total_failures: int,
    ) -> None:
        """Publish an ``unhealthy`` marker for ``url`` to the L2 cache.

        No-op when the shared path is gated off or the sync-Redis client
        is unavailable. Any Redis error is logged at debug and swallowed
        so the LLM retry loop never sees a shared-cache outage.
        """
        if not self._redis_shared_enabled():
            return
        client = self._resolve_sync_redis_client()
        if client is None:
            return
        payload = {
            "status": ENDPOINT_STATUS_UNHEALTHY,
            "unhealthy_until_epoch": float(self._wall_clock() + self._cooldown_s),
            "last_failure_kind": kind,
            "consecutive_failures": int(consecutive_failures),
            "total_failures": int(total_failures),
        }
        try:
            client.set(
                self._redis_key(url),
                json.dumps(payload),
                ex=max(1, int(self._cooldown_s)),
            )
        except _REDIS_ERRORS:
            _log.debug(
                "model_health_router: redis SET failed url=%s",
                url,
                exc_info=True,
            )

    def _delete_redis(self, url: str) -> None:
        """Clear the L2 marker for ``url`` after a fresh success.

        Absence == HEALTHY (fail-open); a delete is the correct primitive
        so peer workers see the recovery immediately instead of waiting
        for the TTL to elapse. Errors swallowed identically to the write
        path.
        """
        if not self._redis_shared_enabled():
            return
        client = self._resolve_sync_redis_client()
        if client is None:
            return
        try:
            client.delete(self._redis_key(url))
        except _REDIS_ERRORS:
            _log.debug(
                "model_health_router: redis DEL failed url=%s",
                url,
                exc_info=True,
            )

    def _read_redis(self, url: str) -> dict[str, Any] | None:
        """Return a peer worker's L2 marker for ``url``, or None on
        miss/error.

        The caller interprets None as HEALTHY (fail-open). A parseable
        payload whose ``unhealthy_until_epoch`` has already elapsed also
        returns None -- the TTL is the source of truth, a stale row is a
        healthy row.
        """
        if not self._redis_shared_enabled():
            return None
        client = self._resolve_sync_redis_client()
        if client is None:
            return None
        try:
            raw = client.get(self._redis_key(url))
        except _REDIS_ERRORS:
            _log.debug(
                "model_health_router: redis GET failed url=%s",
                url,
                exc_info=True,
            )
            return None
        if raw is None:
            return None
        if isinstance(raw, (bytes, bytearray)):
            try:
                raw = raw.decode("utf-8")
            except UnicodeDecodeError:
                _log.debug(
                    "model_health_router: redis payload is not utf-8 url=%s",
                    url,
                    exc_info=True,
                )
                return None
        try:
            payload = json.loads(raw)
        except (TypeError, ValueError):
            _log.debug(
                "model_health_router: redis payload is not JSON url=%s raw=%r",
                url,
                raw,
            )
            return None
        if not isinstance(payload, dict):
            return None
        deadline = payload.get("unhealthy_until_epoch")
        try:
            deadline_f = float(deadline)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            _log.debug(
                "llm-health L2: malformed unhealthy_until_epoch %r for %s; "
                "ignoring peer marker",
                deadline, url,
            )
            return None
        if self._wall_clock() >= deadline_f:
            return None
        return payload

    def _drift_slot(self, model_id: str, task_type: str) -> dict[str, object]:
        """Return the live bookkeeping dict for (``model_id``, ``task_type``),
        creating on demand."""
        key = (model_id, task_type)
        slot = self._drift.get(key)
        if slot is None:
            slot = {
                "status": DRIFT_STATUS_STABLE,
                "degraded_until": 0.0,
                "last_recorded_at": 0.0,
                "total_stable": 0,
                "total_degraded": 0,
            }
            self._drift[key] = slot
        return slot

    def _slot(self, url: str) -> dict[str, object]:
        """Return the live bookkeeping dict for ``url``, creating on demand."""
        slot = self._state.get(url)
        if slot is None:
            slot = {
                "status": ENDPOINT_STATUS_HEALTHY,
                "unhealthy_until": 0.0,
                "consecutive_failures": 0,
                "total_failures": 0,
                "total_successes": 0,
                "last_failure_kind": None,
            }
            self._state[url] = slot
        return slot

    def record_infra_failure(
        self,
        url: str,
        kind: InfraFailureKind = "unknown",
    ) -> None:
        """Mark ``url`` unhealthy for ``cooldown_s`` seconds.

        Called by the LLM client's retry loop on every infra-level
        exception (see :func:`aila.platform.llm.client._record_llm_error`).
        A non-infra provider error (400 validation, 401 auth) MUST NOT
        call this -- second-guessing tool semantics is out of the
        router's scope.

        Idempotent: back-to-back failures roll the cooldown forward and
        increment the counters, but never disable an endpoint permanently.
        The router intentionally never removes a URL from the operator's
        candidate list; the resolver / config surface stays authoritative.
        """
        with self._lock:
            slot = self._slot(url)
            slot["status"] = ENDPOINT_STATUS_UNHEALTHY
            slot["unhealthy_until"] = float(self._clock() + self._cooldown_s)
            slot["consecutive_failures"] = int(
                slot["consecutive_failures"],  # type: ignore[arg-type]
            ) + 1
            slot["total_failures"] = int(
                slot["total_failures"],  # type: ignore[arg-type]
            ) + 1
            slot["last_failure_kind"] = kind
            consecutive_snapshot = int(slot["consecutive_failures"])  # type: ignore[arg-type]
            total_snapshot = int(slot["total_failures"])  # type: ignore[arg-type]
        # #142 L2 write happens OUTSIDE the router lock -- the redis
        # socket is blocking and we must not hold ``self._lock`` across
        # a network round-trip. The dict snapshot above captures the
        # counters at the exact mutation for the L2 payload.
        self._write_redis_unhealthy(
            url,
            kind=kind,
            consecutive_failures=consecutive_snapshot,
            total_failures=total_snapshot,
        )
        _log.info(
            "model_health_router.record_infra_failure url=%s kind=%s "
            "cooldown_s=%.1f consecutive=%d total=%d",
            url, kind, self._cooldown_s,
            consecutive_snapshot, total_snapshot,
        )

    def record_success(self, url: str) -> None:
        """Clear ``url``'s unhealthy state after a successful call.

        Called by the LLM client's retry loop on every non-retryable
        successful return. A single success is enough to re-eligible
        the URL because the caller's next attempt may reject it again
        if the outage returns -- there is no cooldown *up*.
        """
        with self._lock:
            slot = self._slot(url)
            slot["status"] = ENDPOINT_STATUS_HEALTHY
            slot["unhealthy_until"] = 0.0
            slot["consecutive_failures"] = 0
            slot["total_successes"] = int(
                slot["total_successes"],  # type: ignore[arg-type]
            ) + 1
        # #142 clear the shared marker on recovery so peer workers see
        # the endpoint eligible immediately instead of waiting on TTL.
        # DEL runs unconditionally -- the peer marker may have been
        # written by a *different* worker's failure that this call
        # happened to recover, and a DEL of a non-existent key is
        # a cheap round-trip that keeps the reasoning simple.
        self._delete_redis(url)

    def is_healthy(self, url: str) -> bool:
        """Return True iff ``url`` is currently eligible for routing.

        A URL never observed is healthy by default (there is no
        evidence to the contrary). A URL flipped unhealthy becomes
        healthy again once ``unhealthy_until`` slides into the past;
        the recovery is lazy -- ``pick`` and ``is_healthy`` are the
        only touchpoints that observe the clock so a caller that
        never asks never wakes anything up.

        ENHANCEMENT #142: on L1 miss OR L1-healthy the router consults
        the Redis L2 cache for peer worker failure discoveries. An L1
        warm-unhealthy entry short-circuits without a round-trip so the
        hot path stays cheap. A Redis MISS or Redis error is treated
        as HEALTHY (fail-open) so an outage in the shared cache
        degrades to today's per-process behaviour rather than
        blackholing every endpoint. When Redis reports an unhealthy
        peer marker the state is promoted into L1 so the next call on
        the same URL short-circuits.
        """
        with self._lock:
            slot = self._state.get(url)
            if slot is not None and slot["status"] == ENDPOINT_STATUS_UNHEALTHY:
                deadline = float(slot["unhealthy_until"])  # type: ignore[arg-type]
                if self._clock() < deadline:
                    # #142 hot path: warm-unhealthy L1 -> no round-trip.
                    return False
                # Cooldown elapsed locally, fall through to L2 (a peer
                # may have re-flagged it under a fresh outage that this
                # worker hasn't seen a call for yet).
                slot["status"] = ENDPOINT_STATUS_HEALTHY
                slot["unhealthy_until"] = 0.0
        # L1 says healthy (either default-absent, prior success, or
        # elapsed cooldown). #142: check whether a peer worker has
        # flagged this URL since our last observation.
        peer = self._read_redis(url)
        if peer is None:
            return True
        # Adopt the peer's deadline into L1 so subsequent picks skip
        # the round-trip. Wall-clock -> monotonic conversion carries
        # a few-ms skew from the ``time.time()`` reading in
        # ``_read_redis`` but the cooldown window is 60s by default,
        # so the drift is immaterial.
        try:
            deadline_epoch = float(peer["unhealthy_until_epoch"])
        except (KeyError, TypeError, ValueError):
            _log.debug(
                "llm-health L2: peer marker for %s missing/invalid deadline; "
                "treating endpoint as healthy (fail-open)",
                url,
            )
            return True
        remaining = deadline_epoch - self._wall_clock()
        if remaining <= 0:
            return True
        with self._lock:
            slot = self._slot(url)
            slot["status"] = ENDPOINT_STATUS_UNHEALTHY
            slot["unhealthy_until"] = float(self._clock() + remaining)
            peer_kind = peer.get("last_failure_kind")
            if peer_kind is not None:
                slot["last_failure_kind"] = peer_kind
        return False

    def record_drift(
        self,
        model_id: str,
        task_type: str,
        status: str,
    ) -> None:
        """Record one drift observation for (``model_id``, ``task_type``).

        Called from the seal step after :class:`ConfidenceDriftTracker`
        computes a fresh drift status. A ``degrading`` / ``volatile``
        status marks the slot degraded for ``drift_cooldown_s``; a
        ``stable`` observation clears the degradation immediately
        (a single stable sample is enough to re-eligible the model,
        mirroring the infra ``record_success`` contract). Statuses the
        router does not recognise (``insufficient_data``, empty string)
        are silently ignored so a caller that always calls in never
        needs to guard on the tracker's fallback labels.

        Idempotent: back-to-back degrading observations roll the cooldown
        forward and increment ``total_degraded``; back-to-back stable
        observations increment ``total_stable`` without disturbing the
        cooldown timer once it has already elapsed. The router never
        removes a slot; a persistent snapshot remains for operator
        diagnostics.
        """
        if not model_id or not task_type:
            return
        if status not in _DEGRADED_DRIFT_STATUSES and status != DRIFT_STATUS_STABLE:
            # insufficient_data / unknown label -- nothing actionable.
            return
        now = self._clock()
        with self._lock:
            slot = self._drift_slot(model_id, task_type)
            slot["last_recorded_at"] = now
            if status in _DEGRADED_DRIFT_STATUSES:
                slot["status"] = status
                slot["degraded_until"] = float(now + self._drift_cooldown_s)
                slot["total_degraded"] = int(
                    slot["total_degraded"],  # type: ignore[arg-type]
                ) + 1
            else:
                slot["status"] = DRIFT_STATUS_STABLE
                slot["degraded_until"] = 0.0
                slot["total_stable"] = int(
                    slot["total_stable"],  # type: ignore[arg-type]
                ) + 1
        if status in _DEGRADED_DRIFT_STATUSES:
            _log.info(
                "model_health_router.record_drift model=%s task_type=%s "
                "status=%s cooldown_s=%.1f",
                model_id, task_type, status, self._drift_cooldown_s,
            )

    def is_drift_degraded(self, model_id: str, task_type: str) -> bool:
        """Return True iff (``model_id``, ``task_type``) is currently biased against.

        Lazy recovery mirrors :meth:`is_healthy`: a slot whose
        ``degraded_until`` timestamp has slid into the past is treated
        as stable again without a fresh observation, so a model that
        drifted once but was never re-sampled stops biasing pick
        forever after the cooldown lapses.
        """
        if not model_id or not task_type:
            return False
        with self._lock:
            slot = self._drift.get((model_id, task_type))
            if slot is None:
                return False
            if slot["status"] == DRIFT_STATUS_STABLE:
                return False
            deadline = float(slot["degraded_until"])  # type: ignore[arg-type]
            if self._clock() >= deadline:
                slot["status"] = DRIFT_STATUS_STABLE
                slot["degraded_until"] = 0.0
                return False
            return True

    def pick(
        self,
        candidates: list[str],
        *,
        default: str,
        model_id: str | None = None,
        task_type: str | None = None,
    ) -> str:
        """Return the first healthy candidate, falling back to ``default``.

        Behaviour on the happy path (no unhealthy candidates AND no drift
        bias) is deterministic: ``candidates[0]`` when the list is
        non-empty, otherwise ``default``. That determinism is what
        makes the router behaviour-preserving today, when the operator's
        gateway config typically resolves to one URL.

        When ``model_id`` and ``task_type`` are supplied, a drift bias
        for the (model, task_type) pair skips the first healthy candidate
        in favour of the next one -- so a drifting model on the primary
        gateway hands the pick to the operator's fallback URL. When
        every candidate is either infra-unhealthy or drift-biased for
        the same model, the router returns the first infra-healthy URL
        it saw (drift is quality, not infra; a drifting model is still
        preferable to a hard outage). Falls back to ``default`` when
        no candidate is infra-healthy.

        A ``default`` that is itself unhealthy is still returned when
        every candidate is unhealthy -- routing to a known-bad URL
        surfaces the outage as the next call's exception, which is
        the correct signal for the operator; silently dropping the
        call would be worse.
        """
        if not candidates:
            return default
        drift_biased = bool(
            model_id and task_type
            and self.is_drift_degraded(model_id, task_type),
        )
        first_healthy: str | None = None
        for url in candidates:
            if not self.is_healthy(url):
                continue
            if first_healthy is None:
                first_healthy = url
                if not drift_biased:
                    return url
                # Drift bias -- keep looking for a non-primary healthy URL.
                continue
            _log.info(
                "model_health_router.pick drift_bias model=%s task_type=%s "
                "skipping primary=%s picking fallback=%s",
                model_id, task_type, first_healthy, url,
            )
            return url
        if first_healthy is not None:
            if drift_biased:
                _log.info(
                    "model_health_router.pick drift_bias model=%s task_type=%s "
                    "no fallback -- returning drifting primary=%s",
                    model_id, task_type, first_healthy,
                )
            return first_healthy
        _log.warning(
            "model_health_router.pick: every candidate is unhealthy "
            "(%d checked) -- falling back to default=%s",
            len(candidates), default,
        )
        return default

    def pick_model(
        self,
        candidates: list[str],
        *,
        default: str,
        task_type: str,
    ) -> str:
        """Return the first non-drift-degraded model, falling back to ``default``.

        Mirror of :meth:`pick` on the model-id axis. Deterministic when
        no drift is on record: returns ``candidates[0]``. When the
        primary is drift-biased for ``task_type``, prefers the next
        stable candidate; when every candidate is drift-biased,
        returns ``candidates[0]`` (a drifting primary is still
        preferable to picking blindly against no evidence). Falls
        back to ``default`` when ``candidates`` is empty.

        Called from :meth:`LLMConfigProvider.resolve_model` so a
        persistently drifting primary model routes to the operator's
        configured fallback for that task_type without a config edit.
        """
        if not candidates:
            return default
        primary = candidates[0]
        if not self.is_drift_degraded(primary, task_type):
            return primary
        for url in candidates[1:]:
            if not self.is_drift_degraded(url, task_type):
                _log.info(
                    "model_health_router.pick_model drift_bias task_type=%s "
                    "skipping primary=%s picking fallback=%s",
                    task_type, primary, url,
                )
                return url
        _log.info(
            "model_health_router.pick_model task_type=%s every candidate "
            "drift-biased -- returning primary=%s",
            task_type, primary,
        )
        return primary

    def snapshot_drift(self) -> tuple[ModelDrift, ...]:
        """Return an immutable view of every tracked drift slot.

        Diagnostic accessor for the operator dashboard. Sorted by
        (model_id, task_type) so log-line and JSON output are
        deterministic across runs.
        """
        with self._lock:
            keys = sorted(self._drift.keys())
            snap = tuple(
                ModelDrift(
                    model_id=model_id,
                    task_type=task_type,
                    status=str(self._drift[(model_id, task_type)]["status"]),
                    degraded_until_monotonic=float(
                        self._drift[(model_id, task_type)]["degraded_until"],  # type: ignore[arg-type]
                    ),
                    last_recorded_at_monotonic=float(
                        self._drift[(model_id, task_type)]["last_recorded_at"],  # type: ignore[arg-type]
                    ),
                    total_stable=int(
                        self._drift[(model_id, task_type)]["total_stable"],  # type: ignore[arg-type]
                    ),
                    total_degraded=int(
                        self._drift[(model_id, task_type)]["total_degraded"],  # type: ignore[arg-type]
                    ),
                )
                for model_id, task_type in keys
            )
        return snap

    def snapshot(self) -> tuple[EndpointHealth, ...]:
        """Return an immutable view of every tracked URL's state.

        Diagnostic accessor for the operator dashboard. Sorted by URL
        so log-line and JSON output are deterministic across runs.
        A URL never observed is absent from the snapshot; callers
        should treat absence as "no evidence" (i.e. healthy).
        """
        with self._lock:
            urls = sorted(self._state.keys())
            snap = tuple(
                EndpointHealth(
                    url=url,
                    status=str(self._state[url]["status"]),
                    unhealthy_until_monotonic=float(
                        self._state[url]["unhealthy_until"],  # type: ignore[arg-type]
                    ),
                    consecutive_failures=int(
                        self._state[url]["consecutive_failures"],  # type: ignore[arg-type]
                    ),
                    total_failures=int(
                        self._state[url]["total_failures"],  # type: ignore[arg-type]
                    ),
                    total_successes=int(
                        self._state[url]["total_successes"],  # type: ignore[arg-type]
                    ),
                    last_failure_kind=(
                        str(self._state[url]["last_failure_kind"])
                        if self._state[url]["last_failure_kind"] is not None
                        else None
                    ),
                )
                for url in urls
            )
        return snap


def _resolve_redis_shared_gate_default() -> bool:
    """Read ``platform.llm_health_router_redis_shared`` via ConfigRegistry.

    Env > cache > DB > :class:`PlatformConfigSchema` default (True). A
    registry / DB failure defaults to True so a bad DB row cannot
    silently disable the shared cache on an otherwise-configured
    deployment. Deferred import breaks a circular: ``storage.registry``
    imports ``platform.services.redis_pool``, which imports back into
    ``platform`` at module load; keeping the import inside the
    resolver keeps this file leaf-level for cold-load ordering.
    """
    try:
        from ...storage.registry import ConfigRegistry
    except ImportError:
        _log.debug(
            "model_health_router: ConfigRegistry unimportable; "
            "defaulting shared-cache gate to True",
            exc_info=True,
        )
        return True
    try:
        import sqlalchemy.exc as _sa_exc

        _db_errors: tuple[type[BaseException], ...] = (
            OSError, RuntimeError, ValueError, LookupError,
            _sa_exc.SQLAlchemyError,
        )
    except ImportError:  # pragma: no cover - sqlalchemy is a hard dep
        _db_errors = (OSError, RuntimeError, ValueError, LookupError)
    try:
        raw = ConfigRegistry().get_sync(
            _REDIS_SHARED_CONFIG_NS, _REDIS_SHARED_CONFIG_KEY,
        )
    except _db_errors:
        _log.debug(
            "model_health_router: ConfigRegistry.get_sync raised; "
            "defaulting shared-cache gate to True",
            exc_info=True,
        )
        return True
    if raw is None:
        return True
    if isinstance(raw, bool):
        return raw
    # PlatformConfigSchema declares this key as ``bool``, but env-var
    # round-tripping surfaces strings ("1"/"true"/"false"). Mirror the
    # ConfigRegistry coercion tolerantly instead of failing closed.
    if isinstance(raw, str):
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    return bool(raw)


# Process-wide singleton wired into the LLM client's retry loop. Kept
# module-level (not a class attribute) so a test can substitute the
# default via :func:`reset_default_health_router` without reaching into
# the class internals.
_default_router_lock = threading.Lock()
_default_router: ModelHealthRouter | None = None


def get_default_health_router() -> ModelHealthRouter:
    """Return the process-wide :class:`ModelHealthRouter` singleton.

    Constructed on first access with default tuning. The LLM client's
    ``_record_llm_error`` / ``_record_llm_ok`` hooks call this to
    feed per-URL health events without threading a router instance
    through every call site.
    """
    global _default_router
    if _default_router is not None:
        return _default_router
    with _default_router_lock:
        if _default_router is None:
            _default_router = ModelHealthRouter()
        return _default_router


def reset_default_health_router() -> None:
    """Drop the process-wide singleton so the next call rebuilds it empty.

    Test-only helper -- production wiring lets the router live for the
    worker's lifetime. Exposed so per-test fixtures can wipe accumulated
    state without leaking across tests.
    """
    global _default_router
    with _default_router_lock:
        _default_router = None
