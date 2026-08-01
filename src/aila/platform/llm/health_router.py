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
"""
from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

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
        _log.info(
            "model_health_router.record_infra_failure url=%s kind=%s "
            "cooldown_s=%.1f consecutive=%d total=%d",
            url, kind, self._cooldown_s,
            slot["consecutive_failures"], slot["total_failures"],
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

    def is_healthy(self, url: str) -> bool:
        """Return True iff ``url`` is currently eligible for routing.

        A URL never observed is healthy by default (there is no
        evidence to the contrary). A URL flipped unhealthy becomes
        healthy again once ``unhealthy_until`` slides into the past;
        the recovery is lazy -- ``pick`` and ``is_healthy`` are the
        only touchpoints that observe the clock so a caller that
        never asks never wakes anything up.
        """
        with self._lock:
            slot = self._state.get(url)
            if slot is None:
                return True
            if slot["status"] == ENDPOINT_STATUS_HEALTHY:
                return True
            deadline = float(slot["unhealthy_until"])  # type: ignore[arg-type]
            if self._clock() >= deadline:
                # Lazy recovery: cooldown elapsed, mark healthy and
                # let the caller try again. Counter resets happen on
                # the next real success via ``record_success``.
                slot["status"] = ENDPOINT_STATUS_HEALTHY
                slot["unhealthy_until"] = 0.0
                return True
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
