"""RFC-07 phase 2 -- deterministic tool-call reroute via the RFC-11 capability registry.

The ToolRouter is the reactive half of self-healing for MCP dispatch.
The happy path (first capability member answers cleanly) is byte-identical
to today's dispatch: the router yields the first enabled instance and the
caller's ``dispatch`` coroutine returns its response verbatim. The reactive
half only fires on INFRA-level failure of one instance -- a timeout,
connection refusal, HTTP 5xx, or any exception the caller flags via
:class:`ToolInfraError` -- and takes the shortest-path fallback: the next
enabled catalog member of the SAME capability, in the order the caller's
:class:`~aila.platform.mcp.client.InstancePool` handed them out.

Non-INFRA outcomes (an ``error`` envelope from a healthy bridge, an empty
result, an application-level 4xx) are NOT considered reroute-worthy: the
model routes around infrastructure, never around the tool's own semantics.
Second-guessing tool quality is the operator's job, not the router's.

The router disables a repeatedly failing instance by flipping
:attr:`aila.platform.mcp.instance_catalog.McpServerInstance.enabled` off
after ``consecutive_failure_limit`` back-to-back infra failures against
that instance -- the RFC-11 resolver already treats a disabled row as
absent, so the reroute takes effect on the next capability lookup without
a worker restart. The router NEVER touches the operator's model gateway
configuration, the descriptor's ``default_url``, or any process; it only
mutates the DB row's ``enabled`` bit that operators already flip by hand
from the admin UI.

The router carries per-instance consecutive-failure counters in process
memory. A success resets the counter for that instance. Counters reset on
process restart, which is intentional -- a disabled instance stays
disabled in the catalog across restarts, so state that must survive a
restart lives in the DB.
"""
from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Generic, TypeVar

if TYPE_CHECKING:
    from aila.platform.mcp.client import ResolvedInstance
    from aila.platform.mcp.instance_catalog import McpInstanceCatalog

__all__ = [
    "ToolInfraError",
    "ToolRouteAttempt",
    "ToolRouteResult",
    "ToolRouter",
]

_log = logging.getLogger(__name__)

# Default failure ceiling. Three consecutive INFRA failures against ONE
# instance is enough evidence that the instance is genuinely down and not
# hitting a transient blip; the reroute below already covers a single blip
# without escalating to a disable flip. Callers override per-capability
# via the ToolRouter constructor.
_DEFAULT_CONSECUTIVE_FAILURE_LIMIT: int = 3


TResult = TypeVar("TResult")


class ToolInfraError(RuntimeError):
    """Raised (or wrapped) by the dispatch coroutine to signal an INFRA
    failure that the router should reroute past.

    Only network / transport / 5xx conditions qualify. An application
    error envelope from a healthy bridge (``{"status": "error", ...}``)
    is NOT an infra failure and MUST be surfaced as a normal result
    -- the router does not second-guess tool semantics.
    """


@dataclass(frozen=True, slots=True)
class ToolRouteAttempt:
    """One attempt against one resolved instance.

    ``instance_id`` is None for env / config / default tier hits (see
    :class:`~aila.platform.mcp.client.ResolvedInstance`); the router
    records those attempts too so a caller's diagnostic can reconstruct
    the reroute chain, but a None id skips the disable-flip step.
    """

    instance_id: str | None
    url: str
    source: str
    error: str | None = None


@dataclass(frozen=True, slots=True)
class ToolRouteResult(Generic[TResult]):
    """Terminal outcome of one :meth:`ToolRouter.route` call.

    ``ok=True`` implies ``value`` is the caller's dispatch return and
    ``attempts[-1].error is None``. ``ok=False`` means every enabled
    instance raised :class:`ToolInfraError`; ``value`` is None and
    ``attempts`` carries one entry per member exhausted.
    """

    ok: bool
    value: TResult | None
    attempts: tuple[ToolRouteAttempt, ...] = field(default_factory=tuple)


class ToolRouter(Generic[TResult]):
    """Reroute a tool/capability call across every enabled instance.

    Constructed once per module or per turn, then reused for every tool
    call that resolves through the RFC-11 capability registry. The
    router is stateful: it accumulates per-instance failure counters
    used to decide when to flip an instance's ``enabled`` bit off. State
    is process-local; a disabled catalog row is the persistent signal.

    Parameters
    ----------
    catalog:
        The RFC-11 instance catalog used to flip ``enabled`` after
        repeated infra failures. May be ``None`` in test paths that
        want to verify reroute behaviour without touching the DB;
        with a ``None`` catalog the router still reroutes past a
        failed member and records the failure counter, but skips the
        disable-flip step.
    consecutive_failure_limit:
        How many back-to-back INFRA failures against ONE instance
        trigger the ``enabled=False`` flip. Defaults to
        :data:`_DEFAULT_CONSECUTIVE_FAILURE_LIMIT`.
    """

    def __init__(
        self,
        *,
        catalog: McpInstanceCatalog | None = None,
        consecutive_failure_limit: int = _DEFAULT_CONSECUTIVE_FAILURE_LIMIT,
    ) -> None:
        if consecutive_failure_limit < 1:
            raise ValueError(
                "ToolRouter: consecutive_failure_limit must be >= 1, "
                f"got {consecutive_failure_limit!r}",
            )
        self._catalog = catalog
        self._limit = consecutive_failure_limit
        # instance_id -> consecutive INFRA failure count since last success.
        # env/config/default-tier hits have instance_id=None; the counter
        # key skips those so no cross-instance state bleeds through the
        # None sentinel.
        self._failures: dict[str, int] = {}
        # instance_ids the router has already flipped disabled during this
        # process lifetime, kept so a fresh capability lookup that still
        # returns the row (until the next resolver refresh) does not
        # re-fire the flip.
        self._disabled: set[str] = set()

    async def route(
        self,
        candidates: list[ResolvedInstance],
        dispatch: Callable[[ResolvedInstance], Awaitable[TResult]],
        *,
        capability: str | None = None,
    ) -> ToolRouteResult[TResult]:
        """Try each candidate in turn; return the first non-INFRA outcome.

        The happy path is one iteration: the first candidate answers,
        :meth:`record_success` resets its failure counter, and the
        router returns the dispatch value verbatim. Every next iteration
        only fires when the previous ``dispatch`` raised
        :class:`ToolInfraError` -- an application-error envelope is
        NOT an infra failure and belongs in the ``value`` field of the
        returned :class:`ToolRouteResult`.

        ``candidates`` is the list a caller already resolved through
        the RFC-11 :meth:`~aila.platform.mcp.registry.McpRegistryServiceBase.resolve_by_capability`
        (or an equivalent ordered pool) -- the router does not
        re-resolve so a caller's round-robin ordering is preserved.

        An empty ``candidates`` list returns an ``ok=False`` result
        with an empty ``attempts`` tuple so the caller can distinguish
        "no members at all" (config gap, or every member disabled)
        from "every member failed" (returned ``attempts`` populated).
        """
        attempts: list[ToolRouteAttempt] = []
        if not candidates:
            return ToolRouteResult(ok=False, value=None, attempts=())

        for instance in candidates:
            try:
                value = await dispatch(instance)
            except ToolInfraError as exc:
                error_text = str(exc)[:400]
                attempts.append(
                    ToolRouteAttempt(
                        instance_id=instance.instance_id,
                        url=instance.url,
                        source=instance.source,
                        error=error_text,
                    ),
                )
                await self._record_failure(
                    instance, capability=capability, reason=error_text,
                )
                continue
            attempts.append(
                ToolRouteAttempt(
                    instance_id=instance.instance_id,
                    url=instance.url,
                    source=instance.source,
                    error=None,
                ),
            )
            self.record_success(instance)
            return ToolRouteResult(
                ok=True, value=value, attempts=tuple(attempts),
            )

        _log.warning(
            "tool_router.route capability=%s exhausted %d candidate(s); "
            "every member raised ToolInfraError",
            capability, len(attempts),
        )
        return ToolRouteResult(ok=False, value=None, attempts=tuple(attempts))

    def record_success(self, instance: ResolvedInstance) -> None:
        """Reset the consecutive-failure counter for ``instance``.

        Called on every successful dispatch so a single flake does not
        accumulate over hours until it disables an otherwise healthy
        instance. env/config/default-tier hits carry ``instance_id=None``
        and have no counter to clear.
        """
        if instance.instance_id is None:
            return
        # Idiomatic: pop with default so a first-time success on a
        # never-failed instance is a no-op instead of a KeyError.
        self._failures.pop(instance.instance_id, None)

    async def _record_failure(
        self,
        instance: ResolvedInstance,
        *,
        capability: str | None,
        reason: str,
    ) -> None:
        """Increment ``instance``'s counter; flip ``enabled=False`` at the limit.

        The disable flip is an idempotent DB update via
        :meth:`McpInstanceCatalog.set_enabled`; a second call at the
        same limit is a no-op (the row is already disabled) and never
        raises. env/config/default-tier hits carry ``instance_id=None``
        and skip the flip entirely -- disabling a non-catalog endpoint
        would require mutating the operator's ConfigRegistry or the
        code-embedded default, both of which are out of the router's
        scope (see the module docstring's "never touches gateway
        config" invariant).
        """
        instance_id = instance.instance_id
        if instance_id is None:
            _log.info(
                "tool_router.record_failure capability=%s tier=%s url=%s "
                "reason=%s -- skipping counter (no catalog row to disable)",
                capability, instance.source, instance.url, reason,
            )
            return
        count = self._failures.get(instance_id, 0) + 1
        self._failures[instance_id] = count
        _log.info(
            "tool_router.record_failure capability=%s instance_id=%s "
            "consecutive=%d/%d reason=%s",
            capability, instance_id, count, self._limit, reason,
        )
        if count < self._limit:
            return
        if instance_id in self._disabled:
            return
        if self._catalog is None:
            _log.warning(
                "tool_router.record_failure instance_id=%s hit limit=%d "
                "but no catalog is bound -- disable flip skipped",
                instance_id, self._limit,
            )
            return
        try:
            row = await self._catalog.set_enabled(instance_id, False)
        except (OSError, RuntimeError) as exc:
            # A DB blip must not crash the caller's dispatch loop. The
            # counter stays at the limit so the next failure re-tries
            # the flip on the next call; if the operator flips the row
            # back enabled themselves the counter still resets on the
            # first success (record_success clears the entry).
            _log.warning(
                "tool_router.record_failure catalog.set_enabled(%s) "
                "failed: %s -- reaper / operator will reconcile",
                instance_id, exc,
            )
            return
        self._disabled.add(instance_id)
        if row is None:
            _log.warning(
                "tool_router.record_failure catalog.set_enabled(%s) "
                "returned None -- catalog row missing; treating as "
                "already-absent from the enabled pool",
                instance_id,
            )
            return
        _log.warning(
            "tool_router.record_failure capability=%s instance_id=%s "
            "reached %d consecutive INFRA failures -- flipped enabled=False "
            "(RFC-11 resolver now treats the row as absent)",
            capability, instance_id, self._limit,
        )

    def get_consecutive_failures(self, instance_id: str) -> int:
        """Return the current consecutive-failure count for ``instance_id``.

        Diagnostic accessor for the operator dashboard. Zero when the
        counter has been reset by a success or when the instance has
        never failed. Prefixed ``get_`` so callers see it as an
        accessor, not a live probe -- reading the counter never triggers
        a DB write or a state mutation.
        """
        return self._failures.get(instance_id, 0)

    def get_disabled_ids(self) -> tuple[str, ...]:
        """Return every instance id the router has flipped ``enabled=False``.

        Snapshot for the operator dashboard; the set itself lives on
        the router instance and grows only on a hit against the limit.
        Sorted so log lines and diagnostics compare deterministically
        across runs.
        """
        return tuple(sorted(self._disabled))


def _describe_infra_error(exc: BaseException) -> str:
    """Return a compact one-line description of an INFRA failure.

    Public helper for callers wrapping their dispatch layer -- e.g.
    an ``httpx.ConnectError`` or ``httpx.TimeoutException`` wraps into
    :class:`ToolInfraError` via ``raise ToolInfraError(_describe_infra_error(e))``
    -- so the reroute chain records a uniform reason string across
    transports. The caller decides which exception classes count as
    infra; the router only sees :class:`ToolInfraError`.
    """
    return f"{type(exc).__name__}: {exc}"[:400]


# Public re-export of the helper so callers do not import from a private
# name. Kept out of ``__all__`` above so wildcard imports stay narrow.
describe_infra_error = _describe_infra_error
