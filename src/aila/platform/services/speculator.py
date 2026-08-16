"""Speculative tool pre-warming (issue #156).

Interactive speculative planning for the AILA tool loop. While the strong
model on turn N decides the next tool_run, a cheap (Haiku-class) model
runs in parallel to predict the same call and pre-warm the MCP round
trip. When the actual (server, tool, args) match the prediction, the
pre-warmed result is used directly -- latency win, byte-identical
payload; when they disagree the pre-warmed result is discarded so the
strong model's decision is the sole authority (quality LOSSLESS).

Design (per arXiv 2509.01920 / 2510.04371):

* The speculator lives OUTSIDE the strong-model decision loop. The
  :meth:`Speculator.enqueue_next` seam is called at the END of turn N's
  ``ToolExecutorHelpersBase.execute()``, after the current tool result
  is committed. It kicks off a background asyncio.Task that:

    1. Assembles a compact "recent tool calls" prompt for the branch.
    2. Calls the cheap model (task_type ``speculative_next_tool`` by
       default) through :func:`idempotent_llm_call` -- one prediction
       per (branch, turn+1), keyed into the LLM idempotency cache so a
       worker retry does not re-pay.
    3. Parses the reply as a :func:`parse_command` tool_run command.
    4. Validates the predicted (server, tool) pair is (a) inside the
       caller-supplied allowed-server frozenset and (b) marked as a
       READ tool via the platform read-tool registry
       (:func:`get_read_tools`). Any other prediction is DISCARDED --
       state-changing tools are NEVER pre-warmed. This is the safety
       guard the acceptance criterion demands.
    5. Invokes ``bridge.forward(action=tool, **args)`` with a short
       wall-clock cap. The raw dict is stashed in a slot keyed by
       ``(branch_id, target_turn)``.

* At the START of turn N+1's ``execute()`` the executor calls
  :meth:`Speculator.claim` with the strong model's ACTUAL
  ``(server_id, tool_name, args)``. When the stashed slot matches
  byte-for-byte (server + tool + canonical args) the raw dict is
  returned; the caller uses it as if ``bridge.forward`` had just
  returned it. A miss (task not done, prediction differs, task
  errored) returns ``None`` and the caller dispatches normally.

Concurrency model: process-wide singleton, LRU-capped (``max_slots``).
The prediction + pre-warm task runs on the running event loop; the
worker process keeps the same loop across ARQ jobs so a slot enqueued
by job N is visible to job N+1 without any Redis / DB round trip. When
the process dies mid-flight the slot is silently lost -- the caller's
``claim`` returns ``None`` and the normal dispatch runs.

Cost model: on every turn where the flag is on the speculator pays for
one cheap-model prediction plus (optionally) one MCP read-tool round
trip. On a HIT that MCP round trip replaces the one the strong model
would have made -- net zero extra MCP traffic, minus one round trip of
wall-clock latency. On a MISS it is one wasted read-tool call plus the
prediction cost; the strong model still runs its own MCP call. Read
tools are idempotent by contract, so the waste is bounded and safe.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import httpx
from sqlalchemy.exc import SQLAlchemyError

from aila.platform.agents.idempotent_llm import idempotent_llm_call
from aila.platform.agents.tool_execution import parse_command

if TYPE_CHECKING:
    from aila.storage.registry import ConfigRegistry

__all__ = [
    "PrewarmedResult",
    "Speculator",
    "get_default_speculator",
    "is_speculation_enabled",
    "resolve_speculation_settings",
    "SpeculationSettings",
]

_log = logging.getLogger(__name__)

# Broad-but-named failure tuple used everywhere on the best-effort path
# so a bug inside the speculator NEVER escapes into the real tool
# dispatch. Bare ``except Exception`` is banned by the repo rules; this
# tuple covers every failure mode the LLM / bridge / registry paths
# realistically throw.
_SAFE_ERRORS: tuple[type[BaseException], ...] = (
    OSError,           # includes TimeoutError in 3.11+
    RuntimeError,
    ValueError,
    TypeError,
    AttributeError,
    KeyError,
    IndexError,
    json.JSONDecodeError,
    httpx.HTTPError,
    SQLAlchemyError,
)


def _canonical_args(args: dict[str, Any] | None) -> str:
    """JSON-canonicalize ``args`` for a byte-stable equality check.

    Matches the canonicalization used by the repeat-failure circuit
    breaker in ``tool_executor._count_prior_failures`` so a pre-warm
    slot compares equal to the same call irrespective of key insertion
    order.
    """
    try:
        return json.dumps(args or {}, sort_keys=True, default=str)
    except (TypeError, ValueError) as exc:
        _log.debug("speculator: args not JSON-canonicalizable: %s", exc)
        return ""


@dataclass(slots=True)
class PrewarmedResult:
    """One completed speculative pre-warm awaiting a matching dispatch."""

    server_id: str
    tool_name: str
    args_canonical: str
    raw: dict[str, Any]


@dataclass(slots=True, frozen=True)
class SpeculationSettings:
    """Runtime knobs pulled from ``PlatformConfigSchema``."""

    enabled: bool
    task_type: str
    history_max_messages: int
    prewarm_timeout_s: float
    slot_ttl_s: float
    claim_wait_timeout_s: float


BridgeResolver = Callable[[str], Any]
"""Server-id → bridge resolver (typically ``ToolExecutorHelpersBase._bridge_for``)."""

HistorySnapshot = list[dict[str, Any]]
"""Compact per-turn history entries: ``{server, tool, args}``."""


def _as_bool(raw: Any) -> bool:
    if isinstance(raw, bool):
        return raw
    if raw is None:
        return False
    return str(raw).strip().lower() in {"1", "true", "yes", "on", "y"}


async def resolve_speculation_settings(
    registry: ConfigRegistry,
) -> SpeculationSettings:
    """Resolve every speculation knob in one pass.

    Reads run behind :meth:`ConfigRegistry.get` which caches for 60 s
    and honours cross-process invalidation, so this stays a hot-path
    dict lookup on repeat calls. A per-key registry miss falls back to
    the schema-side default.
    """
    async def _get(key: str, default: Any) -> Any:
        try:
            raw = await registry.get("platform", key)
        except _SAFE_ERRORS:
            return default
        return raw if raw is not None else default

    return SpeculationSettings(
        enabled=_as_bool(await _get("speculative_enabled", False)),
        task_type=str(await _get(
            "speculative_task_type", "speculative_next_tool",
        )) or "speculative_next_tool",
        history_max_messages=int(await _get(
            "speculative_history_max_messages", 8,
        ) or 8),
        prewarm_timeout_s=float(await _get(
            "speculative_prewarm_timeout_s", 20.0,
        ) or 20.0),
        slot_ttl_s=float(await _get(
            "speculative_slot_ttl_s", 120.0,
        ) or 120.0),
        claim_wait_timeout_s=float(await _get(
            "speculative_claim_wait_timeout_s", 0.0,
        ) or 0.0),
    )


async def is_speculation_enabled(registry: ConfigRegistry) -> bool:
    """Fast-path enabled check for the hot claim/enqueue sites."""
    try:
        raw = await registry.get("platform", "speculative_enabled")
    except _SAFE_ERRORS:
        return False
    return _as_bool(raw)


class Speculator:
    """Process-wide registry of speculative pre-warmed MCP calls.

    One instance per process; see :func:`get_default_speculator`. Slots
    are keyed by ``(branch_id, target_turn)``. Multiple branches / turns
    are tracked concurrently; the LRU cap bounds memory.
    """

    def __init__(self, *, max_slots: int = 256) -> None:
        self._slots: dict[
            tuple[str, int], asyncio.Task[PrewarmedResult | None]
        ] = {}
        self._created_at: dict[tuple[str, int], float] = {}
        self._lock = asyncio.Lock()
        self._max_slots = max_slots
        self._llm_client: Any | None = None
        # Observability counters -- read by tests + operator log lines.
        self.hits = 0
        self.misses = 0
        self.errors = 0
        self.enqueued = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def enqueue_next(
        self,
        *,
        investigation_id: str,
        branch_id: str,
        target_turn: int,
        recent_tool_history: HistorySnapshot,
        allowed_servers: frozenset[str] | None,
        read_tools: frozenset[tuple[str, str]],
        bridge_for: BridgeResolver,
        registry: ConfigRegistry,
        settings: SpeculationSettings,
    ) -> None:
        """Kick off a background prediction + pre-warm for ``target_turn``.

        Non-blocking. Best-effort by contract -- every failure logs at
        INFO and returns silently. When a prior slot exists for the same
        ``(branch, turn)`` (rare: two consecutive enqueue calls) it is
        cancelled and replaced.
        """
        if not settings.enabled:
            return
        if not read_tools:
            # Nothing safe to pre-warm.
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError as exc:
            # No running loop (e.g. an odd sync call site); enqueue is a
            # pure best-effort seam and skipping is the safe fallback.
            _log.debug("speculator: no running loop, skipping enqueue: %s", exc)
            return
        key = (branch_id, target_turn)
        async with self._lock:
            self._evict_expired_locked(settings.slot_ttl_s)
            self._evict_oldest_locked()
            prior = self._slots.pop(key, None)
            self._created_at.pop(key, None)
        if prior is not None and not prior.done():
            prior.cancel()
        task = loop.create_task(
            self._predict_and_prewarm(
                investigation_id=investigation_id,
                branch_id=branch_id,
                target_turn=target_turn,
                recent_tool_history=list(recent_tool_history or []),
                allowed_servers=allowed_servers,
                read_tools=read_tools,
                bridge_for=bridge_for,
                registry=registry,
                settings=settings,
            ),
            name=f"speculator:{branch_id[:8]}:{target_turn}",
        )
        async with self._lock:
            self._slots[key] = task
            self._created_at[key] = time.monotonic()
            self.enqueued += 1

    async def claim(
        self,
        *,
        branch_id: str,
        turn_number: int,
        server_id: str,
        tool_name: str,
        args: dict[str, Any],
        wait_timeout_s: float = 0.0,
    ) -> dict[str, Any] | None:
        """Return the pre-warmed raw dict when it matches; else ``None``.

        A match requires ``(server, tool, canonical(args))`` byte
        equality against the pre-warmed slot. On mismatch OR error OR
        no slot present, returns ``None`` and the caller MUST dispatch
        normally. Slots are consumed on lookup regardless of match --
        the strong model's decision is authoritative and the slot is a
        one-shot resource.
        """
        key = (branch_id, turn_number)
        async with self._lock:
            task = self._slots.pop(key, None)
            self._created_at.pop(key, None)
        if task is None:
            return None
        try:
            result = await self._resolve_task(task, wait_timeout_s)
        except _SAFE_ERRORS as exc:
            self.errors += 1
            _log.info(
                "speculator: claim resolution error branch=%s turn=%s "
                "(%s: %s)",
                branch_id[:8], turn_number, type(exc).__name__, exc,
            )
            return None
        if result is None:
            self.misses += 1
            return None
        want_canonical = _canonical_args(args)
        if (
            result.server_id != server_id
            or result.tool_name != tool_name
            or result.args_canonical != want_canonical
        ):
            self.misses += 1
            _log.info(
                "speculator MISS branch=%s turn=%s predicted=%s.%s "
                "actual=%s.%s",
                branch_id[:8], turn_number,
                result.server_id, result.tool_name, server_id, tool_name,
            )
            return None
        self.hits += 1
        _log.info(
            "speculator HIT branch=%s turn=%s tool=%s.%s (latency win)",
            branch_id[:8], turn_number, server_id, tool_name,
        )
        return result.raw

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    async def _resolve_task(
        self,
        task: asyncio.Task[PrewarmedResult | None],
        wait_timeout_s: float,
    ) -> PrewarmedResult | None:
        """Await ``task`` up to ``wait_timeout_s``; cancel on timeout."""
        if task.done():
            try:
                return task.result()
            except asyncio.CancelledError:
                _log.debug("speculator: prewarm task was cancelled; miss")
                return None
        if wait_timeout_s <= 0:
            # Non-blocking claim: not ready, so treat as miss. Cancel
            # to reclaim the slot (the prediction is stale once the
            # strong model has already picked its own call).
            task.cancel()
            return None
        try:
            return await asyncio.wait_for(
                asyncio.shield(task), wait_timeout_s,
            )
        except TimeoutError:
            task.cancel()
            return None

    def _evict_expired_locked(self, ttl_s: float) -> None:
        if ttl_s <= 0:
            return
        now = time.monotonic()
        expired = [
            k for k, ts in self._created_at.items()
            if now - ts > ttl_s
        ]
        for k in expired:
            task = self._slots.pop(k, None)
            self._created_at.pop(k, None)
            if task is not None and not task.done():
                task.cancel()

    def _evict_oldest_locked(self) -> None:
        while len(self._slots) >= self._max_slots:
            oldest_key = next(iter(self._slots))
            task = self._slots.pop(oldest_key, None)
            self._created_at.pop(oldest_key, None)
            if task is not None and not task.done():
                task.cancel()

    def _get_llm_client(self, registry: ConfigRegistry) -> Any:
        """Lazily build one :class:`AilaLLMClient` for the process.

        Deferred import breaks the ``platform.services -> platform.llm``
        boot ordering the same way :mod:`platform.agents.auto_steering`
        does when it constructs its own LLM client.
        """
        if self._llm_client is None:
            from aila.platform.llm.client import AilaLLMClient
            from aila.storage.secrets import SecretStore

            self._llm_client = AilaLLMClient(
                registry=registry, secret_store=SecretStore(),
            )
        return self._llm_client

    async def _predict_and_prewarm(
        self,
        *,
        investigation_id: str,
        branch_id: str,
        target_turn: int,
        recent_tool_history: HistorySnapshot,
        allowed_servers: frozenset[str] | None,
        read_tools: frozenset[tuple[str, str]],
        bridge_for: BridgeResolver,
        registry: ConfigRegistry,
        settings: SpeculationSettings,
    ) -> PrewarmedResult | None:
        """Cheap-model prediction + read-only pre-warm.

        Runs entirely on the background asyncio task; the caller never
        awaits this coroutine directly.
        """
        try:
            prompt = self._build_prediction_prompt(
                recent_tool_history=recent_tool_history[
                    -settings.history_max_messages:
                ],
                allowed_servers=allowed_servers,
                read_tools=read_tools,
            )
            client = self._get_llm_client(registry)
            response, _cache_hit = await asyncio.wait_for(
                idempotent_llm_call(
                    client,
                    method="chat",
                    task_type=settings.task_type,
                    messages=[{"role": "user", "content": prompt}],
                    investigation_id=investigation_id,
                    branch_id=branch_id,
                    turn_number=target_turn,
                ),
                timeout=settings.prewarm_timeout_s,
            )
            if getattr(response, "disabled", False):
                return None
            content = (getattr(response, "content", "") or "").strip()
            command_str = _extract_command_json(content)
            if not command_str:
                return None
            parsed = parse_command(command_str)
            if parsed is None:
                return None
            tool_id, args = parsed
            server_id, _, tool_name = tool_id.partition(".")
            if not server_id or not tool_name:
                return None

            # Safety guard 1: allowed-server enforcement mirrors the
            # tool_executor's own module + phase allowlist. The
            # speculator NEVER pre-warms a call the caller could not
            # otherwise dispatch.
            if (
                allowed_servers is not None
                and server_id not in allowed_servers
            ):
                _log.info(
                    "speculator: predicted disallowed server %s -- "
                    "refusing prewarm", server_id,
                )
                return None

            # Safety guard 2 (THE CRITICAL ONE): read-only tools only.
            # Every state-changing tool (submit, patch, mutate) is
            # excluded from the read-tool registry, so a positive
            # membership check is sufficient. Never pre-warm a tool
            # that is not explicitly declared as a lossless read.
            if (server_id, tool_name) not in read_tools:
                _log.info(
                    "speculator: predicted non-read tool %s.%s -- "
                    "refusing prewarm (safety guard)",
                    server_id, tool_name,
                )
                return None

            bridge = bridge_for(server_id)
            if bridge is None:
                return None

            args_canonical = _canonical_args(args)
            t0 = time.monotonic()
            try:
                raw = await asyncio.wait_for(
                    bridge.forward(action=tool_name, **args),
                    timeout=settings.prewarm_timeout_s,
                )
            except TimeoutError:
                _log.info(
                    "speculator: bridge prewarm timeout %s.%s "
                    "(%.2fs cap)",
                    server_id, tool_name, settings.prewarm_timeout_s,
                )
                return None
            except _SAFE_ERRORS as exc:
                _log.info(
                    "speculator: bridge prewarm failed %s.%s (%s: %s)",
                    server_id, tool_name, type(exc).__name__, exc,
                )
                return None
            if not isinstance(raw, dict):
                return None
            elapsed_ms = int((time.monotonic() - t0) * 1000)
            _log.info(
                "speculator: prewarmed %s.%s in %dms (branch=%s "
                "target_turn=%s)",
                server_id, tool_name, elapsed_ms,
                branch_id[:8], target_turn,
            )
            return PrewarmedResult(
                server_id=server_id,
                tool_name=tool_name,
                args_canonical=args_canonical,
                raw=raw,
            )
        except asyncio.CancelledError:
            raise
        except TimeoutError:
            _log.info(
                "speculator: prediction wall-clock timeout inv=%s",
                investigation_id,
            )
            return None
        except _SAFE_ERRORS as exc:
            _log.info(
                "speculator: predict_and_prewarm failed inv=%s (%s: %s)",
                investigation_id, type(exc).__name__, exc,
            )
            return None

    @staticmethod
    def _build_prediction_prompt(
        *,
        recent_tool_history: HistorySnapshot,
        allowed_servers: frozenset[str] | None,
        read_tools: frozenset[tuple[str, str]],
    ) -> str:
        """Compact prompt asking for a single next tool_run JSON."""
        if recent_tool_history:
            hist_lines = []
            for entry in recent_tool_history:
                server = str(entry.get("server") or "?")
                tool = str(entry.get("tool") or "?")
                try:
                    args_txt = json.dumps(
                        entry.get("args") or {},
                        sort_keys=True, default=str,
                    )
                except (TypeError, ValueError):
                    args_txt = "{}"
                # Cap args echo so a huge prior call cannot bloat the
                # cheap-model prompt into the strong-model regime.
                if len(args_txt) > 400:
                    args_txt = args_txt[:400] + "..."
                hist_lines.append(f"- {server}.{tool} args={args_txt}")
            history_block = "\n".join(hist_lines)
        else:
            history_block = "(none yet)"

        allowed_block = (
            ", ".join(sorted(allowed_servers))
            if allowed_servers else "(all)"
        )

        # Narrow the tool-name suggestion to (a) the allowed-server
        # frontier and (b) the READ-tool registry -- the same
        # intersection the safety guard enforces at pre-warm time. Cap
        # to keep the prompt short.
        read_hints: list[str] = []
        for s, t in sorted(read_tools):
            if allowed_servers is not None and s not in allowed_servers:
                continue
            read_hints.append(f"{s}.{t}")
            if len(read_hints) >= 60:
                break
        hints_block = ", ".join(read_hints) if read_hints else "(none)"

        return (
            "You are a low-latency planner. Given the recent tool calls "
            "on this branch, predict the SINGLE next tool_run the main "
            "reasoning agent is most likely to dispatch.\n\n"
            "Reply as a valid JSON object of exactly this shape, on one "
            "line, with no code fences and no prose before or after:\n"
            '{"tool": "<server>.<tool>", "args": {...}}\n\n'
            "Constraints:\n"
            "- The tool MUST be a read-only tool from the catalog below.\n"
            "- If you are not confident, reply exactly: "
            '{"tool": "", "args": {}}\n\n'
            f"Allowed servers: {allowed_block}\n"
            f"Read-only tool catalog (safe to pre-warm): {hints_block}\n"
            f"\nRecent tool calls on this branch:\n{history_block}\n"
        )


def _extract_command_json(content: str) -> str:
    """Best-effort JSON-object extraction from a chat completion.

    Cheap models occasionally wrap the JSON in ``\u0060\u0060\u0060json`` fences
    or add a trailing period. This helper slices the first
    ``{`` -> matching ``}`` span so :func:`parse_command` gets a clean
    payload. Empty string → speculator discards the prediction.
    """
    if not content:
        return ""
    text = content.strip()
    if text.startswith("```"):
        # Strip the leading fence + optional language tag.
        text = text[3:]
        newline_pos = text.find("\n")
        if newline_pos != -1:
            first_line = text[:newline_pos].strip().lower()
            # `json` (or any lang tag) sits on the fence's opening line.
            if first_line and not first_line.startswith("{"):
                text = text[newline_pos + 1:]
        # Drop the trailing fence.
        close = text.rfind("```")
        if close != -1:
            text = text[:close]
        text = text.strip()
    lb = text.find("{")
    if lb < 0:
        return ""
    # Balanced-brace scan to find the matching close.
    depth = 0
    in_str = False
    esc = False
    for i in range(lb, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[lb:i + 1]
    return ""


_DEFAULT_SPECULATOR: Speculator | None = None


def get_default_speculator() -> Speculator:
    """Return the process-wide :class:`Speculator` singleton.

    A single instance is intentional: slots enqueued by one worker job
    must be visible to the next job on the same event loop. Tests that
    need isolation may replace ``_DEFAULT_SPECULATOR`` directly.
    """
    global _DEFAULT_SPECULATOR
    if _DEFAULT_SPECULATOR is None:
        _DEFAULT_SPECULATOR = Speculator()
    return _DEFAULT_SPECULATOR


def _reset_default_speculator_for_tests() -> None:
    """Test-only: drop the process-wide singleton."""
    global _DEFAULT_SPECULATOR
    if _DEFAULT_SPECULATOR is not None:
        for task in list(_DEFAULT_SPECULATOR._slots.values()):
            if not task.done():
                task.cancel()
    _DEFAULT_SPECULATOR = None


