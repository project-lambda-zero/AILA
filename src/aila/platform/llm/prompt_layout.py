"""Immutable-prefix / mutable-tail prompt layout contract (issue #155).

Provider prompt caching (Anthropic ~90% read discount at a ~2-read
break-even, OpenAI 24h retention on recent models) collapses per-turn
prefill cost only when the *first N bytes* of every LLM request are
byte-identical across an investigation's lifetime. A long-horizon
agent that mutates the prefix pays full prefill on every turn.

This module owns the contract that keeps the prefix stable:

* Callers assemble a :class:`PromptLayout` whose ``segments`` are
  tagged with :class:`PromptSegmentKind` ``IMMUTABLE`` or ``MUTABLE``.
* IMMUTABLE holds the pieces that never change within an investigation
  -- system prompt (passed separately), tool definitions, module
  capabilities, static persona, investigation-stable header fields
  (title, kind, question, target, strategy), the available-tools
  catalog, and the trailing response contract.
* MUTABLE holds every per-turn growth surface -- operator messages,
  active directives, per-turn turn/branch markers, the case model,
  CVE intel, applicable patterns, prior submissions, sibling context,
  and any retrieved-knowledge tier.
* :meth:`PromptLayout.render` produces the assembled user-message body
  as ``immutable_body + \"\\n\\n\" + mutable_body`` when the platform
  flag is on; when the flag is off, segments render in strict
  insertion order (behaviour is preserved).
* :meth:`PromptLayout.prefix_hash` returns ``sha256(system_prompt
  + \"\\x00\" + immutable_body)`` -- callers assert this is
  byte-identical across turns of the same investigation to prove the
  cache-preserving contract holds.

Gating: :func:`is_prompt_layout_enabled` resolves
``platform.prompt_layout_enabled`` via :class:`ConfigRegistry`.
Default False -- current behaviour is byte-identical.

Investigation-scoped cache TTL: :func:`resolve_cache_ttl_seconds`
returns the operator-configured lifetime hint the client can attach
to a cache-control block when the provider supports it (Anthropic's
``ttl`` field on ``cache_control``). Default 0 = provider default
(Anthropic 5 min, OpenAI up to 24 h on recent models).

Cache-hit-rate gauge:

* :func:`extract_cache_usage` normalises provider-specific usage
  fields (Anthropic ``cache_read_input_tokens`` /
  ``cache_creation_input_tokens``, OpenAI
  ``prompt_tokens_details.cached_tokens``) into a uniform
  ``{cache_read, cache_write, cached}`` dict.
* :func:`record_cache_metrics` folds a single call's cache tokens
  into cumulative counters on :class:`RunMemory`.
* :func:`get_cache_metrics` reads back the cumulative gauge -- served
  by the cost-surface router on the existing ``/cost/runs/{run_id}``
  endpoint.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ...storage.registry import ConfigRegistry
    from .run_memory import RunMemory


__all__ = [
    "IMMUTABLE",
    "MUTABLE",
    "PromptLayout",
    "PromptLayoutBuilder",
    "PromptSegment",
    "PromptSegmentKind",
    "assert_prefix_stable",
    "compute_cache_hit_rate",
    "extract_cache_usage",
    "get_cache_metrics",
    "is_prompt_layout_enabled",
    "record_cache_metrics",
    "resolve_cache_ttl_seconds",
]


_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Segment model
# ---------------------------------------------------------------------------


class PromptSegmentKind(StrEnum):
    """Prompt-layout partition tag.

    :attr:`IMMUTABLE` -- the segment's body is byte-identical across
    every turn of an investigation. The layout renderer places every
    IMMUTABLE segment before any MUTABLE segment so the provider's
    prefix cache stays warm.

    :attr:`MUTABLE` -- the segment's body may change between turns
    (case model, operator steering, per-turn turn/branch markers).
    Placed after every IMMUTABLE segment so a mutation never
    invalidates the prefix.
    """

    IMMUTABLE = "immutable"
    MUTABLE = "mutable"


# Short aliases for callers.
IMMUTABLE = PromptSegmentKind.IMMUTABLE
MUTABLE = PromptSegmentKind.MUTABLE


@dataclass(frozen=True, slots=True)
class PromptSegment:
    """One labelled block of prompt text with an immutability tag.

    ``body`` is the fully-rendered text. ``label`` is used only for
    debugging (logged on cache-hit-rate reports, referenced when a
    prefix-stability assertion fails).
    """

    kind: PromptSegmentKind
    label: str
    body: str


# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------


# Two-blank-line separator between the immutable prefix and the mutable
# tail. Deliberately long enough to survive a stray leading newline on
# the mutable side without changing the prefix's byte layout.
_SEGMENT_JOIN: str = "\n\n"
_PREFIX_TAIL_JOIN: str = "\n\n"


@dataclass(frozen=True, slots=True)
class PromptLayout:
    """Immutable-prefix / mutable-tail assembly for one turn.

    ``system_prompt`` is the system-role message; it is treated as
    part of the immutable prefix for the ``prefix_hash`` calculation
    but is NOT included in :meth:`render` (the caller passes it as
    the first message to the LLM client).

    ``segments`` is an ordered list of :class:`PromptSegment`; the
    renderer preserves insertion order WITHIN each kind and, when
    :attr:`reorder` is True, places every IMMUTABLE segment before any
    MUTABLE segment.

    ``reorder`` reflects the resolved ``prompt_layout_enabled`` flag
    at build time. When False, :meth:`render` walks segments in
    strict insertion order so the assembled body is byte-identical to
    the pre-flag path (behaviour preserved).
    """

    system_prompt: str
    segments: tuple[PromptSegment, ...]
    reorder: bool = False

    def _immutable_segments(self) -> tuple[PromptSegment, ...]:
        return tuple(s for s in self.segments if s.kind is IMMUTABLE)

    def _mutable_segments(self) -> tuple[PromptSegment, ...]:
        return tuple(s for s in self.segments if s.kind is MUTABLE)

    def split(self) -> tuple[str, str]:
        """Return ``(immutable_body, mutable_body)`` in insertion order.

        Independent of :attr:`reorder`: the caller uses this to inspect
        the two halves (e.g. for a cache-control breakpoint hint) even
        when the assembled output preserves insertion order.
        """
        immutable = _SEGMENT_JOIN.join(
            s.body.rstrip("\n") for s in self._immutable_segments()
        )
        mutable = _SEGMENT_JOIN.join(
            s.body.rstrip("\n") for s in self._mutable_segments()
        )
        return immutable, mutable

    def render(self) -> str:
        """Assemble the user-message body.

        With :attr:`reorder` True: emits every IMMUTABLE segment first
        (insertion order preserved within the group), then a two-blank
        separator, then every MUTABLE segment. Provider prefix caches
        stay warm turn-over-turn.

        With :attr:`reorder` False: emits segments in strict insertion
        order. Byte-identical to the pre-#155 assembly.
        """
        if not self.reorder:
            return _SEGMENT_JOIN.join(
                s.body.rstrip("\n") for s in self.segments
            )
        immutable_body, mutable_body = self.split()
        if immutable_body and mutable_body:
            return immutable_body + _PREFIX_TAIL_JOIN + mutable_body
        return immutable_body or mutable_body

    def prefix_hash(self) -> str:
        """Return sha256 of the frozen prefix.

        Prefix = ``system_prompt`` + NUL + concatenated IMMUTABLE
        segment bodies (insertion order, ``\\n\\n`` joined). Callers
        assert two consecutive turns of the same investigation share
        this hash -- when they do, the provider's KV cache stays warm
        and per-turn prefill collapses to the ~10% cached-read price.
        """
        immutable_body, _ = self.split()
        material = (self.system_prompt or "") + "\x00" + immutable_body
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def prefix_bytes(self) -> int:
        """Return the byte length of the prefix used by :meth:`prefix_hash`."""
        immutable_body, _ = self.split()
        return len(((self.system_prompt or "") + immutable_body).encode("utf-8"))

    def labels(self) -> tuple[tuple[str, str], ...]:
        """Return ``((kind, label), ...)`` in the order they will render.

        Useful for the diagnostic size-log line so an operator can
        confirm which sections landed on the immutable side.
        """
        if not self.reorder:
            return tuple((s.kind.value, s.label) for s in self.segments)
        immutable = tuple(
            (s.kind.value, s.label) for s in self._immutable_segments()
        )
        mutable = tuple(
            (s.kind.value, s.label) for s in self._mutable_segments()
        )
        return immutable + mutable


class PromptLayoutBuilder:
    """Fluent builder for :class:`PromptLayout`.

    Callers push segments in the order they were traditionally
    concatenated; the :meth:`build` step captures the resolved
    reorder flag once so a single layout instance carries its
    intended rendering mode.
    """

    __slots__ = ("_segments", "_system_prompt")

    def __init__(self, *, system_prompt: str) -> None:
        self._system_prompt = system_prompt
        self._segments: list[PromptSegment] = []

    def add(self, kind: PromptSegmentKind, label: str, body: str) -> PromptLayoutBuilder:
        """Append a segment. Returns self for chaining.

        Empty ``body`` is dropped -- an empty section would leave a
        stray separator in the assembled output and shift byte
        offsets in the mutable tail even when the immutable prefix
        was stable.
        """
        text = (body or "").strip("\n")
        if not text:
            return self
        self._segments.append(PromptSegment(kind=kind, label=label, body=text))
        return self

    def add_immutable(self, label: str, body: str) -> PromptLayoutBuilder:
        return self.add(IMMUTABLE, label, body)

    def add_mutable(self, label: str, body: str) -> PromptLayoutBuilder:
        return self.add(MUTABLE, label, body)

    def build(self, *, reorder: bool) -> PromptLayout:
        """Freeze the accumulated segments into a :class:`PromptLayout`."""
        return PromptLayout(
            system_prompt=self._system_prompt,
            segments=tuple(self._segments),
            reorder=reorder,
        )


# ---------------------------------------------------------------------------
# Prefix stability assertion (used by tests + optional runtime checks)
# ---------------------------------------------------------------------------


def assert_prefix_stable(
    layout_a: PromptLayout, layout_b: PromptLayout,
) -> None:
    """Raise :class:`AssertionError` when two layouts differ in their prefix.

    Used by acceptance tests to verify that two consecutive turns of
    the same investigation share the immutable prefix. Callers can
    also invoke this at runtime (behind a debug flag) to fail-closed
    on a prefix-invalidating regression.
    """
    hash_a = layout_a.prefix_hash()
    hash_b = layout_b.prefix_hash()
    if hash_a != hash_b:
        labels_a = [s.label for s in layout_a.segments if s.kind is IMMUTABLE]
        labels_b = [s.label for s in layout_b.segments if s.kind is IMMUTABLE]
        raise AssertionError(
            "prompt_layout: immutable prefix drifted between turns "
            f"(hash_a={hash_a[:16]} hash_b={hash_b[:16]} "
            f"labels_a={labels_a} labels_b={labels_b})"
        )


# ---------------------------------------------------------------------------
# Config resolution
# ---------------------------------------------------------------------------


# Errors the registry read may raise that must degrade to "flag off" /
# "default TTL" instead of propagating into the LLM hot path.
_CONFIG_SAFE_ERRORS: tuple[type[BaseException], ...] = (
    OSError, RuntimeError, ValueError, TypeError, AttributeError,
)


def is_prompt_layout_enabled(registry: ConfigRegistry | None) -> bool:
    """Return True iff ``platform.prompt_layout_enabled`` resolves truthy.

    Any registry read failure (missing registry, DB fault, malformed
    value) returns False so a config-plane outage cannot silently
    reorder prompts and break the caller's byte-stability
    expectations.
    """
    if registry is None:
        return False
    try:
        raw = registry.get_sync("platform", "prompt_layout_enabled")
    except _CONFIG_SAFE_ERRORS:
        return False
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, (int, float)):
        return bool(raw)
    if isinstance(raw, str):
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    return False


def resolve_cache_ttl_seconds(registry: ConfigRegistry | None) -> int:
    """Return the investigation-scoped prompt-cache TTL in seconds.

    ``0`` means "use the provider default" (Anthropic 5 min ephemeral
    cache, OpenAI up to 24 h on recent models). A positive value is
    the operator-configured lifetime hint the client can forward to
    the provider (Anthropic honours it on ``cache_control.ttl``;
    OpenAI ignores it, which is safe -- OpenAI keeps its own 24 h
    default).
    """
    if registry is None:
        return 0
    try:
        raw = registry.get_sync("platform", "prompt_cache_ttl_seconds")
    except _CONFIG_SAFE_ERRORS as exc:
        _log.debug("prompt_cache_ttl_seconds config read failed: %s", exc)
        return 0
    if raw is None:
        return 0
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        _log.debug("prompt_cache_ttl_seconds not an int (%r): %s", raw, exc)
        return 0
    return max(0, value)


# ---------------------------------------------------------------------------
# Cache-usage extraction + gauge
# ---------------------------------------------------------------------------


# Cumulative counters on RunMemory. The gauge is derived from these on
# read (hit_rate = cache_read / prompt_tokens); a per-call rate is not
# stored, only the running sums, so a mid-run process restart can
# rehydrate them from LLMCostRecord in a later slice without losing
# historical shape.
_KEY_CACHE_READ: str = "_cache_read_tokens"
_KEY_CACHE_WRITE: str = "_cache_write_tokens"
_KEY_CACHE_TOTAL_PROMPT: str = "_cache_total_prompt_tokens"
_KEY_CACHE_CALLS: str = "_cache_calls"
_KEY_CACHE_HITS: str = "_cache_calls_with_hit"


# Provider-specific field names we recognise. Anthropic emits
# ``cache_read_input_tokens`` + ``cache_creation_input_tokens`` on the
# usage object; OpenAI nests ``cached_tokens`` under
# ``prompt_tokens_details``. Both surfaces sometimes leak through an
# OpenAI-compatible gateway (e.g. OpenRouter) using the original
# provider names -- the extractor accepts all of them.
_ANTHROPIC_READ_KEYS: tuple[str, ...] = (
    "cache_read_input_tokens",
    "cache_read_tokens",
)
_ANTHROPIC_WRITE_KEYS: tuple[str, ...] = (
    "cache_creation_input_tokens",
    "cache_creation_tokens",
    "cache_write_input_tokens",
)
_OPENAI_CACHED_KEYS: tuple[str, ...] = (
    "cached_tokens",
)


def _coerce_int(value: Any) -> int:
    """Return a non-negative int for a provider-reported token count."""
    if value is None:
        return 0
    try:
        n = int(value)
    except (TypeError, ValueError) as exc:
        _log.debug("cache-usage token not an int (%r): %s", value, exc)
        return 0
    return n if n > 0 else 0


def extract_cache_usage(usage: dict[str, Any] | None) -> dict[str, int]:
    """Normalise provider-specific cache-token fields into uniform keys.

    Returns ``{"cache_read": int, "cache_write": int, "cached": int}``.

    * ``cache_read`` -- tokens served from a prior warm prefix
      (Anthropic ``cache_read_input_tokens``, OpenAI
      ``prompt_tokens_details.cached_tokens``).
    * ``cache_write`` -- tokens the provider wrote INTO the cache on
      this call (Anthropic ``cache_creation_input_tokens``; OpenAI
      does not surface this).
    * ``cached`` -- ``cache_read + cache_write`` (a convenience total
      so callers do not repeat the addition).

    Every value falls back to 0 when the field is absent or non-numeric
    -- providers that do not report cache usage look like a 0% hit-rate
    call, which is the safe default for the gauge.
    """
    if not isinstance(usage, dict):
        return {"cache_read": 0, "cache_write": 0, "cached": 0}
    cache_read = 0
    cache_write = 0
    for key in _ANTHROPIC_READ_KEYS:
        cache_read = max(cache_read, _coerce_int(usage.get(key)))
    for key in _ANTHROPIC_WRITE_KEYS:
        cache_write = max(cache_write, _coerce_int(usage.get(key)))
    details = usage.get("prompt_tokens_details")
    if isinstance(details, dict):
        for key in _OPENAI_CACHED_KEYS:
            cache_read = max(cache_read, _coerce_int(details.get(key)))
    # Some gateways flatten the details block.
    for key in _OPENAI_CACHED_KEYS:
        cache_read = max(cache_read, _coerce_int(usage.get(key)))
    return {
        "cache_read": cache_read,
        "cache_write": cache_write,
        "cached": cache_read + cache_write,
    }


def compute_cache_hit_rate(
    usage: dict[str, Any] | None, cache_usage: dict[str, int] | None = None,
) -> float:
    """Return the fraction of prompt tokens served from cache in one call.

    ``0.0`` when the usage dict is empty, has zero prompt tokens, or
    reports no cached tokens.  Value is clamped to ``[0.0, 1.0]``.
    """
    if not isinstance(usage, dict):
        return 0.0
    prompt_tokens = _coerce_int(usage.get("prompt_tokens"))
    if prompt_tokens <= 0:
        return 0.0
    cu = cache_usage if cache_usage is not None else extract_cache_usage(usage)
    cache_read = _coerce_int(cu.get("cache_read"))
    if cache_read <= 0:
        return 0.0
    rate = cache_read / float(prompt_tokens)
    if rate < 0.0:
        return 0.0
    if rate > 1.0:
        return 1.0
    return rate


def record_cache_metrics(
    memory: RunMemory | None,
    run_id: str | None,
    usage: dict[str, Any] | None,
) -> None:
    """Fold one call's cache tokens into cumulative :class:`RunMemory` counters.

    No-op when ``memory`` or ``run_id`` is unset, or when the usage
    dict has no cache signal -- a provider that does not surface cache
    fields must not accumulate a phantom 0% gauge that would drown out
    the calls that DO have data.

    Errors from the memory backend are swallowed at DEBUG log level;
    the gauge is best-effort telemetry and MUST NOT propagate into
    the LLM hot path.
    """
    if memory is None or not run_id:
        return
    cache_usage = extract_cache_usage(usage)
    prompt_tokens = _coerce_int((usage or {}).get("prompt_tokens"))
    if cache_usage["cached"] <= 0 and prompt_tokens <= 0:
        return
    try:
        current_read = int(memory.get(run_id, _KEY_CACHE_READ, 0) or 0)
        current_write = int(memory.get(run_id, _KEY_CACHE_WRITE, 0) or 0)
        current_total = int(memory.get(run_id, _KEY_CACHE_TOTAL_PROMPT, 0) or 0)
        current_calls = int(memory.get(run_id, _KEY_CACHE_CALLS, 0) or 0)
        current_hits = int(memory.get(run_id, _KEY_CACHE_HITS, 0) or 0)
        memory.put(run_id, _KEY_CACHE_READ, current_read + cache_usage["cache_read"])
        memory.put(run_id, _KEY_CACHE_WRITE, current_write + cache_usage["cache_write"])
        memory.put(run_id, _KEY_CACHE_TOTAL_PROMPT, current_total + prompt_tokens)
        memory.put(run_id, _KEY_CACHE_CALLS, current_calls + 1)
        if cache_usage["cache_read"] > 0:
            memory.put(run_id, _KEY_CACHE_HITS, current_hits + 1)
    except (OSError, RuntimeError, TypeError, ValueError, AttributeError) as exc:
        _log.debug(
            "prompt_layout.record_cache_metrics: RunMemory write failed "
            "run_id=%s err=%s", run_id, exc,
        )


def get_cache_metrics(
    memory: RunMemory | None, run_id: str | None,
) -> dict[str, Any]:
    """Return the cumulative cache gauge for one run.

    Shape::

        {
            "cache_read_tokens": int,   # served from cache across all calls
            "cache_write_tokens": int,  # written to cache across all calls
            "prompt_tokens_total": int, # denominator (sum of prompt_tokens)
            "cache_hit_rate": float,    # cache_read / prompt_tokens_total, 0..1
            "calls": int,               # total LLM calls counted
            "calls_with_cache_hit": int,
        }

    A run with no calls yet returns all-zero fields; a run whose
    calls reported no cache signal returns 0.0 for ``cache_hit_rate``.
    """
    empty = {
        "cache_read_tokens": 0,
        "cache_write_tokens": 0,
        "prompt_tokens_total": 0,
        "cache_hit_rate": 0.0,
        "calls": 0,
        "calls_with_cache_hit": 0,
    }
    if memory is None or not run_id:
        return empty
    try:
        cache_read = int(memory.get(run_id, _KEY_CACHE_READ, 0) or 0)
        cache_write = int(memory.get(run_id, _KEY_CACHE_WRITE, 0) or 0)
        prompt_total = int(memory.get(run_id, _KEY_CACHE_TOTAL_PROMPT, 0) or 0)
        calls = int(memory.get(run_id, _KEY_CACHE_CALLS, 0) or 0)
        hits = int(memory.get(run_id, _KEY_CACHE_HITS, 0) or 0)
    except (OSError, RuntimeError, TypeError, ValueError, AttributeError):
        return empty
    if prompt_total > 0:
        rate = cache_read / float(prompt_total)
        rate = max(0.0, min(1.0, rate))
    else:
        rate = 0.0
    return {
        "cache_read_tokens": cache_read,
        "cache_write_tokens": cache_write,
        "prompt_tokens_total": prompt_total,
        "cache_hit_rate": rate,
        "calls": calls,
        "calls_with_cache_hit": hits,
    }


# Silence unused-import warnings for typing-only names on runtimes without
# a full re-export test suite: field is available for downstream module
# extensions that want to declare additional dataclass metadata without
# re-importing.
_ = field
