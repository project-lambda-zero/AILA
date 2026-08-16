"""Sanitize MCP observation values before they merge into ``case_state`` (#159 part 2).

Raw MCP tool output is the classic prompt-injection carrier: a poisoned
index chunk, a decompiled string literal, or a captured filesystem
listing may contain ``"ignore previous instructions"``, ``"system:"``,
Unicode direction-override runs, or fence-boundary tokens intended to
break out of the surrounding data envelope. Prior to #159 those bytes
were persisted verbatim under an observable key, then rendered into the
next turn's prompt through the case-state view.

This module wraps :func:`aila.platform.llm.sanitize.sanitize_input`
with two additional guarantees needed for the MCP path:

1. It handles observable values recursively -- adapters return the
   observables delta as a ``dict[str, Any]`` and a payload may be a
   nested list / dict; leaf strings get sanitised, non-string leaves
   ride through untouched.

2. It preserves reserved-key observations (``_directive.*``,
   ``_recall.*``, ``_ledger.*``) verbatim. These are platform-authored
   steering messages that legitimately contain strings the injection
   filter would strip (``"system:"``, ``"assistant:"``); running
   ``sanitize_input`` on them would delete the operator's guidance
   text and leave a blank directive.

3. It emits a single-line INFO log the first time it strips content
   from a given ``(server_id, tool_name)`` so operators see the pattern
   without a per-call log flood.

The sanitiser is intentionally lossy on injection markers -- we would
rather delete a suspicious substring than mark it and hope the model
notices. Callers who need the raw bytes (audit trail, forensics
replay) read them off the persisted message row's payload, not the
observables delta the reasoning engine consumes.
"""
from __future__ import annotations

import logging
from typing import Any

from aila.platform.llm.sanitize import sanitize_input

__all__ = [
    "RESERVED_OBSERVABLE_PREFIXES",
    "is_reserved_observable_key",
    "sanitize_observable_value",
    "sanitize_observables_delta",
]

_log = logging.getLogger(__name__)


# Reserved observable-key prefixes -- must mirror the eviction guard in
# :meth:`aila.platform.agents.tool_executor.ToolExecutorHelpersBase._merge_and_report_eviction`
# so a change on one side never lets injection-sanitised bytes destroy
# a platform-authored directive on the other.
RESERVED_OBSERVABLE_PREFIXES: tuple[str, ...] = (
    "_directive.",
    "_recall.",
    "_ledger.",
    "_acked_",  # operator-message acknowledgements written by the agent
)


def is_reserved_observable_key(key: str) -> bool:
    """Return True if ``key`` is a platform-authored reserved observable."""
    return any(key.startswith(prefix) for prefix in RESERVED_OBSERVABLE_PREFIXES)


def sanitize_observable_value(value: Any) -> Any:
    """Return ``value`` with injection markers stripped from every string leaf.

    Pure function, no I/O. Strings are passed through
    :func:`sanitize_input` which folds Unicode look-alikes (NFKC),
    strips zero-width / direction-override characters, and removes
    known injection patterns (``ignore previous instructions``,
    ``system:``, ``[INST]``, backtick role fences, ...). Dicts and
    lists recurse; every other type (int, float, bool, None,
    datetime, bytes) rides through untouched because none of them
    carry text an LLM will re-interpret as an instruction.
    """
    if isinstance(value, str):
        return sanitize_input(value)
    if isinstance(value, dict):
        return {
            str(k): sanitize_observable_value(v) for k, v in value.items()
        }
    if isinstance(value, list):
        return [sanitize_observable_value(v) for v in value]
    if isinstance(value, tuple):
        return tuple(sanitize_observable_value(v) for v in value)
    return value


def sanitize_observables_delta(
    delta: dict[str, Any],
    *,
    server_id: str = "",
    tool_name: str = "",
) -> dict[str, Any]:
    """Return a new delta with injection markers stripped from every non-reserved value.

    Reserved keys (``_directive.*``, ``_recall.*``, ``_ledger.*``,
    ``_acked_*``) are copied through verbatim so a platform-authored
    steering string is never mangled by the injection filter. Every
    other value is walked recursively via
    :func:`sanitize_observable_value`.

    Emits a single INFO log per call when any leaf changed so the
    operator sees which ``(server_id, tool_name)`` produced the
    injection-shaped bytes without a per-key log flood. ``server_id``
    and ``tool_name`` are metadata only; they are safe to omit for the
    narrow unit tests that call this helper directly.
    """
    if not delta:
        return {}
    sanitised: dict[str, Any] = {}
    changed = False
    for key, value in delta.items():
        skey = str(key)
        if is_reserved_observable_key(skey):
            sanitised[skey] = value
            continue
        clean = sanitize_observable_value(value)
        if isinstance(value, str) and clean != value:
            changed = True
        elif isinstance(value, (dict, list, tuple)) and clean != value:
            changed = True
        sanitised[skey] = clean
    if changed:
        _log.info(
            "mcp observation_sanitize: neutralized injection marker(s) in "
            "%s.%s observables delta",
            server_id or "<unknown>", tool_name or "<unknown>",
        )
    return sanitised
