"""Per-module, per-tool dispatch authority (#159 part 3).

Before #159 the platform capability registry gated MCP dispatch at the
*server* granularity: a module could reach every tool exposed by any
server on its ``_AGENT_ALLOWED_SERVERS`` list. That is coarse enough
that a compromised or attacker-added tool on an approved server
inherits agent access automatically -- the exact class of exposure the
"88% of open-source MCP servers have broken auth" datapoint captures.

This module holds an opt-in per-tool allowlist. Modules that want
tighter control declare the exact ``(server_id, tool_name)`` pairs
their agents may invoke; every other tool on the same server is refused
at dispatch even when the server passes the outer allowlist. Modules
that skip the declaration keep the pre-#159 behaviour (any tool on an
allowed server) so this is a purely additive tightening.

The registry lives at the platform MCP layer (not on the executor)
because the RFC-11 direction is: modules declare capability at
``create_module()`` time, the platform enforces at dispatch. The tool
executor consumes :func:`is_tool_authorized` alongside its existing
server + phase gates; the check is O(1) and never touches I/O.
"""
from __future__ import annotations

import threading
from collections.abc import Iterable
from typing import Final

__all__ = [
    "authorized_tools_snapshot",
    "declare_tool_authority",
    "is_tool_authorized",
    "reset_tool_authority",
]


# The sentinel used to represent "no allowlist configured for this
# (module_scope, server_id)" -- read code must NEVER treat an absent
# key as "everything denied" or an existing empty frozenset as "no
# restriction". A declared-but-empty allowlist is a valid deny-all
# state (e.g. a phase that has revoked every tool on a server without
# revoking the server), and we preserve that meaning.
_ABSENT: Final[object] = object()


_lock = threading.Lock()
_allowlist: dict[tuple[str, str], frozenset[str]] = {}


def declare_tool_authority(
    module_scope: str,
    server_id: str,
    tool_names: Iterable[str],
) -> frozenset[str]:
    """Register the exact tool names ``module_scope`` may dispatch on ``server_id``.

    Idempotent under the natural key ``(module_scope, server_id)`` --
    a second call with the same key SUPERSEDES the earlier record so a
    module can rebuild its allowlist (tests, hot-reload, phase pivot)
    without duplicating rows. An empty iterable is a valid input and
    means "deny every tool on this server for this module"; the
    declaration is stored explicitly so :func:`is_tool_authorized`
    distinguishes it from "no allowlist configured".

    Returns the effective (deduplicated, frozen) set stored so the
    caller can hand it back to a follow-up check or log line.
    """
    scope = (module_scope or "").strip()
    server = (server_id or "").strip()
    if not scope or not server:
        raise ValueError(
            "declare_tool_authority: module_scope and server_id must "
            "both be non-empty",
        )
    allowed = frozenset(str(t).strip() for t in tool_names if str(t).strip())
    with _lock:
        _allowlist[(scope, server)] = allowed
    return allowed


def is_tool_authorized(
    module_scope: str,
    server_id: str,
    tool_name: str,
) -> bool:
    """Return True if ``tool_name`` is in ``module_scope``'s allowlist for ``server_id``.

    Contract:

    * No allowlist declared for ``(module_scope, server_id)`` -> True
      (backward-compatible: the outer server allowlist is the only
      bound, matching pre-#159 behaviour).
    * Declared allowlist contains ``tool_name`` -> True.
    * Declared allowlist is empty OR does not contain ``tool_name`` ->
      False (dispatch must refuse).

    Called on the tool-executor's hot path so the lookup runs under
    the registry lock, does no I/O, and never raises.
    """
    scope = (module_scope or "").strip()
    server = (server_id or "").strip()
    tool = (tool_name or "").strip()
    if not scope or not server or not tool:
        return False
    with _lock:
        declared = _allowlist.get((scope, server), _ABSENT)
    if declared is _ABSENT:
        return True
    if not isinstance(declared, frozenset):  # defensive; mutator only stores frozenset
        return False
    return tool in declared


def authorized_tools_snapshot(
    module_scope: str,
    server_id: str,
) -> frozenset[str] | None:
    """Return the declared allowlist for ``(module_scope, server_id)``, or None.

    ``None`` means "no allowlist declared" (dispatch falls back to the
    outer server gate); an empty frozenset means "declared, deny all".
    Used by operator diagnostics and by the executor's error-message
    hint that names the tools an agent MAY still call after a refusal.
    """
    scope = (module_scope or "").strip()
    server = (server_id or "").strip()
    with _lock:
        declared = _allowlist.get((scope, server), _ABSENT)
    if declared is _ABSENT:
        return None
    if not isinstance(declared, frozenset):  # defensive; mutator only stores frozenset
        return frozenset()
    return declared


def reset_tool_authority() -> None:
    """Drop every declared allowlist.

    Test-only helper -- production wiring declares once at
    ``create_module()`` time (or at phase pivot) and never resets.
    """
    with _lock:
        _allowlist.clear()
