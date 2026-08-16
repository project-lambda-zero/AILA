"""Tool-description hash pin (#159 part 1).

A poisoned MCP server can silently swap a tool's description or JSON
schema between two ``tools/list`` calls -- the raw wire keeps the same
tool ``name``, so the reasoning engine treats the new (attacker-chosen)
description as authoritative and threads it into every future prompt.
See OWASP LLM01 (prompt injection) and the Wiz "MCP supply chain"
write-up cited in issue #159.

This module implements a small process-scoped registry that records a
hash of each ``(module_scope, server_id)``'s tool list on first sight
and verifies it on every subsequent load. Two outcomes:

* ``record``      -- first sight, hash pinned, no action needed.
* ``match``       -- current specs still hash to the pinned value.
* ``mismatch``    -- the current specs differ. Always logged at WARNING
                     with the two hashes. When ``strict=True`` a
                     :class:`ToolDescriptionMismatchError` is raised so
                     the caller can refuse the load; otherwise the
                     pinned hash is *replaced* with the new one and a
                     warning is emitted so an operator sees the change
                     in the platform log.

Non-strict is the default because MCP servers legitimately add / drop
tools during a rolling upgrade -- forcing a hard refuse would ground
every deploy until an operator restarted every worker. The strict path
is opt-in via ``platform.mcp_tool_hash_strict`` in the ConfigRegistry
so a security-sensitive deployment can flip the switch without a
worker restart. The check itself is pure Python + a threading Lock, so
it stays inside any UoW / async context without dragging in I/O.
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
from dataclasses import dataclass
from typing import Any

__all__ = [
    "HashVerdict",
    "ToolDescriptionMismatchError",
    "compute_tool_specs_hash",
    "reset_tool_hash_registry",
    "snapshot_tool_hashes",
    "verify_or_record_tool_specs",
]

_log = logging.getLogger(__name__)


class ToolDescriptionMismatchError(RuntimeError):
    """Raised in strict mode when a tool list's hash changed after pin."""


@dataclass(frozen=True, slots=True)
class HashVerdict:
    """Outcome of a single :func:`verify_or_record_tool_specs` call.

    ``action`` is one of ``"record"``, ``"match"``, or ``"mismatch"``.
    ``current_hash`` is the sha256 of the specs the caller just passed;
    ``pinned_hash`` is the hash the registry held before this call (None
    on ``record``). The registry always ends up holding
    ``current_hash`` afterwards -- non-strict callers see the new hash
    pin so subsequent verifications compare against the accepted new
    state (the warning is emitted exactly once per rotation, not on
    every following call).
    """

    action: str
    current_hash: str
    pinned_hash: str | None


# Fields that participate in the hash. Anything else on a spec dict
# (fetched-at timestamps, per-call transient cache markers) MUST NOT
# be hashed or a live-cache refresh would look like a description
# change. Keep this list in sync with the projection that
# :func:`aila.platform.mcp.client.compact_tool_spec` emits.
_HASHED_TOP_LEVEL_FIELDS: tuple[str, ...] = (
    "name",
    "description",
    "params",
    "required",
)
_HASHED_PARAM_FIELDS: tuple[str, ...] = (
    "name",
    "type",
    "required",
    "default",
    "description",
)


def _canonicalize_spec(spec: dict[str, Any]) -> dict[str, Any]:
    """Project ``spec`` to the fields that participate in the hash."""
    params_raw = spec.get("params") or []
    params: list[dict[str, Any]] = []
    if isinstance(params_raw, list):
        for entry in params_raw:
            if not isinstance(entry, dict):
                continue
            params.append({
                key: entry[key]
                for key in _HASHED_PARAM_FIELDS
                if key in entry
            })
    canonical: dict[str, Any] = {}
    for key in _HASHED_TOP_LEVEL_FIELDS:
        if key == "params":
            canonical["params"] = params
        elif key in spec:
            canonical[key] = spec[key]
    return canonical


def compute_tool_specs_hash(specs: list[dict[str, Any]]) -> str:
    """Return a stable sha256 hex digest of ``specs``.

    Specs are sorted by ``name`` before hashing so a server returning
    the same tools in a different order still hashes to the same
    value; the projection strips every non-content field so a live
    cache marker (fetched-at, count-of-refreshes) never spuriously
    invalidates the pin. sha256 is used verbatim from ``hashlib`` --
    the pin is a change-detection tripwire, not a cryptographic
    commitment, and MD5 was ruled out only to keep the audit logs
    reading in the same family as every other content hash we emit.
    """
    canonical = [_canonicalize_spec(s) for s in specs if isinstance(s, dict)]
    canonical.sort(key=lambda s: str(s.get("name") or ""))
    payload = json.dumps(canonical, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


_registry_lock = threading.Lock()
_pinned: dict[tuple[str, str], str] = {}


def verify_or_record_tool_specs(
    module_scope: str,
    server_id: str,
    specs: list[dict[str, Any]],
    *,
    strict: bool = False,
) -> HashVerdict:
    """Pin the tool list on first sight; verify on later loads.

    Called from :meth:`aila.platform.mcp.bridge_tool.McpBridgeTool.list_tool_specs`
    every time a bridge returns a projected catalog. The pin is
    keyed on ``(module_scope, server_id)`` because a single physical
    MCP server may be reached under multiple module scopes (each with
    its own catalog row + config namespace) and each scope MAY have
    approved a different snapshot.

    ``strict=True`` raises :class:`ToolDescriptionMismatchError` on any
    change so the caller can refuse the load. ``strict=False`` warns
    once per rotation and adopts the new hash so subsequent loads
    match; a following operator investigation of the WARNING can lift
    the change to a permanent decision (accept -> nothing to do,
    reject -> flip strict mode).
    """
    scope = (module_scope or "").strip()
    server = (server_id or "").strip()
    if not scope or not server:
        raise ValueError(
            "verify_or_record_tool_specs: module_scope and server_id "
            "must both be non-empty",
        )
    current = compute_tool_specs_hash(specs)
    key = (scope, server)
    with _registry_lock:
        pinned = _pinned.get(key)
        if pinned is None:
            _pinned[key] = current
            _log.info(
                "mcp tool_hash: pinned %s/%s at %s (%d tools)",
                scope, server, current[:12], len(specs),
            )
            return HashVerdict(
                action="record", current_hash=current, pinned_hash=None,
            )
        if pinned == current:
            return HashVerdict(
                action="match", current_hash=current, pinned_hash=pinned,
            )
        # Mismatch. Log at WARNING regardless of strict flag so the
        # operator sees the change in the platform log; strict callers
        # additionally raise to refuse the load. In non-strict mode we
        # ROTATE the pin so the same rotation does not re-warn on
        # every following call (WARNING would otherwise flood the log
        # for the entire life of the process).
        _log.warning(
            "mcp tool_hash MISMATCH %s/%s: pinned=%s current=%s "
            "(%d tools) strict=%s",
            scope, server, pinned[:12], current[:12], len(specs), strict,
        )
        if strict:
            raise ToolDescriptionMismatchError(
                f"MCP tool description hash changed for {scope}/{server}: "
                f"pinned={pinned}, current={current}",
            )
        _pinned[key] = current
        return HashVerdict(
            action="mismatch", current_hash=current, pinned_hash=pinned,
        )


def snapshot_tool_hashes() -> dict[tuple[str, str], str]:
    """Return a copy of the current pin table.

    Used by operator diagnostics and by the test suite; production
    dispatch never reads this.
    """
    with _registry_lock:
        return dict(_pinned)


def reset_tool_hash_registry() -> None:
    """Drop every pinned hash.

    Test-only helper. Production wiring pins once at first sight and
    never resets; tests that exercise the pin lifecycle call this
    from a fixture teardown so later tests do not see leaked pins.
    """
    with _registry_lock:
        _pinned.clear()
