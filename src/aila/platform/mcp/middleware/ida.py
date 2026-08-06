"""RFC-11 Tier C -- IDA headless MCP middleware.

Server-specific behaviour port of ``IDABridgeTool``: kwarg alias map
built from the live catalog, IDA auto-name -> hex coercion, encoding
value aliases, per-call dedup cache, pending-poll retry loop with
dead-worker fail-fast, and the virtual ``upload`` streaming action that
targets ``/upload`` instead of ``/tools/upload``. The transport (HTTP
POST, JSON parse, status normalisation, recorder envelope, catalog
resolution) is owned by :class:`aila.platform.mcp.client.McpClient`;
this module carries only the ida-headless behaviour that has to survive
the collapse of the three bespoke bridge classes onto one generic
:class:`aila.platform.mcp.bridge_tool.McpBridgeTool`.

The plugin is bound to both ``ida_headless`` and ``ida_headless_exp``
by :data:`aila.platform.mcp.factory._MIDDLEWARE_REF`; the two ids share
this logic but resolve through different env vars / config keys
(``IDA_HEADLESS_URL`` vs ``IDA_HEADLESS_EXP_URL``). The dispatch router
pins a specific catalog instance by assigning ``client._resolved``
before calling :meth:`forward` -- every URL read here goes through
``await client.base_url()`` / ``client.resolve()`` fresh so the pin
takes effect on the next call without a middleware-side cache.
"""
from __future__ import annotations

import asyncio
import hashlib
import json as _json
import logging
import os
import re
import time as _time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx

from aila.platform.mcp.middleware._kwarg_alias import (
    build_alias_map,
    build_known_params,
    drop_unknown_pagination_kwargs,
    normalize_kwargs,
)

if TYPE_CHECKING:
    from aila.platform.mcp.client import McpClient
    from aila.platform.mcp.server_specs import ServerSpec

__all__ = ["IdaMiddleware"]

_log = logging.getLogger(__name__)


# ── kwarg family map ─────────────────────────────────────────────────
#
# IDA's catalog uses different canonicals than audit_mcp:
#   * 28 tools take ``address_or_name`` (decompile, xrefs_to, ...)
#     where audit_mcp uses plain ``name``. So the IDA ``name`` family
#     INCLUDES address_or_name as a member; the family algorithm
#     picks address_or_name as the canonical for every tool that
#     accepts it, and aliases name/function/fn/function_name -> it.
#   * 8 tools take plain ``address`` (patch_assemble, set_comment).
#     A separate ``address`` family aliases addr/ea -> address for
#     those. Tools with specialized address params (from_address +
#     to_address, sink_address, etc.) accept two family members at
#     once, so the algorithm correctly leaves those alone.
#   * 7 tools take ``limit`` -- same ``how_many`` shape as audit_mcp.
#   * ``depth`` and ``max_depth`` co-exist (call_chain takes depth,
#     interprocedural_taint takes max_depth) -- same ``depth`` family.
_KW_FAMILIES: dict[str, set[str]] = {
    "how_many": {
        "limit", "top_k", "top_n", "n", "count", "max_results",
        "k", "max_count", "num", "max_n", "max_items",
    },
    "depth": {
        "depth", "max_depth", "max_hops", "traversal_depth",
    },
    "name": {
        "address_or_name", "name", "function_name", "class_name",
        "sink_name", "symbol_name", "fn_name", "fn", "function",
        "symbol", "target_name",
    },
    "address": {
        "address", "addr", "ea",
    },
}

# Manual per-tool overrides for kwarg drift that the family-based
# auto-alias can't catch. Format: ``{action: {alias: canonical}}``.
# Used when the agent reaches for an intuitive-but-wrong kwarg name
# that doesn't fit any of :data:`_KW_FAMILIES`.
_MANUAL_OVERRIDES: dict[str, dict[str, str]] = {
    # search_pattern takes ``pattern_type`` (enum of vuln pattern ids),
    # not free-form ``pattern``. Agents commonly type ``pattern``
    # thinking it's a regex/byte search; the rewrite at least gets the
    # call to the bridge so the MCP can surface a real "unknown
    # pattern_type" error if the value isn't an enum member.
    "search_pattern": {
        "pattern": "pattern_type",
        "pattern_str": "pattern_type",
        "query": "pattern_type",
    },
}


# ── address / encoding coercion tables ───────────────────────────────

# Every kwarg name across the 81 ida-headless tools whose docs describe
# an address / hex EA. Audited by walking each tool's "Args:" block.
# The coercion regex only matches IDA auto-names (sub_<hex>, loc_<hex>,
# ...) so real labels like ``wmain`` / ``_main`` pass through untouched.
# Listing every name lets tools that secretly require hex behind a
# "or name" advertisement (disassemble_function rejects names at
# runtime with ``invalid literal for int() with base 16``) get the
# agent's auto-name rewritten to its embedded address.
_ADDRESS_KWARG_NAMES: frozenset[str] = frozenset({
    # Generic
    "address", "ea",
    # Function-scoped
    "function_address", "caller_address", "callee_address",
    "target_function",
    # Decryption helpers (decrypt_function_strings,
    # decrypt_binary_strings).
    "decryptor_address",
    # Graph / path-finding endpoints
    "root_address", "source_address", "sink_address",
    "target_address", "start_address", "end_address",
    "from_address", "to_address",
    # Optional focus addresses (pseudocode_slice_view).
    "focus_address",
    # Canonical name-or-address kwarg.
    "address_or_name",
})

# List-of-addresses kwarg names. The coercion walks each element and
# rewrites auto-names individually; non-string members and non-auto-name
# strings pass through.
_ADDRESS_LIST_KWARG_NAMES: frozenset[str] = frozenset({
    "avoid_addresses",
})

# ``encoding`` value aliases for the string-family tools
# (``list_strings``, ``get_string_at``). The MCP server emits hits
# under ``by_encoding`` with the label ``"utf16le"``, but the historical
# filter on the server side only accepted ``"utf16"`` -- so an agent
# reading ``count_only`` output and passing the observed encoding value
# back as a filter got zero matches. The ida-headless side now
# normalizes too; this alias map is the defense that ships without an
# MCP restart and keeps the bridge tolerant to either label spelling.
_ENCODING_VALUE_ALIASES: dict[str, str] = {
    "utf-16": "utf16le",
    "utf16": "utf16le",
    "utf-16le": "utf16le",
    "utf16-le": "utf16le",
}
_ENCODING_TOOLS: frozenset[str] = frozenset({
    "list_strings",
    "get_string_at",
})

# IDA's auto-generated symbol prefixes followed by hex. Matches
# ``sub_474FC0``, ``loc_4012A0``, ``unk_402100``, ``byte_409010``, etc.
# Anchored to ^ + $ so it never matches user-given labels that happen
# to contain these substrings.
_IDA_AUTONAME_PATTERN = re.compile(
    r"^(?:sub|loc|unk|byte|word|dword|qword|off|nullsub|j|asc|stru|"
    r"flt|dbl|tbyte|packreal|locret)_([0-9a-fA-F]+)$",
)


# ── dead-worker signature ────────────────────────────────────────────
#
# Shape the ida-headless HTTP server emits when the in-process arbiter
# has not spawned the IDA subprocess. The arbiter is supposed to
# respawn on every tick when work is queued; in practice an
# unrecoverable open_database failure plus the persistent
# crash_counts.json cap (default 3) leaves the arbiter permanently
# refusing to spawn for a given SHA. Callers of the bridge see every
# request return ``status: pending`` for the full 240s poll timeout
# while the worker_heartbeat.json on disk stays days old.
#
# Detection criteria (all must match):
#   * status == "pending"
#   * worker_phase indicating the arbiter isn't running
#     (``exiting_idle`` is the canonical dead signal; we also flag
#     ``crashed`` and the empty-string state as defensive aliases)
#   * heartbeat_age_s above ``_DEAD_WORKER_HEARTBEAT_THRESHOLD``
#     (default 10 min; tunable via
#     ``IDA_HEADLESS_DEAD_WORKER_HEARTBEAT_S``)
#
# When all three line up the middleware short-circuits with a
# structured error rather than polling for 240s, so the agent's next
# turn carries actionable text instead of a silent timeout.
_DEAD_WORKER_PHASES: frozenset[str] = frozenset({
    "exiting_idle", "crashed", "",
})
_DEAD_WORKER_HEARTBEAT_THRESHOLD_S: float = float(
    os.environ.get("IDA_HEADLESS_DEAD_WORKER_HEARTBEAT_S", "600"),
)


# ── dedup-eligible actions ───────────────────────────────────────────
#
# Read-only / deterministic queries where re-issuing the same call
# within TTL must return the same answer. EXCLUDE state-mutating tools
# (open_binary, upload, patch_assemble) and tools whose result depends
# on the caller's freshness expectations (poll_analysis). Also includes
# the heavy graph tools where one cached response served to N sibling
# branches saves significant compute.
_DEDUP_ACTIONS: frozenset[str] = frozenset({
    "xrefs_to", "xrefs_from",
    "decompile", "pseudocode_slice_view",
    "find_api_call_sites", "callers_of",
    "build_call_tree", "call_graph", "call_chain",
    "list_strings", "list_functions",
    "imports", "exports",
    "detect_crypto_primitives", "find_crypto_constants",
    "capa_scan", "verify_capabilities",
    "get_string_at", "read_memory",
    "binary_metadata", "section_info",
    "interprocedural_taint", "def_use",
    "resolve_api_hashes",
})


# ── module-level pipeline helpers ────────────────────────────────────


def _coerce_ida_autoname_to_address(
    action: str, kwargs: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    """Rewrite IDA auto-name strings on address kwargs to ``0x<hex>``.

    Only touches keys in :data:`_ADDRESS_KWARG_NAMES` and list entries
    in :data:`_ADDRESS_LIST_KWARG_NAMES`. Returns the kwargs dict
    (possibly modified) plus a list of human-readable notes (one per
    rewrite) for the bridge log.
    """
    if not kwargs:
        return {}, []
    out: dict[str, Any] = dict(kwargs)
    notes: list[str] = []
    for k in _ADDRESS_KWARG_NAMES:
        v = out.get(k)
        if not isinstance(v, str):
            continue
        m = _IDA_AUTONAME_PATTERN.match(v.strip())
        if not m:
            continue
        hex_tail = m.group(1)
        new_val = f"0x{hex_tail}"
        out[k] = new_val
        notes.append(
            f"{action}: coerced {k}={v!r} -> {new_val!r} "
            f"(IDA auto-name embeds the address)",
        )
    for k in _ADDRESS_LIST_KWARG_NAMES:
        v = out.get(k)
        if not isinstance(v, list):
            continue
        rewritten_count = 0
        new_list: list[Any] = []
        for elem in v:
            if isinstance(elem, str):
                m = _IDA_AUTONAME_PATTERN.match(elem.strip())
                if m:
                    new_list.append(f"0x{m.group(1)}")
                    rewritten_count += 1
                    continue
            new_list.append(elem)
        if rewritten_count > 0:
            out[k] = new_list
            notes.append(
                f"{action}: coerced {rewritten_count} "
                f"auto-name entries in {k} list to 0x<hex>",
            )
    return out, notes


def _coerce_encoding_value(
    action: str, kwargs: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    """Rewrite ``encoding`` values on string-family tools to the
    canonical label that the MCP server accepts as a filter.

    Only touches keys named ``encoding`` on tools listed in
    :data:`_ENCODING_TOOLS`. Values not in the alias map (e.g.
    ``"ascii"``, ``"all"``) pass through unchanged.
    """
    if action not in _ENCODING_TOOLS or "encoding" not in kwargs:
        return kwargs, []
    raw = kwargs["encoding"]
    if not isinstance(raw, str):
        return kwargs, []
    key = raw.strip().lower()
    canonical = _ENCODING_VALUE_ALIASES.get(key)
    if canonical is None or canonical == key:
        return kwargs, []
    out = dict(kwargs)
    out["encoding"] = canonical
    return out, [
        f"{action}: coerced encoding={raw!r} -> {canonical!r} "
        f"(MCP server emits the same label under by_encoding; "
        f"alias map keeps count_only output round-tripping as a filter)",
    ]


def _looks_like_dead_worker(payload: dict[str, Any] | None) -> bool:
    """True when the response shape matches the dead-arbiter signature.

    Conservative: requires all three criteria so a legitimately slow
    worker producing a real ``pending`` doesn't trip the gate.
    """
    if not isinstance(payload, dict):
        return False
    if payload.get("status") != "pending":
        return False
    phase = payload.get("worker_phase")
    if not isinstance(phase, str) or phase not in _DEAD_WORKER_PHASES:
        return False
    hb_age = payload.get("heartbeat_age_s")
    try:
        hb_age_f = float(hb_age) if hb_age is not None else 0.0
    except (TypeError, ValueError):
        return False
    return hb_age_f >= _DEAD_WORKER_HEARTBEAT_THRESHOLD_S


def _dead_worker_error(
    action: str, payload: dict[str, Any],
) -> dict[str, Any]:
    """Build the structured fail-fast error replacement for a
    dead-arbiter response. The message names the symptom + the operator
    action to take so the agent surfaces the right next step rather
    than a generic timeout.
    """
    hb_age = payload.get("heartbeat_age_s", "?")
    queue_depth = payload.get("queue_depth", "?")
    sha = payload.get("binary_id", "?")
    return {
        "status": "error",
        "error": (
            f"ida-headless IDA worker is not alive for {sha}: "
            f"heartbeat_age_s={hb_age} (threshold "
            f"{int(_DEAD_WORKER_HEARTBEAT_THRESHOLD_S)}s), "
            f"queue_depth={queue_depth}, worker_phase="
            f"{payload.get('worker_phase', '?')}. The arbiter has "
            f"stopped spawning subprocesses for this binary (most "
            f"often: open_database failures hit the crash-count cap, "
            f"or the .i64 file is corrupt). Calling {action!r} again "
            f"will time out the same way. Operator action: restart "
            f"ida-headless and clear crash_counts.json for this SHA, "
            f"or re-upload the binary to force fresh analysis."
        ),
        "dead_worker_diagnostic": {
            "sha": sha,
            "heartbeat_age_s": hb_age,
            "queue_depth": queue_depth,
            "worker_phase": payload.get("worker_phase"),
            "action": action,
        },
    }


def _dedup_fingerprint(
    action: str, normalized_kwargs: dict[str, Any],
) -> str:
    """sha256 of (action, sorted kwargs JSON) used as dedup-cache key.

    Sort keys so call-order variance does not split otherwise-identical
    cache entries; ``default=str`` coerces non-JSON-clean values (paths,
    UUIDs) into a stable string form.
    """
    try:
        blob = _json.dumps(
            {"action": action, "kwargs": normalized_kwargs},
            sort_keys=True, default=str,
        )
    except (TypeError, ValueError):
        blob = f"{action}:{normalized_kwargs!r}"
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class IdaMiddleware:
    """RFC-11 Tier C plugin -- server-specific behaviour for ida-headless.

    Instances share this class between the ``ida_headless`` (VR) and
    ``ida_headless_exp`` (malware) server ids; the two endpoints resolve
    through different env vars / config keys but run through the same
    behaviour port.
    """

    def __init__(self, *, spec: ServerSpec, module_id: str) -> None:
        # Transport attributes read by :class:`McpBridgeTool` when it
        # wires the client's resolver + timeout + pool policy. Direct
        # copies of the spec fields so the middleware carries the same
        # facts the generic tool needs -- no re-derivation.
        self.server_id = spec.server_id
        self.tool_name = spec.tool_name
        self.env_var = spec.env_var
        self.config_key = spec.config_key
        self.default_url = spec.default_url
        self.persistent_pool = spec.persistent_pool
        self.default_timeout = float(
            os.environ.get("IDA_HEADLESS_TIMEOUT", str(spec.default_timeout)),
        )
        self.module_id = module_id

        # Per-instance schema cache + alias map. Class-level storage
        # leaked across instances (tests saw stale state) and was
        # never invalidated when the upstream IDA MCP server reloaded
        # its tool catalog.
        self._spec_cache: list[dict[str, Any]] | None = None
        self._auto_alias_map: dict[str, dict[str, str]] = {}
        # Canonical params per action -- used by
        # drop_unknown_pagination_kwargs to strip pagination-style
        # kwargs the agent attaches to snapshot tools that don't
        # support them (capa_scan, pseudocode_slice_view, etc.).
        self._known_params: dict[str, frozenset[str]] = {}

        # Wall-clock cap for the auto-retry loop on status='pending'
        # responses. On observed live traffic, build_call_tree /
        # deflat_function on large binaries routinely takes 90-180s
        # of server-side work before landing ready. The earlier 90s
        # default was tight enough that those tools surfaced pending
        # to the agent and burned a turn. 240s gives even the heavy
        # graph builders headroom; override via env
        # IDA_HEADLESS_PENDING_POLL_TIMEOUT (seconds).
        self._pending_poll_timeout: float = float(
            os.environ.get("IDA_HEADLESS_PENDING_POLL_TIMEOUT", "240"),
        )

        # Per-call dedup cache. Maps fingerprint -> (cached_payload,
        # expiry_ts). Fingerprint key: sha256 of (action, normalized
        # kwargs JSON). Hits return the cached payload immediately
        # without re-dispatching to ida-headless. TTL is short
        # (default 300s) because IDA database state can change when a
        # fresh ``open_binary`` runs against the same SHA -- a stale
        # cache surviving an analysis re-run would surface yesterday's
        # xrefs against today's database. Cache is keyed off the FULL
        # kwargs (including binary_id) so two binaries don't
        # cross-contaminate. Disable via env
        # ``IDA_HEADLESS_DEDUP_TTL_S=0``.
        self._dedup_ttl_s: float = float(
            os.environ.get("IDA_HEADLESS_DEDUP_TTL_S", "300"),
        )
        self._dedup_cache: dict[str, tuple[dict[str, Any], float]] = {}
        # Per-instance eligible-action set. Copied from the module
        # constant so an operator patching the set on one instance
        # (tests, ad-hoc runs) does not leak into others.
        self._dedup_actions: frozenset[str] = _DEDUP_ACTIONS

    # ── pipeline ─────────────────────────────────────────────────────

    def _normalize_kwargs(
        self, action: str, kwargs: dict[str, Any],
    ) -> tuple[dict[str, Any], list[str]]:
        """Run the ida-headless kwarg normalisation pipeline.

        Order: shared alias resolver against the live alias map, then
        strip pagination-style kwargs the tool doesn't declare, then
        coerce IDA-style auto-name strings on address kwargs to
        ``0x<hex>`` so MCP tools that need int addresses don't get a
        ``ValueError: invalid literal for int() with base 16`` back.
        Finally normalise the ``encoding`` VALUE on the string-family
        tools so a value pulled from ``list_strings(count_only=True)``
        round-trips as a filter on the next call.
        """
        renamed, alias_notes = normalize_kwargs(
            action, kwargs, self._auto_alias_map,
        )
        filtered, drop_notes = drop_unknown_pagination_kwargs(
            action, renamed, self._known_params,
        )
        coerced, addr_notes = _coerce_ida_autoname_to_address(
            action, filtered,
        )
        enc_coerced, enc_notes = _coerce_encoding_value(action, coerced)
        return enc_coerced, alias_notes + drop_notes + addr_notes + enc_notes

    # ── dedup ────────────────────────────────────────────────────────

    def _dedup_lookup(self, fingerprint: str) -> dict[str, Any] | None:
        """Return cached payload if present and not expired; else None.

        Lazy cleanup: an expired hit is unlinked on read so the cache
        doesn't grow unbounded across long-running worker lifetimes.
        Eviction at write time (see :meth:`_dedup_store`) handles the
        case where reads never come.
        """
        entry = self._dedup_cache.get(fingerprint)
        if entry is None:
            return None
        cached, expiry = entry
        if _time.monotonic() >= expiry:
            self._dedup_cache.pop(fingerprint, None)
            return None
        return cached

    def _dedup_store(
        self, fingerprint: str, payload: dict[str, Any],
    ) -> None:
        """Cache a ready payload for ``_dedup_ttl_s``.

        Caller is responsible for filtering -- only payloads with
        ``status: ready`` should be stored, never ``pending`` or
        ``error``.
        """
        if self._dedup_ttl_s <= 0:
            return
        # Periodic eviction: when the cache crosses 1024 entries, drop
        # everything already expired. Simple O(n) sweep; the cache
        # rarely grows that large because the TTL is short.
        if len(self._dedup_cache) > 1024:
            now = _time.monotonic()
            self._dedup_cache = {
                k: v for k, v in self._dedup_cache.items() if v[1] > now
            }
        self._dedup_cache[fingerprint] = (
            payload, _time.monotonic() + self._dedup_ttl_s,
        )

    # ── forward + list_tool_specs ────────────────────────────────────

    async def forward(
        self,
        client: McpClient,
        action: str | None,
        kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        """Dispatch to the ida-headless MCP HTTP API.

        Byte-compatible port of ``IDABridgeTool.forward``: kwarg
        normalisation pipeline, dedup lookup, primary POST via
        :meth:`McpClient.post` inside one :meth:`recorder_context`
        envelope, error-field promotion, dead-worker fail-fast, and
        the pending-poll retry loop that re-issues the call without a
        recorder ctx so exactly one audit row is written per
        ``forward`` call with the final resolution stamped as the
        recorded status.
        """
        if not action:
            return await self._list_tools_action(client)
        if action == "upload":
            return await self._upload_binary(client, **kwargs)
        # Drop the recursion guard before the public-facing alias /
        # validation pipeline so it never reaches the MCP server.
        suppress_poll = bool(kwargs.pop("_ida_bridge_no_poll", False))
        # Operator-supplied force-fresh flag bypasses the dedup cache
        # without disabling it for other callers. Strip before the
        # normalize_kwargs pass so it never reaches the MCP server.
        bypass_dedup = bool(kwargs.pop("_ida_bridge_no_dedup", False))
        normalized_kwargs, kw_notes = self._normalize_kwargs(action, kwargs)
        for note in kw_notes:
            _log.info("ida_bridge %s", note)

        # Per-call dedup: identical (action, normalized_kwargs) within
        # the TTL replays the cached payload. Skipped on retry passes
        # (suppress_poll), explicit ``_ida_bridge_no_dedup`` overrides,
        # tools not in ``_dedup_actions``, or when TTL is zero.
        dedup_fp: str | None = None
        if (
            self._dedup_ttl_s > 0
            and not suppress_poll
            and not bypass_dedup
            and action in self._dedup_actions
        ):
            dedup_fp = _dedup_fingerprint(action, normalized_kwargs)
            cached = self._dedup_lookup(dedup_fp)
            if cached is not None:
                _log.info(
                    "ida_bridge %s: dedup HIT (fp=%s)",
                    action, dedup_fp[:12],
                )
                # Mark the cached payload so the executor can
                # distinguish "freshly fetched" from "replay" if it
                # ever wants to surface that to the agent. Cheap copy
                # since the cached dict is small.
                replay = dict(cached)
                replay["_ida_bridge_dedup"] = "hit"
                return replay

        async with client.recorder_context(action) as ctx:
            payload = await client.post(action, normalized_kwargs, ctx=ctx)
            payload_status = (
                payload.get("status") if isinstance(payload, dict) else None
            )
            # Defensive: some tools (search_pattern most prominently)
            # have the frontend wrap a worker-side ValueError into the
            # cached payload but stamp ``status: ready`` on it before
            # returning. The downstream executor then sees ready + a
            # populated ``error`` field and treats the call as success,
            # polluting case_state with a "no matches" reading that
            # isn't actually grounded. Promote any non-empty ``error``
            # field to status=error regardless of the declared status;
            # the response body is unchanged so adapters can still read
            # its shape.
            if (
                isinstance(payload, dict)
                and payload.get("error")
                and isinstance(payload["error"], str)
                and payload_status in ("ready", "completed", "ok", None)
            ):
                _log.info(
                    "ida_bridge %s: promoting status=%r to error -- "
                    "payload carries error field: %s",
                    action, payload_status, payload["error"][:200],
                )
                payload_status = "error"
                ctx["status"] = "error"
                ctx["error_excerpt"] = payload["error"][:400]

            if payload_status in ("ready", "completed", "ok"):
                # Cache the response payload when it lands ready and
                # the action is dedup-eligible. ``pending`` and
                # ``error`` states are never cached -- the next caller
                # for the same fingerprint deserves a fresh attempt.
                if dedup_fp is not None and isinstance(payload, dict):
                    self._dedup_store(dedup_fp, payload)
                return payload

            if payload_status in ("pending", "queued", "running"):
                # Dead-worker short-circuit: when the response shape
                # matches the dead-arbiter signature, polling for 240s
                # is pointless -- the IDA subprocess will not spawn
                # without operator intervention. The middleware swaps
                # in a structured error that names the symptom plus the
                # operator action.
                if _looks_like_dead_worker(payload):
                    err = _dead_worker_error(action, payload)
                    _log.warning(
                        "ida_bridge %s: dead-arbiter signature "
                        "detected; failing fast (heartbeat_age_s=%s, "
                        "queue_depth=%s)",
                        action,
                        payload.get("heartbeat_age_s"),
                        payload.get("queue_depth"),
                    )
                    ctx["status"] = "error"
                    ctx["error_excerpt"] = err["error"][:400]
                    return err
                # Per-call async retry loop. ``poll_analysis`` only
                # reports whether the binary's IDA database (.i64) is
                # loaded -- it does NOT track per-call async jobs like
                # build_call_tree / deflat_function / interprocedural_taint
                # that queue their own server-side work and return
                # ``pending`` until that work finishes. The fix is to
                # just sleep and re-POST the same call until it lands
                # ready, errors, or the wall-clock budget runs out.
                #
                # Skip conditions: already on a retry pass
                # (suppress_poll), action is poll_analysis itself
                # (cheap status read, no point looping).
                if suppress_poll or action == "poll_analysis":
                    return payload
                return await self._poll_pending(
                    client, ctx, action, normalized_kwargs,
                    initial_payload=payload, dedup_fp=dedup_fp,
                )

            if payload_status == "error":
                return payload

            # payload_status is None on HTTP 2xx: the client already
            # injected ``status: ready`` and set ctx.status. Fall
            # through and cache the ready-injected body.
            if payload_status is None and isinstance(payload, dict):
                if dedup_fp is not None:
                    self._dedup_store(dedup_fp, payload)
                return payload

            # Any other status the client couldn't classify: return the
            # coerced-to-error envelope unchanged; the client already
            # set ctx.status = "error".
            return payload

    async def _poll_pending(
        self,
        client: McpClient,
        ctx: dict[str, Any],
        action: str,
        normalized_kwargs: dict[str, Any],
        *,
        initial_payload: dict[str, Any],
        dedup_fp: str | None,
    ) -> dict[str, Any]:
        """Loop-poll a pending response until ready, error, or deadline.

        Every retry re-issues :meth:`McpClient.post` WITHOUT the ctx so
        no extra audit rows are written; on final resolution the
        recorded status on the caller's envelope is overwritten to
        match the outcome (one row per call, final status wins). Byte
        compatible with the old bridge: 2.0s initial delay, 1.5x
        backoff capped at 8.0s, wall-clock deadline from
        ``_pending_poll_timeout``.
        """
        deadline = (
            asyncio.get_event_loop().time() + self._pending_poll_timeout
        )
        delay = 2.0
        attempt = 0
        payload = initial_payload
        while asyncio.get_event_loop().time() < deadline:
            attempt += 1
            await asyncio.sleep(delay)
            delay = min(delay * 1.5, 8.0)
            _log.info(
                "ida_bridge %s: pending retry attempt=%d "
                "(deadline in %.1fs)",
                action, attempt,
                deadline - asyncio.get_event_loop().time(),
            )
            retry_payload = await client.post(action, normalized_kwargs)
            retry_status = (
                retry_payload.get("status")
                if isinstance(retry_payload, dict) else None
            )
            if retry_status in ("ready", "completed", "ok"):
                _log.info(
                    "ida_bridge %s: retry attempt=%d succeeded",
                    action, attempt,
                )
                ctx["status"] = "ready"
                # Cache the recovered ready payload so sibling branches
                # don't re-pay the wait.
                if dedup_fp is not None and isinstance(retry_payload, dict):
                    self._dedup_store(dedup_fp, retry_payload)
                return retry_payload
            # Dead-worker shape can also surface on the retry path --
            # bridge starts polling against a live worker, the worker
            # crashes mid-poll, subsequent retries return the dead-
            # arbiter signature. Short-circuit there too.
            if _looks_like_dead_worker(retry_payload):
                _log.warning(
                    "ida_bridge %s: dead-arbiter signature detected on "
                    "retry attempt=%d; failing fast", action, attempt,
                )
                err = _dead_worker_error(action, retry_payload)
                ctx["status"] = "error"
                ctx["error_excerpt"] = err["error"][:400]
                return err
            if retry_status not in ("pending", "queued", "running"):
                # New status (error / unknown / bare-list wrap):
                # surface the retry payload and set ctx to match.
                if retry_status == "error":
                    ctx["status"] = "error"
                    err_field = (
                        retry_payload.get("error")
                        if isinstance(retry_payload, dict) else None
                    )
                    if isinstance(err_field, str):
                        ctx["error_excerpt"] = err_field[:400]
                return retry_payload
            payload = retry_payload
        _log.warning(
            "ida_bridge %s: retry deadline hit after %d attempt(s); "
            "surfacing pending", action, attempt,
        )
        # Deadline hit; ctx["status"] stays "pending" as set by the
        # last client.post -- but we set ctx explicitly here too to be
        # robust against a final iteration that never touched it.
        ctx["status"] = "pending"
        return payload

    async def list_tool_specs(
        self, client: McpClient,
    ) -> list[dict[str, Any]]:
        """Fetch the ida-headless catalog and derive the alias maps.

        Cached per middleware instance. On first call, delegates to
        :meth:`McpClient.list_tool_specs` (GET /tools + compact_tool_spec)
        then walks the projected specs to build
        :attr:`_auto_alias_map` and :attr:`_known_params` so
        :meth:`forward` can rewrite / drop kwargs against the live
        schema on subsequent calls.
        """
        if self._spec_cache is not None:
            return self._spec_cache
        specs = await client.list_tool_specs()
        self._spec_cache = specs
        self._auto_alias_map = build_alias_map(
            specs, _KW_FAMILIES, _MANUAL_OVERRIDES,
        )
        self._known_params = build_known_params(specs)
        _log.info(
            "ida_bridge: catalog loaded -- %d tools, %d with alias maps",
            len(specs), len(self._auto_alias_map),
        )
        return specs

    # ── virtual actions ──────────────────────────────────────────────

    async def _list_tools_action(
        self, client: McpClient,
    ) -> dict[str, Any]:
        """Return the projected catalog wrapped in the standard envelope."""
        specs = await self.list_tool_specs(client)
        return {
            "status": "ready",
            "tools": [s["name"] for s in specs],
            "count": len(specs),
            "specs": specs,
        }

    async def _upload_binary(
        self,
        client: McpClient,
        file_path: str | None = None,
        **_extra: Any,
    ) -> dict[str, Any]:
        """Upload a local binary to the MCP server for analysis.

        The MCP server saves the file, hashes it, copies to workspace,
        and spawns IDA background analysis. Poll with
        ``action='poll_analysis'`` until state is READY/INDEXED.

        Stream the file in 64KB chunks instead of slurping the entire
        binary into memory. The previous ``read_bytes()`` approach
        required N bytes of resident worker RAM for an N-byte upload;
        a 4GB binary could OOM the worker and kill every in-flight
        investigation. We build the multipart envelope by hand and
        yield chunks from disk, capping memory at one chunk regardless
        of binary size.

        Uses a private ``httpx.AsyncClient`` because the target endpoint
        is ``/upload`` (not ``/tools/<action>``), the payload is
        multipart streaming (not JSON), and the shared
        :meth:`McpClient.post` transport only knows how to POST JSON.
        """
        if not file_path:
            return {"status": "error", "error": "file_path is required for upload"}
        target = Path(file_path)
        # is_file() does a sync stat -- wrap so we don't stall the loop
        # when the file lives on a slow volume.
        if not await asyncio.to_thread(target.is_file):
            return {"status": "error", "error": f"File not found: {file_path}"}
        base = await client.base_url()
        url = f"{base}/upload"

        chunk_size = 65536
        try:
            file_size = (await asyncio.to_thread(target.stat)).st_size
        except OSError as exc:
            return {"status": "error", "error": f"{type(exc).__name__}: {exc}"}
        boundary = uuid.uuid4().hex
        # Sanitize filename for the Content-Disposition header -- double
        # quotes inside filenames would break the multipart framing.
        safe_name = (
            target.name.replace('"', "_").replace("\r", "_").replace("\n", "_")
        )
        preamble = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; '
            f'filename="{safe_name}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
        ).encode()
        epilogue = f"\r\n--{boundary}--\r\n".encode()
        total_length = len(preamble) + file_size + len(epilogue)

        async def _stream_body():  # type: ignore[no-untyped-def]
            yield preamble
            fh = await asyncio.to_thread(open, target, "rb")
            try:
                while True:
                    chunk = await asyncio.to_thread(fh.read, chunk_size)
                    if not chunk:
                        break
                    yield chunk
            finally:
                await asyncio.to_thread(fh.close)
            yield epilogue

        headers = {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(total_length),
        }
        try:
            async with httpx.AsyncClient(timeout=self.default_timeout) as http:
                resp = await http.post(url, content=_stream_body(), headers=headers)
            return resp.json()
        except httpx.ConnectError:
            return {"status": "error", "error": f"Cannot reach {base}"}
        except httpx.TimeoutException:
            return {
                "status": "error",
                "error": f"Upload timeout ({self.default_timeout}s)",
            }
        except (ValueError, OSError) as exc:
            return {"status": "error", "error": f"{type(exc).__name__}: {exc}"}
