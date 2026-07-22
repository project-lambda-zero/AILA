"""IDA Headless MCP bridge -- AILA Tool wrapping the HTTP API.

Translates AILA tool ``forward()`` calls into HTTP POST requests against
the IDA Headless MCP HTTP API.  The bridge is stateless: all binary state
lives in the MCP server's cache/lifecycle layer.

Configuration:
    ``IDA_HEADLESS_URL`` env var or ``vr.ida_headless_url`` config key.
    Default: ``http://127.0.0.1:18821``.

Timeout:
    ``IDA_HEADLESS_TIMEOUT`` env var or ``vr.ida_headless_timeout``.
    Default: 120 seconds (covers heavy decompilation).
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
from typing import Any

import httpx
from sqlalchemy.exc import SQLAlchemyError

from aila.platform.tools import Tool
from aila.storage.registry import ConfigRegistry

from ._kwarg_alias import (
    build_alias_map,
    build_known_params,
    drop_unknown_pagination_kwargs,
    normalize_kwargs,
)
from ._recorder import BridgeRecorder, noop_recorder

__all__ = ["IDABridgeTool"]


def _compact_spec(raw: dict[str, Any]) -> dict[str, Any]:
    """Project an MCP tool catalog entry into the form the prompt
    builder + agent need. See ``audit_mcp_bridge._compact_spec`` for
    rationale -- duplicated rather than imported to keep tools/
    package free of cross-bridge coupling.
    """
    name = str(raw.get("name") or "")
    description = str(raw.get("description") or "").strip()
    schema = raw.get("parameters") or raw.get("inputSchema") or {}
    properties = schema.get("properties") or {}
    required = list(schema.get("required") or [])
    params: list[dict[str, Any]] = []
    for pname in sorted(properties.keys()):
        pspec = properties[pname] or {}
        entry: dict[str, Any] = {
            "name": pname,
            "type": pspec.get("type") or "any",
            "required": pname in required,
        }
        if "default" in pspec:
            entry["default"] = pspec["default"]
        pdesc = pspec.get("description")
        if pdesc:
            entry["description"] = str(pdesc)[:240]
        params.append(entry)
    return {
        "name": name,
        "description": description[:400],
        "params": params,
        "required": required,
    }


class IDABridgeTool(Tool):
    """Multi-action tool proxying 81 MCP tools over HTTP.

    Every MCP tool name (``open_binary``, ``decompile``, ``checksec``, etc.)
    is a valid ``action``. Parameters are forwarded as JSON body fields.

    Usage::

        tool.forward(action="decompile",
                     binary_id="b_32070edcb21b",
                     address_or_name="main")
    """

    name = "vr.ida_bridge"
    description = (
        "IDA Pro headless binary analysis bridge. Supports 81+ tools: "
        "upload (upload binary for analysis), open_binary, decompile, "
        "list_functions, checksec, diff_binary, diff_function, xrefs_to, "
        "xrefs_from, call_graph, call_chain, batch_decompile, search_pattern, "
        "capa_scan, assess_exploitability, detect_obfuscation, "
        "detect_crypto_primitives, and more. "
        "Input: action (tool name) + tool-specific parameters. "
        "Output: tool result dict with status 'ready', 'pending', or 'error'."
    )
    inputs = {
        "action": {"type": "string", "description": "MCP tool name to invoke"},
    }
    output_type = "object"
    skip_forward_signature_validation = True

    def __init__(
        self,
        base_url: str | None = None,
        timeout: float | None = None,
        recorder: BridgeRecorder | None = None,
    ) -> None:
        self._fixed_base_url = base_url.rstrip("/") if base_url else None
        self._timeout = timeout or float(
            os.environ.get("IDA_HEADLESS_TIMEOUT", "120"),
        )
        # fix §211 -- per-instance schema cache + alias map. Class-level
        # storage leaked across instances (tests saw stale state) and
        # was never invalidated when the upstream IDA MCP server
        # reloaded its tool catalog.
        self._spec_cache: list[dict[str, Any]] | None = None
        self._auto_alias_map: dict[str, dict[str, str]] = {}
        # Set of canonical params per action -- used by
        # drop_unknown_pagination_kwargs to strip pagination-style
        # kwargs the agent attaches to snapshot tools that don't
        # support them (capa_scan, pseudocode_slice_view, etc.).
        self._known_params: dict[str, frozenset[str]] = {}
        # Wall-clock cap for the auto-retry loop on status='pending'
        # responses. On observed live traffic, build_call_tree /
        # deflat_function on large binaries (a large Delphi PE sample,
        # roughly 1.4MB) routinely takes 90-180s of server-side work before landing
        # ready. The earlier 90s default was tight enough that those
        # tools surfaced pending to the agent and burned a turn. 240s
        # gives even the heavy graph builders headroom; override via
        # env IDA_HEADLESS_PENDING_POLL_TIMEOUT (seconds) if specific
        # samples need longer.
        self._pending_poll_timeout: float = float(
            os.environ.get("IDA_HEADLESS_PENDING_POLL_TIMEOUT", "240"),
        )
        # Optional per-call audit logger. See ``_recorder.py``; module
        # authors wire their own ``record_call`` here, tests + ad-hoc
        # callers omit it and get a no-op.
        self._recorder: BridgeRecorder = recorder or noop_recorder

        # Per-call dedup cache. Maps fingerprint -> (cached_payload, expiry_ts).
        # Fingerprint key: sha256 of (action, normalized_kwargs JSON). Hits return
        # the cached payload immediately without re-dispatching to ida-headless.
        # TTL is short (default 300s) because IDA database state can change when
        # a fresh ``open_binary`` runs against the same SHA -- a stale cache
        # surviving an analysis re-run would surface yesterday's xrefs against
        # today's database. Cache is keyed off the FULL kwargs (including
        # binary_id) so two binaries don't cross-contaminate. Disable via env
        # ``IDA_HEADLESS_DEDUP_TTL_S=0``.
        self._dedup_ttl_s: float = float(
            os.environ.get("IDA_HEADLESS_DEDUP_TTL_S", "300"),
        )
        self._dedup_cache: dict[str, tuple[dict[str, Any], float]] = {}
        # Tools eligible for dedup -- read-only / deterministic queries
        # where re-issuing the same call within TTL must return the same
        # answer. EXCLUDE state-mutating tools (open_binary, upload,
        # patch_assemble) and tools whose result depends on the
        # caller's freshness expectations (poll_analysis). Also excludes
        # the heavy graph tools where one cached response served to N
        # sibling branches saves significant compute.
        self._dedup_actions: frozenset[str] = frozenset({
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

    async def _resolve_base_url(self) -> str:
        if self._fixed_base_url is not None:
            return self._fixed_base_url
        env_value = os.environ.get("IDA_HEADLESS_URL")
        if env_value:
            return env_value.rstrip("/")
        try:
            cfg_value = await ConfigRegistry().get("vr", "ida_headless_url")
            if isinstance(cfg_value, str) and cfg_value.strip():
                return cfg_value.rstrip("/")
        except (SQLAlchemyError, OSError, RuntimeError, ImportError, ValueError, TypeError) as exc:
            # fix §212 -- broadened from (ValueError, RuntimeError,
            # ImportError). SQLAlchemy errors from ConfigRegistry().get
            # used to propagate and crash the bridge call. URL
            # resolution is a config lookup -- fail-safe to the default.
            # fix §350 -- traceback added; mirror of audit_mcp_bridge §315
            # so a ConfigRegistry break is debuggable from either bridge.
            logging.getLogger(__name__).info(
                "ida_bridge: ConfigRegistry lookup failed "
                "(%s: %s) -- falling back to default URL",
                type(exc).__name__, exc,
                exc_info=True,
            )
        return "http://127.0.0.1:18821"

    # ── LLM kwarg synonym map (data-driven; see _kwarg_alias.py) ──────
    #
    # IDA's catalog uses different canonicals than audit_mcp:
    #   * 28 tools take ``address_or_name`` (decompile, xrefs_to, ...)
    #     where audit_mcp uses plain ``name``. So the IDA `name` family
    #     INCLUDES address_or_name as a member; the family algorithm
    #     picks address_or_name as the canonical for every tool that
    #     accepts it, and aliases name/function/fn/function_name → it.
    #   * 8 tools take plain ``address`` (patch_assemble, set_comment).
    #     A separate `address` family aliases addr/ea → address for
    #     those. Tools with specialized address params (from_address +
    #     to_address, sink_address, etc.) accept two family members at
    #     once, so the algorithm correctly leaves those alone.
    #   * 7 tools take ``limit`` -- same `how_many` shape as audit_mcp.
    #   * `depth` and `max_depth` co-exist (call_chain takes depth,
    #     interprocedural_taint takes max_depth) -- same `depth` family.
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
    # Used when the agent reaches for an intuitive-but-wrong kwarg
    # name that doesn't fit any of :data:`_KW_FAMILIES`.
    _MANUAL_OVERRIDES: dict[str, dict[str, str]] = {
        # search_pattern takes ``pattern_type`` (enum of vuln pattern
        # ids), not free-form ``pattern``. Agents commonly type
        # ``pattern`` thinking it's a regex/byte search; the rewrite
        # at least gets the call to the bridge so the MCP can surface
        # a real "unknown pattern_type" error if the value isn't an
        # enum member.
        "search_pattern": {
            "pattern": "pattern_type",
            "pattern_str": "pattern_type",
            "query": "pattern_type",
        },
    }

    # Address-shaped kwargs that the MCP server expects as integer
    # (hex string) values. When the agent passes an IDA-style auto-name
    # like ``sub_474FC0`` the bridge extracts the hex tail and rewrites
    # before dispatch -- saves a turn cycle on the int() ValueError.
    # Names without an embedded address (e.g. ``_main``, ``wmain``,
    # custom labels) pass through unchanged; the MCP server will then
    # surface the real validation error.
    # Every kwarg name across the 81 ida-headless tools whose docs
    # describe an address / hex EA. Audited 2026-06-25 by walking
    # each tool's "Args:" block. The coercion regex only matches
    # IDA auto-names (sub_<hex>, loc_<hex>, ...) so real labels like
    # ``wmain`` / ``_main`` pass through any of these untouched.
    # Listing every name lets tools that secretly require hex behind
    # a "or name" advertisement (disassemble_function rejects names
    # at runtime with `invalid literal for int() with base 16`) get
    # the agent's auto-name rewritten to its embedded address.
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

    # List-of-addresses kwarg names. The coercion walks each element
    # and rewrites auto-names individually; non-string members and
    # non-auto-name strings pass through.
    _ADDRESS_LIST_KWARG_NAMES: frozenset[str] = frozenset({
        "avoid_addresses",
    })

    # ``encoding`` value aliases for the string-family tools
    # (``list_strings``, ``get_string_at``). The MCP server emits hits
    # under ``by_encoding`` with the label ``"utf16le"``, but the
    # historical filter on the server side only accepted ``"utf16"``
    # -- so an agent reading ``count_only`` output and passing the
    # observed encoding value back as a filter got zero matches
    # (false negative that killed sibling-branch second-stage hunts
    # on an observed sample). The ida-headless side now normalizes too; this
    # alias map is the defense that ships without an MCP restart and
    # keeps the bridge tolerant to either label spelling forever.
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
    # `sub_474FC0`, `loc_4012A0`, `unk_402100`, `byte_409010`, etc.
    # Anchored to ^ + $ so it never matches user-given labels that
    # happen to contain these substrings.
    _IDA_AUTONAME_PATTERN = re.compile(
        r"^(?:sub|loc|unk|byte|word|dword|qword|off|nullsub|j|asc|stru|"
        r"flt|dbl|tbyte|packreal|locret)_([0-9a-fA-F]+)$",
    )

    @classmethod
    def _coerce_ida_autoname_to_address(
        cls, action: str, kwargs: dict[str, Any],
    ) -> tuple[dict[str, Any], list[str]]:
        """Rewrite IDA auto-name strings on address kwargs to ``0x<hex>``.

        Only touches keys in :data:`_ADDRESS_KWARG_NAMES`. Returns the
        kwargs dict (possibly modified) + a list of human-readable
        notes (one per rewrite) for the bridge log.
        """
        if not kwargs:
            return {}, []
        out: dict[str, Any] = dict(kwargs)
        notes: list[str] = []
        for k in cls._ADDRESS_KWARG_NAMES:
            v = out.get(k)
            if not isinstance(v, str):
                continue
            m = cls._IDA_AUTONAME_PATTERN.match(v.strip())
            if not m:
                continue
            hex_tail = m.group(1)
            new_val = f"0x{hex_tail}"
            out[k] = new_val
            notes.append(
                f"{action}: coerced {k}={v!r} -> {new_val!r} "
                f"(IDA auto-name embeds the address)",
            )
        # List-of-addresses kwargs: walk each entry and rewrite
        # in-place; non-string / non-auto-name entries are left.
        for k in cls._ADDRESS_LIST_KWARG_NAMES:
            v = out.get(k)
            if not isinstance(v, list):
                continue
            rewritten_count = 0
            new_list: list[Any] = []
            for elem in v:
                if isinstance(elem, str):
                    m = cls._IDA_AUTONAME_PATTERN.match(elem.strip())
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

    @classmethod
    def _coerce_encoding_value(
        cls, action: str, kwargs: dict[str, Any],
    ) -> tuple[dict[str, Any], list[str]]:
        """Rewrite ``encoding`` values on string-family tools to the
        canonical label that the MCP server accepts as a filter.

        Only touches keys named ``encoding`` on tools listed in
        :data:`_ENCODING_TOOLS`. Values not in the alias map (e.g.
        ``"ascii"``, ``"all"``) pass through unchanged.
        """
        if action not in cls._ENCODING_TOOLS or "encoding" not in kwargs:
            return kwargs, []
        raw = kwargs["encoding"]
        if not isinstance(raw, str):
            return kwargs, []
        key = raw.strip().lower()
        canonical = cls._ENCODING_VALUE_ALIASES.get(key)
        if canonical is None or canonical == key:
            return kwargs, []
        out = dict(kwargs)
        out["encoding"] = canonical
        return out, [
            f"{action}: coerced encoding={raw!r} -> {canonical!r} "
            f"(MCP server emits the same label under by_encoding; "
            f"alias map keeps count_only output round-tripping as a filter)",
        ]

    def _normalize_kwargs(
        self, action: str, kwargs: dict[str, Any],
    ) -> tuple[dict[str, Any], list[str]]:
        """Delegate to the shared resolver against the live alias map,
        then strip pagination-style kwargs the tool doesn't declare,
        then coerce IDA-style auto-name strings on address kwargs to
        ``0x<hex>`` so MCP tools that need int addresses don't get
        a `ValueError: invalid literal for int() with base 16` back.
        Finally normalize the ``encoding`` VALUE on the string-family
        tools so a value pulled from ``list_strings(count_only=True)``
        round-trips as a filter on the next call.
        """
        renamed, alias_notes = normalize_kwargs(
            action, kwargs, self._auto_alias_map,
        )
        filtered, drop_notes = drop_unknown_pagination_kwargs(
            action, renamed, self._known_params,
        )
        coerced, addr_notes = self._coerce_ida_autoname_to_address(
            action, filtered,
        )
        enc_coerced, enc_notes = self._coerce_encoding_value(
            action, coerced,
        )
        return enc_coerced, alias_notes + drop_notes + addr_notes + enc_notes

    async def _call_action_once(
        self, action: str, kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        """Single bridge POST without recorder, kwarg normalization, or
        the pending-retry loop. Used by ``forward()`` to re-issue an
        already-normalized call when the first response came back
        ``pending`` / ``queued`` / ``running``.

        Returns the raw JSON payload (status / error / per-tool fields).
        Network failures and non-JSON bodies are mapped to a synthetic
        error envelope so the caller has a uniform shape to inspect.
        """
        base = await self._resolve_base_url()
        url = f"{base}/tools/{action}"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(url, json=kwargs)
        except httpx.ConnectError as exc:
            return {
                "status": "error",
                "error": f"Cannot reach IDA Headless MCP at {base}: {exc}",
            }
        except httpx.TimeoutException as exc:
            return {
                "status": "error",
                "error": f"Timeout ({self._timeout}s) on retry of {action}: {exc}",
            }
        try:
            payload = resp.json() if resp.content else {}
        except ValueError as exc:
            return {
                "status": "error",
                "error": f"Non-JSON response from {action} retry: {exc}",
            }
        return payload if isinstance(payload, dict) else {"status": "error", "error": "non-dict payload"}

    # Dead-worker signature -- shape the ida-headless HTTP server emits
    # when the in-process arbiter has not spawned the IDA subprocess.
    # The arbiter is supposed to respawn on every tick when work is
    # queued; in practice an unrecoverable open_database failure plus
    # the persistent crash_counts.json cap (default 3) leaves the
    # arbiter permanently refusing to spawn for a given SHA. Callers
    # of the bridge see every request return ``status: pending`` for
    # the full 240s poll timeout while the worker_heartbeat.json on
    # disk stays days old.
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
    # When all three line up the bridge short-circuits with a
    # structured error rather than polling for 240s, so the agent's
    # next turn carries actionable text instead of a silent timeout.
    _DEAD_WORKER_PHASES: frozenset[str] = frozenset({
        "exiting_idle", "crashed", "",
    })
    _DEAD_WORKER_HEARTBEAT_THRESHOLD_S: float = float(
        os.environ.get(
            "IDA_HEADLESS_DEAD_WORKER_HEARTBEAT_S",
            "600",
        ),
    )

    @classmethod
    def _looks_like_dead_worker(
        cls, payload: dict[str, Any] | None,
    ) -> bool:
        """True when the response shape matches the dead-arbiter signature.

        Conservative: requires all three criteria so a legitimately slow
        worker producing a real ``pending`` doesn't trip the gate.
        """
        if not isinstance(payload, dict):
            return False
        if payload.get("status") != "pending":
            return False
        phase = payload.get("worker_phase")
        if not isinstance(phase, str) or phase not in cls._DEAD_WORKER_PHASES:
            return False
        hb_age = payload.get("heartbeat_age_s")
        try:
            hb_age_f = float(hb_age) if hb_age is not None else 0.0
        except (TypeError, ValueError):
            return False
        return hb_age_f >= cls._DEAD_WORKER_HEARTBEAT_THRESHOLD_S

    def _dead_worker_error(
        self, action: str, payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Build the structured fail-fast error replacement for a
        dead-arbiter response. The message names the symptom + the
        operator action to take so the agent surfaces the right next
        step rather than a generic timeout.
        """
        hb_age = payload.get("heartbeat_age_s", "?")
        queue_depth = payload.get("queue_depth", "?")
        sha = payload.get("binary_id", "?")
        return {
            "status": "error",
            "error": (
                f"ida-headless IDA worker is not alive for {sha}: "
                f"heartbeat_age_s={hb_age} (threshold "
                f"{int(self._DEAD_WORKER_HEARTBEAT_THRESHOLD_S)}s), "
                f"queue_depth={queue_depth}, worker_phase="
                f"{payload.get('worker_phase', '?')}. The arbiter has "
                f"stopped spawning subprocesses for this binary (most "
                f"often: open_database failures hit the crash-count "
                f"cap, or the .i64 file is corrupt). Calling {action!r} "
                f"again will time out the same way. Operator action: "
                f"restart ida-headless and clear crash_counts.json for "
                f"this SHA, or re-upload the binary to force fresh "
                f"analysis."
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
        self, action: str, normalized_kwargs: dict[str, Any],
    ) -> str:
        """sha256 of (action, sorted kwargs JSON) used as dedup-cache key.

        Sort keys so call-order variance does not split otherwise-
        identical cache entries; default=str to coerce non-JSON-clean
        values (paths, UUIDs) into a stable string form.
        """
        try:
            blob = _json.dumps(
                {"action": action, "kwargs": normalized_kwargs},
                sort_keys=True, default=str,
            )
        except (TypeError, ValueError):
            blob = f"{action}:{normalized_kwargs!r}"
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

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
        """Cache a ready payload for ``_dedup_ttl_s``. Caller is
        responsible for filtering -- only payloads with
        ``status: ready`` should be stored, never ``pending`` or
        ``error``.
        """
        if self._dedup_ttl_s <= 0:
            return
        # Periodic eviction: when the cache crosses 1024 entries,
        # drop everything already expired. Simple O(n) sweep; the
        # cache rarely grows that large because the TTL is short.
        if len(self._dedup_cache) > 1024:
            now = _time.monotonic()
            self._dedup_cache = {
                k: v for k, v in self._dedup_cache.items()
                if v[1] > now
            }
        self._dedup_cache[fingerprint] = (
            payload, _time.monotonic() + self._dedup_ttl_s,
        )

    async def forward(self, action: str | None = None, **kwargs: Any) -> dict:
        """Dispatch to the MCP HTTP API.

        Args:
            action: MCP tool name (e.g., ``decompile``, ``open_binary``).
            **kwargs: Parameters forwarded to the tool as JSON body fields.

        Returns:
            Tool result dict. The ``status`` field is one of:
            ``ready`` (result available), ``pending`` (queued for processing),
            or ``error`` (failure with ``error`` message).
        """
        if not action:
            return await self._list_tools()
        if action == "upload":
            return await self._upload_binary(**kwargs)
        # Drop the recursion guard before the public-facing alias /
        # validation pipeline so it never reaches the MCP server.
        suppress_poll = bool(kwargs.pop("_ida_bridge_no_poll", False))
        # Operator-supplied force-fresh flag bypasses the dedup cache
        # without disabling it for other callers. Strip before the
        # normalize_kwargs pass so it never reaches the MCP server.
        bypass_dedup = bool(kwargs.pop("_ida_bridge_no_dedup", False))
        normalized_kwargs, kw_notes = self._normalize_kwargs(action, kwargs)
        for note in kw_notes:
            logging.getLogger(__name__).info("ida_bridge %s", note)

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
            dedup_fp = self._dedup_fingerprint(action, normalized_kwargs)
            cached = self._dedup_lookup(dedup_fp)
            if cached is not None:
                logging.getLogger(__name__).info(
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
        base = await self._resolve_base_url()
        url = f"{base}/tools/{action}"

        async with self._recorder(
            server_id="ida_headless", base_url=base, action=action,
        ) as ctx:
            try:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    resp = await client.post(url, json=normalized_kwargs)
            except httpx.ConnectError as exc:
                ctx["status"] = "error"
                ctx["error_excerpt"] = str(exc)[:400]
                return {
                    "status": "error",
                    "error": (
                        f"Cannot reach IDA Headless MCP at {base}. "
                        "Ensure the HTTP server is running "
                        "(ida-headless-http or python -m ida_headless_mcp.http_api)."
                    ),
                }
            except httpx.TimeoutException as exc:
                ctx["status"] = "error"
                ctx["error_excerpt"] = str(exc)[:400]
                return {
                    "status": "error",
                    "error": f"Timeout ({self._timeout}s) calling {action}.",
                }
            ctx["http_status"] = resp.status_code
            try:
                payload = resp.json()
            except ValueError as exc:
                ctx["status"] = "error"
                ctx["error_excerpt"] = str(exc)[:400]
                return {
                    "status": "error",
                    "error": f"Non-JSON response from {action}: {resp.text[:200]}",
                }
            # fix §214 -- whitelist known statuses explicitly; unknown values
            # used to fall through to "ready" when HTTP was 2xx, silently
            # turning {"status": "queued"} into a success in the call log.
            payload_status = payload.get("status") if isinstance(payload, dict) else None
            # Defensive: some tools (search_pattern most prominently)
            # have the frontend wrap a worker-side ValueError into
            # the cached payload but stamp ``status: ready`` on it
            # before returning. The downstream executor then sees
            # ready + a populated ``error`` field and treats the
            # call as success, polluting case_state with a
            # "no matches" reading that isn't actually grounded.
            # Promote any non-empty ``error`` field to status=error
            # regardless of the declared status; the response body
            # is unchanged so adapters can still read its shape.
            if (
                isinstance(payload, dict)
                and payload.get("error")
                and isinstance(payload["error"], str)
                and payload_status in ("ready", "completed", "ok", None)
            ):
                logging.getLogger(__name__).info(
                    "ida_bridge %s: promoting status=%r to error -- "
                    "payload carries error field: %s",
                    action, payload_status,
                    payload["error"][:200],
                )
                payload_status = "error"
            if payload_status in ("ready", "completed", "ok"):
                ctx["status"] = "ready"
            elif payload_status in ("pending", "queued", "running"):
                # Dead-worker short-circuit: when the response shape
                # matches the dead-arbiter signature, polling for 240s
                # is pointless -- the IDA subprocess will not spawn
                # without operator intervention. The bridge swaps in a
                # structured error that names the symptom plus the
                # operator action.
                if self._looks_like_dead_worker(payload):
                    err = self._dead_worker_error(action, payload)
                    logging.getLogger(__name__).warning(
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
                ctx["status"] = "pending"
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
                if not suppress_poll and action != "poll_analysis":
                    deadline = (
                        asyncio.get_event_loop().time()
                        + self._pending_poll_timeout
                    )
                    delay = 2.0
                    attempt = 0
                    while asyncio.get_event_loop().time() < deadline:
                        attempt += 1
                        await asyncio.sleep(delay)
                        delay = min(delay * 1.5, 8.0)
                        logging.getLogger(__name__).info(
                            "ida_bridge %s: pending retry attempt=%d "
                            "(deadline in %.1fs)",
                            action, attempt,
                            deadline - asyncio.get_event_loop().time(),
                        )
                        retry_payload = await self._call_action_once(
                            action, normalized_kwargs,
                        )
                        retry_status = (
                            retry_payload.get("status")
                            if isinstance(retry_payload, dict) else None
                        )
                        if retry_status in ("ready", "completed", "ok"):
                            logging.getLogger(__name__).info(
                                "ida_bridge %s: retry attempt=%d "
                                "succeeded", action, attempt,
                            )
                            # Cache the recovered ready payload so
                            # sibling branches don't re-pay the wait.
                            if (
                                dedup_fp is not None
                                and isinstance(retry_payload, dict)
                            ):
                                self._dedup_store(dedup_fp, retry_payload)
                            return retry_payload
                        # Dead-worker shape can also surface on the
                        # retry path -- bridge starts polling against
                        # a live worker, the worker crashes mid-poll,
                        # subsequent retries return the dead-arbiter
                        # signature. Short-circuit there too.
                        if self._looks_like_dead_worker(retry_payload):
                            logging.getLogger(__name__).warning(
                                "ida_bridge %s: dead-arbiter signature "
                                "detected on retry attempt=%d; failing "
                                "fast", action, attempt,
                            )
                            return self._dead_worker_error(
                                action, retry_payload,
                            )
                        if retry_status not in ("pending", "queued", "running"):
                            return retry_payload
                    else:
                        logging.getLogger(__name__).warning(
                            "ida_bridge %s: retry deadline hit after "
                            "%d attempt(s); surfacing pending",
                            action, attempt,
                        )
            elif payload_status == "error":
                ctx["status"] = "error"
            elif payload_status is None and resp.status_code < 400:
                # Tools like binary_metadata and list_indexes return
                # data with no top-level ``status`` field; HTTP 2xx
                # itself is the success signal. The bridge recorder
                # marks ctx=ready, but the downstream executor's
                # _SUCCESS_STATUSES whitelist re-checks
                # ``raw.get('status')`` and a missing key fails the
                # check, surfacing as ``returned error: ''`` -- empty
                # error string because the payload doesn't carry one
                # either. Inject ``status: ready`` into the payload
                # so every consumer sees the same shape.
                ctx["status"] = "ready"
                if isinstance(payload, dict):
                    payload = {**payload, "status": "ready"}
            else:
                logging.getLogger(__name__).warning(
                    "ida_bridge %s: unknown payload status %r (HTTP %d) -- "
                    "coercing to error",
                    action, payload_status, resp.status_code,
                )
                ctx["status"] = "error"
            if ctx["status"] == "error" and isinstance(payload, dict):
                err = payload.get("error")
                if isinstance(err, str):
                    ctx["error_excerpt"] = err[:400]
            # Cache the response payload when it lands ready and the
            # action is dedup-eligible. ``pending`` and ``error``
            # states are never cached -- the next caller for the same
            # fingerprint deserves a fresh attempt.
            if (
                dedup_fp is not None
                and ctx["status"] == "ready"
                and isinstance(payload, dict)
            ):
                self._dedup_store(dedup_fp, payload)
            return payload

    # fix §211 -- _SPEC_CACHE moved to instance attr in __init__.

    async def _list_tools(self) -> dict:
        """Return available MCP tool names + schemas."""
        specs = await self.list_tool_specs()
        return {
            "status": "ready",
            "tools": [s["name"] for s in specs],
            "count": len(specs),
            "specs": specs,
        }

    async def list_tool_specs(self) -> list[dict[str, Any]]:
        """Fetch the IDA MCP catalog with parsed schemas. Cached per instance."""
        if self._spec_cache is not None:
            return self._spec_cache
        base = await self._resolve_base_url()
        url = f"{base}/tools"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url)
            raw = resp.json()
        except (httpx.ConnectError, httpx.TimeoutException, ValueError) as exc:
            logging.getLogger(__name__).warning(
                "ida_headless catalog fetch failed (%s) -- agent will see "
                "name-only listing without schemas", exc,
            )
            self._spec_cache = []
            return []
        self._spec_cache = [_compact_spec(t) for t in raw]
        # Derive the per-action alias map from the live schema. Every
        # subsequent _normalize_kwargs call resolves through this map.
        self._auto_alias_map = build_alias_map(
            self._spec_cache,
            self._KW_FAMILIES,
            self._MANUAL_OVERRIDES,
        )
        self._known_params = build_known_params(self._spec_cache)
        logging.getLogger(__name__).info(
            "ida_bridge: catalog loaded -- %d tools, %d with alias maps",
            len(self._spec_cache),
            len(self._auto_alias_map),
        )
        return self._spec_cache

    async def _upload_binary(self, file_path: str | None = None, **_extra: Any) -> dict:
        """Upload a local binary to the MCP server for analysis.

        The MCP server saves the file, hashes it, copies to workspace,
        and spawns IDA background analysis. Poll with
        ``action='poll_analysis'`` until state is READY/INDEXED.

        Args:
            file_path: Local filesystem path to the binary.

        Returns:
            open_binary result with binary_id, sha256, state.
        """
        if not file_path:
            return {"status": "error", "error": "file_path is required for upload"}
        target = Path(file_path)
        # is_file() does a sync stat -- wrap so we don't stall the loop
        # when the file lives on a slow volume.
        if not await asyncio.to_thread(target.is_file):
            return {"status": "error", "error": f"File not found: {file_path}"}
        base = await self._resolve_base_url()
        url = f"{base}/upload"

        # fix §213 -- stream the file in 64KB chunks instead of slurping
        # the entire binary into memory. The previous read_bytes()
        # approach required N bytes of resident worker RAM for an
        # N-byte upload; a 4GB binary could OOM the worker and kill
        # every in-flight investigation. We now build the multipart
        # envelope by hand and yield chunks from disk, capping memory
        # at one chunk regardless of binary size.
        chunk_size = 65536
        try:
            file_size = (await asyncio.to_thread(target.stat)).st_size
        except OSError as exc:
            return {"status": "error", "error": f"{type(exc).__name__}: {exc}"}
        boundary = uuid.uuid4().hex
        # Sanitize filename for the Content-Disposition header -- double
        # quotes inside filenames would break the multipart framing.
        safe_name = target.name.replace('"', "_").replace("\r", "_").replace("\n", "_")
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
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(url, content=_stream_body(), headers=headers)
            return resp.json()
        except httpx.ConnectError:
            return {"status": "error", "error": f"Cannot reach {base}"}
        except httpx.TimeoutException:
            return {"status": "error", "error": f"Upload timeout ({self._timeout}s)"}
        except (ValueError, OSError) as exc:
            return {"status": "error", "error": f"{type(exc).__name__}: {exc}"}

    async def health(self) -> dict:
        """Quick reachability check for machine readiness verification."""
        base = await self._resolve_base_url()
        url = f"{base}/health"
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(url)
            return resp.json()
        except (httpx.ConnectError, httpx.TimeoutException, ValueError):
            return {"status": "error", "error": f"Unreachable: {url}"}
