"""Adapters for the IDA Headless MCP server.

v0.3 v1 ships adapters for the two most common audit tools:
  - decompile           -> DECOMPILED_FUNCTION payload
  - find_api_call_sites -> XREF_VIEW payload

Add per-tool adapters when investigations actually invoke them.
"""
from __future__ import annotations

from typing import Any

from aila.modules.vr.contracts import PayloadKind

from .base import AdapterContext, AdapterResult

__all__ = [
    "adapt_decompile",
    "adapt_find_api_call_sites",
]


# Observables value cap so a 50KB pseudocode dump doesn't bloat
# every subsequent prompt. The full result lives in the message
# payload — observables carry only a summary the engine can reason
# over without re-quoting the whole function.
_MAX_OBS_PSEUDOCODE = 3000
_MAX_OBS_CALLSITE_NAMES = 25


def adapt_decompile(raw: dict[str, Any], ctx: AdapterContext) -> AdapterResult:
    """Map IDA Headless `decompile` response to DECOMPILED_FUNCTION payload."""
    function_name = str(raw.get("function_name") or raw.get("name") or "<unknown>")
    address = str(raw.get("address") or ctx.args.get("address_or_name") or "")
    pseudocode = str(raw.get("pseudocode") or "")
    line_count = pseudocode.count("\n") + (1 if pseudocode else 0)

    payload: dict[str, Any] = {
        "function_name": function_name,
        "address": address,
        "pseudocode": pseudocode,
        "line_count": line_count,
        "language": "c",
        "source_provenance": {
            "mcp_server": ctx.mcp_server_id,
            "mcp_tool": ctx.tool_name,
            "call_id": ctx.call_id,
        },
    }

    obs_key = f"decompiled.{function_name}"
    obs_value = pseudocode[:_MAX_OBS_PSEUDOCODE]
    if len(pseudocode) > _MAX_OBS_PSEUDOCODE:
        obs_value += f"\n\n[truncated — full {line_count} lines in message {ctx.call_id}]"

    return AdapterResult(
        payload_kind=PayloadKind.DECOMPILED_FUNCTION,
        payload=payload,
        observables_delta={obs_key: obs_value},
        summary=f"Decompiled {function_name} ({line_count} lines)",
    )


def adapt_find_api_call_sites(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map IDA Headless `find_api_call_sites` response to XREF_VIEW payload.

    Output:
      payload.api_name + payload.call_sites = full list (for UI render)
      observables[f"callsites.{api}"] = compact list of (function_name @ address)
    """
    api_name = str(raw.get("api_name") or ctx.args.get("api_name") or "<unknown>")
    call_sites = raw.get("call_sites") or []

    payload: dict[str, Any] = {
        "api_name": api_name,
        "call_sites": call_sites,
        "total": len(call_sites),
        "source_provenance": {
            "mcp_server": ctx.mcp_server_id,
            "mcp_tool": ctx.tool_name,
            "call_id": ctx.call_id,
        },
    }

    compact_lines: list[str] = []
    for site in call_sites[:_MAX_OBS_CALLSITE_NAMES]:
        if not isinstance(site, dict):
            continue
        fn = site.get("function_name") or site.get("caller_function_name") or "<?>"
        addr = site.get("function_address") or site.get("caller_function_address") or "?"
        compact_lines.append(f"  - {fn} @ {addr}")
    if len(call_sites) > _MAX_OBS_CALLSITE_NAMES:
        compact_lines.append(f"  ... and {len(call_sites) - _MAX_OBS_CALLSITE_NAMES} more")

    obs_value = (
        f"{len(call_sites)} call site(s) for {api_name}:\n"
        + ("\n".join(compact_lines) if compact_lines else "  (none)")
    )

    return AdapterResult(
        payload_kind=PayloadKind.XREF_VIEW,
        payload=payload,
        observables_delta={f"callsites.{api_name}": obs_value},
        summary=f"{len(call_sites)} call sites for {api_name}",
    )
