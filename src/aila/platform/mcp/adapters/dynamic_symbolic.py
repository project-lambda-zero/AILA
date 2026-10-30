"""Adapters for the VR dynamic-analysis tools (issue #148).

The ``symbolic.explore`` and ``dynamic.run_dynamic`` tools
(:mod:`aila.modules.vr.tools.dynamic_analysis`) wrap the platform
concolic + sandbox primitives. These adapters render their structured
result as a TEXT payload AND project a kill-criteria observable keyed
in the exact shape the per-turn evaluator scans:

* ``symbolic:<function>:reached`` -- the reached-blocks / path-constraint
  summary from one concolic walk.
* ``dynamic:<target>:coverage_delta`` -- the new-edge coverage summary
  from one sandboxed run; a ``dynamic:<target>:crash`` observable is
  added alongside when the run terminated abnormally.

The colon-joined ``<prefix>:<subject>:<kind>`` key is what
:meth:`aila.modules.vr.agents.vuln_researcher.HonestVulnResearcher.
_evaluate_kill_criteria_this_turn` matches against each live
hypothesis' ``kill_criterion`` after the ``fuzz:`` / ``symbolic:`` /
``dynamic:`` prefixes were added to its observable allowlist. The
platform ``record_observation`` emit inside the primitives is a
separate, cross-investigation memory write; this adapter is the
same-turn, same-branch case_state projection.

Adapters are pure: no DB, no MCP, no side effects (per
:data:`aila.platform.mcp.adapters.base.AdapterFn`).
"""
from __future__ import annotations

from typing import Any

from aila.platform.contracts.mcp_payload import PayloadKind

from ._shared import provenance_stamp
from .base import AdapterContext, AdapterResult

__all__ = [
    "adapt_dynamic_run",
    "adapt_symbolic_explore",
]


def _str_arg(ctx: AdapterContext, raw: dict[str, Any], *keys: str) -> str:
    """First non-empty string from ``raw`` then ``ctx.args`` across ``keys``."""
    for source in (raw, ctx.args):
        if not isinstance(source, dict):
            continue
        for key in keys:
            value = source.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def adapt_symbolic_explore(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map a ``symbolic.explore`` result to TEXT + a ``symbolic:<fn>:reached``
    observable."""
    status = str(raw.get("status") or "error")
    function = _str_arg(ctx, raw, "function", "symbol_name") or "unknown"
    reached_count = raw.get("reached_count")
    constraints = raw.get("path_constraints") or []
    if not isinstance(constraints, list):
        constraints = []

    if status == "success":
        addrs = raw.get("reached_addresses") or []
        head = ", ".join(str(a) for a in addrs[:8]) if isinstance(addrs, list) else ""
        body = (
            f"symbolic.reached: concolic walk of {function} "
            f"({raw.get('arch') or 'unknown-arch'}) reached "
            f"{reached_count if reached_count is not None else 0} blocks "
            f"[{head or 'none'}]; {len(constraints)} path constraint(s)."
        )
        if constraints:
            body += "\nconstraints:\n" + "\n".join(
                f"  - {c}" for c in constraints[:16]
            )
    else:
        detail = raw.get("error")
        body = (
            f"symbolic.reached: exploration of {function} returned "
            f"status={status}"
            + (f" -- {detail}" if detail else "")
            + "."
        )

    key = f"symbolic:{function}:reached"
    payload: dict[str, Any] = {
        "text": body,
        "tool": f"{ctx.mcp_server_id}.{ctx.tool_name}",
        "function": function,
        "exploration_status": status,
        "raw": raw,
        "source_provenance": provenance_stamp(ctx),
    }
    if status in ("error",):
        payload["is_error"] = True
    return AdapterResult(
        payload_kind=PayloadKind.TEXT,
        payload=payload,
        observables_delta={key: body},
        summary=f"symbolic.explore {function}: {status}",
    )


def adapt_dynamic_run(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map a ``dynamic.run_dynamic`` result to TEXT + a
    ``dynamic:<target>:coverage_delta`` observable (plus a
    ``dynamic:<target>:crash`` observable on an abnormal exit)."""
    status = str(raw.get("status") or "error")
    target = _str_arg(ctx, raw, "target", "subject") or "unknown"
    delta_count = raw.get("coverage_delta_count")
    if not isinstance(delta_count, int):
        delta_count = 0
    exit_code = raw.get("exit_code")
    crashed = bool(raw.get("crashed"))

    sample = raw.get("coverage_delta_edges") or []
    sample_text = ", ".join(str(e) for e in sample[:8]) if isinstance(sample, list) else ""
    coverage_body = (
        f"dynamic.coverage_delta: run of {target} (status={status}, "
        f"exit={exit_code}) opened {delta_count} new edge(s)"
        + (f" [{sample_text}]" if sample_text else "")
        + "."
    )

    observables: dict[str, Any] = {
        f"dynamic:{target}:coverage_delta": coverage_body,
    }
    if crashed:
        crash_body = (
            f"dynamic.crash: target {target} terminated abnormally -- "
            f"{raw.get('reason') or 'abnormal termination'} (exit={exit_code})."
        )
        observables[f"dynamic:{target}:crash"] = crash_body

    payload: dict[str, Any] = {
        "text": coverage_body,
        "tool": f"{ctx.mcp_server_id}.{ctx.tool_name}",
        "target": target,
        "run_status": status,
        "crashed": crashed,
        "raw": raw,
        "source_provenance": provenance_stamp(ctx),
    }
    if status in ("error", "backend_error"):
        payload["is_error"] = True
    return AdapterResult(
        payload_kind=PayloadKind.TEXT,
        payload=payload,
        observables_delta=observables,
        summary=(
            f"dynamic.run {target}: {status}, "
            f"{delta_count} new edge(s)"
            + (", crashed" if crashed else "")
        ),
    )
