"""VR agent-callable wrappers over the platform dynamic-analysis primitives (issue #148).

The reasoning loop can now TRIGGER the two platform dynamic-analysis
drivers mid-investigation, the same way it drives ``audit_mcp`` /
``rea`` / ``reverser_belt`` / ``poc_runner``:

* :class:`SymbolicExploreTool` wraps
  :func:`aila.platform.services.symbolic.explore` -- a bounded concolic
  walk of one function. Reached blocks + emitted path constraints land
  in the platform observation channel (the existing
  ``record_observation`` emit inside ``explore`` is untouched) AND the
  tool returns a structured dict the specialised adapter
  (:func:`aila.platform.mcp.adapters.dynamic_symbolic.adapt_symbolic_explore`)
  projects into ``case_state.observables`` under
  ``symbolic:<function>:reached`` -- the key shape the per-turn
  kill-criteria evaluator scans (see
  :meth:`aila.modules.vr.agents.vuln_researcher.HonestVulnResearcher.
  _evaluate_kill_criteria_this_turn`).

* :class:`DynamicRunTool` wraps
  :func:`aila.platform.services.dynamic_execution.run_dynamic` -- a
  single sandboxed execution with coverage + crash capture. Its adapter
  projects ``dynamic:<target>:coverage_delta`` (and
  ``dynamic:<target>:crash`` on an abnormal exit).

Both tools are fail-soft by construction: the underlying primitives
never raise for the disabled / unavailable / backend-error cases (they
return typed statuses), and these wrappers additionally convert any
bad-input / validation fault into a clean ``{"status": "error", ...}``
dict so a malformed agent call surfaces as a tool result, never an
uncaught exception that breaks dispatch. ``miasm`` absence degrades to
``status="unavailable"`` with no observation written.

The owning ``module`` id and workspace scope are injected SERVER-SIDE
by the VR tool executor's ``_pre_dispatch_correct_args`` (mirroring the
``poc_runner`` SSH integration + ``knowledge`` namespace injection), so
the agent can never point a run at another workspace.
"""
from __future__ import annotations

import logging
from typing import Any

from aila.platform.services.dynamic_execution import (
    DynamicInputs,
    DynamicTarget,
    run_dynamic,
)
from aila.platform.services.symbolic import (
    FunctionRef,
    Precondition,
    explore,
)
from aila.platform.tools import Tool

_log = logging.getLogger(__name__)

__all__ = [
    "DynamicRunTool",
    "SymbolicExploreTool",
]

# Server ids the agent dispatches against (``<server>.<tool>``). Kept in
# lockstep with the adapter registry (KNOWN_TOOLS + _SPECIALIZED) and the
# VR tool executor's _AGENT_ALLOWED_SERVERS.
SYMBOLIC_SERVER_ID = "symbolic"
SYMBOLIC_TOOL_NAME = "explore"
DYNAMIC_SERVER_ID = "dynamic"
DYNAMIC_TOOL_NAME = "run_dynamic"


def _err(message: str) -> dict[str, Any]:
    """Uniform clean-error envelope (never raises upward)."""
    return {"status": "error", "error": message}


def _coerce_code_bytes(value: object) -> bytes | None:
    """Return function bytes from a hex string or raw bytes, or ``None``.

    The agent surface carries bytes as a hex string (JSON has no bytes
    type); an in-process caller may pass ``bytes`` directly. Any other
    shape, or an odd-length / non-hex string, yields ``None`` so the
    caller returns a clean error instead of raising.
    """
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        cleaned = value.strip().replace(" ", "").replace("0x", "")
        if not cleaned:
            return None
        try:
            return bytes.fromhex(cleaned)
        except ValueError:
            _log.debug("symbolic_explore: code is not valid hex; returning None")
            return None
    return None


class SymbolicExploreTool(Tool):
    """Agent surface for the platform concolic driver (issue #148)."""

    name = "vr.symbolic_explore"
    description = (
        "Run a bounded concolic (symbolic) exploration of a single "
        "function. Records reached basic blocks and emitted path "
        "constraints so a hypothesis kill-criterion keyed on 'this branch "
        "is reachable under X' can be confirmed or refuted. Requires the "
        "platform.symbolic_enabled flag and the [symbolic] extra (miasm); "
        "returns status=disabled / unavailable cleanly otherwise."
    )
    inputs = {
        "action": {
            "type": "string",
            "description": "explore",
        },
    }
    output_type = "object"
    skip_forward_signature_validation = True

    async def list_tool_specs(self) -> list[dict[str, Any]]:
        """Return the prompt-catalog spec for the single ``explore`` tool."""
        return [
            {
                "name": SYMBOLIC_TOOL_NAME,
                "description": (
                    "Concolic walk of one function. Supply the function "
                    "bytes as hex plus arch + entry_address; reached blocks "
                    "and path constraints feed hypothesis kill-criteria. "
                    "module and workspace are set automatically."
                ),
                "params": [
                    {
                        "name": "symbol_name", "type": "string",
                        "required": True,
                        "description": "Human-readable function name.",
                    },
                    {
                        "name": "arch", "type": "string", "required": True,
                        "description": "miasm arch, e.g. x86_32 / x86_64 / aarch64l.",
                    },
                    {
                        "name": "entry_address", "type": "integer",
                        "required": True,
                        "description": "Function entry offset in the flat map.",
                    },
                    {
                        "name": "code_bytes", "type": "string",
                        "required": True,
                        "description": "Function bytes as a hex string.",
                    },
                    {
                        "name": "end_address", "type": "integer",
                        "required": False,
                        "description": "Optional early-exit PC.",
                    },
                    {
                        "name": "initial_regs", "type": "object",
                        "required": False,
                        "description": "Concrete register seeds {name: int}.",
                    },
                    {
                        "name": "symbolic_regs", "type": "array",
                        "required": False,
                        "description": "Register names to leave symbolic.",
                    },
                    {
                        "name": "symbolic_memory", "type": "array",
                        "required": False,
                        "description": "Symbolic memory regions [{addr,size,name}].",
                    },
                    {
                        "name": "max_steps", "type": "integer",
                        "required": False,
                        "description": "Instruction budget (default 10000).",
                    },
                    {
                        "name": "max_constraints", "type": "integer",
                        "required": False,
                        "description": "Cap on emitted constraints (default 64).",
                    },
                ],
            },
        ]

    async def forward(
        self, action: str | None = None, **kwargs: Any,
    ) -> dict[str, Any]:
        if action not in (None, SYMBOLIC_TOOL_NAME):
            return _err(f"unknown action: {action!r} (expected 'explore')")

        module = str(kwargs.get("module") or "").strip()
        workspace_id = str(kwargs.get("workspace_id") or "").strip()
        if not module or not workspace_id:
            return _err(
                "module + workspace_id are injected server-side; this call "
                "reached the tool without them (investigation scope "
                "unresolved).",
            )
        symbol_name = str(kwargs.get("symbol_name") or "").strip()
        if not symbol_name:
            return _err("symbol_name is required")
        arch = str(kwargs.get("arch") or "").strip()
        if not arch:
            return _err("arch is required (e.g. x86_32)")
        entry_address = kwargs.get("entry_address")
        if not isinstance(entry_address, int) or isinstance(entry_address, bool):
            return _err("entry_address must be an integer")
        if entry_address < 0:
            return _err("entry_address must be >= 0")
        code = _coerce_code_bytes(kwargs.get("code_bytes"))
        if not code:
            return _err("code_bytes is required as a non-empty hex string")

        end_address = kwargs.get("end_address")
        if end_address is not None and (
            not isinstance(end_address, int) or isinstance(end_address, bool)
        ):
            return _err("end_address must be an integer or omitted")

        try:
            function_ref = FunctionRef(
                module=module,
                workspace_id=workspace_id,
                symbol_name=symbol_name,
                arch=arch,
                entry_address=entry_address,
                code_bytes=code,
                end_address=end_address,
            )
            precondition = Precondition(
                initial_regs=dict(kwargs.get("initial_regs") or {}),
                symbolic_regs=list(kwargs.get("symbolic_regs") or []),
                symbolic_memory=list(kwargs.get("symbolic_memory") or []),
                max_steps=int(kwargs.get("max_steps", 10_000)),
                max_constraints=int(kwargs.get("max_constraints", 64)),
            )
        except (ValueError, TypeError) as exc:
            return _err(f"invalid symbolic-exploration arguments: {exc}")

        result = await explore(
            function_ref,
            precondition,
            investigation_id=kwargs.get("investigation_id"),
            branch_id=kwargs.get("branch_id"),
            turn_number=kwargs.get("turn_number"),
        )
        # Flatten the discriminated-union result into a stable dict the
        # adapter keys the ``symbolic:<function>:reached`` observable off.
        return {
            "status": result.status.value,
            "function": symbol_name,
            "subject": result.subject,
            "arch": arch,
            "reached_count": len(result.reached_addresses),
            "reached_addresses": [
                f"0x{a:x}" for a in result.reached_addresses[:32]
            ],
            "path_constraints": result.path_constraints[:32],
            "steps_executed": result.steps_executed,
            "observation_id": result.observation_id,
            "error": result.error,
        }


class DynamicRunTool(Tool):
    """Agent surface for the platform sandboxed dynamic-execution driver."""

    name = "vr.dynamic_run"
    description = (
        "Execute a target once in the platform sandbox and capture its "
        "exit, crash status, and coverage delta. A new-edge delta or a "
        "crash confirms a reachability / fault hypothesis and feeds the "
        "kill-criteria. Requires the platform.dynamic_execution_enabled "
        "flag and a configured sandbox backend; returns status=disabled / "
        "unavailable cleanly otherwise."
    )
    inputs = {
        "action": {
            "type": "string",
            "description": "run_dynamic",
        },
    }
    output_type = "object"
    skip_forward_signature_validation = True

    async def list_tool_specs(self) -> list[dict[str, Any]]:
        """Return the prompt-catalog spec for the single ``run_dynamic`` tool."""
        return [
            {
                "name": DYNAMIC_TOOL_NAME,
                "description": (
                    "Run a target once in the sandbox. Supply a subject "
                    "(probe id / target+input fingerprint) and argv; set "
                    "capture_coverage to diff edges against prior_coverage_"
                    "edges. A crash or new-edge delta feeds kill-criteria. "
                    "module and workspace are set automatically."
                ),
                "params": [
                    {
                        "name": "subject", "type": "string", "required": True,
                        "description": "Identity of the thing under test.",
                    },
                    {
                        "name": "argv", "type": "array", "required": True,
                        "description": "Command + args to exec in the sandbox.",
                    },
                    {
                        "name": "stdin", "type": "string", "required": False,
                        "description": "Optional stdin text.",
                    },
                    {
                        "name": "input_files", "type": "object",
                        "required": False,
                        "description": "Workdir-relative path -> content.",
                    },
                    {
                        "name": "timeout_s", "type": "number", "required": False,
                        "description": "Wall-clock ceiling (default 30).",
                    },
                    {
                        "name": "expected_exit_code", "type": "integer",
                        "required": False,
                        "description": "Exit code treated as clean completion.",
                    },
                    {
                        "name": "capture_coverage", "type": "boolean",
                        "required": False,
                        "description": "Collect + diff coverage edges.",
                    },
                    {
                        "name": "prior_coverage_edges", "type": "array",
                        "required": False,
                        "description": "Edges already seen for this subject.",
                    },
                    {
                        "name": "coverage_output_path", "type": "string",
                        "required": False,
                        "description": "Workdir-relative coverage file override.",
                    },
                    {
                        "name": "env", "type": "object", "required": False,
                        "description": "Extra sandbox env vars.",
                    },
                    {
                        "name": "workdir", "type": "string", "required": False,
                        "description": "Sandbox workdir (default /work).",
                    },
                    {
                        "name": "network", "type": "boolean", "required": False,
                        "description": "Grant sandbox network (policy-gated).",
                    },
                    {
                        "name": "output_globs", "type": "array",
                        "required": False,
                        "description": "Extra output globs to collect.",
                    },
                ],
            },
        ]

    async def forward(
        self, action: str | None = None, **kwargs: Any,
    ) -> dict[str, Any]:
        if action not in (None, DYNAMIC_TOOL_NAME):
            return _err(f"unknown action: {action!r} (expected 'run_dynamic')")

        module = str(kwargs.get("module") or "").strip()
        workspace_id = str(kwargs.get("workspace_id") or "").strip()
        if not module or not workspace_id:
            return _err(
                "module + workspace_id are injected server-side; this call "
                "reached the tool without them (investigation scope "
                "unresolved).",
            )
        subject = str(kwargs.get("subject") or "").strip()
        if not subject:
            return _err("subject is required")
        argv = kwargs.get("argv")
        if not isinstance(argv, list) or not argv or not all(
            isinstance(a, str) and a for a in argv
        ):
            return _err("argv must be a non-empty list of non-empty strings")

        try:
            target = DynamicTarget(
                module=module,
                workspace_id=workspace_id,
                subject=subject,
                argv=list(argv),
                env=dict(kwargs.get("env") or {}),
                workdir=str(kwargs.get("workdir") or "/work"),
                investigation_id=kwargs.get("investigation_id"),
                branch_id=kwargs.get("branch_id"),
                turn_number=kwargs.get("turn_number"),
            )
            inputs = DynamicInputs(
                stdin=kwargs.get("stdin"),
                input_files=dict(kwargs.get("input_files") or {}),
                timeout_s=float(kwargs.get("timeout_s", 30.0)),
                network=bool(kwargs.get("network", False)),
                output_globs=list(kwargs.get("output_globs") or []),
                expected_exit_code=kwargs.get("expected_exit_code"),
                coverage_output_path=kwargs.get("coverage_output_path"),
                prior_coverage_edges=list(kwargs.get("prior_coverage_edges") or []),
            )
        except (ValueError, TypeError) as exc:
            return _err(f"invalid dynamic-run arguments: {exc}")

        result = await run_dynamic(
            target,
            inputs,
            capture_coverage=bool(kwargs.get("capture_coverage", False)),
        )
        exit_code = (
            result.sandbox_result.exit_code
            if result.sandbox_result is not None else None
        )
        return {
            "status": result.status.value,
            "target": subject,
            "reason": result.reason,
            "exit_code": exit_code,
            "crashed": result.status.value == "crashed",
            "coverage_edge_count": len(result.coverage_edges),
            "coverage_delta_edges": result.coverage_delta_edges[:32],
            "coverage_delta_count": len(result.coverage_delta_edges),
            "observations_emitted": list(result.observations_emitted),
        }
