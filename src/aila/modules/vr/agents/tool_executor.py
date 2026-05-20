"""Tool executor — dispatches tool_run decisions through MCP bridges (M3.R-3).

The reasoning agent (``HonestVulnResearcher``) emits a tool_run decision
with ``command`` set to a JSON string describing which MCP tool to call.
The executor:
  1. Parses ``command`` as JSON: ``{"tool": "<server>.<tool>", "args": {...}}``
  2. Looks up the adapter via ``mcp_adapters.get_adapter``
  3. Dispatches to the matching bridge (IDABridgeTool / AuditMcpBridgeTool)
  4. Invokes the adapter on the raw response to get an AdapterResult
  5. Writes a new ENGINE message with the typed payload
  6. Merges the observables delta into the branch's ReasoningCaseState
     so the next reasoning turn sees the result

Unknown tools / malformed commands / MCP errors all write an
informative ENGINE message (PayloadKind.TEXT) and do NOT mutate
observables — the engine sees the error in the next turn and can
recover.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from sqlmodel import select as _select

from aila.modules.vr.agents.mcp_adapters import (
    AdapterContext,
    get_adapter,
    registered_tools,
)
from aila.modules.vr.contracts import PayloadKind, SenderKind
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationMessageRecord,
)
from aila.modules.vr.tools.audit_mcp_bridge import AuditMcpBridgeTool
from aila.modules.vr.tools.ida_bridge import IDABridgeTool
from aila.platform.contracts._common import utc_now
from aila.platform.uow import UnitOfWork

__all__ = [
    "ToolExecutionResult",
    "ToolExecutor",
]

_log = logging.getLogger(__name__)


@dataclass(slots=True)
class ToolExecutionResult:
    """Outcome of one tool_run dispatch."""

    server_id: str
    tool_name: str
    message_id: str | None
    success: bool
    error: str = ""


class ToolExecutor:
    """Per-investigation tool dispatcher. Injects the two MCP bridges.

    Tests can construct with fake bridges that have a ``.forward(action, **kwargs)``
    method returning a canned dict.
    """

    def __init__(
        self,
        ida: IDABridgeTool | Any,
        audit_mcp: AuditMcpBridgeTool | Any,
    ) -> None:
        self._bridges: dict[str, Any] = {
            "ida_headless": ida,
            "audit_mcp": audit_mcp,
        }

    async def execute(
        self,
        investigation_id: str,
        branch_id: str,
        command_raw: str,
        at_turn: int | None = None,
    ) -> ToolExecutionResult:
        """Dispatch one tool call. Writes a result message + updates observables."""
        call_id = str(uuid4())

        parsed = _parse_command(command_raw)
        if parsed is None:
            err = (
                f"Malformed tool_run command — expected JSON with "
                f"'tool' (e.g. 'ida_headless.decompile') and 'args' dict. "
                f"Got: {command_raw[:200]!r}"
            )
            msg_id = await self._write_error_message(
                investigation_id, branch_id, err, at_turn,
            )
            return ToolExecutionResult(
                server_id="", tool_name="",
                message_id=msg_id, success=False, error=err,
            )

        tool_id, args = parsed
        server_id, _, tool_name = tool_id.partition(".")
        if not tool_name:
            err = (
                f"tool_run command 'tool' field must be '<server>.<tool>' "
                f"(e.g. 'ida_headless.decompile'). Got: {tool_id!r}. "
                f"Registered tools: {', '.join(registered_tools())}"
            )
            msg_id = await self._write_error_message(
                investigation_id, branch_id, err, at_turn,
            )
            return ToolExecutionResult(
                server_id=server_id, tool_name="",
                message_id=msg_id, success=False, error=err,
            )

        adapter = get_adapter(server_id, tool_name)
        if adapter is None:
            err = (
                f"No adapter registered for {server_id}.{tool_name}. "
                f"Registered tools: {', '.join(registered_tools())}"
            )
            msg_id = await self._write_error_message(
                investigation_id, branch_id, err, at_turn,
            )
            return ToolExecutionResult(
                server_id=server_id, tool_name=tool_name,
                message_id=msg_id, success=False, error=err,
            )

        bridge = self._bridges.get(server_id)
        if bridge is None:
            err = f"No bridge configured for MCP server {server_id!r}"
            msg_id = await self._write_error_message(
                investigation_id, branch_id, err, at_turn,
            )
            return ToolExecutionResult(
                server_id=server_id, tool_name=tool_name,
                message_id=msg_id, success=False, error=err,
            )

        try:
            raw = await bridge.forward(action=tool_name, **args)
        except (OSError, TimeoutError, RuntimeError) as exc:
            err = f"{server_id}.{tool_name} bridge call raised: {exc}"
            msg_id = await self._write_error_message(
                investigation_id, branch_id, err, at_turn,
            )
            return ToolExecutionResult(
                server_id=server_id, tool_name=tool_name,
                message_id=msg_id, success=False, error=err,
            )

        if raw.get("status") == "error":
            raw_err = raw.get("error") or ""
            err = f"{server_id}.{tool_name} returned error: {raw_err!r}"
            # Common false-negative: audit_mcp.read_function says
            # 'Function X not indexed' — but the identifier is a
            # #define macro, not a function. Append a hint so the
            # agent's next turn calls audit_mcp.search_macros instead
            # of grinding on more search_source attempts.
            if (
                server_id == "audit_mcp"
                and tool_name == "read_function"
                and isinstance(raw_err, str)
                and "not indexed" in raw_err.lower()
            ):
                requested = args.get("name") or args.get("function") or "<symbol>"
                err += (
                    f"\n\nHINT: '{requested}' may be a macro (#define), not a function. "
                    f"Try audit_mcp.search_macros(name={requested!r}) BEFORE giving up — "
                    f"identifiers that look like function calls (e.g. ngx_http_v2_write_*) "
                    f"are often macros that read_function can't see."
                )
            msg_id = await self._write_error_message(
                investigation_id, branch_id, err, at_turn,
            )
            return ToolExecutionResult(
                server_id=server_id, tool_name=tool_name,
                message_id=msg_id, success=False, error=err,
            )

        ctx = AdapterContext(
            mcp_server_id=server_id,
            tool_name=tool_name,
            investigation_id=investigation_id,
            branch_id=branch_id,
            call_id=call_id,
            args=args,
        )
        adapter_result = adapter(raw, ctx)

        msg_id = await self._write_result_message(
            investigation_id, branch_id,
            payload_kind=adapter_result.payload_kind,
            payload=adapter_result.payload,
            at_turn=at_turn,
        )
        await self._merge_observables(branch_id, adapter_result.observables_delta)

        _log.info(
            "tool_executor OK server=%s tool=%s args=%s summary=%s",
            server_id, tool_name, list(args.keys()), adapter_result.summary,
        )
        return ToolExecutionResult(
            server_id=server_id, tool_name=tool_name,
            message_id=msg_id, success=True,
        )

    async def _write_result_message(
        self,
        investigation_id: str,
        branch_id: str,
        *,
        payload_kind: PayloadKind,
        payload: dict[str, Any],
        at_turn: int | None,
    ) -> str:
        async with UnitOfWork() as uow:
            msg = VRInvestigationMessageRecord(
                investigation_id=investigation_id,
                branch_id=branch_id,
                sender_kind=SenderKind.ENGINE.value,
                sender_id="tool_executor",
                payload_kind=payload_kind.value,
                payload_json=json.dumps(payload),
                at_turn=at_turn,
                evidence_refs_json="[]",
            )
            uow.session.add(msg)
            await uow.session.commit()
            await uow.session.refresh(msg)
            return msg.id

    async def _write_error_message(
        self,
        investigation_id: str,
        branch_id: str,
        error_text: str,
        at_turn: int | None,
    ) -> str:
        return await self._write_result_message(
            investigation_id, branch_id,
            payload_kind=PayloadKind.TEXT,
            payload={"text": error_text, "is_error": True},
            at_turn=at_turn,
        )

    async def _merge_observables(
        self,
        branch_id: str,
        delta: dict[str, Any],
    ) -> None:
        if not delta:
            return
        async with UnitOfWork() as uow:
            branch = (await uow.session.exec(
                _select(VRInvestigationBranchRecord).where(
                    VRInvestigationBranchRecord.id == branch_id,
                )
            )).first()
            if branch is None:
                _log.warning(
                    "tool_executor: branch %s vanished during observables merge",
                    branch_id,
                )
                return
            try:
                case_state = json.loads(branch.case_state_json or "{}")
            except json.JSONDecodeError:
                case_state = {}
            observables = case_state.get("observables")
            if not isinstance(observables, dict):
                observables = {}
            observables.update({str(k): v for k, v in delta.items()})
            case_state["observables"] = observables
            branch.case_state_json = json.dumps(case_state)
            branch.updated_at = utc_now()
            uow.session.add(branch)
            await uow.commit()


def _parse_command(raw: str) -> tuple[str, dict[str, Any]] | None:
    """Parse a tool_run command string into (tool_id, args).

    Expected JSON shape:
        {"tool": "<server>.<tool>", "args": {<kwargs>}}
    Returns None on any parse failure so the executor can report the
    error back to the engine via a TEXT message.
    """
    if not raw or not raw.strip():
        return None
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        _log.warning(
            "tool_executor._parse_command: JSON decode failed (raw len=%d): %s",
            len(raw), exc,
        )
        return None
    if not isinstance(decoded, dict):
        return None
    tool_id = decoded.get("tool")
    args = decoded.get("args", {})
    if not isinstance(tool_id, str) or not isinstance(args, dict):
        return None
    return tool_id, args
