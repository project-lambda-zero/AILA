"""Platform LSP tools (issue #154) -- ``lsp.definition`` /
``lsp.references`` / ``lsp.hover`` / ``lsp.diagnostics``.

Each :class:`Tool` subclass here wraps one :class:`LspService`
operation, publishes its input contract for platform-side tool
registration, and reuses :func:`aila.platform.agents.observation
.record_observation` (issue #137) so a caller that passes
``workspace_id`` -- typically a module executor threading through the
investigation context -- gets a durable ``lsp.<op>`` observation
alongside the return value.

Fail-open by contract: an ``unavailable`` result from :class:`LspService`
(flag off, binary missing, server dead, timeout) becomes an empty typed
payload on the tool's return path. NEVER raises. A caller can rely on
the tool being safe to invoke regardless of whether pyright / gopls
are installed on the host.
"""

from __future__ import annotations

import logging
from typing import Any

from aila.platform.agents.observation import (
    ObservationPolarity,
    PlatformObservation,
    record_observation,
)

from ..services.lsp import LspResult, LspService, get_lsp_service
from ._common import Tool, require_text

__all__ = [
    "LspDefinitionTool",
    "LspDiagnosticsTool",
    "LspHoverTool",
    "LspReferencesTool",
]

_log = logging.getLogger(__name__)

_OBSERVATION_MODULE_MAX = 32
_OBSERVATION_WORKSPACE_MAX = 64
_OBSERVATION_SUBJECT_MAX = 256


class _LspToolBase(Tool):
    """Shared plumbing for the four LSP tool subclasses.

    ``module`` binds the observation writer's owning module id -- the
    same value the caller's investigation-side executor would pass
    when it records observations of its own. Defaults to ``"platform"``
    so a tool instance registered under :data:`PLATFORM_TOOL_KEYS`
    still writes observations under the ``platform.observation.workspace.*``
    bucket without a module-specific binding.
    """

    _op: str = ""
    _kind: str = ""
    _default_polarity: ObservationPolarity = ObservationPolarity.NEUTRAL

    def __init__(self, module: str = "platform", *, service: LspService | None = None) -> None:
        self._module = require_text(module, tool_name=self.__class__.__name__, field_name="module")
        self._service = service

    def _lsp(self) -> LspService:
        if self._service is not None:
            return self._service
        return get_lsp_service()

    async def _record(
        self,
        *,
        result: LspResult,
        subject: str,
        workspace_id: str | None,
        investigation_id: str | None,
        branch_id: str | None,
        turn_number: int | None,
        content: str,
    ) -> None:
        if not workspace_id:
            return
        # Sanitise the fields the platform contract bounds. A caller
        # that passed an out-of-range subject / workspace still writes
        # an observation -- the record just carries a clipped value
        # instead of raising.
        module = self._module[:_OBSERVATION_MODULE_MAX] or "platform"
        workspace = workspace_id[:_OBSERVATION_WORKSPACE_MAX]
        subj = (subject or self._op)[:_OBSERVATION_SUBJECT_MAX] or self._op
        polarity = self._resolve_polarity(result)
        observation = PlatformObservation(
            module=module,
            workspace_id=workspace,
            subject=subj,
            kind=self._kind,
            polarity=polarity,
            content=content,
            investigation_id=investigation_id[:64] if investigation_id else None,
            branch_id=branch_id[:64] if branch_id else None,
            turn_number=turn_number,
            extra={
                "op": result.op,
                "status": result.status,
                "language": result.language,
                "elapsed_ms": result.elapsed_ms,
                "reason": result.reason,
            },
        )
        await record_observation(observation)

    def _resolve_polarity(self, result: LspResult) -> ObservationPolarity:
        # An ``empty`` result is first-class NEGATIVE material (per #137
        # ObservationKind docstring: "we looked for X in this workspace
        # and it isn't there") EXCEPT for hover, where empty is more
        # commonly "server has no docs for this symbol" than a real
        # dead end. ``unavailable`` (flag off, binary absent) is neutral
        # -- absence of tool output is not a factual claim.
        if result.status == "ok":
            return self._default_polarity
        if result.status == "empty":
            if self._op == "hover":
                return ObservationPolarity.NEUTRAL
            return ObservationPolarity.NEGATIVE
        return ObservationPolarity.NEUTRAL


def _dedent_kwargs(kwargs: dict[str, Any]) -> tuple[str | None, str | None, str | None, int | None]:
    """Extract the observation-context kwargs a caller may pass through."""
    workspace_id = kwargs.pop("workspace_id", None)
    investigation_id = kwargs.pop("investigation_id", None)
    branch_id = kwargs.pop("branch_id", None)
    turn_number = kwargs.pop("turn_number", None)
    if workspace_id is not None:
        workspace_id = str(workspace_id).strip() or None
    if investigation_id is not None:
        investigation_id = str(investigation_id).strip() or None
    if branch_id is not None:
        branch_id = str(branch_id).strip() or None
    if turn_number is not None:
        try:
            turn_number = int(turn_number)
        except (TypeError, ValueError):
            turn_number = None
    return workspace_id, investigation_id, branch_id, turn_number


_POSITION_INPUTS: dict[str, dict[str, Any]] = {
    "root": {
        "type": "string",
        "description": "Absolute path to the indexed workspace root the language server binds to.",
    },
    "file": {
        "type": "string",
        "description": "Path to the source file. Relative paths resolve against `root`.",
    },
    "line": {
        "type": "integer",
        "description": "Zero-based line index of the symbol position (LSP convention).",
    },
    "character": {
        "type": "integer",
        "description": "Zero-based UTF-16 code-unit index within `line` (LSP convention).",
    },
    "workspace_id": {
        "type": "string",
        "description": "Optional workspace id -- when set, the result is recorded as an `lsp.*` observation.",
        "nullable": True,
    },
    "investigation_id": {
        "type": "string",
        "description": "Optional investigation id stamped on the observation.",
        "nullable": True,
    },
    "branch_id": {
        "type": "string",
        "description": "Optional branch id stamped on the observation.",
        "nullable": True,
    },
    "turn_number": {
        "type": "integer",
        "description": "Optional turn number stamped on the observation.",
        "nullable": True,
    },
}


class LspDefinitionTool(_LspToolBase):
    """Resolve the definition site of the symbol at (file, line, character)."""

    name = "lsp_definition"
    description = (
        "LSP `textDocument/definition` for the symbol at a source position. "
        "Fail-open: returns status='unavailable' with empty locations when "
        "the LSP flag is off, the binary is absent, or the server is dead."
    )
    inputs: dict[str, dict[str, Any]] = dict(_POSITION_INPUTS)
    output_type = "object"

    _op = "definition"
    _kind = "lsp.definition"
    _default_polarity = ObservationPolarity.POSITIVE

    async def forward(
        self, root: str, file: str, line: int, character: int, **kwargs: Any,
    ) -> dict[str, Any]:
        workspace_id, investigation_id, branch_id, turn_number = _dedent_kwargs(kwargs)
        result = await self._lsp().definition(
            root=root, file=file, line=int(line), character=int(character),
        )
        subject = f"{file}:{line}:{character}"
        content = _format_locations_content(subject, result)
        await self._record(
            result=result, subject=subject,
            workspace_id=workspace_id,
            investigation_id=investigation_id,
            branch_id=branch_id, turn_number=turn_number,
            content=content,
        )
        return result.to_dict()


class LspReferencesTool(_LspToolBase):
    """Find references to the symbol at (file, line, character)."""

    name = "lsp_references"
    description = (
        "LSP `textDocument/references` for the symbol at a source position. "
        "Fail-open: returns status='unavailable' with empty locations when "
        "the LSP flag is off, the binary is absent, or the server is dead."
    )
    inputs: dict[str, dict[str, Any]] = {
        **_POSITION_INPUTS,
        "include_declaration": {
            "type": "boolean",
            "description": "Include the declaration site in the response (default: true).",
            "nullable": True,
        },
    }
    output_type = "object"

    _op = "references"
    _kind = "lsp.references"
    _default_polarity = ObservationPolarity.POSITIVE

    async def forward(
        self, root: str, file: str, line: int, character: int,
        include_declaration: bool | None = None, **kwargs: Any,
    ) -> dict[str, Any]:
        workspace_id, investigation_id, branch_id, turn_number = _dedent_kwargs(kwargs)
        result = await self._lsp().references(
            root=root, file=file, line=int(line), character=int(character),
            include_declaration=(True if include_declaration is None else bool(include_declaration)),
        )
        subject = f"{file}:{line}:{character}"
        content = _format_locations_content(subject, result)
        await self._record(
            result=result, subject=subject,
            workspace_id=workspace_id,
            investigation_id=investigation_id,
            branch_id=branch_id, turn_number=turn_number,
            content=content,
        )
        return result.to_dict()


class LspHoverTool(_LspToolBase):
    """Return the hover blob (signature + docs) for a source position."""

    name = "lsp_hover"
    description = (
        "LSP `textDocument/hover` for the symbol at a source position. "
        "Fail-open: returns status='unavailable' with empty contents when "
        "the LSP flag is off, the binary is absent, or the server is dead."
    )
    inputs: dict[str, dict[str, Any]] = dict(_POSITION_INPUTS)
    output_type = "object"

    _op = "hover"
    _kind = "lsp.hover"
    _default_polarity = ObservationPolarity.NEUTRAL

    async def forward(
        self, root: str, file: str, line: int, character: int, **kwargs: Any,
    ) -> dict[str, Any]:
        workspace_id, investigation_id, branch_id, turn_number = _dedent_kwargs(kwargs)
        result = await self._lsp().hover(
            root=root, file=file, line=int(line), character=int(character),
        )
        subject = f"{file}:{line}:{character}"
        contents = result.payload.get("contents") if result.payload else ""
        content = (
            f"lsp.hover {subject} [{result.status}] -- {contents}"
            if contents
            else f"lsp.hover {subject} [{result.status}] -- (no hover)"
        )
        await self._record(
            result=result, subject=subject,
            workspace_id=workspace_id,
            investigation_id=investigation_id,
            branch_id=branch_id, turn_number=turn_number,
            content=content,
        )
        return result.to_dict()


class LspDiagnosticsTool(_LspToolBase):
    """Return the latest push-diagnostics for a source file."""

    name = "lsp_diagnostics"
    description = (
        "Latest LSP `textDocument/publishDiagnostics` for a source file. "
        "Fail-open: returns status='unavailable' with empty diagnostics when "
        "the LSP flag is off, the binary is absent, or the server is dead."
    )
    inputs: dict[str, dict[str, Any]] = {
        "root": _POSITION_INPUTS["root"],
        "file": _POSITION_INPUTS["file"],
        "wait_s": {
            "type": "number",
            "description": "Seconds to wait for the first publishDiagnostics push (default: platform config).",
            "nullable": True,
        },
        "workspace_id": _POSITION_INPUTS["workspace_id"],
        "investigation_id": _POSITION_INPUTS["investigation_id"],
        "branch_id": _POSITION_INPUTS["branch_id"],
        "turn_number": _POSITION_INPUTS["turn_number"],
    }
    output_type = "object"

    _op = "diagnostics"
    _kind = "lsp.diagnostics"
    _default_polarity = ObservationPolarity.NEUTRAL

    async def forward(
        self, root: str, file: str, wait_s: float | None = None, **kwargs: Any,
    ) -> dict[str, Any]:
        workspace_id, investigation_id, branch_id, turn_number = _dedent_kwargs(kwargs)
        wait_arg: float | None
        if wait_s is None:
            wait_arg = None
        else:
            try:
                wait_arg = float(wait_s)
            except (TypeError, ValueError):
                wait_arg = None
        result = await self._lsp().diagnostics(root=root, file=file, wait_s=wait_arg)
        diagnostics = result.payload.get("diagnostics") if result.payload else []
        subject = str(file)
        # An ``ok`` diagnostics result carries findings the server sees as
        # problems. Flip the polarity to NEGATIVE so retrieval treats it
        # as a first-class "the tool flagged issue X in this file"
        # signal instead of a neutral note.
        polarity = (
            ObservationPolarity.NEGATIVE
            if result.status == "ok" and diagnostics
            else self._resolve_polarity(result)
        )
        content = _format_diagnostics_content(subject, result, diagnostics)
        if workspace_id:
            observation = PlatformObservation(
                module=self._module[:_OBSERVATION_MODULE_MAX] or "platform",
                workspace_id=workspace_id[:_OBSERVATION_WORKSPACE_MAX],
                subject=subject[:_OBSERVATION_SUBJECT_MAX] or self._op,
                kind=self._kind,
                polarity=polarity,
                content=content,
                investigation_id=investigation_id[:64] if investigation_id else None,
                branch_id=branch_id[:64] if branch_id else None,
                turn_number=turn_number,
                extra={
                    "op": result.op,
                    "status": result.status,
                    "language": result.language,
                    "elapsed_ms": result.elapsed_ms,
                    "reason": result.reason,
                    "diagnostic_count": len(diagnostics) if isinstance(diagnostics, list) else 0,
                },
            )
            await record_observation(observation)
        return result.to_dict()


def _format_locations_content(subject: str, result: LspResult) -> str:
    locations = result.payload.get("locations") if result.payload else []
    if not locations:
        return f"lsp.{result.op} {subject} [{result.status}] -- no locations"
    lines: list[str] = [
        f"lsp.{result.op} {subject} [{result.status}] -- {len(locations)} location(s):",
    ]
    for loc in locations[:20]:
        range_obj = loc.get("range") or {}
        start = range_obj.get("start") or {}
        lines.append(
            f"  {loc.get('path', loc.get('uri', '?'))}:"
            f"{start.get('line', '?')}:{start.get('character', '?')}",
        )
    if len(locations) > 20:
        lines.append(f"  ... {len(locations) - 20} more")
    return "\n".join(lines)


def _format_diagnostics_content(
    subject: str, result: LspResult, diagnostics: Any,
) -> str:
    if not isinstance(diagnostics, list) or not diagnostics:
        if result.status == "unavailable":
            return f"lsp.diagnostics {subject} [unavailable] -- {result.reason or 'no reason'}"
        return f"lsp.diagnostics {subject} [{result.status}] -- no diagnostics"
    lines: list[str] = [
        f"lsp.diagnostics {subject} [{result.status}] -- {len(diagnostics)} diagnostic(s):",
    ]
    for diag in diagnostics[:20]:
        if not isinstance(diag, dict):
            continue
        range_obj = diag.get("range") or {}
        start = range_obj.get("start") or {}
        message = diag.get("message", "")
        source = diag.get("source", "")
        severity = diag.get("severity", "")
        lines.append(
            f"  {start.get('line', '?')}:{start.get('character', '?')} "
            f"[{source}/{severity}] {message}",
        )
    if len(diagnostics) > 20:
        lines.append(f"  ... {len(diagnostics) - 20} more")
    return "\n".join(lines)
