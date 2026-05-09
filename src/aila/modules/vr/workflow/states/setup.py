"""Setup state — upload binaries to the IDA headless MCP and prime budgets.

Responsibilities:
1. Resolve target_path / patched_path from input + the project DB row.
2. Upload the vulnerable binary to MCP and poll until analysis is ready.
3. Upload the patched binary (if provided) and poll it as well.
4. Run checksec on the vulnerable binary to extract mitigations.
5. Initialize a BudgetState from VR module config and stash it as JSON.
6. Persist binary_id / patched_binary_id / mitigations onto the project row.

Failure modes surface as raised exceptions; the engine handles retry per
the StateSpec retriable_on tuple. Project status is set to "analyzing"
once setup begins.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from sqlmodel import select as _select

from aila.modules.vr.contracts.project import VRProjectStatus
from aila.modules.vr.db_models import VRProjectRecord
from aila.platform.contracts.budget import BudgetConfig, BudgetState
from aila.platform.uow import UnitOfWork
from aila.platform.workflows.types import StateResult

__all__ = ["state_setup"]

_log = logging.getLogger(__name__)

_POLL_INTERVAL_S = 2.0
_POLL_BUDGET_S = 60.0


async def _load_project(project_id: str) -> VRProjectRecord | None:
    if not project_id:
        return None
    async with UnitOfWork() as uow:
        row = (
            await uow.session.exec(
                _select(VRProjectRecord).where(VRProjectRecord.id == project_id)
            )
        ).first()
        return row


async def _persist_setup(
    project_id: str,
    binary_id: str,
    patched_binary_id: str | None,
    mitigations: dict[str, Any],
    budget_json: str,
) -> None:
    async with UnitOfWork() as uow:
        row = (
            await uow.session.exec(
                _select(VRProjectRecord).where(VRProjectRecord.id == project_id)
            )
        ).first()
        if row is None:
            return
        row.binary_id = binary_id
        if patched_binary_id:
            row.patched_binary_id = patched_binary_id
        row.mitigations_json = json.dumps(mitigations)
        row.budget_json = budget_json
        row.status = VRProjectStatus.ANALYZING.value
        uow.session.add(row)
        await uow.commit()


async def _upload_and_wait(ida_bridge: Any, file_path: str) -> dict[str, Any]:
    """Upload a binary and poll until analysis is ready.

    Returns the final ``poll_analysis`` payload (always includes a
    ``binary_id`` once upload succeeds). Re-uses an existing analysis if
    the MCP server already has the binary cached (state=READY immediately).
    """
    upload = await asyncio.to_thread(
        ida_bridge.forward, action="upload", file_path=file_path,
    )
    if upload.get("status") == "error":
        raise RuntimeError(f"upload failed for {file_path}: {upload.get('error')}")
    binary_id = upload.get("binary_id") or upload.get("id")
    if not binary_id:
        raise RuntimeError(f"upload returned no binary_id: {upload}")

    waited = 0.0
    last: dict[str, Any] = upload
    while waited < _POLL_BUDGET_S:
        if upload.get("analysis_ready") or upload.get("state") in ("READY", "INDEXED"):
            return last
        last = await asyncio.to_thread(
            ida_bridge.forward, action="poll_analysis", binary_id=binary_id,
        )
        if last.get("status") == "error":
            raise RuntimeError(f"poll_analysis error: {last.get('error')}")
        if last.get("analysis_ready") or last.get("state") in ("READY", "INDEXED"):
            return last
        await asyncio.sleep(_POLL_INTERVAL_S)
        waited += _POLL_INTERVAL_S
    # Treat budget exhaustion as a soft pass; the agent state will surface
    # a clearer failure if downstream calls keep returning "pending".
    _log.warning(
        "setup: analysis still not ready after %.0fs for binary_id=%s — proceeding",
        _POLL_BUDGET_S, binary_id,
    )
    return last


async def state_setup(input: dict[str, Any], services: Any) -> StateResult:
    """Upload binaries, run checksec, initialize the budget."""
    project_id = str(input.get("project_id") or "")
    target_path = str(input.get("target_path") or "")
    patched_path = input.get("patched_path") or None

    project = await _load_project(project_id)
    if project is not None:
        target_path = target_path or (project.target_path or "")
        patched_path = patched_path or project.patched_path

    if not target_path:
        raise ValueError("state_setup: target_path is required (input or project row)")

    _log.info(
        "state_setup START project_id=%s target=%s patched=%s",
        project_id, target_path, patched_path,
    )

    vuln_meta = await _upload_and_wait(services.ida_bridge, target_path)
    binary_id = str(vuln_meta.get("binary_id") or "")
    if not binary_id:
        raise RuntimeError("state_setup: vulnerable binary upload yielded no binary_id")

    patched_binary_id: str | None = None
    if patched_path:
        patched_meta = await _upload_and_wait(services.ida_bridge, str(patched_path))
        patched_binary_id = str(patched_meta.get("binary_id") or "") or None

    checksec_result = await asyncio.to_thread(
        services.ida_bridge.forward, action="checksec", binary_id=binary_id,
    )
    mitigations: dict[str, Any] = {}
    if checksec_result.get("status") == "ready":
        mitigations = {
            k: v for k, v in checksec_result.items()
            if k not in ("status", "binary_id")
        }

    budget = BudgetState(
        config=BudgetConfig(
            max_turns=services.config.nday_max_turns,
            max_tool_time_seconds=services.config.nday_tool_time_seconds,
        ),
    )
    budget_json = json.dumps(budget.to_json())

    await _persist_setup(
        project_id, binary_id, patched_binary_id, mitigations, budget_json,
    )

    return StateResult(
        next_state="research",
        output={
            "project_id": project_id,
            "target_path": target_path,
            "patched_path": patched_path,
            "binary_id": binary_id,
            "patched_binary_id": patched_binary_id,
            "mitigations": mitigations,
            "budget_json": budget.to_json(),
            "context_notes": str(input.get("context_notes") or (project.context_notes if project else "")),
            "cve_id": input.get("cve_id") or (project.cve_id if project else None),
            "integration": input.get("integration") or {},
        },
    )
