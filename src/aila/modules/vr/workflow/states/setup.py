"""Setup state — ingest the target, upload to IDA MCP, prime budgets.

Responsibilities:
1. Resolve the target onto the analyzer workstation based on input_source:
   - ``upload``     : SCP a previously-staged AILA upload to the workstation
   - ``git_repo``   : ``git clone`` (and optional build) on the workstation
   - ``http_url``   : ``curl``-download onto the workstation
   - pre-existing ``binary_id`` : skip ingestion, just poll MCP
2. Upload the resolved workstation-side file to the IDA headless MCP and
   poll until analysis is ready.
3. Repeat (1)+(2) for the optional patched target. Patched target may use
   a different ``input_source`` than the vulnerable target.
4. Run checksec on the vulnerable binary to extract mitigations.
5. Initialize a BudgetState from VR module config and stash it as JSON.
6. Persist binary_id / patched_binary_id / mitigations / target_path onto
   the project row.

Failure modes surface as raised exceptions; the engine handles retry per
the StateSpec retriable_on tuple. Project status is set to "analyzing"
once setup begins.

The output dict propagates ``analysis_integration`` and ``poc_integration``
so downstream states (research, poc_development) can target the correct
machine — the PoC machine may be a different host (e.g. the vulnerable
software is installed only there).
"""
from __future__ import annotations

import asyncio
import json
import logging
import tempfile
from pathlib import Path
from typing import Any

from sqlmodel import select as _select

from aila.modules.vr.contracts.project import VRProjectStatus
from aila.modules.vr.db_models import VRProjectRecord
from aila.platform.contracts._common import utc_now
from aila.platform.contracts.budget import BudgetConfig, BudgetState
from aila.platform.uow import UnitOfWork
from aila.platform.workflows.types import StateResult

__all__ = ["VR_UPLOAD_STAGING", "state_setup"]

_log = logging.getLogger(__name__)

_POLL_INTERVAL_S = 2.0
_POLL_BUDGET_S = 60.0

# AILA-local staging directory for multipart uploads. The API multipart
# handler writes ``<filename>`` here; this state handler reads it, SCPs it
# to the analyzer workstation, and may clean it up afterward.
VR_UPLOAD_STAGING: Path = Path(tempfile.gettempdir()) / "aila_vr_uploads"


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
    target_path: str,
    patched_path: str | None,
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
        if target_path:
            row.target_path = target_path
        if patched_path:
            row.patched_path = patched_path
        row.mitigations_json = json.dumps(mitigations)
        row.budget_json = budget_json
        row.status = VRProjectStatus.ANALYZING.value
        row.updated_at = utc_now()
        uow.session.add(row)
        await uow.commit()


async def _upload_and_wait(ida_bridge: Any, file_path: str) -> dict[str, Any]:
    """Upload a binary and poll until analysis is ready.

    Returns the final ``poll_analysis`` payload (always includes a
    ``binary_id`` once upload succeeds). Re-uses an existing analysis if
    the MCP server already has the binary cached (state=READY immediately).
    """
    upload = await ida_bridge.forward(action="upload", file_path=file_path)
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
        last = await ida_bridge.forward(
            action="poll_analysis", binary_id=binary_id,
        )
        if last.get("status") == "error":
            raise RuntimeError(f"poll_analysis error: {last.get('error')}")
        if last.get("analysis_ready") or last.get("state") in ("READY", "INDEXED"):
            return last
        await asyncio.sleep(_POLL_INTERVAL_S)
        waited += _POLL_INTERVAL_S
    _log.warning(
        "setup: analysis still not ready after %.0fs for binary_id=%s — proceeding",
        _POLL_BUDGET_S, binary_id,
    )
    return last


async def _wait_until_ready(ida_bridge: Any, binary_id: str) -> dict[str, Any]:
    """Poll an existing binary_id until analysis is ready or budget exhausts."""
    waited = 0.0
    last: dict[str, Any] = {}
    while waited < _POLL_BUDGET_S:
        last = await ida_bridge.forward(
            action="poll_analysis", binary_id=binary_id,
        )
        if last.get("status") == "error":
            raise RuntimeError(f"poll_analysis error: {last.get('error')}")
        if last.get("analysis_ready") or last.get("state") in ("READY", "INDEXED"):
            return last
        await asyncio.sleep(_POLL_INTERVAL_S)
        waited += _POLL_INTERVAL_S
    _log.warning(
        "setup: analysis still not ready after %.0fs for binary_id=%s — proceeding",
        _POLL_BUDGET_S, binary_id,
    )
    return last


async def _ingest_target(
    ingestion: Any,
    integration: dict[str, Any],
    *,
    label: str,
    input_source: str,
    upload_filename: str | None,
    repo_url: str | None,
    ref: str | None,
    build_command: str | None,
    build_artifact: str | None,
    download_url: str | None,
) -> str:
    """Resolve a target onto the analyzer workstation, return remote path.

    Dispatches on ``input_source``. Each branch raises ``ValueError`` if
    the inputs required for that source are missing, so misuse fails
    loudly rather than silently producing an empty path.
    """
    if input_source == "upload":
        if not upload_filename:
            raise ValueError(
                f"{label}: input_source='upload' requires 'upload_filename'",
            )
        local_path = VR_UPLOAD_STAGING / upload_filename
        if not local_path.is_file():
            raise FileNotFoundError(
                f"{label}: staged upload not found at {local_path} — the "
                "API may have cleaned it before setup ran, or the multipart "
                "handler never wrote it",
            )
        return await ingestion.ingest_upload(
            integration=integration,
            local_path=local_path,
        )

    if input_source == "git_repo":
        if not repo_url:
            raise ValueError(
                f"{label}: input_source='git_repo' requires 'repo_url'",
            )
        return await ingestion.ingest_git_repo(
            integration=integration,
            repo_url=repo_url,
            ref=ref,
            build_command=build_command,
            build_artifact=build_artifact,
        )

    if input_source == "http_url":
        if not download_url:
            raise ValueError(
                f"{label}: input_source='http_url' requires 'download_url'",
            )
        return await ingestion.ingest_http_url(
            integration=integration,
            download_url=download_url,
        )

    raise ValueError(
        f"{label}: unsupported input_source '{input_source}' — "
        "expected 'upload' | 'git_repo' | 'http_url'",
    )


async def state_setup(input: dict[str, Any], services: Any) -> StateResult:
    """Ingest target(s), upload to IDA MCP, run checksec, initialize budget."""
    project_id = str(input.get("project_id") or "")

    analysis_integration = input.get("analysis_integration") or input.get("integration") or {}
    poc_integration = input.get("poc_integration") or analysis_integration

    input_binary_id = str(input.get("binary_id") or "")
    input_patched_binary_id = str(input.get("patched_binary_id") or "") or None

    input_source = str(input.get("input_source") or "upload")
    upload_filename = input.get("upload_filename") or None
    repo_url = input.get("repo_url") or None
    vulnerable_ref = input.get("vulnerable_ref") or None
    build_command = input.get("build_command") or None
    build_artifact = input.get("build_artifact") or None
    download_url = input.get("download_url") or None

    # Patched-target ingestion may use a different input_source. Fall back
    # to the vulnerable target's source when the caller didn't specify.
    patched_input_source = str(input.get("patched_input_source") or input_source)
    patched_upload_filename = input.get("patched_upload_filename") or None
    patched_repo_url = input.get("patched_repo_url") or repo_url
    patched_ref = input.get("patched_ref") or None
    patched_build_command = input.get("patched_build_command") or build_command
    patched_build_artifact = input.get("patched_build_artifact") or build_artifact
    patched_download_url = input.get("patched_download_url") or None

    project = await _load_project(project_id)

    # ── Resolve vulnerable target onto the analyzer workstation ─────────
    if input_binary_id:
        target_path = ""
    else:
        target_path = await _ingest_target(
            services.ingestion,
            analysis_integration,
            label="vulnerable target",
            input_source=input_source,
            upload_filename=upload_filename,
            repo_url=repo_url,
            ref=vulnerable_ref,
            build_command=build_command,
            build_artifact=build_artifact,
            download_url=download_url,
        )

    # ── Resolve patched target (optional) ───────────────────────────────
    patched_path: str | None
    if input_patched_binary_id:
        patched_path = None
    elif (
        patched_upload_filename
        or patched_download_url
        or (patched_repo_url and patched_ref)
    ):
        patched_path = await _ingest_target(
            services.ingestion,
            analysis_integration,
            label="patched target",
            input_source=patched_input_source,
            upload_filename=patched_upload_filename,
            repo_url=patched_repo_url,
            ref=patched_ref,
            build_command=patched_build_command,
            build_artifact=patched_build_artifact,
            download_url=patched_download_url,
        )
    else:
        patched_path = project.patched_path if project else None

    _log.info(
        "state_setup START project_id=%s input_source=%s target=%s patched=%s "
        "pre_binary=%s pre_patched=%s",
        project_id,
        input_source,
        target_path,
        patched_path,
        input_binary_id or None,
        input_patched_binary_id,
    )

    # ── Upload to IDA MCP ───────────────────────────────────────────────
    if input_binary_id:
        binary_id = input_binary_id
        await _wait_until_ready(services.ida_bridge, binary_id)
    else:
        if not target_path:
            raise RuntimeError(
                "state_setup: ingestion produced no workstation path for the "
                "vulnerable target",
            )
        vuln_meta = await _upload_and_wait(services.ida_bridge, target_path)
        binary_id = str(vuln_meta.get("binary_id") or "")
        if not binary_id:
            raise RuntimeError(
                "state_setup: vulnerable binary upload yielded no binary_id",
            )

    patched_binary_id: str | None = None
    if input_patched_binary_id:
        patched_binary_id = input_patched_binary_id
        await _wait_until_ready(services.ida_bridge, patched_binary_id)
    elif patched_path:
        patched_meta = await _upload_and_wait(services.ida_bridge, str(patched_path))
        patched_binary_id = str(patched_meta.get("binary_id") or "") or None

    # ── Mitigations + budget ────────────────────────────────────────────
    checksec_result = await services.ida_bridge.forward(
        action="checksec", binary_id=binary_id,
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
        project_id,
        binary_id,
        patched_binary_id,
        target_path,
        patched_path,
        mitigations,
        budget_json,
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
            "context_notes": str(
                input.get("context_notes")
                or (project.context_notes if project else "")
            ),
            "cve_id": input.get("cve_id") or (project.cve_id if project else None),
            "analysis_integration": analysis_integration,
            "poc_integration": poc_integration,
            # Legacy alias preserved so research/poc_development states that
            # haven't migrated yet still find an integration dict.
            "integration": analysis_integration,
            "team_id": project.team_id if project else None,
        },
    )
