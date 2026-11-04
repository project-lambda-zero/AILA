"""Stage a VR project's target binaries on the analysis workstation.

The investigation setup hook calls :func:`stage_investigation_binaries` before
the hub workflow runs. For a project-linked investigation it places the
vulnerable target and, when declared, the patched target onto the workstation,
then records ``workstation_path`` on each target descriptor. The tool layer
reads it back through ``resolve_investigation_binary_path`` and
``resolve_investigation_patched_binary_path``.
"""
from __future__ import annotations

import json
import logging
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlmodel import select

from aila.config import get_settings
from aila.modules.vr.db_models import VRInvestigationRecord, VRProjectRecord, VRTargetRecord
from aila.modules.vr.services.analysis_system import resolve_investigation_integration
from aila.modules.vr.services.target_ingestion import TargetIngestionService
from aila.platform.config import build_platform_settings
from aila.platform.contracts import utc_now
from aila.platform.services import SSHService
from aila.platform.uow import UnitOfWork

__all__ = ["VR_UPLOAD_STAGING", "stage_investigation_binaries"]

_log = logging.getLogger(__name__)

# Server-side staging for multipart uploads. The upload endpoint writes the
# file to ``VR_UPLOAD_STAGING / <target_id> / <filename>`` and records that
# exact path in the target's ``mcp_handles_json["target_path"]``.
VR_UPLOAD_STAGING: Path = Path(tempfile.gettempdir()) / "aila_vr_uploads"


@dataclass(frozen=True)
class _TargetSnapshot:
    """Plain copy of the target columns staging reads (safe after the UoW closes)."""

    target_id: str
    descriptor: dict[str, Any]
    upload_path: Path | None


@dataclass(frozen=True)
class _IngestSpec:
    """Resolved ingest inputs for one target role (vulnerable or patched)."""

    label: str
    input_source: str
    upload_filename: str | None
    upload_path: Path | None
    repo_url: str | None
    ref: str | None
    build_command: str | None
    build_artifact: str | None
    download_url: str | None


async def _load_snapshot(target_id: str) -> _TargetSnapshot | None:
    async with UnitOfWork() as uow:
        row = (await uow.session.exec(
            select(VRTargetRecord).where(VRTargetRecord.id == target_id),
        )).first()
        if row is None:
            return None
        handles = json.loads(row.mcp_handles_json or "{}")
        handled_path = handles.get("target_path")
        return _TargetSnapshot(
            target_id=row.id,
            descriptor=json.loads(row.descriptor_json or "{}"),
            upload_path=Path(str(handled_path)) if handled_path else None,
        )


async def _project_target_ids(investigation_id: str) -> tuple[str, str | None] | None:
    """Return ``(target_id, patched_target_id)`` for a project-linked investigation.

    ``None`` means the investigation has no project, so there is nothing to stage.
    """
    async with UnitOfWork() as uow:
        inv = (await uow.session.exec(
            select(VRInvestigationRecord).where(
                VRInvestigationRecord.id == investigation_id,
            ),
        )).first()
        if inv is None or not inv.project_id:
            return None
        project = (await uow.session.exec(
            select(VRProjectRecord).where(VRProjectRecord.id == inv.project_id),
        )).first()
        if project is None:
            return None
        return project.target_id, project.patched_target_id


def _primary_spec(snapshot: _TargetSnapshot) -> _IngestSpec:
    d = snapshot.descriptor
    return _IngestSpec(
        label="vulnerable target",
        input_source=str(d.get("input_source") or "upload"),
        upload_filename=d.get("upload_filename") or None,
        upload_path=snapshot.upload_path,
        repo_url=d.get("repo_url") or None,
        ref=d.get("vulnerable_ref") or None,
        build_command=d.get("build_command") or None,
        build_artifact=d.get("build_artifact") or None,
        download_url=d.get("download_url") or None,
    )


def _patched_spec(snapshot: _TargetSnapshot, primary: _IngestSpec) -> _IngestSpec | None:
    """Return the patched ingest spec, or ``None`` when no patched source is declared.

    Matches the rule the target setup applied: the patched target is staged only
    when it has an upload, a download URL, or a repo with a ref. Unset repo and
    build fields fall back to the vulnerable target's values.
    """
    d = snapshot.descriptor
    spec = _IngestSpec(
        label="patched target",
        input_source=str(d.get("input_source") or primary.input_source),
        upload_filename=d.get("upload_filename") or None,
        upload_path=snapshot.upload_path,
        repo_url=d.get("repo_url") or primary.repo_url,
        ref=d.get("patched_ref") or None,
        build_command=d.get("build_command") or primary.build_command,
        build_artifact=d.get("build_artifact") or primary.build_artifact,
        download_url=d.get("download_url") or None,
    )
    if spec.upload_filename or spec.download_url or (spec.repo_url and spec.ref):
        return spec
    return None


async def _ingest(
    ingestion: TargetIngestionService,
    integration: dict[str, Any],
    spec: _IngestSpec,
) -> str:
    """Place one target on the workstation and return its remote path.

    Each branch raises ``ValueError`` (or ``FileNotFoundError`` for a missing
    upload) when the inputs for that source are absent, so misuse fails loudly.
    """
    if spec.input_source == "upload":
        if not spec.upload_filename:
            raise ValueError(f"{spec.label}: input_source='upload' requires 'upload_filename'")
        if spec.upload_path is None or not spec.upload_path.is_file():
            raise FileNotFoundError(
                f"{spec.label}: staged upload not found at {spec.upload_path} -- the "
                "upload endpoint has not received the file, or it was cleaned up",
            )
        return await ingestion.ingest_upload(
            integration=integration,
            local_path=spec.upload_path,
            filename=spec.upload_filename,
        )

    if spec.input_source == "git_repo":
        if not spec.repo_url:
            raise ValueError(f"{spec.label}: input_source='git_repo' requires 'repo_url'")
        if not spec.build_artifact:
            raise ValueError(
                f"{spec.label}: input_source='git_repo' requires 'build_artifact' "
                "(the built binary path inside the clone)",
            )
        clone_dir = await ingestion.ingest_git_repo(
            integration=integration,
            repo_url=spec.repo_url,
            vulnerable_ref=spec.ref,
        )
        if spec.build_command:
            await ingestion.build_from_source(
                integration=integration,
                source_dir=clone_dir,
                build_command=spec.build_command,
            )
        return f"{clone_dir}/{spec.build_artifact.lstrip('/')}"

    if spec.input_source == "http_url":
        if not spec.download_url:
            raise ValueError(f"{spec.label}: input_source='http_url' requires 'download_url'")
        return await ingestion.ingest_http_url(
            integration=integration,
            download_url=spec.download_url,
        )

    raise ValueError(
        f"{spec.label}: unsupported input_source '{spec.input_source}' -- "
        "expected 'upload' | 'git_repo' | 'http_url'",
    )


async def _record_workstation_path(target_id: str, workstation_path: str) -> None:
    async with UnitOfWork() as uow:
        row = (await uow.session.exec(
            select(VRTargetRecord).where(VRTargetRecord.id == target_id),
        )).first()
        if row is None:
            raise RuntimeError(f"VR target {target_id} vanished during binary staging")
        descriptor = json.loads(row.descriptor_json or "{}")
        descriptor["workstation_path"] = workstation_path
        row.descriptor_json = json.dumps(descriptor)
        row.updated_at = utc_now()
        uow.session.add(row)
        await uow.commit()


async def _stage_one(
    ingestion: TargetIngestionService,
    integration: dict[str, Any],
    snapshot: _TargetSnapshot,
    spec: _IngestSpec,
) -> None:
    """Ingest one target unless it already carries a ``workstation_path``.

    A recorded path means an earlier run already placed the binary, so a
    re-enqueued investigation does not repeat the transfer, clone, or build.
    """
    if snapshot.descriptor.get("workstation_path"):
        return
    workstation_path = await _ingest(ingestion, integration, spec)
    await _record_workstation_path(snapshot.target_id, workstation_path)


async def stage_investigation_binaries(investigation_id: str) -> None:
    """Place the investigation project's target binaries on the workstation.

    No-op for an investigation with no project. Raises when the project has no
    resolvable analysis workstation, rather than silently skipping staging.
    """
    ids = await _project_target_ids(investigation_id)
    if ids is None:
        return
    target_id, patched_target_id = ids

    primary = await _load_snapshot(target_id)
    if primary is None:
        raise RuntimeError(f"VR investigation {investigation_id}: target {target_id} not found")
    primary_spec = _primary_spec(primary)
    patched: _TargetSnapshot | None = None
    patched_spec: _IngestSpec | None = None
    if patched_target_id:
        patched = await _load_snapshot(patched_target_id)
        if patched is not None:
            patched_spec = _patched_spec(patched, primary_spec)

    integration = await resolve_investigation_integration(investigation_id)
    if integration is None:
        raise RuntimeError(
            f"VR investigation {investigation_id}: no analysis workstation is "
            "resolvable for the project, so its target binaries cannot be staged",
        )
    ingestion = TargetIngestionService(
        ssh=SSHService(build_platform_settings(get_settings())),
    )

    await _stage_one(ingestion, integration, primary, primary_spec)
    if patched is not None and patched_spec is not None:
        await _stage_one(ingestion, integration, patched, patched_spec)

    _log.info(
        "stage_investigation_binaries investigation=%s target=%s patched=%s",
        investigation_id,
        target_id,
        patched_spec is not None,
    )
