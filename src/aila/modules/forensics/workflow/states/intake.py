"""Evidence intake state handler.

Scans the evidence directory on the analyzer machine, classifies files
by type (disk_image, memory_dump, pcap, etc.), and persists
``ProjectEvidenceRecord`` rows.

Intake is the single evidence hashing path. Each file whose size is at or
below ``ForensicsConfigSchema.intake_hash_max_bytes`` is hashed on the
analyzer via ``_compute_file_hash`` and the digest is stored in
``file_hash_sha256``. Files above the cap and files whose hash command fails
keep a null digest; ``metadata_json`` records the ``hash_status``
(``computed``, ``deferred_over_cap`` or ``failed``) so an unhashed file is
distinguishable from a missing value. A row that already holds a digest for
an unchanged size is not re-hashed.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from pydantic import ValidationError
from sqlmodel import select as _select

from aila.modules.forensics.config_schema import ForensicsConfigSchema
from aila.modules.forensics.contracts.status import ProjectStatus
from aila.modules.forensics.db_models import ForensicsProjectRecord, ProjectEvidenceRecord
from aila.modules.forensics.workflow.inputs import IntakeInput
from aila.platform.events import (
    ModuleWorkflowStarted,
    ModuleWorkflowStartedPayload,
    publish,
)
from aila.platform.exceptions import AILAError
from aila.platform.uow import UnitOfWork
from aila.storage.registry import ConfigRegistry

__all__ = ["state_intake"]

_log = logging.getLogger(__name__)

state_intake_parallel_safe = False
state_intake_writes_fields = ["evidence_files", "active_lanes"]


async def _intake_hash_cap_bytes() -> int:
    """Resolve ``forensics.intake_hash_max_bytes`` through ConfigRegistry.

    Falls back to the ForensicsConfigSchema field default when the key is
    unset, the registry read fails, or the value is not an integer, so a
    transient DB blip does not fail intake.
    """
    default = int(ForensicsConfigSchema.model_fields["intake_hash_max_bytes"].default)
    try:
        raw = await ConfigRegistry().get("forensics", "intake_hash_max_bytes")
    except (OSError, RuntimeError, AILAError) as exc:
        _log.warning("forensics.intake_hash_max_bytes registry read failed (%s); using default %d", exc, default)
        return default
    if raw is None:
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        _log.warning("forensics.intake_hash_max_bytes config value %r not an integer; using default %d", raw, default)
        return default


async def _hash_evidence_file(
    ssh: Any,
    integration: dict[str, Any],
    analyzer_os: str,
    file_path: str,
    size_bytes: int,
    cap_bytes: int,
) -> tuple[str | None, str]:
    """Return ``(digest, hash_status)`` for one evidence file.

    ``hash_status`` is one of ``computed``, ``deferred_over_cap`` or
    ``failed``. The digest is non-null only when the status is ``computed``.
    Files over the cap are never sent to the analyzer.
    """
    from aila.modules.forensics.services.evidence_classifier import _compute_file_hash

    if size_bytes > cap_bytes:
        return None, "deferred_over_cap"
    digest = await _compute_file_hash(ssh, integration, file_path, analyzer_os)
    if digest is None:
        return None, "failed"
    return digest, "computed"


async def _set_project_status(
    project_id: str,
    status: ProjectStatus,
    failure_reason: str | None = None,
) -> None:
    """Single UoW open to update project.status and failure_reason together.

    ``failure_reason`` is written on every call, so any non-failed status
    clears a reason left by an earlier failed intake."""
    if not project_id:
        return
    async with UnitOfWork() as uow:
        proj = (await uow.session.exec(
            _select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == project_id)
        )).first()
        if proj is not None:
            proj.status = status.value
            proj.failure_reason = failure_reason
            uow.session.add(proj)
            await uow.commit()


def _intake_failure_reason(exc: BaseException) -> str:
    """Bounded, non-empty failure reason recorded on the project row."""
    return f"intake failed: {type(exc).__name__}: {str(exc)[:500]}"


async def uow_prefetch_evidence(project_id: str) -> list[ProjectEvidenceRecord]:
    """Fetch every ProjectEvidenceRecord already on file for this project.

    Used by ``state_intake`` to implement idempotent persistence: we never
    want a second intake run to produce duplicate rows for the same
    ``(project_id, file_path)`` pair.
    """
    async with UnitOfWork() as uow:
        rows = (await uow.session.exec(
            _select(ProjectEvidenceRecord).where(ProjectEvidenceRecord.project_id == project_id)
        )).all()
        return list(rows)


async def state_intake(
    input: dict[str, Any],
    services: Any,
) -> dict[str, Any]:
    """Scan evidence directory and classify files.

    Returns a StateResult that routes to the ``collection`` state.
    """
    # Parse the input contract up-front. Missing/empty fields (notably
    # evidence_directory) now raise a clear ValidationError instead of hanging
    # later with a runaway Get-ChildItem -Recurse on an empty path.
    try:
        data = IntakeInput.model_validate({
            **input,
            "evidence_directory": input.get("evidence_directory") or services.evidence_directory,
            "integration": input.get("integration") or services.integration,
        })
    except ValidationError as exc:
        pid = input.get("project_id", "")
        msg = f"Intake input invalid: {exc.errors()}"
        _log.error("state_intake ABORT: %s", msg)
        await services.emitter.emit(
            "intake",
            f"Intake aborted: {msg}",
            {"stage": "config_error", "project_id": pid, "errors": exc.errors()},
        )
        await _set_project_status(pid, ProjectStatus.FAILED, _intake_failure_reason(exc))
        raise

    project_id = data.project_id
    evidence_directory = data.evidence_directory
    integration = data.integration
    analyzer_os = data.analyzer_os
    project_kind = data.project_kind or "disk_evidence"

    _log.info(
        "state_intake START: project_id=%s, dir=%s, os=%s, kind=%s",
        project_id, evidence_directory, analyzer_os, project_kind,
    )
    await _set_project_status(project_id, ProjectStatus.ANALYZING)
    # Domain-event emission for the investigation workflow start
    # (RFC-05 Phase 3). The intake state is the first handler the
    # forensics workflow runs. Guarded so a payload-construction fault
    # never blocks intake; the bus isolates subscriber errors.
    try:
        run_id = str(getattr(services, "run_id", "") or "")
        publish(
            ModuleWorkflowStarted(
                source_module="forensics",
                payload=ModuleWorkflowStartedPayload(
                    module_id="forensics",
                    run_id=run_id,
                    workflow_id="investigation",
                    metadata={
                        "project_id": project_id,
                        "project_kind": project_kind,
                        "analyzer_os": analyzer_os,
                    },
                ),
            ),
        )
    except (RuntimeError, ValueError, TypeError, AttributeError) as exc:
        _log.warning(
            "module.workflow.started publish failed for project %s: %s",
            project_id,
            exc,
        )
    await services.emitter.emit(
        "intake",
        f"Connecting to analyzer ({analyzer_os}) -- scanning: {evidence_directory}",
        {"stage": "scan_start", "path": evidence_directory, "os": analyzer_os},
    )

    from aila.modules.forensics.services.evidence_classifier import classify_evidence_directory

    try:
        result = await classify_evidence_directory(
            services.settings,
            integration,
            evidence_directory,
            analyzer_os=analyzer_os,
            emitter=services.emitter,
            project_kind=project_kind,
        )
        _log.info("classify_evidence_directory() returned: files=%d", len(result.get("files", [])))
    except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
        _log.exception("classify_evidence_directory() FAILED: %s", exc)
        await services.emitter.emit(
            "intake",
            f"Evidence scan FAILED: {str(exc)[:200]}",
            {"stage": "scan_failed", "error": str(exc)},
        )
        await _set_project_status(project_id, ProjectStatus.FAILED, _intake_failure_reason(exc))
        raise

    files = result.get("files", [])
    await services.emitter.emit(
        "intake",
        f"Directory scan complete -- {len(files)} file(s) found.",
        {"stage": "scan_done", "file_count": len(files)},
    )

    type_counts: dict[str, int] = {}
    for f in files:
        t = f.get("evidence_type", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1
    if type_counts:
        breakdown = ", ".join(f"{n}× {t}" for t, n in sorted(type_counts.items()))
        await services.emitter.emit(
            "intake",
            f"Evidence breakdown: {breakdown}",
            {"stage": "classify_done", "type_counts": type_counts},
        )

    await services.emitter.emit(
        "intake",
        f"Persisting {len(files)} evidence record(s) to database...",
        {"stage": "db_write_start"},
    )

    # Idempotent upsert: every intake pass re-scans the evidence directory, so
    # on re-runs we either (a) update the existing row's size/metadata/type or
    # (b) insert a new row for files that appeared since the last scan. Never
    # blindly append -- that produced N duplicate rows per file across N runs.
    existing_rows = (await uow_prefetch_evidence(project_id))
    existing_by_path: dict[str, ProjectEvidenceRecord] = {
        row.file_path: row for row in existing_rows
    }

    # Hash before opening the UoW: each hash is a remote command that can
    # take minutes, and no DB transaction should be held across it.
    from aila.modules.forensics.tools._ssh_helper import get_ssh_service

    cap_bytes = await _intake_hash_cap_bytes()
    ssh = await get_ssh_service(services.settings)
    hashes: dict[str, tuple[str | None, str]] = {}
    for f in files:
        prior = existing_by_path.get(f["file_path"])
        # A stored digest is only ever written with status "computed", so a
        # digest on an unchanged file means it is already hashed.
        if prior is not None and prior.file_hash_sha256 and prior.size_bytes == f["size_bytes"]:
            hashes[f["file_path"]] = (prior.file_hash_sha256, "computed")
            continue
        hashes[f["file_path"]] = await _hash_evidence_file(
            ssh, integration, analyzer_os, f["file_path"], f["size_bytes"], cap_bytes,
        )

    inserted_count = 0
    updated_count = 0
    async with UnitOfWork() as uow:
        for f in files:
            sha, hash_status = hashes[f["file_path"]]
            extras = {
                k: v for k, v in f.items()
                if k not in ("file_path", "evidence_type", "size_bytes", "file_name")
            }
            extras["hash_status"] = hash_status
            meta_json = json.dumps(extras)
            etype = f.get("evidence_type", "unknown")
            sbytes = f.get("size_bytes")
            existing = existing_by_path.get(f["file_path"])
            if existing is not None:
                # Re-fetch under this session so updates flush on commit.
                row = (await uow.session.exec(
                    _select(ProjectEvidenceRecord).where(ProjectEvidenceRecord.id == existing.id)
                )).first()
                if row is not None:
                    changed = False
                    if row.evidence_type != etype:
                        row.evidence_type = etype
                        changed = True
                    if row.size_bytes != sbytes and sbytes is not None:
                        row.size_bytes = sbytes
                        changed = True
                    if row.file_hash_sha256 != sha:
                        row.file_hash_sha256 = sha
                        changed = True
                    if row.metadata_json != meta_json:
                        row.metadata_json = meta_json
                        changed = True
                    if changed:
                        uow.session.add(row)
                        updated_count += 1
                continue
            record = ProjectEvidenceRecord(
                project_id=project_id,
                file_path=f["file_path"],
                evidence_type=etype,
                size_bytes=sbytes,
                file_hash_sha256=sha,
                metadata_json=meta_json,
            )
            uow.session.add(record)
            inserted_count += 1
        await uow.commit()

    _log.info(
        "intake persistence: %d inserted, %d updated, %d unchanged (total files=%d)",
        inserted_count, updated_count, len(files) - inserted_count - updated_count, len(files),
    )

    from aila.platform.workflows.types import RESERVED_SUCCEEDED, StateResult

    if project_kind == "raw_directory":
        # No collection / deep_analysis / promotion for raw directories.
        # The free-flow investigator reads files directly off the analyzer
        # filesystem using the ProjectEvidenceRecord rows we just wrote.
        await _set_project_status(project_id, ProjectStatus.COMPLETED)
        await services.emitter.emit(
            "intake",
            f"Raw-directory intake complete -- {len(files)} file(s) catalogued. "
            "No pre/full-analysis pipeline will run; ask questions directly.",
            {
                "stage": "intake_done",
                "evidence_count": len(files),
                "active_lanes": [],
                "type_counts": type_counts,
                "project_kind": "raw_directory",
            },
        )
        return StateResult(
            next_state=RESERVED_SUCCEEDED,
            output={
                "evidence_files": files,
                "active_lanes": [],
                "project_id": project_id,
                "integration": integration,
                "evidence_directory": evidence_directory,
                "analyzer_os": analyzer_os,
                "project_kind": project_kind,
            },
        )

    active_lanes: set[str] = set()
    for f in files:
        etype = f.get("evidence_type", "unknown")
        if etype == "disk_image":
            # Disk lane runs dissect queries (prefetch, runkeys, bashhistory,
            # etc.) and the binary_analysis lane runs capa/FLOSS/strings on
            # every suspicious sample discovered on the same image. Both
            # consume disk_image files.
            active_lanes.add("disk")
            active_lanes.add("binary_analysis")
        elif etype == "memory_dump":
            active_lanes.add("memory")
        elif etype == "pcap":
            active_lanes.add("network")
        elif etype == "log_file":
            active_lanes.add("log")

    lanes_list = sorted(active_lanes)
    await services.emitter.emit(
        "intake",
        f"Intake complete -- {len(files)} file(s) catalogued. Active analysis lanes: {', '.join(lanes_list) or 'none'}.",
        {
            "stage": "intake_done",
            "evidence_count": len(files),
            "active_lanes": lanes_list,
            "type_counts": type_counts,
        },
    )

    return StateResult(
        next_state="collection",
        output={
            "evidence_files": files,
            "active_lanes": lanes_list,
            "project_id": project_id,
            "integration": integration,
            "evidence_directory": evidence_directory,
            "analyzer_os": analyzer_os,
            "project_kind": project_kind,
        },
    )


state_intake.parallel_safe = state_intake_parallel_safe  # type: ignore[attr-defined]
state_intake.writes_fields = state_intake_writes_fields  # type: ignore[attr-defined]
