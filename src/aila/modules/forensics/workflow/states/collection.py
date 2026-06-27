"""Artifact collection state handler.

Thin orchestrator: validates input, dispatches to per-lane collectors in
``collectors/``, persists artifact records, and emits progress events at
every meaningful boundary (collection start, per-lane start/done, per-file
start/done, per-file error). The heavy lifting (OS detection, query
execution, Volatility plugin runs) lives in the lane-specific modules.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from aila.platform.exceptions import AILAError

from .collectors import (
    collect_binary_analysis_artifacts,
    collect_disk_artifacts,
    collect_log_artifacts,
    collect_memory_artifacts,
    collect_network_artifacts,
)
from .collectors._helpers import sq


async def _evidence_is_reachable(
    ssh: Any, integration: dict, path: str, analyzer_os: str,
) -> tuple[bool, str]:
    """Confirm ``path`` is readable from the worker's SSH session.

    Returns ``(ok, diagnostic)``. A failed probe means the file simply
    isn't visible to this session -- wrong path, missing permissions,
    or the drive wasn't online when the worker spawned. Running 20+
    tool invocations after that is wasted time, so we fail the file
    with one clear message instead.
    """
    if analyzer_os == "windows":
        probe_cmd = (
            f'powershell -NoProfile -Command "'
            f"if (Test-Path -LiteralPath '{path}' -PathType Leaf) "
            f"{{ exit 0 }} else {{ exit 2 }}"
            f'"'
        )
    else:
        probe_cmd = f"test -r {sq(path, analyzer_os)}"
    try:
        await ssh.run_command(integration, probe_cmd, timeout_seconds=30.0)
    except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
        hint = (
            "Confirm the file exists on the analyzer and the SSH user "
            "has read permission. If the evidence lives on an external "
            "drive, make sure the drive is attached and the SSH user "
            "can see it."
        )
        return False, f"{hint} Underlying error: {str(exc)[:300]}"
    return True, ""

__all__ = ["state_collection"]

_log = logging.getLogger(__name__)

state_collection_parallel_safe = False
state_collection_writes_fields = ["artifacts"]


_LANE_DISPATCH = {
    "disk": collect_disk_artifacts,
    "binary_analysis": collect_binary_analysis_artifacts,
    "memory": collect_memory_artifacts,
    "network": collect_network_artifacts,
    "log": collect_log_artifacts,
}

# Many-to-many -- a disk_image file feeds both ``disk`` (dissect queries)
# and ``binary_analysis`` (capa/FLOSS/strings on discovered samples).
# Kept as a mapping of lane -> set of evidence types so the matcher is
# symmetric and obvious.
_LANE_EVIDENCE_TYPES: dict[str, set[str]] = {
    "disk": {"disk_image"},
    "binary_analysis": {"disk_image"},
    "memory": {"memory_dump"},
    "network": {"pcap"},
    "log": {"log_file"},
}


def _file_matches_lane(f: dict[str, Any], lane: str) -> bool:
    etype = f.get("evidence_type", "unknown")
    return etype in _LANE_EVIDENCE_TYPES.get(lane, set())


async def state_collection(
    input: dict[str, Any],
    services: Any,
) -> dict[str, Any]:
    """Extract artifacts from evidence using forensic tools, lane-by-lane.

    Emits: collection_start, lane_start, file_start, file_done, file_error,
    lane_done, collection_done -- so the xray log reflects the full graph.
    """
    project_id = input.get("project_id", "")
    active_lanes = input.get("active_lanes", [])
    evidence_files = input.get("evidence_files", [])
    integration = input.get("integration", services.integration)
    analyzer_os = input.get("analyzer_os", "linux")
    emitter = services.emitter

    _log.info(
        "state_collection START: project_id=%s lanes=%s files=%d os=%s",
        project_id, active_lanes, len(evidence_files), analyzer_os,
    )
    await emitter.emit(
        "collection",
        f"Starting artifact collection -- {len(active_lanes)} lane(s), {len(evidence_files)} file(s).",
        {
            "stage": "collection_start",
            "lanes": list(active_lanes),
            "file_count": len(evidence_files),
            "analyzer_os": analyzer_os,
        },
    )

    from sqlmodel import select as _select

    from aila.modules.forensics.db_models import ArtifactRecord
    from aila.modules.forensics.tools._ssh_helper import get_ssh_service
    from aila.platform.uow import UnitOfWork

    # Lazy -- skip SSH if there is literally nothing to do so a no-op call path
    # doesn't drag in the paramiko stack + secret store unlock.
    ssh = await get_ssh_service(services.settings) if active_lanes and evidence_files else None
    artifacts_by_family: dict[str, int] = {}
    artifacts_by_lane: dict[str, int] = {}
    artifact_count = 0
    file_error_count = 0
    skipped_file_count = 0

    # Pre-fetch every (source_evidence_id, artifact_type, source_tool) tuple
    # already persisted for this project so we skip queries that have results
    # carried over from a prior run. Incremental collection is the rule --
    # "full analysis from scratch" is only what the very first run does.
    async with UnitOfWork() as uow_prefetch:
        existing_rows = (await uow_prefetch.session.exec(
            _select(
                ArtifactRecord.source_evidence_id,
                ArtifactRecord.artifact_type,
                ArtifactRecord.source_tool,
            ).where(ArtifactRecord.project_id == project_id)
        )).all()
    already_collected: set[tuple[str | None, str, str]] = {
        (row[0], row[1], row[2]) for row in existing_rows
    }
    await emitter.emit(
        "collection",
        f"Incremental mode -- {len(already_collected)} artifact(s) already on record for this project.",
        {
            "stage": "incremental_prefetch",
            "existing_artifact_count": len(already_collected),
        },
    )

    for lane in active_lanes:
        collector = _LANE_DISPATCH.get(lane)
        if collector is None:
            _log.warning("Unknown collection lane %s -- skipping", lane)
            await emitter.emit(
                "collection",
                f"Unknown lane {lane!r} -- skipping.",
                {"stage": "lane_skipped", "lane": lane},
            )
            continue

        lane_files = [f for f in evidence_files if _file_matches_lane(f, lane)]
        await emitter.emit(
            "collection",
            f"Lane {lane}: {len(lane_files)} file(s) to process.",
            {"stage": "lane_start", "lane": lane, "file_count": len(lane_files)},
        )
        lane_artifact_count = 0

        for f in lane_files:
            path = f.get("file_path", "")
            evidence_id = f.get("id")
            size_bytes = f.get("size_bytes")
            await emitter.emit(
                "collection",
                f"{lane}: start {path}",
                {"stage": "file_start", "lane": lane, "path": path, "size_bytes": size_bytes},
            )

            # Pre-flight reachability check. Fails the single file with a
            # clear actionable diagnostic instead of letting every tool
            # invocation (vol, dissect, tshark, ...) independently fail
            # describing a cryptic ``drive not found`` / ``no such file``.
            if ssh is not None:
                ok, diag = await _evidence_is_reachable(ssh, integration, path, analyzer_os)
                if not ok:
                    file_error_count += 1
                    await emitter.emit(
                        "collection",
                        f"{lane}: SKIPPED {path} -- not reachable from worker SSH session. {diag}",
                        {
                            "stage": "file_unreachable",
                            "lane": lane,
                            "path": path,
                            "analyzer_os": analyzer_os,
                            "diagnostic": diag,
                        },
                    )
                    continue

            # Persist each artifact the moment it's produced, inside its own
            # UoW. A worker killed mid-collector loses at most the in-flight
            # artifact; everything before it survives and is skipped on the
            # next run via the already_collected set.
            new_records: list[ArtifactRecord] = []
            file_skipped = 0

            async def _on_artifact(art: dict[str, Any]) -> None:
                atype = art.get("type", "unknown")
                stool = art.get("source_tool", "")
                key = (evidence_id, atype, stool)
                if key in already_collected:
                    nonlocal file_skipped
                    file_skipped += 1
                    return
                already_collected.add(key)
                rec = ArtifactRecord(
                    project_id=project_id,
                    artifact_family=art.get("family", "unknown"),
                    artifact_type=atype,
                    source_tool=stool,
                    source_evidence_id=evidence_id,
                    data_json=json.dumps(art.get("data", {})),
                )
                async with UnitOfWork() as uow_art:
                    uow_art.session.add(rec)
                    await uow_art.commit()
                new_records.append(rec)

            try:
                # memory collector needs project_id to evaluate directives
                # explanation: Tier 3 (credential-extraction) gating. Other lanes
                # don't accept the kwarg.
                if lane == "memory":
                    await collector(
                        ssh, integration, path, analyzer_os,
                        emitter=emitter, on_artifact=_on_artifact,
                        project_id=project_id,
                    )
                else:
                    await collector(
                        ssh, integration, path, analyzer_os,
                        emitter=emitter, on_artifact=_on_artifact,
                    )
            except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
                _log.warning(
                    "%s collection failed for %s: %s", lane, path, exc, exc_info=True,
                )
                file_error_count += 1
                await emitter.emit(
                    "collection",
                    f"{lane}: FAILED for {path} -- {str(exc)[:200]}",
                    {
                        "stage": "file_error",
                        "lane": lane,
                        "path": path,
                        "error": str(exc),
                    },
                )
                continue

            # new_records was already populated + committed by _on_artifact
            # callback fired per-query inside the collector. Tally the running
            # totals here from the callback's results.
            for rec in new_records:
                artifact_count += 1
                lane_artifact_count += 1
                fam = rec.artifact_family
                artifacts_by_family[fam] = artifacts_by_family.get(fam, 0) + 1

            await emitter.emit(
                "collection",
                f"{lane}: done {path} -- {len(new_records)} new artifact(s)"
                + (f", {file_skipped} already on record." if file_skipped else "."),
                {
                    "stage": "file_done",
                    "lane": lane,
                    "path": path,
                    "artifact_count": len(new_records),
                    "skipped_existing": file_skipped,
                },
            )
            if file_skipped and not new_records:
                skipped_file_count += 1

        artifacts_by_lane[lane] = lane_artifact_count
        await emitter.emit(
            "collection",
            f"Lane {lane}: complete -- {lane_artifact_count} new artifact(s) from {len(lane_files)} file(s).",
            {
                "stage": "lane_done",
                "lane": lane,
                "artifact_count": lane_artifact_count,
                "file_count": len(lane_files),
            },
        )

    await emitter.emit(
        "collection",
        (
            f"Collection complete -- {artifact_count} new artifact(s) across "
            f"{len(active_lanes)} lane(s), {file_error_count} file error(s), "
            f"{skipped_file_count} file(s) fully cached from a prior run."
        ),
        {
            "stage": "collection_done",
            "artifact_count": artifact_count,
            "by_family": artifacts_by_family,
            "by_lane": artifacts_by_lane,
            "file_errors": file_error_count,
            "files_fully_cached": skipped_file_count,
        },
    )
    _log.info(
        "state_collection COMPLETE: new_artifacts=%d by_lane=%s errors=%d cached_files=%d",
        artifact_count, artifacts_by_lane, file_error_count, skipped_file_count,
    )

    from aila.platform.workflows.types import StateResult

    return StateResult(
        next_state="deep_analysis",
        output={
            "artifact_count": artifact_count,
            "artifacts_by_family": artifacts_by_family,
            "artifacts_by_lane": artifacts_by_lane,
            "file_error_count": file_error_count,
            "project_id": project_id,
            "evidence_files": evidence_files,
            "integration": integration,
            "evidence_directory": input.get("evidence_directory", ""),
            "analyzer_os": analyzer_os,
        },
    )


state_collection.parallel_safe = state_collection_parallel_safe  # type: ignore[attr-defined]
state_collection.writes_fields = state_collection_writes_fields  # type: ignore[attr-defined]
