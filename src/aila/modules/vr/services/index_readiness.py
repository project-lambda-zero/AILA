"""Target-readiness probe for the VR investigation loop gate.

Operator-requested (2026): an investigation must never fire agent turns
against a half-built target. Two failure modes were observed live:

  * source_repo / android_apk targets whose audit-mcp graph (trailmark)
    or semantic (semble) index is still building -- every ``read_function``
    then fails and the agent burns turns flailing (Tomcat / OFBiz hunts).
  * native_binary / kernel / hypervisor / ipa / jar / dotnet_assembly
    targets whose binary artifact was not yet ingested -- every
    ``rea.*`` / ``reverser_belt.*`` call errors and the agent burns
    30 min turns re-issuing the same read (observed live on the nvcuda
    hunt where ``capability_profile`` had failed at the reaper timeout
    and every subsequent branch turn produced only error messages).

This probe resolves an investigation's primary target and returns
``(ready, detail)``. Ready requires ALL of:

  * ``vr_targets.analysis_state == 'ready'`` (rolls up ingestion +
    capability_profile + function_ranking).
  * For binary-like kinds with a bound local artifact path: the file
    exists on disk. REA / reverser_belt open targets by local path per
    call; there is no index-build phase to poll.
  * For source-code-like kinds with a bound audit-mcp index: the
    graph (trailmark) AND semantic (semble) indexes both report
    ``status == 'ready'``. When the graph is ready but semble has
    not started, a single ``semantic_search`` is fired to kick the
    lazy build so the next probe converges to ready.

The platform loop / hub gate (``investigation_loop_base`` /
``phase_graph``) calls this through the ``index_readiness_fn`` binding;
when it returns not-ready the run is deferred (re-enqueued) with ZERO
turns until the target becomes ready, so the investigation simply sits
on the queue and auto-resumes once the target flips to ready. A target
in ``analysis_state='failed'`` holds indefinitely (bounded by
``_MAX_INDEX_WAIT_CYCLES``) and resumes automatically once the operator
retries ingestion and the row flips back to ``ready``.

Fail-open: any resolution / probe fault returns ``(True, ...)`` so a
probe defect never wedges an investigation -- the per-call tool guards
still apply. A missing target (deleted after investigation creation) is
treated as ready so the run proceeds and the tool layer reports the
real error rather than the run waiting forever.
"""
from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from sqlalchemy.exc import SQLAlchemyError

if TYPE_CHECKING:
    from aila.platform.mcp.client import McpClient

__all__ = ["vr_index_readiness"]

_log = logging.getLogger(__name__)

# audit-mcp four-tier resolver inputs -- mirror server_specs.audit_mcp so
# an operator PATCH on the catalog row / config key is honoured here too.
_AUDIT_MCP_ENV_VAR = "AUDIT_MCP_URL"
_AUDIT_MCP_CONFIG_KEY = "audit_mcp_url"
_AUDIT_MCP_DEFAULT_URL = "http://127.0.0.1:18822"

# Operator escape hatch. Default True == gate on.
_GATE_CONFIG_KEY = "index_readiness_gate_enabled"

_PROBE_ERRORS = (OSError, TimeoutError, RuntimeError, ValueError, TypeError)

# Target kinds whose ingestion path binds a local binary artifact
# (opened per call by REA / reverser_belt). Mirrors
# ``services.target_analysis`` and ``profile_builder``. Kept as a
# frozenset (not an import from ``TargetKind``) so the readiness probe
# stays cheap and dependency-light.
_BINARY_KINDS: frozenset[str] = frozenset({
    "native_binary",
    "kernel_image",
    "kernel_module",
    "hypervisor_image",
    "ipa",
    "jar",
    "dotnet_assembly",
})


async def _gate_enabled() -> bool:
    """Resolve ``platform.index_readiness_gate_enabled`` (default True)."""
    from aila.storage.registry import ConfigRegistry

    try:
        raw = await ConfigRegistry().get("platform", _GATE_CONFIG_KEY)
    except (SQLAlchemyError, OSError, RuntimeError, ValueError, TypeError):
        return True
    if raw is None:
        return True
    if isinstance(raw, bool):
        return raw
    return str(raw).strip().lower() not in ("0", "false", "no", "off")


async def _resolve_target(
    investigation_id: str,
) -> tuple[str, str, dict[str, str], dict[str, Any]] | None:
    """Resolve investigation -> primary target row.

    Returns ``(kind, analysis_state, handles, descriptor)`` or ``None``
    when the investigation is missing / has no bound target / target has
    been deleted. ``handles`` is the parsed ``mcp_handles_json`` payload
    (``audit_mcp_index_id`` for source repos, ``target_path`` for binary
    kinds, ``audit_mcp_decompiled_index_id`` for android_apk);
    ``descriptor`` is the parsed ``descriptor_json`` (carries the
    artifact path keys for binary kinds).
    """
    from sqlmodel import select

    from aila.modules.vr.db_models import (
        VRInvestigationRecord,
        VRTargetRecord,
    )
    from aila.platform.uow import UnitOfWork

    async with UnitOfWork() as uow:
        inv = (await uow.session.exec(
            select(VRInvestigationRecord).where(
                VRInvestigationRecord.id == investigation_id,
            ),
        )).first()
        if inv is None or not inv.target_id:
            return None
        target = (await uow.session.exec(
            select(VRTargetRecord).where(VRTargetRecord.id == inv.target_id),
        )).first()
        if target is None:
            return None
        kind = str(target.kind or "")
        analysis_state = str(target.analysis_state or "")
        handles_json = target.mcp_handles_json or "{}"
        descriptor_json = target.descriptor_json or "{}"
    try:
        raw = json.loads(handles_json or "{}")
    except (ValueError, TypeError) as exc:
        _log.debug(
            "vr_index_readiness: malformed mcp_handles_json for inv=%s: %s",
            investigation_id, exc,
        )
        raw = {}
    handles: dict[str, str] = {}
    if isinstance(raw, dict):
        for key, value in raw.items():
            if value is None:
                continue
            handles[str(key)] = str(value)
    try:
        descriptor = json.loads(descriptor_json or "{}")
    except (ValueError, TypeError) as exc:
        _log.debug(
            "vr_index_readiness: malformed descriptor_json for inv=%s: %s",
            investigation_id, exc,
        )
        descriptor = {}
    if not isinstance(descriptor, dict):
        descriptor = {}
    return kind, analysis_state, handles, descriptor


async def _audit_mcp_client() -> McpClient:
    """Build an :class:`McpClient` bound to the resolved audit-mcp URL."""
    from aila.platform.mcp.client import McpClient, resolve_instance

    resolved = await resolve_instance(
        module_scope="vr",
        server_name="audit_mcp",
        env_var=_AUDIT_MCP_ENV_VAR,
        config_key=_AUDIT_MCP_CONFIG_KEY,
        default_url=_AUDIT_MCP_DEFAULT_URL,
    )
    return McpClient(
        server_id="audit_mcp", base_url=resolved.url, timeout=30.0,
    )


async def _probe_binary_artifact(
    handles: dict[str, str], descriptor: dict[str, Any],
) -> tuple[bool, str]:
    """Check the target's local binary artifact exists on disk.

    REA / reverser_belt open targets by absolute local path per call --
    there is no index-build state to poll, so readiness reduces to
    "the artifact is actually there". A missing artifact holds the run
    (the operator re-stages / re-ingests, at which point the probe
    flips); a transport-level probe defect fails open so the per-call
    tool guards surface the real error instead.
    """
    from pathlib import Path

    from aila.modules.vr.services.binary_path import binary_path_from_target

    path = binary_path_from_target(descriptor, handles)
    if not path:
        # analysis_state==ready but no bound path is an inconsistent
        # row -- treat as ready so the tool layer surfaces the real
        # error instead of the gate silently wedging the run.
        return True, "no-bound-artifact-path"
    try:
        if Path(path).is_file():
            return True, f"artifact present ({path})"
    except (OSError, RuntimeError, ValueError) as exc:
        return True, f"artifact-probe-error:{type(exc).__name__}"
    return False, f"artifact missing on disk ({path})"


async def _probe_audit_mcp(index_id: str) -> tuple[bool, str]:
    """Poll audit_mcp for graph + semble readiness on *index_id*."""
    try:
        client = await _audit_mcp_client()
        resp = await client.post("poll_index", {"index_id": index_id})
    except _PROBE_ERRORS as exc:
        return True, f"poll-error:{type(exc).__name__}"
    data = resp.json() if hasattr(resp, "json") else resp
    if not isinstance(data, dict):
        return True, "poll-nonjson"
    status = str(data.get("status") or "")
    semble = str(data.get("semble_status") or "")
    if status == "ready" and semble == "ready":
        return True, f"audit_mcp ready (status={status}, semble={semble})"
    if status == "ready" and semble in ("", "pending"):
        # Graph is ready but nothing has triggered the semble build yet.
        # Kick it once so the next probe makes progress instead of
        # waiting on a build no caller ever started.
        try:
            await client.post(
                "semantic_search",
                {
                    "index_id": index_id,
                    "query": "index readiness warm",
                    "top_k": 1,
                },
            )
        except _PROBE_ERRORS:
            pass
    return False, (
        f"audit_mcp building (status={status or '?'}, "
        f"semble={semble or '?'})"
    )


async def vr_index_readiness(investigation_id: str) -> tuple[bool, str]:
    """Return ``(ready, detail)`` for the investigation's primary target.

    Composite gate (see module docstring):

    1. ``vr_targets.analysis_state`` must be ``ready``. Any other value
       (``pending`` / ``ingesting`` / ``failed``) HOLDS the investigation
       so it never fires an agent turn against a half-built target.
       A ``failed`` target auto-resumes as soon as the operator retries
       ingestion and the row flips back to ``ready``.
    2. For binary-like kinds (native_binary / kernel_* / hypervisor_image
       / ipa / jar / dotnet_assembly): the local artifact must exist on
       disk (REA / reverser_belt open it per call; there is no
       index-build phase to poll).
    3. For source-code-like kinds (source_repo / android_apk): the
       audit-mcp graph AND semble indexes must both be ready.

    Fail-open on any resolve / probe fault. A missing target or an
    ingestion-less target kind (cve / protocol_capture / crash_input /
    patch_diff) is treated as ready.
    """
    if not await _gate_enabled():
        return True, "gate-disabled"
    try:
        resolved = await _resolve_target(investigation_id)
    except _PROBE_ERRORS as exc:
        return True, f"resolve-error:{type(exc).__name__}"
    if resolved is None:
        return True, "no-bound-target"
    kind, analysis_state, handles, descriptor = resolved

    # (1) Target-row readiness. Rolls up ingestion + capability_profile +
    # function_ranking through ``services.stage_tracker``. A row in
    # anything other than ``ready`` HOLDS. A ``failed`` row holds too --
    # it resumes automatically once the operator retries ingestion and
    # the row flips back to ``ready``; the emit-state's bounded
    # ``_MAX_INDEX_WAIT_CYCLES`` counter prevents an indefinitely broken
    # target from re-enqueueing forever.
    if analysis_state != "ready":
        return False, (
            f"target not-ready (kind={kind or '?'}, "
            f"analysis_state={analysis_state or '?'})"
        )

    # (2) Binary-like kinds: the local artifact must be present.
    if kind in _BINARY_KINDS:
        return await _probe_binary_artifact(handles, descriptor)

    # (3) Source-code-like kinds: audit-mcp graph + semble must be ready.
    index_id = (
        handles.get("audit_mcp_index_id")
        or handles.get("audit_mcp_decompiled_index_id")
        or ""
    )
    if not index_id:
        return True, f"no-bound-index (kind={kind})"
    return await _probe_audit_mcp(index_id)
