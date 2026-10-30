"""Resolve a VR target's local on-disk binary path.

REA and re_analytics both open targets by ABSOLUTE LOCAL PATH -- there
is no upload / binary-id registration step. The path comes from the
target's ``descriptor_json`` (one of the well-known artifact keys an
operator or the upload endpoint wrote) or from the ``target_path`` entry
``services.target_analysis`` stamps into ``mcp_handles_json`` once
ingestion has bound the artifact.

Everything here is fail-soft: callers treat an empty result as
"unresolved" and let the tool layer surface the real error, mirroring
the index-id resolution pattern in ``agents.tool_executor``.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from sqlmodel import select as _select

from aila.modules.vr.db_models import (
    VRInvestigationRecord,
    VRTargetRecord,
)
from aila.platform.uow import UnitOfWork

__all__ = [
    "TARGET_PATH_DESCRIPTOR_KEYS",
    "binary_path_from_target",
    "resolve_investigation_binary_path",
    "resolve_target_binary_path",
]

_log = logging.getLogger(__name__)

# Descriptor keys that can name the on-disk artifact, in priority order.
# Mirrors the path keys ``TargetAnalysisService._ingest_binary`` accepts;
# ``workstation_path`` is written by the project setup state.
TARGET_PATH_DESCRIPTOR_KEYS: tuple[str, ...] = (
    "binary_path",
    "image_path",
    "ko_path",
    "apk_path",
    "ipa_path",
    "jar_path",
    "dll_path",
    "workstation_path",
)


def binary_path_from_target(
    descriptor: dict[str, Any],
    handles: dict[str, Any] | None = None,
) -> str:
    """Return the absolute local path for a target, or "" when unbound.

    ``handles["target_path"]`` (written by ingestion) wins over the
    descriptor keys so a refreshed analysis rebinds the artifact the
    platform actually opened.
    """
    handles = handles or {}
    stamped = handles.get("target_path")
    if isinstance(stamped, str) and stamped:
        return stamped
    for key in TARGET_PATH_DESCRIPTOR_KEYS:
        value = descriptor.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


async def resolve_target_binary_path(target_id: str) -> str:
    """Resolve one target row to its local binary path ("" when missing)."""
    try:
        async with UnitOfWork() as uow:
            target = (await uow.session.exec(
                _select(VRTargetRecord).where(VRTargetRecord.id == target_id),
            )).first()
            if target is None:
                return ""
            descriptor = json.loads(target.descriptor_json or "{}")
            handles = json.loads(target.mcp_handles_json or "{}")
    except (OSError, RuntimeError, ValueError, TypeError) as exc:
        _log.info(
            "resolve_target_binary_path: failed for target=%s (%s: %s)",
            target_id, type(exc).__name__, exc,
            exc_info=True,
        )
        return ""
    if not isinstance(descriptor, dict):
        descriptor = {}
    if not isinstance(handles, dict):
        handles = {}
    return binary_path_from_target(descriptor, handles)


async def resolve_investigation_binary_path(investigation_id: str) -> str:
    """Resolve an investigation's primary target to its local binary path."""
    try:
        async with UnitOfWork() as uow:
            inv = (await uow.session.exec(
                _select(VRInvestigationRecord).where(
                    VRInvestigationRecord.id == investigation_id,
                ),
            )).first()
            if inv is None or not inv.target_id:
                return ""
            target = (await uow.session.exec(
                _select(VRTargetRecord).where(VRTargetRecord.id == inv.target_id),
            )).first()
            if target is None:
                return ""
            descriptor = json.loads(target.descriptor_json or "{}")
            handles = json.loads(target.mcp_handles_json or "{}")
    except (OSError, RuntimeError, ValueError, TypeError) as exc:
        _log.info(
            "resolve_investigation_binary_path: failed for inv=%s (%s: %s)",
            investigation_id, type(exc).__name__, exc,
            exc_info=True,
        )
        return ""
    if not isinstance(descriptor, dict):
        descriptor = {}
    if not isinstance(handles, dict):
        handles = {}
    return binary_path_from_target(descriptor, handles)
