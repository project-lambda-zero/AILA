"""TargetAnalysisService — backend-only ingestion of an operator-created target.

The operator submits descriptors that contain ONLY what they actually
know (a repo URL, a file path, a kernel version). This service reads
the descriptor, calls the right MCP bridge to ingest the artifact,
polls until ready, and stores the resulting internal handles in
``vr_targets._mcp_handles_json`` for downstream enrichment + ranking.

Per-kind dispatch:

  source_repo:      audit_mcp.index_codebase(repo_url, ref) → poll_index → store index_id
  native_binary:    ida_headless.upload(file_path) → poll_analysis → store binary_id
  kernel_image:     ida_headless.upload(image_path) → poll_analysis → store binary_id
  kernel_module:    ida_headless.upload(ko_path) → poll_analysis → store binary_id
  hypervisor_image: ida_headless.upload(binary_path) → poll_analysis → store binary_id
  apk / ipa / jar / dotnet_assembly: ida_headless.upload(path) → poll_analysis → store binary_id
  cve / protocol_capture / crash_input / patch_diff:
                    No ingestion needed — capability_profile builds from descriptor alone.

After ingestion the service auto-detects primary_language when the
operator didn't supply one (audit_mcp.detect_languages or
ida_headless.binary_survey).
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from sqlmodel import select as _select

from aila.modules.vr.contracts.target import AnalysisState, TargetKind
from aila.modules.vr.db_models import VRTargetRecord
from aila.modules.vr.tools.audit_mcp_bridge import AuditMcpBridgeTool
from aila.modules.vr.tools.ida_bridge import IDABridgeTool
from aila.platform.contracts._common import utc_now
from aila.platform.uow import UnitOfWork

__all__ = ["TargetAnalysisError", "TargetAnalysisService"]

_log = logging.getLogger(__name__)

_POLL_INTERVAL_SECONDS = 3.0
_POLL_TIMEOUT_SECONDS = 1800.0  # 30 minutes hard cap

# Kinds that need NO ingestion — descriptor alone drives capability profile.
_NO_INGEST_KINDS: frozenset[TargetKind] = frozenset({
    TargetKind.CVE,
    TargetKind.PROTOCOL_CAPTURE,
    TargetKind.CRASH_INPUT,
    TargetKind.PATCH_DIFF,
})

class TargetAnalysisError(Exception):
    """Raised when ingestion cannot proceed (bad descriptor, MCP unreachable)."""


class TargetAnalysisService:
    """Pair-write: vr_targets row + per-kind MCP ingestion call."""

    def __init__(
        self,
        ida: IDABridgeTool | Any | None = None,
        audit_mcp: AuditMcpBridgeTool | Any | None = None,
    ) -> None:
        self._ida = ida or IDABridgeTool()
        self._audit_mcp = audit_mcp or AuditMcpBridgeTool()

    async def analyze(self, target_id: str) -> None:
        """Run the full ingestion lifecycle for one target.

        Idempotent for READY rows. Transitions PENDING / FAILED rows
        through INGESTING → READY (or → FAILED with a clear message).
        """
        await self._mark_ingesting(target_id)
        try:
            target = await self._load(target_id)
            kind = TargetKind(target.kind)
            descriptor = json.loads(target.descriptor_json or "{}")

            if kind in _NO_INGEST_KINDS:
                # Nothing to ingest; just mark ready so dispatchers proceed.
                await self._mark_ready(target_id, handles={}, language=None)
                return

            handles: dict[str, Any]
            language: str | None
            if kind == TargetKind.SOURCE_REPO:
                handles, language = await self._ingest_source_repo(descriptor)
            elif kind in {
                TargetKind.NATIVE_BINARY,
                TargetKind.KERNEL_IMAGE,
                TargetKind.KERNEL_MODULE,
                TargetKind.HYPERVISOR_IMAGE,
                TargetKind.APK,
                TargetKind.IPA,
                TargetKind.JAR,
                TargetKind.DOTNET_ASSEMBLY,
            }:
                handles, language = await self._ingest_binary(kind, descriptor)
            else:
                raise TargetAnalysisError(
                    f"target kind {kind.value!r} has no ingestion path",
                )

            await self._mark_ready(target_id, handles=handles, language=language)
        except TargetAnalysisError as exc:
            await self._mark_failed(target_id, str(exc))
            raise
        except (OSError, RuntimeError, TimeoutError) as exc:
            await self._mark_failed(target_id, f"{type(exc).__name__}: {exc}")
            raise

    # ─── per-kind ingestion ─────────────────────────────────────────────

    async def _ingest_source_repo(
        self, descriptor: dict[str, Any],
    ) -> tuple[dict[str, Any], str | None]:
        repo_url = descriptor.get("repo_url")
        if not repo_url:
            raise TargetAnalysisError(
                "source_repo target requires repo_url in descriptor",
            )
        ref_explicit = descriptor.get("ref") or descriptor.get("branch")
        ref = ref_explicit or "main"
        # Architecture: AILA does NOT shell out — it orchestrates remote
        # MCP servers (D-33). For URLs, ask audit-mcp to clone on its own
        # workstation; for local paths, pass straight through (operator on
        # the same box is allowed for dev).
        looks_like_url = "://" in repo_url or repo_url.startswith("git@")
        if looks_like_url:
            clone_resp = await self._audit_mcp.forward(
                action="clone_repo",
                repo_url=repo_url,
                ref=ref_explicit or "",
            )
            if clone_resp.get("status") != "ready":
                raise TargetAnalysisError(
                    f"audit_mcp.clone_repo failed: {clone_resp.get('error') or clone_resp!r}",
                )
            mcp_path = clone_resp.get("path")
            if not mcp_path:
                raise TargetAnalysisError(
                    f"audit_mcp.clone_repo returned no path: {clone_resp!r}",
                )
            _log.info("vr.mcp_clone repo_url=%s ref=%s mcp_path=%s", repo_url, ref, mcp_path)
        else:
            mcp_path = repo_url

        kickoff = await self._audit_mcp.forward(
            action="index_codebase", path=mcp_path,
        )
        if kickoff.get("status") == "error":
            raise TargetAnalysisError(
                f"audit_mcp.index_codebase failed: {kickoff.get('error')}",
            )
        index_id = (
            kickoff.get("index_id")
            or (kickoff.get("data") or {}).get("index_id")
        )
        if not index_id:
            raise TargetAnalysisError(
                f"audit_mcp.index_codebase returned no index_id: {kickoff!r}",
            )

        await self._poll_audit_mcp(index_id)

        language = None
        try:
            langs = await self._audit_mcp.forward(
                action="detect_languages", path=mcp_path,
            )
            if isinstance(langs, dict):
                primary = (
                    langs.get("primary_language")
                    or (langs.get("languages") or [None])[0]
                )
                if isinstance(primary, str):
                    language = primary
        except (OSError, RuntimeError, TimeoutError) as exc:
            _log.warning(
                "audit_mcp.detect_languages failed for %s: %s — leaving language unset",
                index_id, exc,
            )

        # mcp_path is the path on the MCP workstation, not on AILA.
        # Never assume AILA can read it.
        handles: dict[str, Any] = {
            "audit_mcp_index_id": index_id,
            "repo_url": repo_url,
            "ref": ref,
            "mcp_path": mcp_path,
        }
        return handles, language

    async def _ingest_binary(
        self, kind: TargetKind, descriptor: dict[str, Any],
    ) -> tuple[dict[str, Any], str | None]:
        path_keys = ("binary_path", "image_path", "ko_path", "apk_path", "ipa_path", "jar_path", "dll_path")
        binary_path: str | None = None
        for key in path_keys:
            v = descriptor.get(key)
            if isinstance(v, str) and v:
                binary_path = v
                break
        if not binary_path:
            raise TargetAnalysisError(
                f"{kind.value} target requires one of {list(path_keys)} in descriptor",
            )

        kickoff = await self._ida.forward(
            action="upload", file_path=binary_path,
        )
        if kickoff.get("status") == "error":
            raise TargetAnalysisError(
                f"ida.upload failed: {kickoff.get('error')}",
            )
        binary_id = (
            kickoff.get("binary_id")
            or (kickoff.get("data") or {}).get("binary_id")
        )
        if not binary_id:
            raise TargetAnalysisError(
                f"ida.upload returned no binary_id: {kickoff!r}",
            )

        await self._poll_ida(binary_id)

        language = None
        try:
            survey = await self._ida.forward(
                action="binary_survey", binary_id=binary_id,
            )
            if isinstance(survey, dict):
                lang_guess = survey.get("primary_language") or survey.get("language")
                if isinstance(lang_guess, str):
                    language = lang_guess.lower()
        except (OSError, RuntimeError, TimeoutError) as exc:
            _log.warning(
                "ida.binary_survey failed for %s: %s — leaving language unset",
                binary_id, exc,
            )

        handles: dict[str, Any] = {"binary_id": binary_id}
        if descriptor.get("kernel_version"):
            handles["kernel_version"] = descriptor["kernel_version"]
        if descriptor.get("arch"):
            handles["arch"] = descriptor["arch"]
        if descriptor.get("hypervisor_kind"):
            handles["hypervisor_kind"] = descriptor["hypervisor_kind"]
        return handles, language

    # ─── polling ────────────────────────────────────────────────────────

    async def _poll_ida(self, binary_id: str) -> None:
        deadline = utc_now().timestamp() + _POLL_TIMEOUT_SECONDS
        while utc_now().timestamp() < deadline:
            resp = await self._ida.forward(
                action="poll_analysis", binary_id=binary_id,
            )
            state = (resp or {}).get("state") or (resp or {}).get("status")
            if state in {"READY", "INDEXED", "ready", "complete", "completed"}:
                return
            if state in {"FAILED", "failed", "error"}:
                raise TargetAnalysisError(
                    f"ida analysis failed: {resp.get('error') or resp}",
                )
            await asyncio.sleep(_POLL_INTERVAL_SECONDS)
        raise TargetAnalysisError(
            f"ida analysis timed out after {_POLL_TIMEOUT_SECONDS:.0f}s",
        )

    async def _poll_audit_mcp(self, index_id: str) -> None:
        deadline = utc_now().timestamp() + _POLL_TIMEOUT_SECONDS
        while utc_now().timestamp() < deadline:
            resp = await self._audit_mcp.forward(
                action="poll_index", index_id=index_id,
            )
            state = (resp or {}).get("state") or (resp or {}).get("status")
            if state in {"READY", "ready", "complete", "completed"}:
                return
            if state in {"FAILED", "failed", "error"}:
                raise TargetAnalysisError(
                    f"audit_mcp index failed: {resp.get('error') or resp}",
                )
            await asyncio.sleep(_POLL_INTERVAL_SECONDS)
        raise TargetAnalysisError(
            f"audit_mcp index timed out after {_POLL_TIMEOUT_SECONDS:.0f}s",
        )

    # ─── DB transitions ─────────────────────────────────────────────────

    async def _load(self, target_id: str) -> VRTargetRecord:
        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _select(VRTargetRecord).where(VRTargetRecord.id == target_id),
            )).first()
            if row is None:
                raise TargetAnalysisError(f"target {target_id} not found")
            return row

    async def _mark_ingesting(self, target_id: str) -> None:
        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _select(VRTargetRecord).where(VRTargetRecord.id == target_id),
            )).first()
            if row is None:
                raise TargetAnalysisError(f"target {target_id} not found")
            now = utc_now()
            row.analysis_state = AnalysisState.INGESTING.value
            row.analysis_state_message = None
            row.analysis_started_at = now
            row.updated_at = now
            uow.session.add(row)
            await uow.session.commit()

    async def _mark_ready(
        self,
        target_id: str,
        *,
        handles: dict[str, Any],
        language: str | None,
    ) -> None:
        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _select(VRTargetRecord).where(VRTargetRecord.id == target_id),
            )).first()
            if row is None:
                raise TargetAnalysisError(f"target {target_id} not found")
            now = utc_now()
            row.analysis_state = AnalysisState.READY.value
            row.analysis_state_message = None
            row.analysis_completed_at = now
            row.mcp_handles_json = json.dumps(handles)
            if language and not row.primary_language:
                row.primary_language = language
            row.updated_at = now
            uow.session.add(row)
            await uow.session.commit()

    async def _mark_failed(self, target_id: str, message: str) -> None:
        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _select(VRTargetRecord).where(VRTargetRecord.id == target_id),
            )).first()
            if row is None:
                return  # row vanished mid-flight; nothing to do
            now = utc_now()
            row.analysis_state = AnalysisState.FAILED.value
            row.analysis_state_message = message
            row.analysis_completed_at = now
            row.updated_at = now
            uow.session.add(row)
            await uow.session.commit()
