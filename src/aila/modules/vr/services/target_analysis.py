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
import os
from typing import Any

from sqlmodel import select as _select

from aila.modules.vr.contracts.target import TargetKind
from aila.modules.vr.contracts.target_stages import (
    StageName,
    StageState,
    StageStatus,
)
from aila.modules.vr.db_models import VRTargetRecord
from aila.modules.vr.services.stage_tracker import (
    StageAlreadyDoneError,
    StageInFlightError,
    StageTracker,
    load_target_stages,
    save_target_stages,
)
from aila.modules.vr.tools.android_mcp_bridge import AndroidMcpBridgeTool
from aila.modules.vr.tools.audit_mcp_bridge import AuditMcpBridgeTool
from aila.modules.vr.tools.ida_bridge import IDABridgeTool
from aila.platform.contracts._common import utc_now
from aila.platform.uow import UnitOfWork

__all__ = ["TargetAnalysisError", "TargetAnalysisService"]

_log = logging.getLogger(__name__)

_POLL_INTERVAL_SECONDS = 3.0
_POLL_TIMEOUT_SECONDS = 14400.0  # 4 hours — monorepo-scale ceiling (chromium ~30min, firefox should fit similar; nginx ~30s)



# File extension → language identifier used in capability_profile +
# tool-filter (must match the keys in mcp_adapters.known_tools.
# LANGUAGE_UNRELIABLE_TOOLS for the suppression logic to fire).
_EXT_TO_LANGUAGE: dict[str, str] = {
    # C / C++
    ".c": "c", ".h": "c",
    ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".c++": "cpp",
    ".hpp": "cpp", ".hxx": "cpp", ".hh": "cpp", ".h++": "cpp",
    ".inl": "cpp", ".ipp": "cpp", ".tcc": "cpp",
    # JS / TS
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    # Other heavy hitters
    ".py": "python",
    ".rs": "rust",
    ".go": "go",
    ".java": "java",
    ".kt": "kotlin", ".kts": "kotlin",
    ".swift": "swift",
    ".m": "objective-c", ".mm": "objective-c",
    ".cs": "csharp",
    ".scala": "scala",
    ".rb": "ruby",
    ".php": "php",
    ".pl": "perl",
    ".lua": "lua",
    ".dart": "dart",
    ".ex": "elixir", ".exs": "elixir",
    ".erl": "erlang",
    ".hs": "haskell",
    ".ml": "ocaml",
    ".zig": "zig",
    ".v": "v",
    ".nim": "nim",
    ".cr": "crystal",
}

# Directories to skip when sampling — build artifacts, vendored deps,
# minified bundles, and test fixtures distort language counts in ways
# that don't reflect what an operator is actually trying to audit.
_SKIP_DIR_NAMES: frozenset[str] = frozenset({
    ".git", ".hg", ".svn",
    "node_modules", "vendor", "third_party", "third-party", "extern",
    "build", "dist", "out", "target", "bin", "obj",
    ".cache", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".venv", "venv", "env",
    ".idea", ".vscode",
})


def _detect_primary_language_from_path(
    repo_path: str,
) -> tuple[str | None, list[str]]:
    """Walk ``repo_path`` and rank source languages by total byte size.

    Returns ``(primary, secondaries)`` where ``primary`` is the
    language with the largest source-code footprint (None if no source
    files found) and ``secondaries`` is the remaining languages in
    descending byte order.

    We weight by BYTES, not file count: 100k tiny test fixtures shouldn't
    outvote 10k heavy implementation files. Skips known build / vendored
    / cache directories — auditing a tree shouldn't be skewed by the
    minified jquery shipped under third_party/.

    Returns (None, []) when the path doesn't exist or AILA can't read
    it (remote MCP setup). Caller should fall back to whatever signal
    is available in that case.
    """
    import os  # noqa: PLC0415

    if not repo_path or not os.path.isdir(repo_path):
        return None, []

    bytes_per_lang: dict[str, int] = {}
    try:
        for root, dirs, files in os.walk(repo_path):
            # Mutate dirs in-place to prune the traversal.
            dirs[:] = [d for d in dirs if d not in _SKIP_DIR_NAMES and not d.startswith(".")]
            for name in files:
                # Lowercased extension, including the dot.
                ext = os.path.splitext(name)[1].lower()
                lang = _EXT_TO_LANGUAGE.get(ext)
                if lang is None:
                    continue
                try:
                    size = os.path.getsize(os.path.join(root, name))
                except OSError:
                    continue
                bytes_per_lang[lang] = bytes_per_lang.get(lang, 0) + size
    except OSError as exc:
        _log.warning(
            "language detection: walk failed for %s: %s — falling back",
            repo_path, exc,
        )
        return None, []

    if not bytes_per_lang:
        return None, []

    ranked = sorted(bytes_per_lang.items(), key=lambda kv: kv[1], reverse=True)
    primary = ranked[0][0]
    secondaries = [lang for lang, _ in ranked[1:]]
    _log.info(
        "language detection: %s primary=%s (%.1f MiB) secondaries=%s",
        repo_path, primary, ranked[0][1] / (1024 * 1024),
        [(lang, f"{bytes_ // (1024 * 1024)}MiB") for lang, bytes_ in ranked[1:6]],
    )
    return primary, secondaries
# Kinds that need NO ingestion — descriptor alone drives capability profile.
_NO_INGEST_KINDS: frozenset[TargetKind] = frozenset({
    TargetKind.CVE,
    TargetKind.PROTOCOL_CAPTURE,
    TargetKind.CRASH_INPUT,
    TargetKind.PATCH_DIFF,
})

# Per-kind applicable stage sets (PRD §C-20). Source-repo / binary /
# no-ingest kinds run the legacy INGESTION / CAPABILITY_PROFILE /
# FUNCTION_RANKING trio. Android APKs run the five android-mcp stages
# instead. Stages NOT in the kind's applicable set are pre-marked
# DONE-skipped by ``_skip_inapplicable_stages`` at analyze() entry,
# so ``roll_up_overall_state`` (which requires every stage at DONE
# before returning READY) converges once the applicable subset runs.
_LEGACY_STAGES: frozenset[StageName] = frozenset({
    StageName.INGESTION,
    StageName.CAPABILITY_PROFILE,
    StageName.FUNCTION_RANKING,
})
_ANDROID_STAGES: frozenset[StageName] = frozenset({
    StageName.APK_DECODE,
    StageName.JADX_DECOMPILE,
    StageName.INDEX_DECOMPILED,
    StageName.STATIC_SUMMARY,
    StageName.MOBSF_SCAN,
})


def _applicable_stages_for(kind: TargetKind) -> frozenset[StageName]:
    """Return the stage set that applies to a given target kind."""
    if kind == TargetKind.ANDROID_APK:
        return _ANDROID_STAGES
    return _LEGACY_STAGES


class TargetAnalysisError(Exception):
    """Raised when ingestion cannot proceed (bad descriptor, MCP unreachable)."""


class TargetAnalysisService:
    """Pair-write: vr_targets row + per-kind MCP ingestion call."""

    def __init__(
        self,
        ida: IDABridgeTool | Any | None = None,
        audit_mcp: AuditMcpBridgeTool | Any | None = None,
        android_mcp: AndroidMcpBridgeTool | Any | None = None,
    ) -> None:
        self._ida = ida or IDABridgeTool()
        self._audit_mcp = audit_mcp or AuditMcpBridgeTool()
        self._android_mcp = android_mcp or AndroidMcpBridgeTool()

    async def analyze(self, target_id: str) -> None:
        """Run the ingestion stage(s) for one target.

        Dispatches by target kind:

        * ``android_apk`` → drives the five android-mcp stages
          (APK_DECODE / JADX_DECOMPILE / INDEX_DECOMPILED /
          STATIC_SUMMARY / MOBSF_SCAN)
          sequentially, each under its own StageTracker. See
          :meth:`_analyze_android_apk`.
        * All other kinds → run the legacy INGESTION stage (clone /
          upload / index via audit-mcp or ida-headless-mcp).

        Stages that don't apply to the kind are pre-marked DONE-skipped
        at entry so ``roll_up_overall_state`` converges on READY once
        the applicable stages all finish. Idempotent: stages already
        DONE / RUNNING / FAILED are left alone.

        Wraps the per-stage work in StageTracker so:

        * Re-running an already-ingested target is a no-op.
        * Concurrent invocations on the same row refuse the second one
          (StageInFlightError) rather than racing.
        * On any uncaught exception the stage is marked FAILED with
          the error message; the operator can resume via
          POST /vr/targets/:id/resume-analysis.
        """
        target = await self._load(target_id)
        kind = TargetKind(target.kind)
        applicable = _applicable_stages_for(kind)

        # Pre-mark inapplicable stages as DONE-skipped so the rollup
        # converges once the applicable stages complete. This is
        # idempotent — only touches stages still at PENDING with
        # attempts == 0 (i.e. untouched on a fresh target row).
        await self._skip_inapplicable_stages(target_id, applicable)

        if kind == TargetKind.ANDROID_APK:
            await self._analyze_android_apk(target_id)
            return

        # Legacy INGESTION flow — source_repo / binary kinds / CVE etc.
        try:
            async with StageTracker(
                target_id,
                StageName.INGESTION,
                stage_timeout_s=_POLL_TIMEOUT_SECONDS,
            ) as tracker:
                # Re-read inside the tracker — the row may have changed
                # between the dispatch-time load above and the tracker
                # taking ownership.
                target = await self._load(target_id)
                descriptor = json.loads(target.descriptor_json or "{}")
                current_handles = json.loads(target.mcp_handles_json or "{}")

                if kind in _NO_INGEST_KINDS:
                    # Nothing to ingest — stage just records "done"
                    # with empty handles; downstream stages can run.
                    tracker.record_output(mcp_handles_json=json.dumps({}))
                    return

                handles: dict[str, Any]
                language: str | None
                secondaries: list[str]
                if kind == TargetKind.SOURCE_REPO:
                    handles, language, secondaries = await self._ingest_source_repo(descriptor)
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
                    handles, language = await self._ingest_binary(
                        kind, descriptor, current_handles,
                    )
                    secondaries = []
                else:
                    raise TargetAnalysisError(
                        f"target kind {kind.value!r} has no ingestion path",
                    )

                # Persist the work-product in the SAME commit that flips
                # the stage to DONE — no crash window between writing
                # handles and recording success.
                extras: dict[str, Any] = {"mcp_handles_json": json.dumps(handles)}
                record = await self._load(target_id)
                if language and not record.primary_language:
                    extras["primary_language"] = language
                if secondaries:
                    # Always overwrite secondaries when we have fresh data —
                    # the byte-counter is authoritative and may have shifted
                    # since last analysis (repo grew, new languages added).
                    extras["secondary_languages_json"] = json.dumps(secondaries)
                tracker.record_output(**extras)
        except StageAlreadyDoneError:
            _log.info("vr.target_analysis: target %s already ingested — skip", target_id)
            return
        except StageInFlightError:
            _log.info("vr.target_analysis: target %s ingestion in flight — skip", target_id)
            return

    # ─── stage gating ───────────────────────────────────────────────────

    async def _skip_inapplicable_stages(
        self,
        target_id: str,
        applicable: frozenset[StageName],
    ) -> None:
        """Mark stages NOT in ``applicable`` as DONE if still untouched.

        ``roll_up_overall_state`` requires every StageName entry to be
        DONE before returning READY. Targets only run a subset of stages
        relevant to their kind, so the inapplicable ones get marked
        DONE-skipped here. Idempotent: only stages currently at PENDING
        with ``attempts == 0`` are mutated; anything already DONE /
        RUNNING / FAILED is left alone so a real failure can never be
        masked by this helper.

        Skipped stages carry ``started_at=None`` and ``attempts=0`` so
        operators can distinguish them from stages that genuinely ran.
        """
        stages = await load_target_stages(target_id)
        now = utc_now()
        mutated = False
        for stage_name, status in stages.all_stages():
            if stage_name in applicable:
                continue
            if status.state != StageState.PENDING or status.attempts != 0:
                continue
            stages.set(stage_name, StageStatus(
                state=StageState.DONE,
                started_at=None,
                completed_at=now,
                attempts=0,
                error=None,
            ))
            mutated = True
        if mutated:
            await save_target_stages(target_id, stages)

    # ─── android_apk staged ingestion (PRD §C-20) ──────────────────────

    async def _analyze_android_apk(self, target_id: str) -> None:
        """Drive the android-mcp + audit-mcp ingestion stages sequentially.

        APK_DECODE → JADX_DECOMPILE → INDEX_DECOMPILED → STATIC_SUMMARY
        → MOBSF_SCAN. Each runs under its own StageTracker so the
        operator can resume any single failed stage via
        POST /vr/targets/:id/resume-analysis without re-running the
        ones that already succeeded.

        INDEX_DECOMPILED hands the jadx Java tree to audit-mcp's
        ``index_codebase`` so VR personas auditing an APK get the same
        Trailmark/Semble surface they get against source-repo targets
        (semantic_search, callers_of, read_function over decompiled
        Java methods). The audit-mcp index_id flows through
        ``mcp_handles_json.audit_mcp_decompiled_index_id`` to the
        agent prompt's target snapshot (F-4).

        Outputs accumulate into ``mcp_handles_json`` across stages so
        downstream consumers (VR personas, refresh-source button) read
        a single coherent handles dict instead of stitching together
        per-stage scratch files.

        Stops the chain on the first hard failure — the failing stage
        is left at FAILED state by its tracker, downstream stages stay
        at PENDING until the operator resumes. A stage already DONE
        on a re-run is logged and the chain proceeds (idempotent).
        """
        await self._run_android_stage(
            target_id, StageName.APK_DECODE, self._android_apk_decode,
        )
        await self._run_android_stage(
            target_id, StageName.JADX_DECOMPILE, self._android_jadx_decompile,
        )
        await self._run_android_stage(
            target_id, StageName.INDEX_DECOMPILED, self._android_index_decompiled,
        )
        await self._run_android_stage(
            target_id, StageName.STATIC_SUMMARY, self._android_static_summary,
        )
        await self._run_android_stage(
            target_id, StageName.MOBSF_SCAN, self._android_mobsf_scan,
        )

    async def _run_android_stage(
        self,
        target_id: str,
        stage: StageName,
        worker: Any,
    ) -> None:
        """Wrap one android stage in a StageTracker.

        The ``worker`` callable receives ``(target_id, descriptor,
        current_handles, tracker)`` and is responsible for calling
        ``tracker.record_output(...)`` with the accumulated
        ``mcp_handles_json``. Raises ``TargetAnalysisError`` on hard
        failure; the tracker captures it as FAILED and re-raises so
        the chain stops.
        """
        try:
            async with StageTracker(target_id, stage) as tracker:
                target = await self._load(target_id)
                descriptor = json.loads(target.descriptor_json or "{}")
                current_handles = json.loads(target.mcp_handles_json or "{}")
                await worker(target_id, descriptor, current_handles, tracker)
        except StageAlreadyDoneError:
            _log.info(
                "vr.target_analysis: target %s stage %s already done — skip",
                target_id, stage.value,
            )
        except StageInFlightError:
            _log.info(
                "vr.target_analysis: target %s stage %s in flight — stop chain",
                target_id, stage.value,
            )
            raise

    def _resolve_apk_path(self, descriptor: dict[str, Any]) -> str:
        """Pull the APK path from the descriptor for an android_apk target."""
        apk_path = descriptor.get("apk_path")
        if not isinstance(apk_path, str) or not apk_path:
            raise TargetAnalysisError(
                "android_apk target requires apk_path in descriptor "
                "(set by POST /vr/targets/upload-apk)",
            )
        return apk_path

    async def _android_apk_decode(
        self,
        target_id: str,
        descriptor: dict[str, Any],
        current_handles: dict[str, Any],
        tracker: StageTracker,
    ) -> None:
        apk_path = self._resolve_apk_path(descriptor)
        resp = await self._android_mcp.forward(
            action="apktool_decode", apk_path=apk_path,
        )
        if not isinstance(resp, dict) or resp.get("status") == "error":
            err = resp.get("error") if isinstance(resp, dict) else resp
            raise TargetAnalysisError(
                f"android-mcp.apktool_decode failed: {err}",
            )
        output_dir = resp.get("output_dir")
        if not output_dir:
            raise TargetAnalysisError(
                f"android-mcp.apktool_decode returned no output_dir: {resp!r}",
            )
        current_handles["android_mcp_decoded_dir"] = output_dir
        if resp.get("apk_sha256"):
            current_handles["android_mcp_apk_sha256"] = resp["apk_sha256"]
        if resp.get("manifest_path"):
            current_handles["android_mcp_manifest_path"] = resp["manifest_path"]
        tracker.record_output(mcp_handles_json=json.dumps(current_handles))
        _log.info(
            "vr.android.apk_decode target=%s output_dir=%s",
            target_id, output_dir,
        )

    async def _android_jadx_decompile(
        self,
        target_id: str,
        descriptor: dict[str, Any],
        current_handles: dict[str, Any],
        tracker: StageTracker,
    ) -> None:
        apk_path = self._resolve_apk_path(descriptor)
        resp = await self._android_mcp.forward(
            action="jadx_decompile", apk_path=apk_path,
        )
        if not isinstance(resp, dict) or resp.get("status") == "error":
            err = resp.get("error") if isinstance(resp, dict) else resp
            raise TargetAnalysisError(
                f"android-mcp.jadx_decompile failed: {err}",
            )
        # jadx returns either ``sources_dir`` (preferred — the parent of
        # the per-class trees) or ``output_dir`` (root). Persist both
        # when present so downstream YARA / find_secrets can pick.
        sources_dir = resp.get("sources_dir") or resp.get("output_dir")
        if not sources_dir:
            raise TargetAnalysisError(
                f"android-mcp.jadx_decompile returned no sources_dir / output_dir: {resp!r}",
            )
        current_handles["android_mcp_decompiled_dir"] = sources_dir
        if resp.get("output_dir") and resp.get("output_dir") != sources_dir:
            current_handles["android_mcp_jadx_root"] = resp["output_dir"]
        if isinstance(resp.get("class_count"), int):
            current_handles["android_mcp_jadx_class_count"] = resp["class_count"]
        tracker.record_output(mcp_handles_json=json.dumps(current_handles))
        _log.info(
            "vr.android.jadx_decompile target=%s sources_dir=%s classes=%s",
            target_id, sources_dir, resp.get("class_count"),
        )

    async def _android_index_decompiled(
        self,
        target_id: str,
        descriptor: dict[str, Any],
        current_handles: dict[str, Any],
        tracker: StageTracker,
    ) -> None:
        """Hand the jadx Java tree to audit-mcp's ``index_codebase``.

        Reads ``android_mcp_decompiled_dir`` (written by JADX_DECOMPILE)
        out of the current handles, kicks off
        ``audit_mcp.index_codebase(path=<dir>, language="java")``,
        polls until READY via the existing ``_poll_audit_mcp`` helper,
        and writes ``audit_mcp_decompiled_index_id`` +
        ``audit_mcp_decompiled_indexed_at`` into ``mcp_handles_json``.

        After this stage runs, VR personas auditing an APK target get
        the same source-graph surface (``semantic_search``,
        ``callers_of``, ``read_function``) as personas auditing
        source-repo targets — they just point at the Java methods
        recovered by jadx instead of the original handwritten source.

        Soft-skips when JADX_DECOMPILE didn't write a decompiled dir
        (operator may have force-marked JADX_DECOMPILE DONE on a
        bad APK). Records ``{"skipped": "no jadx output"}`` instead of
        raising so the chain proceeds to STATIC_SUMMARY.
        """
        # Validate the descriptor invariant up-front: every android_apk
        # target carries apk_path in its descriptor (POST /vr/targets/
        # upload-apk writes it). Failing fast here gives a clearer
        # error than letting audit-mcp reject a stray call later.
        apk_path = self._resolve_apk_path(descriptor)

        decompiled_dir = current_handles.get("android_mcp_decompiled_dir")
        if not isinstance(decompiled_dir, str) or not decompiled_dir:
            current_handles["audit_mcp_decompiled_index"] = {
                "skipped": "no jadx output",
            }
            tracker.record_output(mcp_handles_json=json.dumps(current_handles))
            _log.warning(
                "vr.android.index_decompiled target=%s apk=%s skipped — "
                "no android_mcp_decompiled_dir in handles",
                target_id, apk_path,
            )
            return

        kickoff = await self._audit_mcp.forward(
            action="index_codebase", path=decompiled_dir, language="java",
        )
        if not isinstance(kickoff, dict) or kickoff.get("status") == "error":
            err = kickoff.get("error") if isinstance(kickoff, dict) else kickoff
            raise TargetAnalysisError(
                f"audit_mcp.index_codebase (decompiled) failed: {err}",
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

        current_handles["audit_mcp_decompiled_index_id"] = index_id
        current_handles["audit_mcp_decompiled_indexed_at"] = utc_now().isoformat()
        tracker.record_output(mcp_handles_json=json.dumps(current_handles))
        _log.info(
            "vr.android.index_decompiled target=%s apk=%s index_id=%s path=%s",
            target_id, apk_path, index_id, decompiled_dir,
        )

    async def _android_static_summary(
        self,
        target_id: str,
        descriptor: dict[str, Any],
        current_handles: dict[str, Any],
        tracker: StageTracker,
    ) -> None:
        apk_path = self._resolve_apk_path(descriptor)
        resp = await self._android_mcp.forward(
            action="androguard_summary", apk_path=apk_path,
        )
        if not isinstance(resp, dict) or resp.get("status") == "error":
            err = resp.get("error") if isinstance(resp, dict) else resp
            raise TargetAnalysisError(
                f"android-mcp.androguard_summary failed: {err}",
            )
        # The full androguard summary (package, permissions, certs,
        # exported components) is small enough to embed verbatim — no
        # paths to chase, downstream personas read it inline.
        current_handles["android_mcp_static_summary"] = resp
        package = resp.get("package")
        if isinstance(package, str) and package:
            # Mirror the existing uploaded_filename pattern so the
            # frontend display name can fall back to the package id
            # once STATIC_SUMMARY completes (PRD §C-21).
            current_handles["android_mcp_package_name"] = package
        tracker.record_output(mcp_handles_json=json.dumps(current_handles))
        _log.info(
            "vr.android.static_summary target=%s package=%s permissions=%d",
            target_id, package,
            len(resp.get("permissions") or []),
        )

    async def _android_mobsf_scan(
        self,
        target_id: str,
        descriptor: dict[str, Any],
        current_handles: dict[str, Any],
        tracker: StageTracker,
    ) -> None:
        """MobSF static scan. Skipped when MOBSF_API_KEY is unset."""
        mobsf_api_key = os.environ.get("MOBSF_API_KEY", "").strip()
        if not mobsf_api_key:
            _log.info(
                "vr.android.mobsf_scan target=%s skipped (MOBSF_API_KEY unset)",
                target_id,
            )
            current_handles["android_mcp_mobsf_scan"] = {
                "skipped": True,
                "reason": "MOBSF_API_KEY env var not set on the AILA host",
            }
            tracker.record_output(mcp_handles_json=json.dumps(current_handles))
            return

        apk_path = self._resolve_apk_path(descriptor)
        resp = await self._android_mcp.forward(
            action="mobsf_scan", apk_path=apk_path,
        )
        if not isinstance(resp, dict) or resp.get("status") == "error":
            err = resp.get("error") if isinstance(resp, dict) else resp
            raise TargetAnalysisError(
                f"android-mcp.mobsf_scan failed: {err}",
            )
        current_handles["android_mcp_mobsf_scan"] = resp
        tracker.record_output(mcp_handles_json=json.dumps(current_handles))
        _log.info(
            "vr.android.mobsf_scan target=%s scan_hash=%s",
            target_id, resp.get("_scan_hash"),
        )

    # ─── per-kind ingestion ─────────────────────────────────────────────

    async def _ingest_source_repo(
        self, descriptor: dict[str, Any],
    ) -> tuple[dict[str, Any], str | None, list[str]]:
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

        # Language detection — prefer byte-weighted ranking against the
        # actual repo bytes over audit_mcp.detect_languages because the
        # MCP tool returns trailmark's "languages present" list with no
        # weighting. ``languages[0]`` is whatever happens to come first
        # in trailmark's iteration order, which on firefox is 'python'
        # (~30 MiB of mach/taskcluster scripts) instead of 'cpp' (~3 GiB
        # of Gecko/SpiderMonkey/etc.). That misclassification poisons
        # capability_profile + suppresses C++-applicable tools across
        # the entire investigation loop — agent then concludes "no C++
        # code here" and gives up.
        #
        # Byte-weighted ranking against the local mcp_path is reliable
        # when AILA + the MCP workstation share a filesystem (single-host
        # dev setup, current deployment). When AILA can't read the path
        # (future remote MCP), the byte-counter returns (None, []) and
        # we fall back to detect_languages even though it lies, because
        # any signal beats no signal.
        language = None
        secondaries: list[str] = []
        byte_primary, byte_secondaries = _detect_primary_language_from_path(mcp_path)
        if byte_primary:
            language = byte_primary
            secondaries = byte_secondaries
        else:
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
                    other = langs.get("languages") or []
                    secondaries = [
                        s for s in other
                        if isinstance(s, str) and s != language
                    ]
            except (OSError, RuntimeError, TimeoutError) as exc:
                _log.warning(
                    "audit_mcp.detect_languages failed for %s: %s — "
                    "leaving language unset (byte-counter also unavailable)",
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
        return handles, language, secondaries

    async def _ingest_binary(
        self,
        kind: TargetKind,
        descriptor: dict[str, Any],
        current_handles: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], str | None]:
        """Resolve a binary handle on the IDA MCP.

        Two paths:

        1. The browser uploaded the file via POST ``/vr/targets/{id}/upload``
           — that endpoint streams bytes through to the IDA MCP and stores
           the returned ``binary_id`` in ``mcp_handles_json``. We just poll.
        2. Operator pasted a path in the descriptor that already exists on
           the IDA MCP filesystem. Dispatch ``ida.upload(file_path=...)``
           and store the new ``binary_id``.
        """
        current_handles = current_handles or {}
        binary_id = current_handles.get("binary_id")
        if not binary_id:
            path_keys = (
                "binary_path", "image_path", "ko_path", "apk_path",
                "ipa_path", "jar_path", "dll_path",
            )
            binary_path: str | None = None
            for key in path_keys:
                v = descriptor.get(key)
                if isinstance(v, str) and v:
                    binary_path = v
                    break
            if not binary_path:
                raise TargetAnalysisError(
                    f"{kind.value} target requires an upload via "
                    f"POST /vr/targets/{{id}}/upload, or a descriptor field "
                    f"naming a file path the IDA MCP can read: {list(path_keys)}",
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
        # Preserve upload metadata across re-analysis.
        if current_handles.get("uploaded_filename"):
            handles["uploaded_filename"] = current_handles["uploaded_filename"]
        if current_handles.get("uploaded_sha256"):
            handles["uploaded_sha256"] = current_handles["uploaded_sha256"]
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

