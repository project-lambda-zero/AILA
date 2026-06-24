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
import hashlib
import json
import logging
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from sqlmodel import select as _select

from aila.modules.vr.contracts.target import TargetKind
from aila.modules.vr.contracts.target_stages import (
    StageName,
    StageState,
    StageStatus,
)
from aila.modules.vr.db_models import VRTargetRecord
from aila.modules.vr.services.mcp_call_logger import record_call
from aila.modules.vr.services.stage_tracker import (
    StageAlreadyDoneError,
    StageInFlightError,
    StageTracker,
    load_target_stages,
    save_target_stages,
)
from aila.platform.contracts._common import utc_now
from aila.platform.mcp.bridges.android_mcp import AndroidMcpBridgeTool
from aila.platform.mcp.bridges.audit_mcp import AuditMcpBridgeTool
from aila.platform.mcp.bridges.ida_headless import IDABridgeTool
from aila.platform.uow import UnitOfWork

__all__ = [
    "TargetAnalysisError",
    "TargetAnalysisService",
    # fix §268, §269 — consumers in api_router / reporting / agents
    # call these to resolve the artifact-file pointer back to its
    # full JSON payload.
    "load_target_artifact_payload",
]

_log = logging.getLogger(__name__)

_POLL_INTERVAL_SECONDS = 3.0
# fix §241 — operator-overridable poll timeout. Default 14400 (4h)
# fits the chromium / firefox / android-mcp ingestion envelope; large
# monorepos (chromium ~30min observed, mainline kernel possibly more)
# benefit from an extension knob. Read once at module load — workers
# pick up changes on restart, which matches the rest of the VR env
# surface (VR_*_TIMEOUT_S constants).
def _read_poll_timeout_env() -> float:
    raw = os.environ.get("VR_INGESTION_POLL_TIMEOUT_S")
    if not raw:
        return 14400.0
    try:
        value = float(raw)
    except ValueError:
        _log.warning(
            "VR_INGESTION_POLL_TIMEOUT_S=%r is not a number — using default 14400s",
            raw,
        )
        return 14400.0
    if value <= 0:
        _log.warning(
            "VR_INGESTION_POLL_TIMEOUT_S=%r is non-positive — using default 14400s",
            raw,
        )
        return 14400.0
    return value


_POLL_TIMEOUT_SECONDS = _read_poll_timeout_env()


# fix §268, §269 — artifact-file storage for the heavy android-mcp
# stage outputs (androguard summary + MobSF scan). The full payloads
# (40KB-2MB each) used to live inline in ``mcp_handles_json`` where
# every read of the row paid the parse cost. They now live in a
# content-addressed JSON file under
# ``VR_TARGET_ARTIFACT_DIR/{target_id}/{name}.json``; only a small
# digest + pointer is kept inline so API projections and the MASVS
# dispatcher stay cheap. Defaults to ``~/.aila/vr_target_artifacts``
# (same shape as ANDROID_MCP_UPLOAD_DIR's ``~/.android-mcp/uploads``).
def _artifact_root() -> Path:
    raw = os.environ.get("VR_TARGET_ARTIFACT_DIR", "").strip()
    if raw:
        return Path(raw).expanduser()
    return Path.home() / ".aila" / "vr_target_artifacts"


def _write_target_artifact(
    target_id: str, name: str, payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Persist a JSON payload to the per-target artifact dir.

    Writes ``{root}/{target_id}/{name}.json`` and returns a pointer
    dict (``_artifact_path``, ``_artifact_sha256``, ``_artifact_size``,
    ``_artifact_written_at``) suitable to embed in
    ``mcp_handles_json``. Callers merge the pointer with any
    pre-computed digest fields they want available without round-
    tripping to disk.

    The write goes through a temp file in the same directory + rename
    so a crash mid-write can never leave a half-written JSON behind
    that a future ``_load_target_artifact_payload`` would choke on.
    """
    target_dir = _artifact_root() / target_id
    target_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = target_dir / f"{name}.json"
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    body_bytes = body.encode("utf-8")
    sha = hashlib.sha256(body_bytes).hexdigest()
    tmp_path = target_dir / f".{name}.json.tmp"
    tmp_path.write_bytes(body_bytes)
    os.replace(tmp_path, artifact_path)
    return {
        "_artifact_path": str(artifact_path.resolve()),
        "_artifact_sha256": sha,
        "_artifact_size": len(body_bytes),
        "_artifact_written_at": utc_now().isoformat(),
    }


def _load_target_artifact_payload(
    handle_value: Any,
) -> Mapping[str, Any]:
    """Resolve an inline handle reference to its full JSON payload.

    ``handle_value`` is the value stored under one of the heavy
    android-mcp keys (``android_mcp_static_summary``,
    ``android_mcp_mobsf_scan``). Two shapes are supported:

    * **Pointer form** (current): a dict carrying ``_artifact_path``
      plus any pre-computed digest fields. The JSON file at
      ``_artifact_path`` is read and parsed; on read failure (file
      missing / corrupt JSON / unreadable) the inline dict is
      returned as a graceful fallback so renderers still get the
      digest fields they can render.
    * **Legacy inline form**: a dict that already holds the full
      payload. Returned as-is. Covers rows ingested before the
      §268 / §269 cutover.

    Non-mapping input returns an empty mapping.
    """
    if not isinstance(handle_value, Mapping):
        return {}
    artifact_path = handle_value.get("_artifact_path")
    if not isinstance(artifact_path, str) or not artifact_path:
        return handle_value
    try:
        with open(artifact_path, encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, ValueError) as exc:
        _log.warning(
            "vr.target_analysis: failed to load artifact %s: %s — "
            "falling back to inline digest",
            artifact_path, exc,
        )
        return handle_value
    if isinstance(payload, Mapping):
        return payload
    _log.warning(
        "vr.target_analysis: artifact %s decoded as %s, not Mapping — "
        "falling back to inline digest",
        artifact_path, type(payload).__name__,
    )
    return handle_value


def _static_summary_digest_fields(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Extract the small inline digest from an androguard summary.

    Carries the scalars an api_router / masvs-seed call would project
    plus pre-computed list counts so the projection layer never has
    to ``len()`` a 200-entry permission list on every request.
    """
    digest: dict[str, Any] = {}
    for key in (
        "package", "version_name", "version_code",
        "min_sdk", "target_sdk", "compile_sdk",
        "application_class", "main_activity",
        "signing_scheme",
    ):
        value = payload.get(key)
        if value is not None:
            digest[key] = value
    for key in (
        "permissions", "dangerous_permissions",
        "exported_activities", "exported_services",
        "exported_receivers", "exported_providers",
        "native_libs", "certificates",
    ):
        value = payload.get(key)
        if isinstance(value, list):
            digest[f"{key}_count"] = len(value)
    return digest


def _mobsf_digest_fields(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Extract the operator-display digest from a MobSF scan response.

    The full MobSF scan is multi-MB and must never enter LLM prompts
    (PIPELINE_ONLY_TOOLS — see ``android_mcp_bridge._PIPELINE_ONLY_TOOLS``
    comment). The inline digest carries only fields safe to show on
    the target overview / PDF cover (security score + tracker count +
    per-severity finding buckets); everything else lives in the
    artifact file behind ``prompt_safe=False``.
    """
    digest: dict[str, Any] = {}
    if payload.get("skipped"):
        digest["skipped"] = True
        if payload.get("reason") is not None:
            digest["reason"] = payload["reason"]
        return digest
    if payload.get("security_score") is not None:
        digest["security_score"] = payload["security_score"]
    trackers = payload.get("trackers")
    if isinstance(trackers, Mapping):
        detected = trackers.get("detected_trackers")
        if detected is not None:
            digest["trackers_detected"] = detected
    buckets = {"high": 0, "warning": 0, "info": 0, "good": 0, "secure": 0}
    for section_key in (
        "code_analysis", "manifest_analysis",
        "android_api", "network_security",
    ):
        section = payload.get(section_key)
        if isinstance(section, dict):
            for finding in section.values():
                if isinstance(finding, dict):
                    sev = str(
                        finding.get("severity") or finding.get("status") or "",
                    ).lower()
                    if sev in buckets:
                        buckets[sev] += 1
    if any(buckets.values()):
        digest["findings_by_severity"] = buckets
    return digest


# Public re-export so api_router / reporting / agents can resolve
# pointer-form handles without reaching into a `_`-prefixed symbol.
load_target_artifact_payload = _load_target_artifact_payload


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
    StageName.REACT_NATIVE_EXTRACT,
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


# ─── React Native unification helpers ─────────────────────────────────

_DEFAULT_APK_WORKDIR = Path(
    os.environ.get("ANDROID_MCP_WORKDIR", "~/.android-mcp/work"),
).expanduser()


def _hash_path_for_cache(apk_path: str) -> str:
    """Cache-key the APK path itself when no SHA was persisted on the
    handle row. Used as a fallback for the unified staging dir name."""
    return hashlib.sha256(apk_path.encode("utf-8")).hexdigest()[:16]


def _build_unified_staging(
    apk_sha: str,
    java_dir: str | None,
    react_dir: str | None,
    apktool_dir: str | None = None,
) -> str:
    """Create the unified staging tree at
    ``~/.android-mcp/work/apk-unified-<sha>/`` with junction/symlink
    entries pointing at the jadx Java output, the RN decompile output,
    and the apktool extract (manifest + res/ + smali). Returns the
    absolute staging path.

    Idempotent — running twice on the same APK rebuilds the staging
    layout against the current source dirs (which may have moved if
    the operator force-rebuilt any of them).

    Junction strategy: on Windows uses ``os.symlink`` first (succeeds
    when developer mode is on), then falls back to
    ``ctypes.CreateSymbolicLinkW`` with the ALLOW_UNPRIVILEGED flag,
    finally to ``shutil.copytree``. All three leave the original tree
    in place; only the link entry consumes filesystem state. On POSIX
    ``os.symlink`` always succeeds without admin.
    """
    staging = _DEFAULT_APK_WORKDIR / f"apk-unified-{apk_sha[:16]}"
    if staging.exists():
        import shutil as _shutil
        _shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True, exist_ok=True)
    if java_dir:
        _link_dir(Path(java_dir), staging / "java")
    if react_dir:
        _link_dir(Path(react_dir), staging / "react")
    if apktool_dir:
        # apktool tree contains AndroidManifest.xml, res/, smali — not
        # source-code per audit-mcp's FastIndexer (XML/smali ignored
        # by extension) but read_lines needs them in scope for
        # manifest-driven MSTG-ARCH audits.
        _link_dir(Path(apktool_dir), staging / "apktool")
    return str(staging)


def _link_dir(source: Path, target: Path) -> None:
    """Cross-platform directory junction.

    Windows: ``mklink /J`` via ``subprocess`` is the standard but
    operator banned subprocess.run — we use ``_winapi.CreateJunction``
    when available (Python 3.13+ exposes it under ctypes.windll.kernel32)
    via ``os.symlink`` with ``target_is_directory=True``. When that
    fails (no developer-mode + no admin) we fall back to bulk copy via
    ``shutil.copytree`` — slower one-time, then the staging dir persists.
    POSIX: ``os.symlink`` always works.
    """
    if not source.exists():
        return
    try:
        os.symlink(source, target, target_is_directory=True)
        return
    except (OSError, NotImplementedError):
        # Symlink failed — Windows often denies non-admin symlinks.
        # Fall through to junction or copy.
        pass
    if os.name == "nt":
        # Try Windows native junction via ctypes (no subprocess).
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.CreateSymbolicLinkW.restype = ctypes.c_ubyte
            # SYMBOLIC_LINK_FLAG_DIRECTORY=0x1, ALLOW_UNPRIVILEGED=0x2
            ok = kernel32.CreateSymbolicLinkW(
                str(target), str(source), 0x3,
            )
            if ok:
                return
        except OSError:
            pass
    # Last-resort: copy. Slower but always works.
    import shutil as _shutil
    _shutil.copytree(source, target, symlinks=False, dirs_exist_ok=False)


# Maps file extensions to audit-mcp / trailmark language names. Mirrors
# trailmark's FastIndexer._build_ext_map (java, kotlin, javascript,
# typescript, c, cpp, objc, swift). Listed here so we don't have to
# the indexer module just to ask "what language is .kt?". Add new
# entries as audit-mcp grows its supported set.
_STAGING_EXT_TO_LANG: dict[str, str] = {
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".cc": "cpp",
    ".hh": "cpp",
    ".cxx": "cpp",
    ".m": "objc",
    ".mm": "objc",
    ".swift": "swift",
    ".go": "go",
    ".rs": "rust",
}

# Directory names to skip during the extension probe — mirrors the
# FastIndexer's own skip list so we don't claim "we have ruby" because
# some vendored gem shipped a .rb under node_modules/.
_STAGING_SKIP_DIRS: frozenset[str] = frozenset({
    ".git", ".svn", "node_modules", "vendor", "venv", ".venv",
    "__pycache__", "build", "out", "dist", "target",
    ".tox", ".mypy_cache",
})

# Early-exit once every supported language has been seen — we don't
# need to enumerate every file just to build a set. An APK staging
# easily holds 100k+ files; pure os.walk over a tree that deep is
# only a few seconds but bailing as soon as we've covered the full
# set keeps the common case sub-second.
_STAGING_PROBE_MAX_LANGS: int = len(set(_STAGING_EXT_TO_LANG.values()))


def _detect_staging_languages(staging: Path) -> list[str]:
    """Walk ``staging`` and return the audit-mcp language names whose
    file extensions are present.

    Used to build the explicit ``language=...`` argument for
    ``audit_mcp.index_codebase``. Skipping ``auto`` (which lets
    trailmark's ``detect_languages`` majority-vote minority languages
    out — an APK's RN bundle slices lose to its Java class count and
    get dropped) means every language we actually have on disk gets
    indexed. Walks the full tree by default and returns the union of
    languages present; bails early once every supported language has
    been seen at least once so the common Java+Kotlin+JS APK case
    stays sub-second.
    """
    if not staging.exists():
        return []
    seen: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(staging):
        dirnames[:] = [
            d for d in dirnames
            if d not in _STAGING_SKIP_DIRS and not d.startswith(".")
        ]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            lang = _STAGING_EXT_TO_LANG.get(ext)
            if lang is not None:
                seen.add(lang)
        if len(seen) >= _STAGING_PROBE_MAX_LANGS:
            return sorted(seen)
    return sorted(seen)


class TargetAnalysisService:
    """Pair-write: vr_targets row + per-kind MCP ingestion call."""

    def __init__(
        self,
        ida: IDABridgeTool | Any | None = None,
        audit_mcp: AuditMcpBridgeTool | Any | None = None,
        android_mcp: AndroidMcpBridgeTool | Any | None = None,
    ) -> None:
        self._ida = ida or IDABridgeTool(recorder=record_call)
        self._audit_mcp = audit_mcp or AuditMcpBridgeTool(recorder=record_call)
        self._android_mcp = android_mcp or AndroidMcpBridgeTool(recorder=record_call)

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
            # fix §242 — mirror the legacy ingestion path's exception
            # contract so android targets follow the same operator-
            # resume flow on stage state collisions. Without this, a
            # StageAlreadyDoneError / StageInFlightError raised from
            # any of the five android stages propagated raw into the
            # ARQ task: the worker logged ERROR + marked the task
            # failed, leaving the operator to dig through logs instead
            # of seeing the harmless idempotency log line.
            try:
                await self._analyze_android_apk(target_id)
            except StageAlreadyDoneError:
                _log.info(
                    "vr.target_analysis: target %s android stage already done — skip",
                    target_id,
                )
            except StageInFlightError:
                _log.info(
                    "vr.target_analysis: target %s android stage in flight — skip",
                    target_id,
                )
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
                    # leaving handles empty; downstream stages can run.
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
        """Drive the android-mcp + audit-mcp ingestion stages.

        fix §240 — wall-clock optimisation: the four stages that take an
        APK path as their sole input are independent (apktool, jadx,
        androguard, MobSF run against the same file with disjoint output
        keys) so we fan them out via ``asyncio.gather``.
        INDEX_DECOMPILED depends on JADX_DECOMPILE writing
        ``android_mcp_decompiled_dir`` and runs sequentially after.

        On a typical APK:
          - APK_DECODE        ~30s   (apktool)
          - JADX_DECOMPILE    5-15min
          - STATIC_SUMMARY    ~30s   (androguard)
          - MOBSF_SCAN        5-30min (optional, skipped if no API key)
          - INDEX_DECOMPILED  varies (audit-mcp index of jadx output)

        Sequential wall-clock: ~50min worst case.
        Group-parallel: ~max(group_1) + index = ~30min worst case.

        Concurrent ``mcp_handles_json`` writes are race-protected by a
        per-worker SELECT FOR UPDATE merge (see ``_merge_handles_locked``):
        each worker grabs the row lock briefly to merge its disjoint keys
        into the latest snapshot, so parallel completions can't overwrite
        each other.

        Stops on the first hard failure — the failing stage is left at
        FAILED by its tracker, downstream stages stay at PENDING until
        the operator resumes. A stage already DONE on a re-run is logged
        and the chain proceeds (idempotent).
        """
        # GROUP 1: independent stages — fan out.
        # asyncio.gather propagates the FIRST exception and cancels
        # outstanding tasks; that matches the existing sequential chain's
        # "stop on first failure" contract.
        # REACT_NATIVE_EXTRACT runs in this group too: it reads the APK
        # directly (no apktool dependency) and produces decompiled JS
        # the unified-index stage joins with the jadx Java tree.
        await asyncio.gather(
            self._run_android_stage(
                target_id, StageName.APK_DECODE, self._android_apk_decode,
            ),
            self._run_android_stage(
                target_id, StageName.JADX_DECOMPILE, self._android_jadx_decompile,
            ),
            self._run_android_stage(
                target_id, StageName.REACT_NATIVE_EXTRACT,
                self._android_react_native_extract,
            ),
            self._run_android_stage(
                target_id, StageName.STATIC_SUMMARY, self._android_static_summary,
            ),
            self._run_android_stage(
                target_id, StageName.MOBSF_SCAN, self._android_mobsf_scan,
            ),
        )
        # GROUP 2: unified index over BOTH the jadx Java tree AND the
        # React Native decompile (when present). Personas see ONE
        # index_id whose semantic_search / read_function / callers_of
        # span both languages — no per-language index juggling at the
        # bridge or in the system prompt.
        await self._run_android_stage(
            target_id, StageName.INDEX_DECOMPILED, self._android_index_decompiled,
        )

    async def _merge_handles_locked(
        self,
        target_id: str,
        new_keys: dict[str, Any],
    ) -> None:
        """Atomically merge ``new_keys`` into the target row's
        ``mcp_handles_json``.

        fix §240 — parallel android stages must not overwrite each
        other's contributions. Each worker calls this AFTER its MCP
        action returns and BEFORE the StageTracker commits DONE. The
        SELECT FOR UPDATE serialises the read-modify-write across
        concurrent stages so disjoint keys (apktool's
        ``android_mcp_decoded_dir``, jadx's ``android_mcp_decompiled_dir``,
        etc.) all survive into the final row.

        Trade-off vs §322 (persist-work-product-in-same-commit-as-DONE):
        this introduces a small crash window between the merge commit
        and the tracker's DONE commit. If a crash lands in that window,
        the row carries the worker's keys but the stage stays RUNNING;
        the stage reaper times it out → FAILED, and the next operator-
        resume re-runs the stage (idempotent because android MCP
        actions are content-addressed and re-run with force=True).
        """
        if not new_keys:
            return
        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _select(VRTargetRecord)
                .where(VRTargetRecord.id == target_id)
                .with_for_update(),
            )).first()
            if row is None:
                raise TargetAnalysisError(
                    f"target {target_id} vanished during handles merge",
                )
            merged = json.loads(row.mcp_handles_json or "{}")
            merged.update(new_keys)
            row.mcp_handles_json = json.dumps(merged)
            uow.session.add(row)
            await uow.commit()

    async def _run_android_stage(
        self,
        target_id: str,
        stage: StageName,
        worker: Any,
    ) -> None:
        """Wrap one android stage in a StageTracker.

        The ``worker`` callable receives ``(target_id, descriptor,
        current_handles, tracker)``. ``current_handles`` is read AT
        STAGE ENTRY from the DB — useful for stages that need to read
        a prior stage's output (INDEX_DECOMPILED reads
        ``android_mcp_decompiled_dir`` written by JADX_DECOMPILE).

        Workers MUST NOT pass ``mcp_handles_json`` through
        ``tracker.record_output``: parallel siblings would overwrite
        each other's disjoint keys. Use ``self._merge_handles_locked``
        instead to atomically merge new keys into the row. The tracker
        still owns the DONE/FAILED state transition and records the
        non-handles work-product columns.

        Raises ``TargetAnalysisError`` on hard failure; the tracker
        captures it as FAILED and re-raises so the chain stops.
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
        del current_handles, tracker  # dispatch contract; consumed by sibling stages
        apk_path = self._resolve_apk_path(descriptor)
        # force=True so a retried stage doesn't trip apktool's
        # "destination directory already exists" check against a partial
        # output from a prior failed attempt. Retry SHOULD be idempotent;
        # the workspace dir is content-addressed by sha (apktool-<sha[:16]>)
        # so overwriting is the correct behavior. Without this, every
        # retry after a single failure perma-fails until manual cleanup.
        resp = await self._android_mcp.forward(
            action="apktool_decode", apk_path=apk_path, force=True, _agent_bypass=True,
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
        new_keys: dict[str, Any] = {"android_mcp_decoded_dir": output_dir}
        if resp.get("apk_sha256"):
            new_keys["android_mcp_apk_sha256"] = resp["apk_sha256"]
        if resp.get("manifest_path"):
            new_keys["android_mcp_manifest_path"] = resp["manifest_path"]
        # fix §240 — locked merge into mcp_handles_json so parallel
        # group-1 stages don't overwrite each other's disjoint keys.
        await self._merge_handles_locked(target_id, new_keys)
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
        del current_handles, tracker  # dispatch contract; consumed by sibling stages
        apk_path = self._resolve_apk_path(descriptor)
        # fix §267 — mirror apktool_decode's force=True. Without it, a
        # retry after partial JADX failure trips JADX's "destination
        # exists" guard and perma-fails until manual cleanup. The
        # workspace dir is content-addressed by sha so overwriting is
        # the correct retry behavior; same reasoning the comment on
        # _android_apk_decode line ~480 spells out.
        resp = await self._android_mcp.forward(
            action="jadx_decompile", apk_path=apk_path, force=True, _agent_bypass=True,
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
        new_keys: dict[str, Any] = {"android_mcp_decompiled_dir": sources_dir}
        if resp.get("output_dir") and resp.get("output_dir") != sources_dir:
            new_keys["android_mcp_jadx_root"] = resp["output_dir"]
        if isinstance(resp.get("class_count"), int):
            new_keys["android_mcp_jadx_class_count"] = resp["class_count"]
        # fix §240 — locked merge so parallel group-1 stages don't
        # overwrite each other's disjoint keys.
        await self._merge_handles_locked(target_id, new_keys)
        _log.info(
            "vr.android.jadx_decompile target=%s sources_dir=%s classes=%s",
            target_id, sources_dir, resp.get("class_count"),
        )

    async def _android_react_native_extract(
        self,
        target_id: str,
        descriptor: dict[str, Any],
        current_handles: dict[str, Any],
        tracker: StageTracker,
    ) -> None:
        """Extract + decompile + slice the React Native JS bundle from
        the APK, when one exists.

        Calls android-mcp's ``react_native_extract`` tool which reads
        the APK directly (no dependency on apktool output) and writes
        per-module / per-slice JS files into a content-addressed
        staging dir. The returned ``decompiled_dir`` lands in the
        target's handles under ``android_mcp_rn_decompiled_dir`` so
        ``_android_index_decompiled`` can junction it into the unified
        staging tree.

        Soft-skips when the APK contains no RN bundle — the tool
        returns ``decompiled_dir=None`` and we record that as a
        ``{"skipped": "no rn bundle"}`` handle entry so the unified
        index stage knows to only feed the jadx tree.
        """
        del current_handles, tracker  # dispatch contract; consumed elsewhere
        apk_path = self._resolve_apk_path(descriptor)
        resp = await self._android_mcp.forward(
            action="react_native_extract",
            apk_path=apk_path,
            force=True,
            _agent_bypass=True,
        )
        if not isinstance(resp, dict) or resp.get("status") == "error":
            err = resp.get("error") if isinstance(resp, dict) else resp
            raise TargetAnalysisError(
                f"android-mcp.react_native_extract failed: {err}",
            )
        decompiled_dir = resp.get("decompiled_dir")
        bundles_found = resp.get("bundles_found") or []
        if not decompiled_dir:
            await self._merge_handles_locked(
                target_id,
                {"android_mcp_rn_extract": {
                    "skipped": "no rn bundle",
                    "bundles_found": 0,
                }},
            )
            _log.info(
                "vr.android.react_native_extract target=%s — no RN bundle in APK",
                target_id,
            )
            return
        new_keys: dict[str, Any] = {
            "android_mcp_rn_decompiled_dir": decompiled_dir,
            "android_mcp_rn_extract": {
                "bundles_found": len(bundles_found),
                "bundle_kinds": [b.get("kind") for b in bundles_found],
                "js_module_count": resp.get("js_module_count"),
                "sourcemap_used": resp.get("sourcemap_used"),
                "cache_hit": resp.get("cache_hit"),
            },
        }
        await self._merge_handles_locked(target_id, new_keys)
        _log.info(
            "vr.android.react_native_extract target=%s decompiled_dir=%s "
            "bundles=%d modules=%d sourcemap=%s cache_hit=%s",
            target_id, decompiled_dir, len(bundles_found),
            resp.get("js_module_count"), resp.get("sourcemap_used"),
            resp.get("cache_hit"),
        )

    async def _android_index_decompiled(
        self,
        target_id: str,
        descriptor: dict[str, Any],
        current_handles: dict[str, Any],
        tracker: StageTracker,
    ) -> None:
        """Build ONE audit-mcp index over both the jadx Java tree AND
        the React Native JS decompile (when present).

        Personas see a single ``audit_mcp_decompiled_index_id`` whose
        semantic_search / read_function / callers_of span both
        languages. No prompt-side index-id juggling, no bridge fan-out
        — audit-mcp's own FastIndexer recognises ``.java`` / ``.kt`` /
        ``.js`` / ``.jsx`` / ``.ts`` / ``.tsx`` by extension and the
        ``language="auto"`` switch turns on multi-language detection.

        Implementation: builds a per-target staging dir at
        ``~/.android-mcp/work/apk-unified-<sha[:16]>/`` and drops a
        junction (Windows) or symlink (POSIX) into it pointing at each
        source tree:

            staging/java/   -> jadx output (always, when jadx ran)
            staging/react/  -> RN decompile (only when bundle present)

        audit-mcp's FastIndexer recurses through the links; the
        combined index has functions, call-graphs, embeddings spanning
        both languages. Junctions are zero-copy and free on disk.

        Soft-skips when neither java nor react dir is present.
        """
        del tracker  # dispatch contract; state owned by _run_android_stage
        apk_path = self._resolve_apk_path(descriptor)
        java_dir = current_handles.get("android_mcp_decompiled_dir")
        react_dir = current_handles.get("android_mcp_rn_decompiled_dir")
        # The apktool extract holds AndroidManifest.xml + res/ + smali —
        # MSTG-ARCH-* audits literally need to read the manifest, and
        # MSTG-PLATFORM / MSTG-STORAGE audits need res/xml/ +
        # res/values/. audit-mcp's FastIndexer skips non-source files
        # by extension so junctioning the dir adds zero index nodes,
        # but `read_lines` walks any file under the index root — so
        # manifest + resources become reachable via the same index_id
        # the personas already use. Without this an ARCH-1 audit dies
        # on `read_lines: file_path escapes index root`.
        apktool_dir = current_handles.get("android_mcp_decoded_dir")
        if not (isinstance(java_dir, str) and java_dir) and \
           not (isinstance(react_dir, str) and react_dir):
            await self._merge_handles_locked(
                target_id,
                {"audit_mcp_decompiled_index": {
                    "skipped": "no jadx or rn output",
                }},
            )
            _log.warning(
                "vr.android.index_decompiled target=%s apk=%s skipped — "
                "no java or react decompile dir in handles",
                target_id, apk_path,
            )
            return

        # Build the unified staging dir. Cache-key on the APK sha so a
        # re-run on the same APK reuses the same staging path (the
        # junctions inside re-resolve to the current jadx + rn dirs).
        apk_sha = current_handles.get("android_mcp_apk_sha256") or \
            _hash_path_for_cache(apk_path)
        staging = await asyncio.to_thread(
            _build_unified_staging,
            apk_sha=str(apk_sha),
            java_dir=java_dir if isinstance(java_dir, str) else None,
            react_dir=react_dir if isinstance(react_dir, str) else None,
            apktool_dir=apktool_dir if isinstance(apktool_dir, str) else None,
        )

        # Probe the staging dir for present source extensions and pass
        # the union of languages explicitly. Passing ``auto`` lets
        # trailmark's detect_languages drop minority languages (an
        # APK's 691 decompiled JS slices lose to its 13k Java classes
        # + 45k smali files, so .js gets filtered out and the cached
        # Java-only graph is returned). Anything the staging actually
        # contains we want indexed, regardless of count, so Kotlin
        # source / native JNI / TypeScript bundles all show up too.
        langs = _detect_staging_languages(Path(staging))
        kickoff = await self._audit_mcp.forward(
            action="index_codebase",
            path=staging,
            language=",".join(langs) if langs else "auto",
        )
        if not isinstance(kickoff, dict) or kickoff.get("status") == "error":
            err = kickoff.get("error") if isinstance(kickoff, dict) else kickoff
            raise TargetAnalysisError(
                f"audit_mcp.index_codebase (unified) failed: {err}",
            )
        index_id = (
            kickoff.get("index_id")
            or (kickoff.get("data") or {}).get("index_id")
        )
        if not index_id:
            raise TargetAnalysisError(
                f"audit_mcp.index_codebase returned no index_id: {kickoff!r}",
            )

        # fix §270 — long-tail audit-mcp indexing on a unified Java +
        # React tree can run for hours, bounded by _POLL_TIMEOUT_SECONDS
        # (default 4h, operator-overridable via VR_INGESTION_POLL_TIMEOUT_S).
        # Inline poll at 60s intervals — see prior §270 fallback note.
        await self._poll_audit_mcp(index_id, interval_s=60.0)

        await self._merge_handles_locked(target_id, {
            "audit_mcp_decompiled_index_id": index_id,
            "audit_mcp_decompiled_indexed_at": utc_now().isoformat(),
            "audit_mcp_unified_staging_dir": staging,
        })
        _log.info(
            "vr.android.index_decompiled target=%s apk=%s index_id=%s "
            "staging=%s java=%s react=%s",
            target_id, apk_path, index_id, staging,
            bool(java_dir), bool(react_dir),
        )

    async def _android_static_summary(
        self,
        target_id: str,
        descriptor: dict[str, Any],
        current_handles: dict[str, Any],
        tracker: StageTracker,
    ) -> None:
        del current_handles, tracker  # dispatch contract; consumed by sibling stages
        apk_path = self._resolve_apk_path(descriptor)
        resp = await self._android_mcp.forward(
            action="androguard_summary", apk_path=apk_path,
        )
        if not isinstance(resp, dict) or resp.get("status") == "error":
            err = resp.get("error") if isinstance(resp, dict) else resp
            raise TargetAnalysisError(
                f"android-mcp.androguard_summary failed: {err}",
            )
        # fix §268 — the full androguard summary (manifest XML, full
        # permission list, every certificate fingerprint, every
        # exported-component class name) can hit 1-2 MB on real APKs.
        # Embedding it verbatim in ``mcp_handles_json`` made every
        # /vr/targets list request parse + serialize the blob, and
        # bloated worker logs that echo the row state. Persist to a
        # content-addressed artifact under ``VR_TARGET_ARTIFACT_DIR``
        # and keep only the digest + pointer inline. The PDF renderer
        # and any other full-payload consumer pulls the file via
        # ``load_target_artifact_payload``.
        artifact_ref = _write_target_artifact(
            target_id, "static_summary", resp,
        )
        digest = _static_summary_digest_fields(resp)
        inline_ref: dict[str, Any] = {**artifact_ref, **digest}
        new_keys: dict[str, Any] = {"android_mcp_static_summary": inline_ref}
        package = resp.get("package")
        if isinstance(package, str) and package:
            # Mirror the existing uploaded_filename pattern so the
            # frontend display name can fall back to the package id
            # once STATIC_SUMMARY completes (PRD §C-21).
            new_keys["android_mcp_package_name"] = package
        # fix §240 — locked merge so parallel group-1 stages don't
        # overwrite each other's disjoint keys.
        await self._merge_handles_locked(target_id, new_keys)
        _log.info(
            "vr.android.static_summary target=%s package=%s permissions=%d "
            "artifact=%s size=%d",
            target_id, package,
            len(resp.get("permissions") or []),
            artifact_ref["_artifact_path"], artifact_ref["_artifact_size"],
        )

    async def _android_mobsf_scan(
        self,
        target_id: str,
        descriptor: dict[str, Any],
        current_handles: dict[str, Any],
        tracker: StageTracker,
    ) -> None:
        """MobSF static scan. Skipped when MOBSF_API_KEY is unset.

        fix §269 — MobSF output is multi-MB (every code/manifest
        finding plus tracker fingerprints plus the original mapped
        APK upload metadata) and is operator-mandated off-policy for
        LLM prompts (see ``android_mcp_bridge._PIPELINE_ONLY_TOOLS``
        comment). Persist the full payload to
        ``VR_TARGET_ARTIFACT_DIR/{target_id}/mobsf_scan.json`` and
        keep an inline digest + pointer with an explicit
        ``prompt_safe=False`` marker so any future prompt-builder
        that lands on this key has an unambiguous denial in shape.
        """
        del current_handles, tracker  # dispatch contract; consumed by sibling stages
        mobsf_api_key = os.environ.get("MOBSF_API_KEY", "").strip()
        if not mobsf_api_key:
            _log.info(
                "vr.android.mobsf_scan target=%s skipped (MOBSF_API_KEY unset)",
                target_id,
            )
            # fix §240 — locked merge.
            # Skipped stage stays inline (no artifact written) — the
            # ``skipped``/``reason`` fields are operator-display only
            # and tiny enough to keep on the row. ``prompt_safe=False``
            # still applies in case a future renderer treats skipped
            # MobSF as a value to project.
            await self._merge_handles_locked(target_id, {
                "android_mcp_mobsf_scan": {
                    "skipped": True,
                    "reason": "MOBSF_API_KEY env var not set on the AILA host",
                    "prompt_safe": False,
                },
            })
            return

        apk_path = self._resolve_apk_path(descriptor)
        resp = await self._android_mcp.forward(
            action="mobsf_scan", apk_path=apk_path, _agent_bypass=True,
        )
        if not isinstance(resp, dict) or resp.get("status") == "error":
            err = resp.get("error") if isinstance(resp, dict) else resp
            raise TargetAnalysisError(
                f"android-mcp.mobsf_scan failed: {err}",
            )
        artifact_ref = _write_target_artifact(
            target_id, "mobsf_scan", resp,
        )
        digest = _mobsf_digest_fields(resp)
        inline_ref: dict[str, Any] = {
            **artifact_ref,
            **digest,
            # Explicit prompt-safe marker — load-bearing for D-100.
            # MobSF output must NEVER reach LLM prompts. The marker
            # makes intent unmistakable for the prompt builder and
            # any future tool that surfaces the inline handle.
            "prompt_safe": False,
        }
        scan_hash = resp.get("_scan_hash")
        if scan_hash is not None:
            inline_ref["_scan_hash"] = scan_hash
        # fix §240 — locked merge so parallel group-1 stages don't
        # overwrite each other's disjoint keys.
        await self._merge_handles_locked(
            target_id, {"android_mcp_mobsf_scan": inline_ref},
        )
        _log.info(
            "vr.android.mobsf_scan target=%s scan_hash=%s artifact=%s size=%d",
            target_id, scan_hash,
            artifact_ref["_artifact_path"], artifact_ref["_artifact_size"],
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

    async def _poll_audit_mcp(
        self, index_id: str, interval_s: float | None = None,
    ) -> None:
        """Poll ``audit_mcp.poll_index`` until READY / FAILED / timeout.

        ``interval_s`` overrides the default ``_POLL_INTERVAL_SECONDS``
        (3.0). The override exists for §270 — long-tail audit-mcp
        indexing (decompiled APK Java trees in particular: trailmark +
        semble cold-build on a ~100k-class jadx output can run for
        hours) is still bound by ``_POLL_TIMEOUT_SECONDS`` (default 4h)
        but doesn't need a 3-second poll cadence the entire way. A 60s
        cadence cuts the per-call HTTP traffic to audit-mcp by 20x and
        keeps log noise proportional to the wait.
        """
        sleep_for = interval_s if interval_s is not None else _POLL_INTERVAL_SECONDS
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
            await asyncio.sleep(sleep_for)
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

