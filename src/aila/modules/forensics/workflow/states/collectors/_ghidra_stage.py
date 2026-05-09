"""Ghidra-headless post-processing stage for the binary_analysis lane.

For every suspicious PE / ELF sample the discovery script has already
written into ``%TEMP%\\aila_ba\\<sha8>\\<sha12>_<basename>`` on the
analyzer, this module runs two Ghidra headless passes:

1. ``ListFunctions.java``           — enumerate all functions with address + size
2. ``ExportDecompilationJson.java`` — decompile the top 200 by size, cap each at 8000 chars

Both pass results become ``binary_analysis`` artifacts the investigator
can query through ``artifact_query`` — no need for the LLM to invoke
``analyzeHeadless.bat`` by hand. The stage also computes a deterministic
``summary`` that buckets imports/callees by intent (execution / network /
crypto / persistence / injection / anti-debug / filesystem) so the
agent can steer to the interesting functions without reading the full
decompilation up front.

Design invariants
-----------------
* Stage is OFF the hot path — runs after the main discovery JSON has
  been parsed and one artifact per sample has already been emitted.
* Scratch file path is derived from the discovery script's naming
  scheme, so we never re-extract from the disk image here.
* Static analysis only — no execution of the sample.
* One isolated project dir per sha (so Ghidra's "project already exists"
  never fires and samples don't collide).
* Per-sample 900 s wall-clock cap; failure emits an event and continues
  to the next sample instead of aborting the lane.
* Cache by (sha256, "ghidra_decompilation", "ghidra") via the
  ``on_artifact`` dispatcher's ``already_collected`` set — second run
  on the same image short-circuits.
"""
from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

from aila.platform.exceptions import AILAError

from ._helpers import safe_emit

__all__ = ["run_ghidra_on_sample", "MAX_BINARY_SIZE_BYTES", "PER_SAMPLE_TIMEOUT_S"]

_log = logging.getLogger(__name__)

# Ghidra struggles beyond ~60 MB — the auto-analysis step can easily blow
# past the wall-clock budget on a single sample. Skip anything larger.
MAX_BINARY_SIZE_BYTES = 60 * 1024 * 1024

PER_SAMPLE_TIMEOUT_S = 900.0

# Intent buckets for the deterministic summary. Substring match
# (case-insensitive) against the import name + function name set.
_INTENT_BUCKETS: dict[str, tuple[str, ...]] = {
    "execution": (
        "createprocess", "winexec", "shellexecute", "system", "execve",
        "fork", "posix_spawn", "cmd.exe", "/bin/sh",
    ),
    "network": (
        "wsasocket", "wsastartup", "connect", "send", "recv", "accept",
        "bind", "listen", "gethostbyname", "getaddrinfo",
        "internetopen", "internetconnect", "internetreadfile",
        "httpsendrequest", "winhttp", "urldownloadtofile",
        "curl_easy", "socket", "sendto", "recvfrom",
    ),
    "crypto": (
        "cryptacquire", "cryptimport", "cryptdecrypt", "cryptencrypt",
        "cryptcreatehash", "crypthashdata",
        "bcryptencrypt", "bcryptdecrypt", "bcryptopenalgorithm",
        "evp_encryptinit", "evp_decryptinit", "evp_cipherinit",
        "aes_encrypt", "aes_decrypt", "rsa_public_encrypt",
        "sha256", "md5_init", "hmac_init",
    ),
    "persistence": (
        "regcreatekey", "regsetvalue", "regopenkey", "createservice",
        "startservicectrl", "schtasks", "createscheduledtask",
        "autorun", "runonce", "currentversion\\run", "userinit",
    ),
    "injection": (
        "virtualallocex", "virtualprotectex", "writeprocessmemory",
        "readprocessmemory", "createremotethread", "createthread",
        "ntcreatethreadex", "ntmapviewofsection", "ntunmapviewofsection",
        "queueuserapc", "nttestalert", "setwindowshookex",
        "setthreadcontext", "getthreadcontext", "resumethread",
        "zwcreatesection", "rtlcreateuserthread",
    ),
    "filesystem": (
        "createfile", "movefile", "deletefile", "copyfile", "findfirstfile",
        "fopen", "fwrite", "fread", "open", "close", "unlink",
        "mkdir", "rmdir", "chmod", "chown",
    ),
    "registry": (
        "regcreate", "regdelete", "regenum", "regquery", "regopen",
    ),
    "anti_debug": (
        "isdebuggerpresent", "checkremotedebuggerpresent",
        "ntqueryinformationprocess", "outputdebugstring",
        "getticktick", "queryperformancecounter",
        "findwindow", "processhollowing",
    ),
    "privilege": (
        "adjusttokenprivileges", "lookupprivilegevalue", "openprocesstoken",
        "impersonate", "seimpersonate", "sedebug", "setuid",
    ),
}

# JSON sentinel markers — must match ExportDecompilationJson.java.
_JSON_BEGIN = "AILA_GHIDRA_JSON_BEGIN"
_JSON_END = "AILA_GHIDRA_JSON_END"

_FUNC_LIST_RE = re.compile(
    r"^FUNC\s+(?P<addr>\S+)\s+(?P<name>\S+)\s+size=(?P<size>\d+)\s*$",
    re.MULTILINE,
)


def _sq_win(path: str) -> str:
    """Quote a path for Windows cmd / SSH."""
    return f'"{path}"'


def _extract_json_blob(stdout: str) -> dict[str, Any] | None:
    """Pull the ExportDecompilationJson payload out of mixed stdout."""
    if _JSON_BEGIN not in stdout or _JSON_END not in stdout:
        return None
    try:
        body = stdout.split(_JSON_BEGIN, 1)[1].split(_JSON_END, 1)[0].strip()
    except (IndexError, ValueError):
        return None
    if not body:
        return None
    try:
        return json.loads(body)
    except (json.JSONDecodeError, ValueError) as exc:
        _log.debug("ghidra json parse failed: %s (body head=%r)", exc, body[:200])
        return None


def _parse_function_list(stdout: str) -> list[dict[str, Any]]:
    """Parse ListFunctions.java output into rows."""
    rows: list[dict[str, Any]] = []
    for m in _FUNC_LIST_RE.finditer(stdout):
        try:
            rows.append({
                "address": m.group("addr"),
                "name": m.group("name"),
                "size": int(m.group("size")),
            })
        except (TypeError, ValueError):
            continue
    return rows


def _collect_import_names(sample: dict[str, Any]) -> list[str]:
    """Flatten PE/ELF import names out of the discovery artifact's payload."""
    names: list[str] = []
    pe = sample.get("pe") or {}
    for entry in pe.get("imports") or []:
        for name in entry.get("imports") or []:
            names.append(name)
    elf = sample.get("elf") or {}
    for name in elf.get("symbols_sample") or []:
        names.append(name)
    return names


def _classify_intent(
    import_names: list[str],
    function_rows: list[dict[str, Any]],
) -> dict[str, list[str]]:
    """Bucket import + function names into intent groups (substring match)."""
    haystack: list[str] = []
    for n in import_names:
        if n:
            haystack.append(n)
    for r in function_rows:
        nm = r.get("name") or ""
        if nm:
            haystack.append(nm)

    buckets: dict[str, list[str]] = {k: [] for k in _INTENT_BUCKETS}
    seen_per_bucket: dict[str, set[str]] = {k: set() for k in _INTENT_BUCKETS}
    for item in haystack:
        low = item.lower()
        for bucket, needles in _INTENT_BUCKETS.items():
            for needle in needles:
                if needle in low and item not in seen_per_bucket[bucket]:
                    buckets[bucket].append(item)
                    seen_per_bucket[bucket].add(item)
                    break
    # Cap each bucket so the summary stays prompt-friendly.
    return {k: v[:60] for k, v in buckets.items() if v}


def _summarise(
    total_functions: int,
    function_rows: list[dict[str, Any]],
    decomp_rows: list[dict[str, Any]],
    import_names: list[str],
) -> dict[str, Any]:
    # Top functions by size — useful to orient an analyst / agent.
    top_by_size = sorted(
        function_rows, key=lambda r: int(r.get("size") or 0), reverse=True,
    )[:40]
    intent = _classify_intent(import_names, function_rows)
    return {
        "total_functions": total_functions,
        "functions_with_c_source": len(decomp_rows),
        "top_functions_by_size": [
            {"address": r.get("address"), "name": r.get("name"), "size": r.get("size")}
            for r in top_by_size
        ],
        "intent_map": intent,
        "intent_bucket_counts": {k: len(v) for k, v in intent.items()},
    }


def _is_signed_hint(sample: dict[str, Any]) -> bool:
    """Best-effort signed hint from prior tooling output.

    The discovery script doesn't run signtool directly; we look at two
    secondary signals it does produce:
      - ``pe.imports`` includes ``WINTRUST.DLL`` → verification surface
        but NOT proof of signing.
      - ``strings_sample`` contains an Authenticode OID signature.
    The honest default is "unsigned" — we'd rather run Ghidra once too
    often than skip it on a trojanised binary that ships a stolen cert.
    """
    strings = sample.get("strings_sample") or []
    for s in strings:
        if isinstance(s, str) and ("1.3.6.1.4.1.311.2.1" in s or "Microsoft Code Signing" in s):
            return True
    return False


async def _run_analyzer_cmd(
    ssh: Any, integration: dict, cmd: str, timeout_s: float,
) -> tuple[str, int]:
    """Run a Windows-analyzer command; return (stdout, exit_code)."""
    try:
        stdout = await ssh.run_command(integration, cmd, timeout_seconds=timeout_s)
        return stdout or "", 0
    except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
        _log.debug("ghidra analyzer cmd failed: %s", exc)
        return f"[error] {exc}", 1


async def _scratch_file_exists(
    ssh: Any, integration: dict, path: str,
) -> bool:
    cmd = f'if exist "{path}" (echo YES) else (echo NO)'
    out, _ = await _run_analyzer_cmd(ssh, integration, cmd, timeout_s=10.0)
    return "YES" in (out or "")


async def run_ghidra_on_sample(
    ssh: Any,
    integration: dict,
    sample: dict[str, Any],
    emitter: Any,
    on_artifact: Any,
    already_collected: set | None = None,
) -> list[dict[str, Any]]:
    """Run the two Ghidra passes on one discovery result and emit artifacts.

    ``sample`` is one dict from ``payload["results"]`` produced by the
    discovery script inside ``binary_analysis.py``. Must contain at
    least: ``sha256``, ``size``, ``filetype``, ``basename``.
    """
    sha = (sample.get("sha256") or "").strip()
    filetype = (sample.get("filetype") or "").lower()
    size = int(sample.get("size") or 0)
    basename = sample.get("basename") or "sample.bin"

    if not sha:
        await safe_emit(emitter, "ghidra_stage_skipped",
                        f"ghidra: skipped {basename} — no sha256 on record",
                        {"basename": basename, "reason": "no_sha256"})
        return []
    if filetype not in ("pe", "elf"):
        await safe_emit(emitter, "ghidra_stage_skipped",
                        f"ghidra: skipped {basename} — filetype={filetype}",
                        {"sha256": sha, "basename": basename,
                         "reason": "filetype_not_pe_or_elf", "filetype": filetype})
        return []
    if size <= 0 or size > MAX_BINARY_SIZE_BYTES:
        await safe_emit(emitter, "ghidra_stage_skipped",
                        f"ghidra: skipped {basename} — size {size:,}B exceeds cap",
                        {"sha256": sha, "basename": basename,
                         "reason": "size_over_cap", "size": size,
                         "cap": MAX_BINARY_SIZE_BYTES})
        return []
    if _is_signed_hint(sample):
        await safe_emit(emitter, "ghidra_stage_skipped",
                        f"ghidra: skipped {basename} — looks signed",
                        {"sha256": sha, "basename": basename, "reason": "signed_hint"})
        return []

    cache_key = (None, "ghidra_decompilation", "ghidra")
    if already_collected is not None:
        # Dispatcher tracks by (source_evidence_id, artifact_type, source_tool).
        # We don't have an evidence-id scoped cache here — the dispatcher
        # will still collapse duplicates per-evidence via that tuple — but
        # we add an in-process guard keyed by sha256 to avoid double-runs
        # within the same collection pass.
        sha_key = ("__ghidra_sha__", sha)
        if sha_key in already_collected:
            await safe_emit(emitter, "ghidra_stage_skipped",
                            f"ghidra: skipped {basename} — already analyzed in this pass",
                            {"sha256": sha, "reason": "sha_cached_in_pass"})
            return []
        already_collected.add(sha_key)
        del cache_key  # kept for intent; not used here

    scratch = rf"%TEMP%\aila_ba\{sha[:2]}\{sha[:12]}_{basename}"
    project_dir = rf"%TEMP%\aila_gh\{sha[:8]}"
    script_dir = r"%TEMP%\aila_ghidra_scripts"
    headless = r'"C:\Tools\ghidra\support\analyzeHeadless.bat"'

    if not await _scratch_file_exists(ssh, integration, scratch):
        await safe_emit(emitter, "ghidra_stage_skipped",
                        f"ghidra: skipped {basename} — scratch file missing at {scratch}",
                        {"sha256": sha, "basename": basename,
                         "reason": "scratch_missing", "scratch": scratch})
        return []

    await _run_analyzer_cmd(
        ssh, integration,
        f'if not exist "{project_dir}" mkdir "{project_dir}"',
        timeout_s=15.0,
    )

    # Upload the Java scripts on first use (idempotent — the helper
    # checks per-file existence too). This reuses the shared uploader
    # that ``tools/ghidra_runner.py`` already defined, so any future
    # script additions go there and are automatically picked up here.
    from aila.modules.forensics.tools.ghidra_runner import (
        _ensure_ghidra_scripts_uploaded,
    )
    try:
        await _ensure_ghidra_scripts_uploaded(
            ssh, integration, script_dir, analyzer_os="windows",
        )
    except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
        await safe_emit(emitter, "ghidra_stage_failed",
                        f"ghidra: {basename} — script upload failed: {exc}",
                        {"sha256": sha, "basename": basename,
                         "error": str(exc)[:400]})
        return []

    await safe_emit(emitter, "ghidra_stage_begin",
                    f"ghidra: {basename} sha={sha[:12]} size={size:,}B",
                    {"sha256": sha, "basename": basename, "size": size,
                     "filetype": filetype})

    artifacts: list[dict[str, Any]] = []

    # --- Pass 1: list functions ------------------------------------------
    list_cmd = (
        f'{headless} "{project_dir}" prj -import "{scratch}" '
        f'-overwrite -readOnly -scriptPath "{script_dir}" '
        f'-postScript ListFunctions.java'
    )
    t0 = time.monotonic()
    out_list, rc_list = await _run_analyzer_cmd(
        ssh, integration, list_cmd, timeout_s=PER_SAMPLE_TIMEOUT_S,
    )
    func_elapsed = round(time.monotonic() - t0, 1)
    function_rows = _parse_function_list(out_list)

    if not function_rows:
        await safe_emit(emitter, "ghidra_list_functions_empty",
                        f"ghidra: {basename} — list_functions returned 0 rows (rc={rc_list}, elapsed={func_elapsed}s)",
                        {"sha256": sha, "basename": basename,
                         "exit_code": rc_list, "elapsed_s": func_elapsed,
                         "stderr_tail": out_list[-600:]})
        return []  # if we can't even enumerate functions, decomp is pointless

    total_functions = len(function_rows)
    await safe_emit(emitter, "ghidra_list_functions_done",
                    f"ghidra: {basename} — {total_functions} functions in {func_elapsed}s",
                    {"sha256": sha, "basename": basename,
                     "function_count": total_functions, "elapsed_s": func_elapsed})

    functions_art = {
        "family": "binary_analysis",
        "type": "ghidra_functions",
        "source_tool": "ghidra",
        "data": {
            "sha256": sha,
            "basename": basename,
            "scratch_path": scratch,
            "function_count": total_functions,
            "records": function_rows,
        },
    }
    artifacts.append(functions_art)
    if on_artifact:
        await on_artifact(functions_art)

    # --- Pass 2: export decompilation ------------------------------------
    # Reuse the same project dir — Ghidra will pick up the analysis it
    # just ran instead of re-analyzing. The -import flag is idempotent
    # alongside -overwrite.
    decomp_cmd = (
        f'{headless} "{project_dir}" prj -process "{scratch}" '
        f'-readOnly -scriptPath "{script_dir}" '
        f'-postScript ExportDecompilationJson.java'
    )
    t1 = time.monotonic()
    out_decomp, rc_decomp = await _run_analyzer_cmd(
        ssh, integration, decomp_cmd, timeout_s=PER_SAMPLE_TIMEOUT_S,
    )
    decomp_elapsed = round(time.monotonic() - t1, 1)

    blob = _extract_json_blob(out_decomp)
    decomp_rows: list[dict[str, Any]] = []
    if blob:
        funcs = blob.get("functions") or []
        if isinstance(funcs, list):
            decomp_rows = [r for r in funcs if isinstance(r, dict)]

    if not decomp_rows:
        await safe_emit(emitter, "ghidra_decompilation_empty",
                        f"ghidra: {basename} — decompilation produced 0 rows (rc={rc_decomp}, elapsed={decomp_elapsed}s)",
                        {"sha256": sha, "basename": basename,
                         "exit_code": rc_decomp, "elapsed_s": decomp_elapsed,
                         "stderr_tail": out_decomp[-600:]})
        # Still emit a decompilation artifact so the UI can show the
        # failure; empty records[] is a legitimate state.
    else:
        await safe_emit(emitter, "ghidra_decompilation_done",
                        f"ghidra: {basename} — decompiled {len(decomp_rows)} function(s) in {decomp_elapsed}s",
                        {"sha256": sha, "basename": basename,
                         "records_stored": len(decomp_rows),
                         "elapsed_s": decomp_elapsed})

    import_names = _collect_import_names(sample)
    summary = _summarise(
        total_functions=total_functions,
        function_rows=function_rows,
        decomp_rows=decomp_rows,
        import_names=import_names,
    )

    decomp_art = {
        "family": "binary_analysis",
        "type": "ghidra_decompilation",
        "source_tool": "ghidra",
        "data": {
            "sha256": sha,
            "basename": basename,
            "scratch_path": scratch,
            "records": decomp_rows,
            "summary": summary,
            "elapsed_s": decomp_elapsed,
            "list_elapsed_s": func_elapsed,
        },
    }
    artifacts.append(decomp_art)
    if on_artifact:
        await on_artifact(decomp_art)

    # Best-effort cleanup: drop the project dir so the next run on a
    # different sha doesn't carry state. We keep the scripts around.
    await _run_analyzer_cmd(
        ssh, integration,
        f'rmdir /s /q "{project_dir}" 2>nul',
        timeout_s=15.0,
    )

    return artifacts
