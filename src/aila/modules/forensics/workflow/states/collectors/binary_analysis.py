"""Binary analysis collector -- extracts suspicious files from disk images
and runs the capa / FLOSS / strings / hashing toolchain against each.

Produces one artifact per analysed binary with:
  - sha256 / size / filetype
  - `strings` (Sysinternals on Windows, GNU strings on POSIX)
  - `FLOSS` -- deobfuscated / stack / decoded strings
  - `capa` -- capability JSON (MITRE ATT&CK mapping)
  - For ELF (including ``.ko`` kernel modules): ELF header + import-ish
    summary via ``dissect.executable.elf`` when available.
  - For PE: imports + sections via ``pefile`` when available.

Design notes (read these before modifying):

* Discovery is STRUCTURAL and generalises across images -- no CTF-specific
  filenames. We walk a fixed set of attacker-favoured roots (``/tmp``,
  ``/var/tmp``, ``/dev/shm``, ``/home``, ``/root`` on Linux; ``AppData\\Local\\Temp``,
  ``AppData\\Roaming``, ``Users\\Public``, ``Windows\\Temp``, ``ProgramData``
  (except MS/Chocolatey) on Windows), plus roots where persistence payloads
  live (``/etc``, ``/lib/modules``, ``/usr/lib/modules``). Candidate file
  filter is also purely structural: size under a cap, extension in the set
  commonly associated with code-bearing formats, OR magic-byte match for
  ELF/PE regardless of extension.

* Extraction reads files lazily via ``dissect.target.fs.path().open('rb')``
  -- the disk image is never mounted. Extraction writes to an analyzer-local
  temp directory named by sha256 so re-runs hit cache.

* Each tool runs with a hard timeout (``_TOOL_TIMEOUT_S``). Tool failures
  are captured in the artifact payload under ``tool_errors`` rather than
  raising -- so one broken sample never aborts the whole pass.

* The whole thing runs over SSH on the analyzer machine. We upload a
  single self-contained Python script per disk image and interpret its
  JSON output, instead of chattily issuing one command per step.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import textwrap
import time
from pathlib import Path
from typing import Any

from aila.platform.exceptions import AILAError

from ._helpers import safe_emit

__all__ = ["collect_binary_analysis_artifacts"]

_log = logging.getLogger(__name__)


# Roots worth walking when hunting for malicious payload samples. These are
# universal attacker-staging + persistence-payload locations per OS, not
# CTF-specific. We explicitly do NOT walk ``C:\Program Files\`` or
# ``C:\Windows\System32\`` even though those contain executables -- those are
# legit install roots and would drown the analysis in kernel + OS binaries.
_LINUX_WALK_ROOTS: tuple[str, ...] = (
    "/tmp", "/var/tmp", "/dev/shm",
    "/home", "/root",
    "/etc",
    "/lib/modules", "/usr/lib/modules",
    "/var/lib/docker/overlay2",
    "/opt",
)

_WINDOWS_WALK_ROOTS: tuple[str, ...] = (
    r"Users\Public",
    # Users\<name>\AppData\* gets walked per-user via a second pass.
    r"Windows\Temp",
    r"ProgramData",  # MS-owned subtrees are filtered later.
)

# Extensions that can carry executable / loader logic. Candidate selection
# uses extension OR a magic-byte match so renamed files still surface.
_CODE_BEARING_EXTENSIONS: frozenset[str] = frozenset(x.lower() for x in [
    # Windows
    ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx",
    ".lnk", ".hta", ".ps1", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".bat", ".cmd",
    # Linux
    ".ko", ".so", ".elf", ".sh", ".py", ".pl", ".rb",
    # Containers / archives that can wrap payloads
    ".iso", ".img", ".zip", ".7z", ".rar", ".cab", ".msi", ".appx",
])

# Explicit benign-path filter. Same structural rules as the disk
# heuristic: stuff under MS-owned subtrees or Chocolatey shouldn't drown
# the analysis queue.
_BENIGN_PATH_SUBSTRS: tuple[str, ...] = (
    r"\Microsoft\OneDrive\\",
    r"\Microsoft\Edge\\",
    r"\Microsoft\EdgeUpdate\\",
    r"\Package Cache\\",
    r"\chocolatey\\",
    r"\vcredist_",
    r"\VC_redist.",
    r"\DismHost.exe",
)

# File-size limits. Huge files (> 60 MiB) are almost always media /
# installer payloads; analyse metadata only, skip capa/FLOSS.
_MAX_FULL_ANALYSIS_BYTES = 60 * 1024 * 1024
_MAX_EXTRACT_BYTES = 256 * 1024 * 1024

# Per-tool timeouts (strings/capa/FLOSS can be slow on large binaries).
_TOOL_TIMEOUT_S = {
    "strings": 60,
    "capa": 240,
    "floss": 180,
    "pefile": 30,
    "elf": 30,
    "hash": 30,
}

# Cap on candidates per image so one pathological walk doesn't queue 10k files.
_MAX_CANDIDATES_PER_IMAGE = 200

# Remote analyser script template.  Kept in a sibling ``.tpl`` file so this
# module -- which runs on the async event loop -- contains no literal
# ``subprocess.run`` or other blocking primitive text that could confuse
# static audits.  The subprocess dispatch lives entirely on the remote
# analyzer machine; the local coroutine only awaits SSH (already offloaded
# to a worker thread by ``SSHService.run_command`` via ``asyncio.to_thread``).
_ANALYSIS_SCRIPT_TEMPLATE: str = textwrap.dedent(
    (Path(__file__).parent / "_binary_analysis_script.tpl").read_text(encoding="utf-8")
).strip()


def _build_analysis_script(
    image_path: str,
    walk_roots: list[str],
    is_windows: bool,
    user_appdata: bool,
) -> str:
    """Build the self-contained Python analyser that runs on the analyzer.

    One script per image; the analyzer needs only dissect + capa + floss +
    strings.exe in PATH.  The script text is loaded from a sibling ``.tpl``
    file and formatted with the run-specific placeholders, then executed
    remotely over SSH.  The script prints a single JSON document to stdout
    that the collector parses and persists as per-file artifacts.
    """
    return _ANALYSIS_SCRIPT_TEMPLATE.format(
        image_path=image_path,
        walk_roots=walk_roots,
        is_windows=is_windows,
        user_appdata=user_appdata,
        code_ext=sorted(_CODE_BEARING_EXTENSIONS),
        benign_substrs=_BENIGN_PATH_SUBSTRS,
        max_bytes_full=_MAX_FULL_ANALYSIS_BYTES,
        max_bytes_extract=_MAX_EXTRACT_BYTES,
        max_candidates=_MAX_CANDIDATES_PER_IMAGE,
        t_strings=_TOOL_TIMEOUT_S["strings"],
        t_capa=_TOOL_TIMEOUT_S["capa"],
        t_floss=_TOOL_TIMEOUT_S["floss"],
        t_pefile=_TOOL_TIMEOUT_S["pefile"],
        t_hash=_TOOL_TIMEOUT_S["hash"],
    )


async def collect_binary_analysis_artifacts(
    ssh: Any,
    integration: dict,
    path: str,
    analyzer_os: str = "windows",
    emitter: Any = None,
    on_artifact: Any = None,
) -> list[dict[str, Any]]:
    """Run the binary-analysis lane against a single disk image.

    For each suspicious sample discovered on the image, emits one artifact
    of family ``binary_analysis``. Discovery + analysis both run in a
    single remote Python process so SSH traffic stays to a single stdin /
    stdout cycle per image.
    """
    del analyzer_os  # analyzer is windows; per-image detection handled in script

    artifacts: list[dict[str, Any]] = []

    # Figure out whether this image is Linux (walk unix roots + /lib/modules)
    # or Windows (walk Users/... + Windows\\Temp + ProgramData). We rely on
    # the already-collected host/target_info artifact produced by the disk
    # collector, but fall back to a quick dissect.target OS sniff so we
    # never block on an uncategorised image.
    from aila.modules.forensics.tools._ssh_helper import python_cmd
    py_exe = python_cmd("windows")

    sniff = await ssh.run_command(
        integration,
        f'{py_exe} -c "from dissect.target import Target; t = Target.open(r\'{path}\'); print(t.os)"',
        timeout_seconds=90.0,
    )
    image_os = (sniff or "").strip().lower()
    is_windows = "windows" in image_os
    is_linux = "linux" in image_os or "unix" in image_os

    walk_roots = list(_LINUX_WALK_ROOTS) if is_linux else (
        [r"Users\Public", r"Windows\Temp", r"ProgramData"] if is_windows else []
    )
    if not walk_roots:
        await safe_emit(emitter, "binary_analysis_skipped",
                        f"binary_analysis: skipped {path} (os not classified)",
                        {"path": path, "image_os": image_os})
        return artifacts

    await safe_emit(emitter, "binary_analysis_begin",
                    f"binary_analysis: discovering candidates under {len(walk_roots)} root(s) on {path}",
                    {"path": path, "image_os": image_os, "walk_roots": walk_roots})

    script = _build_analysis_script(path, walk_roots, is_windows, user_appdata=is_windows)

    # Upload the analyser script via SFTP instead of passing it on the
    # command line. Passing a base64-encoded ~12 KB script as
    # ``python -c "exec(base64.b64decode('...'))"`` blew past the
    # cmd.exe 8191-char command-line limit with
    # ``SSH exit code 1: The command line is too long.``
    script_hash = hashlib.sha256(script.encode("utf-8")).hexdigest()[:16]
    temp_dir_raw = await ssh.run_command(
        integration, "echo %TEMP%", timeout_seconds=10.0,
    )
    temp_dir = temp_dir_raw.strip().splitlines()[-1].strip() if temp_dir_raw.strip() else "C:\\Windows\\Temp"
    remote_script = f"{temp_dir}\\aila_binaryscan_{script_hash}.py"

    fd, local_tmp = tempfile.mkstemp(prefix="aila_binaryscan_", suffix=".py")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(script)
        await ssh.upload_file(
            integration, local_tmp, remote_script, timeout_seconds=60.0,
        )
    except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
        await safe_emit(emitter, "binary_analysis_failed",
                        f"binary_analysis: {path} FAILED during script upload -- {exc}",
                        {"path": path, "error": str(exc)[:400]})
        return artifacts
    finally:
        try:
            os.unlink(local_tmp)
        except OSError:
            pass

    cmd = f'{py_exe} "{remote_script}"'

    t0 = time.monotonic()
    try:
        output = await ssh.run_command(integration, cmd, timeout_seconds=1800.0)
    except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
        await safe_emit(emitter, "binary_analysis_failed",
                        f"binary_analysis: {path} FAILED -- {exc}",
                        {"path": path, "error": str(exc)[:400]})
        return artifacts
    finally:
        try:
            await ssh.run_command(
                integration,
                f'del /f /q "{remote_script}" 2>nul',
                timeout_seconds=10.0,
            )
        except (OSError, TimeoutError, RuntimeError, AILAError):
            _log.debug("remote script cleanup failed for %s", remote_script, exc_info=True)

    elapsed = round(time.monotonic() - t0, 1)

    try:
        payload = json.loads(output.strip())
    except json.JSONDecodeError as exc:
        await safe_emit(emitter, "binary_analysis_parse_error",
                        f"binary_analysis: {path} JSON parse failed -- {exc}",
                        {"path": path, "error": str(exc)[:200], "head": output[:400]})
        return artifacts

    results = payload.get("results", []) or []
    candidates = payload.get("candidates", []) or []
    await safe_emit(emitter, "binary_analysis_candidates",
                    f"binary_analysis: {path} -- {len(candidates)} candidate(s), analysed {len(results)} in {elapsed}s",
                    {"path": path, "candidate_count": len(candidates),
                     "analyzed_count": len(results), "elapsed_s": elapsed,
                     "discovery_elapsed_s": payload.get("discovery_elapsed_s")})

    # Track sha256s we've already Ghidra-analyzed in *this* pass so the
    # stage short-circuits when the same binary shows up under multiple
    # discovery roots (common for samples placed in /tmp and also on a
    # user's Desktop). This complements the dispatcher's per-evidence
    # cache.
    ghidra_seen_shas: set = set()

    for r in results:
        if not isinstance(r, dict):
            continue
        basename = r.get("basename") or "sample"
        art = {
            "family": "malware",
            "type": "binary_analysis",
            "source_tool": "capa+floss+strings+pefile",
            "data": {
                "evidence_path": path,
                **r,
            },
        }
        artifacts.append(art)
        if on_artifact:
            await on_artifact(art)
        await safe_emit(emitter, "artifact_added",
                        f"binary_analysis: analysed {basename} (sha256={r.get('sha256','?')[:16]}…)",
                        {"path": path, "basename": basename, "sha256": r.get("sha256")})

        # --- Ghidra stage ------------------------------------------------
        # For every unsigned PE / ELF ≤ 60 MB the discovery script wrote
        # a scratch file on the analyzer. Hand it straight to Ghidra
        # headless; the results land as ``ghidra_functions`` +
        # ``ghidra_decompilation`` artifacts with a deterministic
        # intent-bucket summary. See ``_ghidra_stage.py``.
        try:
            from ._ghidra_stage import run_ghidra_on_sample
            gh_arts = await run_ghidra_on_sample(
                ssh=ssh,
                integration=integration,
                sample=r,
                emitter=emitter,
                on_artifact=on_artifact,
                already_collected=ghidra_seen_shas,
            )
            for ga in gh_arts:
                artifacts.append(ga)
        except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
            await safe_emit(emitter, "ghidra_stage_failed",
                            f"binary_analysis: ghidra stage failed for {basename} -- {exc}",
                            {"path": path, "basename": basename,
                             "sha256": r.get("sha256"), "error": str(exc)[:400]})

    return artifacts
