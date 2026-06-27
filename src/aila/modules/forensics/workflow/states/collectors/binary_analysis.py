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


def _build_analysis_script(
    image_path: str,
    walk_roots: list[str],
    is_windows: bool,
    user_appdata: bool,
) -> str:
    """Build the self-contained Python analyser that runs on the analyzer.

    One script per image; the analyzer needs only dissect + capa + floss +
    strings.exe in PATH. The script prints a single JSON document to stdout
    that the collector parses and persists as per-file artifacts.
    """
    return textwrap.dedent(rf'''
        import sys, os, json, hashlib, subprocess, time, shutil, pathlib, tempfile
        sys.stdout.reconfigure(encoding="utf-8")
        from dissect.target import Target
        target = Target.open(r"{image_path}")

        WALK_ROOTS = {walk_roots!r}
        IS_WINDOWS = {is_windows!r}
        USER_APPDATA = {user_appdata!r}
        CODE_EXT = {sorted(_CODE_BEARING_EXTENSIONS)!r}
        BENIGN = {_BENIGN_PATH_SUBSTRS!r}
        MAX_BYTES_FULL = {_MAX_FULL_ANALYSIS_BYTES}
        MAX_BYTES_EXTRACT = {_MAX_EXTRACT_BYTES}
        MAX_CAND = {_MAX_CANDIDATES_PER_IMAGE}
        T_STRINGS = {_TOOL_TIMEOUT_S["strings"]}
        T_CAPA = {_TOOL_TIMEOUT_S["capa"]}
        T_FLOSS = {_TOOL_TIMEOUT_S["floss"]}
        T_PEFILE = {_TOOL_TIMEOUT_S["pefile"]}
        T_HASH = {_TOOL_TIMEOUT_S["hash"]}

        def _is_benign(p_str):
            s = p_str.replace("/", "\\\\").lower()
            return any(b.lower() in s for b in BENIGN)

        ELF_MAGIC = b"\\x7fELF"
        PE_MZ = b"MZ"
        def _magic_hit(data_head):
            return data_head.startswith(ELF_MAGIC) or data_head.startswith(PE_MZ)

        def _walk_for_candidates():
            cands = []
            seen = set()
            # Linux-style / Windows-absolute walk.
            for root in WALK_ROOTS:
                try:
                    rp = target.fs.path(root)
                except Exception:
                    continue
                if not rp.exists():
                    continue
                try:
                    it = rp.rglob("*")
                except Exception:
                    it = []
                for p in it:
                    try:
                        if not p.is_file():
                            continue
                        s = str(p)
                        if _is_benign(s):
                            continue
                        try:
                            size = p.stat().st_size
                        except Exception:
                            size = 0
                        if size == 0 or size > MAX_BYTES_EXTRACT:
                            continue
                        ext = os.path.splitext(s)[1].lower()
                        interesting = ext in CODE_EXT
                        if not interesting:
                            try:
                                with p.open("rb") as f:
                                    head = f.read(4)
                                if _magic_hit(head):
                                    interesting = True
                            except Exception:
                                pass
                        if not interesting:
                            continue
                        if s not in seen:
                            seen.add(s)
                            cands.append((s, size))
                        if len(cands) >= MAX_CAND:
                            return cands
                    except Exception:
                        continue

            # Windows per-user AppData walk for Users\*\AppData\{{Local\Temp,Roaming}}.
            if USER_APPDATA:
                try:
                    users_root = target.fs.path("Users")
                    if users_root.exists():
                        for u in users_root.iterdir():
                            if not u.is_dir():
                                continue
                            for sub in (r"AppData\\Local\\Temp", r"AppData\\Roaming"):
                                try:
                                    rp = target.fs.path(f"Users\\\\{{u.name}}\\\\{{sub}}")
                                except Exception:
                                    continue
                                if not rp.exists():
                                    continue
                                try:
                                    it = rp.rglob("*")
                                except Exception:
                                    continue
                                for p in it:
                                    try:
                                        if not p.is_file():
                                            continue
                                        s = str(p)
                                        if _is_benign(s):
                                            continue
                                        size = p.stat().st_size
                                        if size == 0 or size > MAX_BYTES_EXTRACT:
                                            continue
                                        ext = os.path.splitext(s)[1].lower()
                                        if ext not in CODE_EXT:
                                            try:
                                                with p.open("rb") as f:
                                                    head = f.read(4)
                                                if not _magic_hit(head):
                                                    continue
                                            except Exception:
                                                continue
                                        if s not in seen:
                                            seen.add(s)
                                            cands.append((s, size))
                                        if len(cands) >= MAX_CAND:
                                            return cands
                                    except Exception:
                                        continue
                except Exception:
                    pass
            return cands

        def _sha256_of(data):
            return hashlib.sha256(data).hexdigest()

        def _run_tool(cmd, timeout, stdin_bytes=None):
            t0 = time.monotonic()
            try:
                r = subprocess.run(
                    cmd, input=stdin_bytes,
                    capture_output=True, timeout=timeout, shell=False,
                )
                return {{
                    "cmd": cmd[0] if cmd else "",
                    "ok": r.returncode == 0,
                    "exit": r.returncode,
                    "stdout": r.stdout.decode("utf-8", "replace"),
                    "stderr": r.stderr.decode("utf-8", "replace")[-2000:],
                    "elapsed_s": round(time.monotonic() - t0, 2),
                }}
            except subprocess.TimeoutExpired:
                return {{"cmd": cmd[0], "ok": False, "exit": -1, "stdout": "", "stderr": f"TIMEOUT after {{timeout}}s", "elapsed_s": timeout}}
            except FileNotFoundError:
                return {{"cmd": cmd[0], "ok": False, "exit": -2, "stdout": "", "stderr": "tool not on PATH", "elapsed_s": 0}}
            except Exception as e:
                return {{"cmd": cmd[0], "ok": False, "exit": -3, "stdout": "", "stderr": f"{{type(e).__name__}}: {{e}}", "elapsed_s": 0}}

        def _analyse(p_str, size):
            try:
                with target.fs.path(p_str).open("rb") as f:
                    data = f.read(min(size, MAX_BYTES_EXTRACT))
            except Exception as e:
                return {{"path": p_str, "error": f"read failed: {{e}}"}}
            sha = _sha256_of(data)
            head = data[:16]
            filetype = "unknown"
            if head.startswith(ELF_MAGIC):
                filetype = "elf"
            elif head.startswith(PE_MZ):
                filetype = "pe"
            elif head.startswith(b"#!"):
                filetype = "script"
            elif head.startswith(b"MSCF"):
                filetype = "cab"
            elif head.startswith(b"PK\\x03\\x04"):
                filetype = "zip"
            elif head[:8] == b"\\x7B\\x5C\\x72\\x74\\x66\\x31\\x00\\x00":
                filetype = "rtf"
            elif p_str.lower().endswith(".lnk"):
                filetype = "lnk"

            # Scratch file for tool invocation.
            tmp_dir = os.path.join(tempfile.gettempdir(), "aila_ba", sha[:2])
            os.makedirs(tmp_dir, exist_ok=True)
            basename = os.path.basename(p_str) or "sample.bin"
            scratch = os.path.join(tmp_dir, f"{{sha[:12]}}_{{basename}}")
            try:
                with open(scratch, "wb") as f:
                    f.write(data)
            except Exception as e:
                return {{"path": p_str, "sha256": sha, "size": size, "filetype": filetype,
                        "error": f"scratch write failed: {{e}}"}}

            result = {{
                "path": p_str, "basename": basename, "sha256": sha, "size": size,
                "filetype": filetype, "tool_errors": [],
            }}

            # strings -- Sysinternals (-accepteula quiet), fall back to no-flag run.
            strings_r = _run_tool(["strings.exe", "-accepteula", "-nobanner", "-n", "6", scratch], T_STRINGS)
            if not strings_r["ok"]:
                strings_r = _run_tool(["strings.exe", "-accepteula", "-n", "6", scratch], T_STRINGS)
            if strings_r["ok"]:
                lines = strings_r["stdout"].splitlines()
                result["strings_count"] = len(lines)
                # Keep a bounded sample -- LLM prompt can't absorb 50k lines.
                result["strings_sample"] = lines[:600]
            else:
                result["tool_errors"].append({{"tool": "strings", "err": strings_r["stderr"][:400]}})

            # capa -- only on PE / ELF and only below the full-analysis cap.
            if filetype in ("pe", "elf") and size <= MAX_BYTES_FULL:
                capa_r = _run_tool(["capa.exe", "-j", scratch], T_CAPA)
                if capa_r["ok"] and capa_r["stdout"].strip().startswith("{{"):
                    try:
                        result["capa"] = json.loads(capa_r["stdout"])
                    except Exception as e:
                        result["tool_errors"].append({{"tool": "capa", "err": f"json parse: {{e}}"}})
                else:
                    result["tool_errors"].append({{"tool": "capa", "exit": capa_r["exit"], "err": capa_r["stderr"][:400]}})
            # FLOSS -- same guardrails.
            if filetype in ("pe", "elf") and size <= MAX_BYTES_FULL:
                floss_r = _run_tool(["floss.exe", "--json", "-q", scratch], T_FLOSS)
                if floss_r["ok"]:
                    try:
                        result["floss"] = json.loads(floss_r["stdout"])
                    except Exception:
                        # Older FLOSS prints mixed text+json -- take first decoded_strings block we can parse.
                        result["floss_raw_head"] = floss_r["stdout"][:4000]
                else:
                    result["tool_errors"].append({{"tool": "floss", "exit": floss_r["exit"], "err": floss_r["stderr"][:400]}})

            # pefile -- imports + sections.
            if filetype == "pe":
                try:
                    import pefile
                    pe = pefile.PE(scratch, fast_load=True)
                    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
                    imports = []
                    for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
                        entry = {{"dll": e.dll.decode("ascii", "ignore"), "imports": []}}
                        for imp in e.imports or []:
                            nm = (imp.name or b"").decode("ascii", "ignore") if imp.name else f"ordinal#{{imp.ordinal}}"
                            entry["imports"].append(nm)
                        imports.append(entry)
                    sections = [
                        {{"name": s.Name.rstrip(b"\\x00").decode("ascii", "ignore"),
                         "virtual_size": s.Misc_VirtualSize, "raw_size": s.SizeOfRawData,
                         "entropy": round(s.get_entropy(), 2)}}
                        for s in pe.sections
                    ]
                    result["pe"] = {{
                        "machine": hex(pe.FILE_HEADER.Machine),
                        "timestamp": pe.FILE_HEADER.TimeDateStamp,
                        "imports": imports[:200],
                        "sections": sections,
                    }}
                except Exception as e:
                    result["tool_errors"].append({{"tool": "pefile", "err": f"{{type(e).__name__}}: {{e}}"}})

            # ELF header -- dissect.executable.elf when available, else raw parse.
            if filetype == "elf":
                try:
                    from dissect.executable import elf as _elf
                    with open(scratch, "rb") as f:
                        ef = _elf.ELF(f)
                    syms = []
                    try:
                        # ELF symbol enumeration varies by dissect version; best-effort.
                        for s in (ef.symtab or []):
                            nm = getattr(s, "name", None) or ""
                            if nm:
                                syms.append(nm)
                            if len(syms) >= 400:
                                break
                    except Exception:
                        pass
                    result["elf"] = {{
                        "class": getattr(ef.header, "ei_class", None),
                        "machine": str(getattr(ef.header, "e_machine", None)),
                        "entry": hex(getattr(ef.header, "e_entry", 0) or 0),
                        "symbol_count": len(syms),
                        "symbols_sample": syms[:200],
                    }}
                except Exception as e:
                    # Fallback -- just pull the ei_class / machine bytes manually.
                    try:
                        ei_class = data[4] if len(data) > 4 else 0
                        machine = int.from_bytes(data[18:20], "little") if len(data) > 20 else 0
                        entry_off = 0x18 if ei_class == 2 else 0x18
                        entry = int.from_bytes(data[entry_off:entry_off+8], "little") if len(data) > entry_off+8 else 0
                        result["elf"] = {{"class": ei_class, "machine": machine, "entry": hex(entry)}}
                    except Exception:
                        result["tool_errors"].append({{"tool": "elf", "err": f"{{type(e).__name__}}: {{e}}"}})

            return result

        out = {{"image": r"{image_path}", "candidates": [], "results": []}}
        t_disco = time.monotonic()
        cands = _walk_for_candidates()
        out["candidates"] = [{{"path": p, "size": sz}} for p, sz in cands]
        out["discovery_elapsed_s"] = round(time.monotonic() - t_disco, 2)
        for p, sz in cands:
            r = _analyse(p, sz)
            out["results"].append(r)
        print(json.dumps(out, default=str))
    ''').strip()


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
