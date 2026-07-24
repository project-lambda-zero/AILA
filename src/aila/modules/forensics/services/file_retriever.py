"""Extract a file or directory from a disk image and pull it to the API host.

Flow:

1. Build a small Python script that opens the disk image with
   ``dissect.target`` on the analyzer, resolves the requested in-image
   path, and either:
     - reads a single file's bytes in chunks into a temp file, or
     - zips a directory tree into a temp ``.zip`` on the analyzer.
   The script emits a JSON header on stdout with ``kind``
   (``"file"`` | ``"dir"``), ``size``, ``sha256`` and the temp-file
   path.
2. Run the script via ``ScriptExecutorTool`` (the same mechanism the
   agent uses, but bypassing the agent so no LLM round-trip is needed).
3. Parse the JSON header, SFTP-pull the temp file to the API host,
   and return the local path + metadata. Caller is responsible for
   streaming the bytes back and deleting the local temp copy.

The analyzer-side temp file is deleted by the script itself on success.
If the script errors, stderr is surfaced verbatim.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path

from aila.config import Settings
from aila.modules.forensics.services.hash_ledger import (
    HashMismatchError,
    verify_file_or_raise,
)
from aila.modules.forensics.tools._ssh_helper import get_ssh_service
from aila.modules.forensics.tools.script_tool import ScriptExecutorTool
from aila.platform.exceptions import AILAError
from aila.platform.services.runtime import run_blocking_io

__all__ = [
    "FileRetrievalError",
    "retrieve_file_from_image",
    "retrieve_from_raw_directory",
]

_log = logging.getLogger(__name__)

# Hard upper bound. Override via ``AILA_FORENSICS_RETRIEVE_MAX_BYTES``.
_DEFAULT_MAX_BYTES = 500 * 1024 * 1024  # 500 MB


class FileRetrievalError(AILAError):
    """Raised when retrieval fails (path missing, too large, permission)."""


def _max_retrieve_bytes() -> int:
    raw = os.environ.get("AILA_FORENSICS_RETRIEVE_MAX_BYTES")
    if not raw:
        return _DEFAULT_MAX_BYTES
    try:
        value = int(raw)
    except ValueError:
        return _DEFAULT_MAX_BYTES
    return max(1024, value)


def _build_extraction_script(
    *,
    disk_image_path: str,
    virtual_path: str,
    max_bytes: int,
    analyzer_os: str,
) -> str:
    """Return a self-contained Python script that extracts the file.

    The script:
      - opens the disk image with ``dissect.target``
      - normalises POSIX/Windows separators
      - probes several mount roots (``sysvol``, ``c:``, ``/``, drive
        letters) because dissect can expose the filesystem under
        different paths depending on image type
      - reads bytes into a temp file on the analyzer
      - prints ``##AILA-RETRIEVE## <json>`` on the last stdout line
    """
    script_tmpl = r'''import hashlib, json, os, sys, tempfile, zipfile
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from dissect.target import Target

DISK_IMAGE = {disk_image!r}
VIRTUAL_PATH = {virtual_path!r}
MAX_BYTES = {max_bytes}
ANALYZER_OS = {analyzer_os!r}

# Normalise separators -- accept either backslash or forward-slash paths.
raw = VIRTUAL_PATH.replace("\\", "/").rstrip("/").lstrip("/")

# Strip a leading drive letter if present; dissect mounts Windows volumes
# under "sysvol/" or the lowercase drive prefix, not under a literal
# upper-case "C:" top-level.
drive_prefix = None
if len(raw) >= 2 and raw[1] == ":":
    drive_prefix = raw[:2].lower()
    raw = raw[2:].lstrip("/")

t = Target.open(DISK_IMAGE)

# Candidate mount roots to try, most-likely first.
candidates = []
if drive_prefix:
    candidates.append(drive_prefix + "/" + raw)            # c:/Users/...
    candidates.append("sysvol/" + raw)                      # dissect NTFS
candidates.append(raw)                                      # /Users/...
candidates.append("/" + raw)

resolved = None
for cand in candidates:
    try:
        p = t.fs.path(cand)
        if p.exists():
            resolved = p
            break
    except Exception:
        continue

if resolved is None:
    print(json.dumps({{
        "error": "not_found",
        "message": "path not found in image",
        "virtual_path": VIRTUAL_PATH,
        "tried": candidates,
    }}))
    sys.exit(2)


def _fail_too_large(cur_size):
    print(json.dumps({{
        "error": "too_large",
        "message": "read exceeded max " + str(MAX_BYTES) + " bytes",
        "size": cur_size,
        "max_bytes": MAX_BYTES,
    }}))
    sys.exit(3)


if resolved.is_dir():
    # Zip the directory tree into a temp archive on the analyzer.
    fd, tmp_path = tempfile.mkstemp(prefix="aila_retrieve_", suffix=".zip")
    os.close(fd)
    h = hashlib.sha256()
    file_count = 0
    root_name = resolved.name or "retrieved_dir"
    try:
        with zipfile.ZipFile(tmp_path, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
            stack = [resolved]
            while stack:
                current = stack.pop()
                try:
                    children = list(current.iterdir())
                except Exception as exc:
                    # Record unreadable dir as a marker; don't abort the whole job.
                    try:
                        rel = str(current.relative_to(resolved))
                    except Exception:
                        rel = current.name
                    zf.writestr(
                        root_name + "/" + rel.replace("\\", "/") + "/_UNREADABLE.txt",
                        "could not list directory: " + str(exc),
                    )
                    continue
                for child in children:
                    try:
                        if child.is_dir():
                            stack.append(child)
                            continue
                        try:
                            rel = str(child.relative_to(resolved))
                        except Exception:
                            rel = child.name
                        arcname = root_name + "/" + rel.replace("\\", "/")
                        with child.open("rb") as src:
                            # Stream into zip via open() for member streaming.
                            with zf.open(arcname, "w", force_zip64=True) as dst:
                                while True:
                                    chunk = src.read(65536)
                                    if not chunk:
                                        break
                                    dst.write(chunk)
                                    h.update(chunk)
                        file_count += 1
                        # Enforce size ceiling against the archive on disk.
                        try:
                            cur_archive_size = os.path.getsize(tmp_path)
                        except OSError:
                            cur_archive_size = 0
                        if cur_archive_size > MAX_BYTES:
                            try:
                                os.unlink(tmp_path)
                            except OSError:
                                pass
                            _fail_too_large(cur_archive_size)
                    except Exception as exc:
                        try:
                            rel = str(child.relative_to(resolved))
                        except Exception:
                            rel = child.name
                        zf.writestr(
                            root_name + "/" + rel.replace("\\", "/") + ".ERROR.txt",
                            "read failed: " + str(exc),
                        )
    except SystemExit:
        raise
    except Exception as exc:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        print(json.dumps({{"error": "read_failed", "message": str(exc)}}))
        sys.exit(4)

    try:
        archive_size = os.path.getsize(tmp_path)
    except OSError:
        archive_size = -1

    print("##AILA-RETRIEVE## " + json.dumps({{
        "ok": True,
        "kind": "dir",
        "tmp_path": tmp_path,
        "size": archive_size,
        "sha256": h.hexdigest(),
        "resolved": str(resolved),
        "file_count": file_count,
        "root_name": root_name,
    }}))
    sys.exit(0)

# Single-file path.
try:
    size = resolved.stat().st_size
except Exception:
    size = -1

if size >= 0 and size > MAX_BYTES:
    print(json.dumps({{
        "error": "too_large",
        "message": "file is " + str(size) + " bytes, max is " + str(MAX_BYTES),
        "size": size,
        "max_bytes": MAX_BYTES,
    }}))
    sys.exit(3)

h = hashlib.sha256()
fd, tmp_path = tempfile.mkstemp(prefix="aila_retrieve_", suffix=".bin")
written = 0
try:
    with os.fdopen(fd, "wb") as out, resolved.open("rb") as src:
        while True:
            chunk = src.read(65536)
            if not chunk:
                break
            written += len(chunk)
            if written > MAX_BYTES:
                out.close()
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                _fail_too_large(written)
            out.write(chunk)
            h.update(chunk)
except SystemExit:
    raise
except Exception as exc:
    try:
        os.unlink(tmp_path)
    except OSError:
        pass
    print(json.dumps({{"error": "read_failed", "message": str(exc)}}))
    sys.exit(4)

print("##AILA-RETRIEVE## " + json.dumps({{
    "ok": True,
    "kind": "file",
    "tmp_path": tmp_path,
    "size": written,
    "sha256": h.hexdigest(),
    "resolved": str(resolved),
}}))
'''
    return script_tmpl.format(
        disk_image=disk_image_path,
        virtual_path=virtual_path,
        max_bytes=max_bytes,
        analyzer_os=analyzer_os,
    )


def _build_raw_extraction_script(
    *,
    target_path: str,
    max_bytes: int,
    analyzer_os: str,
) -> str:
    """Return a script that reads a real filesystem path on the analyzer.

    Unlike :func:`_build_extraction_script`, this never opens a disk
    image -- it reads the file (or zips the directory) directly from the
    analyzer's local filesystem. Used by raw-directory projects where
    the evidence dir *is* the artefact.
    """
    script_tmpl = r'''import hashlib, json, os, sys, tempfile, zipfile
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

TARGET = {target!r}
MAX_BYTES = {max_bytes}
ANALYZER_OS = {analyzer_os!r}


def _fail_too_large(cur_size):
    print(json.dumps({{
        "error": "too_large",
        "message": "read exceeded max " + str(MAX_BYTES) + " bytes",
        "size": cur_size,
        "max_bytes": MAX_BYTES,
    }}))
    sys.exit(3)


if not os.path.exists(TARGET):
    print(json.dumps({{
        "error": "not_found",
        "message": "path does not exist on analyzer",
        "target": TARGET,
    }}))
    sys.exit(2)

if os.path.isdir(TARGET):
    fd, tmp_path = tempfile.mkstemp(prefix="aila_retrieve_raw_", suffix=".zip")
    os.close(fd)
    h = hashlib.sha256()
    file_count = 0
    root_name = os.path.basename(os.path.normpath(TARGET)) or "retrieved_dir"
    try:
        with zipfile.ZipFile(tmp_path, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
            for dirpath, _dirs, filenames in os.walk(TARGET):
                for fname in filenames:
                    full = os.path.join(dirpath, fname)
                    try:
                        rel = os.path.relpath(full, TARGET).replace("\\", "/")
                        arcname = root_name + "/" + rel
                        with open(full, "rb") as src, zf.open(arcname, "w", force_zip64=True) as dst:
                            while True:
                                chunk = src.read(65536)
                                if not chunk:
                                    break
                                dst.write(chunk)
                                h.update(chunk)
                        file_count += 1
                        try:
                            cur_archive_size = os.path.getsize(tmp_path)
                        except OSError:
                            cur_archive_size = 0
                        if cur_archive_size > MAX_BYTES:
                            try:
                                os.unlink(tmp_path)
                            except OSError:
                                pass
                            _fail_too_large(cur_archive_size)
                    except Exception as exc:
                        try:
                            rel = os.path.relpath(full, TARGET).replace("\\", "/")
                        except Exception:
                            rel = fname
                        zf.writestr(
                            root_name + "/" + rel + ".ERROR.txt",
                            "read failed: " + str(exc),
                        )
    except SystemExit:
        raise
    except Exception as exc:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        print(json.dumps({{"error": "read_failed", "message": str(exc)}}))
        sys.exit(4)

    try:
        archive_size = os.path.getsize(tmp_path)
    except OSError:
        archive_size = -1

    print("##AILA-RETRIEVE## " + json.dumps({{
        "ok": True,
        "kind": "dir",
        "tmp_path": tmp_path,
        "size": archive_size,
        "sha256": h.hexdigest(),
        "resolved": TARGET,
        "file_count": file_count,
        "root_name": root_name,
    }}))
    sys.exit(0)

# Single-file path.
try:
    size = os.path.getsize(TARGET)
except OSError:
    size = -1

if size >= 0 and size > MAX_BYTES:
    print(json.dumps({{
        "error": "too_large",
        "message": "file is " + str(size) + " bytes, max is " + str(MAX_BYTES),
        "size": size,
        "max_bytes": MAX_BYTES,
    }}))
    sys.exit(3)

h = hashlib.sha256()
fd, tmp_path = tempfile.mkstemp(prefix="aila_retrieve_raw_", suffix=".bin")
written = 0
try:
    with os.fdopen(fd, "wb") as out, open(TARGET, "rb") as src:
        while True:
            chunk = src.read(65536)
            if not chunk:
                break
            written += len(chunk)
            if written > MAX_BYTES:
                out.close()
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                _fail_too_large(written)
            out.write(chunk)
            h.update(chunk)
except SystemExit:
    raise
except Exception as exc:
    try:
        os.unlink(tmp_path)
    except OSError:
        pass
    print(json.dumps({{"error": "read_failed", "message": str(exc)}}))
    sys.exit(4)

print("##AILA-RETRIEVE## " + json.dumps({{
    "ok": True,
    "kind": "file",
    "tmp_path": tmp_path,
    "size": written,
    "sha256": h.hexdigest(),
    "resolved": TARGET,
}}))
'''
    return script_tmpl.format(
        target=target_path,
        max_bytes=max_bytes,
        analyzer_os=analyzer_os,
    )


def _parse_header(stdout: str) -> dict:
    """Extract the final ``##AILA-RETRIEVE## {json}`` payload from stdout."""
    needle = "##AILA-RETRIEVE## "
    idx = stdout.rfind(needle)
    if idx == -1:
        # Script exited early with an error JSON on its own line -- find it.
        for line in reversed(stdout.strip().splitlines()):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
        raise FileRetrievalError(
            f"Extraction script produced no parseable result. stdout tail: {stdout[-400:]!r}"
        )
    payload = stdout[idx + len(needle):].splitlines()[0].strip()
    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        raise FileRetrievalError(f"Invalid JSON header: {exc}") from exc


async def _run_script_and_pull(
    *,
    settings: Settings,
    integration: dict,
    analyzer_os: str,
    script: str,
    not_found_message: str,
    max_bytes: int,
) -> tuple[Path, int, str, str]:
    """Execute an extraction script, SFTP-pull the result, return metadata.

    Returns ``(local_temp_path, size_bytes, sha256_hex, kind)``. The
    caller is responsible for choosing the final filename (single-file
    vs directory-zip).
    """
    tool = ScriptExecutorTool(settings)
    result = await tool.forward(
        script_content=script,
        integration=integration,
        analyzer_os=analyzer_os,
        timeout_seconds=300.0,
    )

    stdout = result.get("stdout") or ""
    stderr = result.get("stderr") or ""
    exit_code = int(result.get("exit_code", 0))
    header = _parse_header(stdout)

    if "error" in header:
        err = header.get("error")
        msg = header.get("message") or err
        if err == "not_found":
            raise FileRetrievalError(not_found_message)
        if err == "too_large":
            raise FileRetrievalError(
                f"File exceeds size limit ({max_bytes} bytes). "
                f"Raise AILA_FORENSICS_RETRIEVE_MAX_BYTES to override."
            )
        raise FileRetrievalError(f"Extraction failed: {msg}")

    if exit_code != 0 or not header.get("ok"):
        raise FileRetrievalError(
            f"Extraction script exit={exit_code}. stderr tail: {stderr[-400:]!r}"
        )

    tmp_path_on_analyzer = header["tmp_path"]
    size = int(header["size"])
    sha256_hex = str(header["sha256"])
    kind = str(header.get("kind") or "file")

    ssh = await get_ssh_service(settings)
    local_fd, local_path = tempfile.mkstemp(prefix="aila_retrieve_in_", suffix=".bin")
    os.close(local_fd)
    try:
        await ssh.download_file(
            integration,
            tmp_path_on_analyzer,
            local_path,
            timeout_seconds=300.0,
        )
    except (OSError, TimeoutError, RuntimeError, AILAError):
        try:
            os.unlink(local_path)
        except OSError:
            pass
        raise

    try:
        if analyzer_os == "windows":
            await ssh.run_command(
                integration,
                f'cmd /c del /q "{tmp_path_on_analyzer}"',
                timeout_seconds=30.0,
            )
        else:
            await ssh.run_command(
                integration,
                f"rm -f '{tmp_path_on_analyzer}'",
                timeout_seconds=30.0,
            )
    except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
        _log.warning("analyzer temp cleanup failed: %s", exc)

    # Finding 58-2: local re-hash of the pulled bytes. The analyzer host
    # is untrusted per this module's docstring; ``sha256_hex`` is what the
    # analyzer-side script REPORTED, not proof. Recompute over the bytes
    # actually delivered and quarantine the local copy on mismatch.
    # Streamed 1 MB chunk read in a worker thread so a 500 MB acquisition
    # neither loads into memory nor blocks the event loop.
    try:
        verified_sha256 = await run_blocking_io(
            verify_file_or_raise,
            Path(local_path),
            sha256_hex,
            source=tmp_path_on_analyzer,
        )
    except HashMismatchError as exc:
        _log.warning(
            "forensic hash mismatch source=%s claimed=%s computed=%s size=%s -- quarantining local copy",
            tmp_path_on_analyzer,
            exc.claimed_sha256[:16],
            exc.computed_sha256[:16],
            exc.size_bytes,
        )
        try:
            os.unlink(local_path)
        except OSError:
            pass
        raise FileRetrievalError(
            f"forensic hash mismatch: analyzer reported {exc.claimed_sha256[:16]}..., "
            f"local recompute {exc.computed_sha256[:16]}...; file quarantined"
        ) from exc

    # From here on the LOCAL recomputation is the authoritative hash; the
    # untrusted header value is intentionally discarded.
    return Path(local_path), size, verified_sha256, kind


def _final_basename(source_path: str, kind: str) -> str:
    basename = source_path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    if not basename:
        basename = "retrieved_dir" if kind == "dir" else "retrieved.bin"
    if kind == "dir" and not basename.lower().endswith(".zip"):
        basename = basename + ".zip"
    return basename


async def retrieve_file_from_image(
    *,
    settings: Settings,
    integration: dict,
    analyzer_os: str,
    disk_image_path: str,
    virtual_path: str,
) -> tuple[Path, int, str, str, str]:
    """Extract ``virtual_path`` (file or directory) from ``disk_image_path``.

    For a file, the bytes are streamed verbatim. For a directory, the
    directory tree is zipped on the analyzer and the archive is pulled
    back.

    Returns ``(local_temp_path, size_bytes, sha256_hex, filename, kind)``
    where ``kind`` is ``"file"`` or ``"dir"``. For ``"dir"`` the
    ``filename`` already has a ``.zip`` suffix and the payload is a
    zip archive. The caller MUST ``unlink`` ``local_temp_path`` once it
    has been streamed.
    """
    if not virtual_path.strip():
        raise FileRetrievalError("virtual_path must be non-empty.")
    if not disk_image_path:
        raise FileRetrievalError("disk_image_path must be non-empty.")

    max_bytes = _max_retrieve_bytes()
    script = _build_extraction_script(
        disk_image_path=disk_image_path,
        virtual_path=virtual_path,
        max_bytes=max_bytes,
        analyzer_os=analyzer_os,
    )
    local_path, size, sha256_hex, kind = await _run_script_and_pull(
        settings=settings,
        integration=integration,
        analyzer_os=analyzer_os,
        script=script,
        not_found_message=f"Path not found in image: {virtual_path}",
        max_bytes=max_bytes,
    )
    return local_path, size, sha256_hex, _final_basename(virtual_path, kind), kind


async def retrieve_from_raw_directory(
    *,
    settings: Settings,
    integration: dict,
    analyzer_os: str,
    target_path: str,
) -> tuple[Path, int, str, str, str]:
    """Read a file or zip a directory directly off the analyzer filesystem.

    Used for ``project_kind == "raw_directory"`` projects where the
    evidence path is already a real filesystem location (no disk image
    to open). Returns the same 5-tuple as
    :func:`retrieve_file_from_image`.
    """
    if not target_path.strip():
        raise FileRetrievalError("target_path must be non-empty.")

    max_bytes = _max_retrieve_bytes()
    script = _build_raw_extraction_script(
        target_path=target_path,
        max_bytes=max_bytes,
        analyzer_os=analyzer_os,
    )
    local_path, size, sha256_hex, kind = await _run_script_and_pull(
        settings=settings,
        integration=integration,
        analyzer_os=analyzer_os,
        script=script,
        not_found_message=f"Path not found on analyzer: {target_path}",
        max_bytes=max_bytes,
    )
    return local_path, size, sha256_hex, _final_basename(target_path, kind), kind
