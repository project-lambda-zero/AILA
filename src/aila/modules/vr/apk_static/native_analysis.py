"""Static analysis of the native (.so) libraries bundled in an APK.

An APK ships its native code as ELF shared objects under
``lib/<abi>/*.so`` inside the (zip) package. the static summary
only lists those paths; nothing analyzes them. This module reads each
ELF with LIEF and produces a compact, prompt-safe ``native_analysis``
summary that the APK static audit's NATIVE checks consume directly (via
the seed builder) instead of asking the agent to reconstruct binary
facts it cannot see in the jadx tree.

Per library it records the binary-hardening posture (NX, PIE, RELRO,
stack canary, FORTIFY), whether the library is stripped, the JNI export
surface (``Java_*`` symbols and JNIEnv accessor imports), and version
hints for commonly-bundled libraries (openssl, sqlite, ffmpeg, libpng,
libwebp) fingerprinted from embedded version strings.

Pure static: no process launch, no device, no network. LIEF does the ELF
parsing; the classification of its attributes into hardening verdicts is
the only logic here, factored into pure helpers so it is unit-testable
without a real binary.
"""
from __future__ import annotations

import re
import zipfile
from typing import Any

__all__ = [
    "analyze_apk_natives",
    "classify_binary",
]

# Cap the amount of per-library detail that flows into an LLM prompt. A
# real app can bundle dozens of libraries with thousands of symbols; the
# audit only needs a representative surface, and unbounded lists blow the
# per-turn context budget.
_MAX_LIBS = 40
_MAX_JNI_EXPORTS = 30
_MAX_ENV_CALLS = 20
_SO_READ_CAP_BYTES = 64 * 1024 * 1024  # skip pathological >64MB members

# Unsafe libc primitives whose presence next to a JNI export marks a
# candidate for out-of-bounds read/write worth manual review. Presence
# is a heuristic (no dataflow without disassembly), not a confirmed bug.
_UNSAFE_LIBC = frozenset({
    "memcpy", "memmove", "strcpy", "strncpy", "strcat", "strncat",
    "sprintf", "vsprintf", "snprintf", "gets", "scanf", "sscanf",
    "alloca", "system", "popen",
})

# JNIEnv accessor imports that mark a managed-to-native data crossing.
_JNI_ENV_CALLS = frozenset({
    "GetStringUTFChars", "GetStringChars", "GetByteArrayElements",
    "GetPrimitiveArrayCritical", "GetDirectBufferAddress", "GetArrayLength",
    "GetStringUTFLength", "GetStringLength", "NewByteArray",
    "SetByteArrayRegion", "GetByteArrayRegion",
})

# Version-string fingerprints for commonly-vendored native libraries.
# Each pattern captures a version token from the library's embedded
# strings; a match resolves the (library, version) pair the CVE check
# reasons over.
_VERSION_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("openssl", re.compile(rb"OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)")),
    ("boringssl", re.compile(rb"BoringSSL")),
    ("sqlite", re.compile(rb"3\.\d+\.\d+\b.{0,40}?SQLite|SQLite.{0,40}?(\d+\.\d+\.\d+)")),
    ("ffmpeg", re.compile(rb"(?:Lavc|libavcodec)\s*(\d+\.\d+\.\d+)")),
    ("libpng", re.compile(rb"libpng version\s+(\d+\.\d+\.\d+)")),
    ("libwebp", re.compile(rb"libwebp\s+(\d+\.\d+\.\d+)")),
    ("zlib", re.compile(rb"(?:inflate|deflate) (\d+\.\d+\.\d+) Copyright")),
)


def _relro_state(binary: Any) -> str:
    """Classify RELRO as ``full`` / ``partial`` / ``none``.

    ``partial`` = a GNU_RELRO segment is present. ``full`` additionally
    requires immediate binding (DT_BIND_NOW or DF_BIND_NOW / DF_1_NOW),
    which resolves and read-only-maps the GOT at load time.
    """
    has_relro = any(
        str(getattr(seg, "type", "")).endswith("GNU_RELRO")
        for seg in binary.segments
    )
    if not has_relro:
        return "none"
    for entry in binary.dynamic_entries:
        tag = str(getattr(entry, "tag", ""))
        if tag.endswith("BIND_NOW"):
            return "full"
        # DF_BIND_NOW = 0x8, DF_1_NOW = 0x1
        if (tag.endswith("FLAGS") or tag.endswith("FLAGS_1")) and (
            int(getattr(entry, "value", 0) or 0) & 0x9
        ):
            return "full"
    return "partial"


def _nx_enabled(binary: Any) -> bool:
    """True when the stack is non-executable.

    A GNU_STACK segment without the execute flag means NX. Absence of the
    segment defaults to executable-stack on many toolchains, so treat a
    missing GNU_STACK as NX-off (conservative).
    """
    for seg in binary.segments:
        if str(getattr(seg, "type", "")).endswith("GNU_STACK"):
            flags = int(getattr(seg, "flags", 0) or 0)
            return not (flags & 0x1)  # PF_X = 0x1
    return False


def _import_names(binary: Any) -> list[str]:
    return [str(f) for f in binary.imported_functions]


def _export_names(binary: Any) -> list[str]:
    return [str(f) for f in binary.exported_functions]


def _is_stripped(binary: Any) -> bool:
    """True when the binary carries no ``.symtab`` section."""
    return not any(
        getattr(s, "name", "") == ".symtab" for s in binary.sections
    )


def classify_binary(binary: Any, raw: bytes) -> dict[str, Any]:
    """Reduce one parsed LIEF ELF binary to a hardening + surface record.

    Pure over ``(binary, raw)`` so it is unit-testable with a stub that
    mimics the small LIEF surface used here. ``raw`` backs the
    version-string scan.
    """
    imports = _import_names(binary)
    exports = _export_names(binary)
    jni_exports = [n for n in exports if n.startswith("Java_")]
    env_calls = sorted({n for n in imports if n in _JNI_ENV_CALLS})
    canary = "__stack_chk_fail" in imports or "__stack_chk_guard" in imports
    fortify = any(n.endswith("_chk") for n in imports)
    unsafe_libc = sorted({n for n in imports if n in _UNSAFE_LIBC})

    version_hints: dict[str, str] = {}
    for lib, pat in _VERSION_PATTERNS:
        m = pat.search(raw)
        if m:
            ver = ""
            for g in m.groups():
                if g:
                    ver = g.decode("ascii", "replace")
                    break
            version_hints[lib] = ver or "present"

    pie = bool(getattr(binary, "is_pie", False))
    header = getattr(binary, "header", None)
    arch = (
        str(getattr(header, "machine_type", "unknown")).rsplit(".", 1)[-1]
        if header is not None else "unknown"
    )

    return {
        "arch": arch,
        "nx": _nx_enabled(binary),
        "pie": pie,
        "relro": _relro_state(binary),
        "stack_canary": canary,
        "fortify": fortify,
        "stripped": _is_stripped(binary),
        "jni_export_count": len(jni_exports),
        "jni_exports": jni_exports[:_MAX_JNI_EXPORTS],
        "jni_env_calls": env_calls[:_MAX_ENV_CALLS],
        "unsafe_libc_imports": unsafe_libc,
        "registers_natives": b"RegisterNatives" in raw,
        "version_hints": version_hints,
    }


def _abi_of(path: str) -> str:
    parts = path.split("/")
    return parts[1] if len(parts) >= 3 and parts[0] == "lib" else "unknown"


def analyze_apk_natives(apk_path: str) -> dict[str, Any]:
    """Analyze every ``lib/<abi>/*.so`` in an APK.

    Returns a compact, prompt-safe summary::

        {
          "present": bool,          # any native library at all
          "lib_count": int,
          "abis": [str, ...],
          "libraries": [ {path, abi, ...classify_binary...}, ... ],
          "hardening_gaps": [str, ...],   # human-readable one-liners
          "truncated": bool,        # more libs than the display cap
        }

    Never raises on a malformed or unreadable member -- a per-library
    parse failure is recorded and skipped so one bad ``.so`` cannot abort
    the whole summary. Requires LIEF; imported lazily so the module
    imports cleanly on hosts without it (the caller degrades to an empty
    summary).
    """
    try:
        # Lazy import: LIEF is a heavy, optional dependency; keep it out
        # of module import so this module loads on hosts without it.
        import lief
        try:
            lief.logging.disable()
        except (AttributeError, RuntimeError, TypeError):
            pass
    except ImportError:
        return {
            "present": False,
            "lib_count": 0,
            "abis": [],
            "libraries": [],
            "hardening_gaps": [],
            "truncated": False,
            "error": "lief_unavailable",
        }

    libraries: list[dict[str, Any]] = []
    abis: set[str] = set()
    try:
        with zipfile.ZipFile(apk_path) as zf:
            so_members = [
                info for info in zf.infolist()
                if info.filename.startswith("lib/")
                and info.filename.endswith(".so")
            ]
            total = len(so_members)
            for info in so_members[:_MAX_LIBS]:
                abi = _abi_of(info.filename)
                abis.add(abi)
                if info.file_size > _SO_READ_CAP_BYTES:
                    libraries.append({
                        "path": info.filename, "abi": abi,
                        "error": "too_large",
                    })
                    continue
                try:
                    raw = zf.read(info)
                    binary = lief.parse(raw)
                    if binary is None:
                        libraries.append({
                            "path": info.filename, "abi": abi,
                            "error": "unparseable",
                        })
                        continue
                    rec = {"path": info.filename, "abi": abi}
                    rec.update(classify_binary(binary, raw))
                    libraries.append(rec)
                except (
                    OSError, RuntimeError, ValueError, TypeError,
                    AttributeError, MemoryError,
                ) as exc:
                    # classify_binary reads LIEF attributes that can vary
                    # by version / be absent on a malformed ELF; a failure
                    # is recorded per-library (not silently swallowed) so
                    # one bad .so cannot abort the whole summary.
                    libraries.append({
                        "path": info.filename, "abi": abi,
                        "error": f"parse_failed: {type(exc).__name__}",
                    })
    except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
        return {
            "present": False,
            "lib_count": 0,
            "abis": [],
            "libraries": [],
            "hardening_gaps": [],
            "truncated": False,
            "error": f"apk_unreadable: {type(exc).__name__}",
        }

    gaps = _hardening_gaps(libraries)
    return {
        "present": bool(libraries),
        "lib_count": total,
        "abis": sorted(abis),
        "libraries": libraries,
        "hardening_gaps": gaps,
        "truncated": total > _MAX_LIBS,
    }


def _hardening_gaps(libraries: list[dict[str, Any]]) -> list[str]:
    """Summarize missing-hardening findings as reviewer-facing one-liners."""
    gaps: list[str] = []
    for lib in libraries:
        if "error" in lib:
            continue
        missing = []
        if not lib.get("nx"):
            missing.append("NX")
        if not lib.get("pie"):
            missing.append("PIE")
        if lib.get("relro") != "full":
            missing.append(f"RELRO={lib.get('relro')}")
        if not lib.get("stack_canary"):
            missing.append("no-canary")
        if not lib.get("fortify"):
            missing.append("no-FORTIFY")
        if missing:
            gaps.append(f"{lib['path']}: {', '.join(missing)}")
    return gaps
