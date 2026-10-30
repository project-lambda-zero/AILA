"""Shared binary-analysis helpers for the ``re_analytics`` tool groups.

One module owns the mechanics every tool needs: loading the target from
an absolute local path, PE parsing, VA/offset translation, capstone
disassembly, function/call-graph recovery, string extraction, and the
session-scoped annotation/patch overlay that backs the mutation tools.

The server is stateless across calls in the IDA sense -- there is no
database and no worker. ``_Overlay`` is the one piece of mutable state:
rename/comment/type annotations and byte patches live for the life of
the stdio server process, keyed by resolved target path, and are applied
to the read paths of the tools that render functions or bytes. Nothing
is ever written back to the target file on disk.
"""
from __future__ import annotations

import math
import re
import threading
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aila.platform.re_analytics._tooldef import ToolError

__all__ = [
    "LoadedBinary",
    "FunctionInfo",
    "annotations",
    "load_binary",
    "require_pe",
    "disasm",
    "iter_function_starts",
    "function_bounds",
    "build_call_graph",
    "extract_strings",
    "string_at_va",
    "shannon_entropy",
    "resolve_function",
    "hex_to_int",
    "x86_arg_register",
]

try:  # optional heavy deps -- every use site degrades honestly
    import pefile
except ImportError:  # pragma: no cover - environment guard
    pefile = None  # type: ignore[assignment]

try:
    import capstone
    from capstone import CS_ARCH_ARM, CS_ARCH_ARM64, CS_ARCH_X86, Cs, CsInsn
    from capstone.x86_const import (
        X86_OP_IMM,
        X86_OP_MEM,
        X86_REG_RBP,
        X86_REG_RSP,
    )
except ImportError:  # pragma: no cover - environment guard
    capstone = None  # type: ignore[assignment]
    Cs = CsInsn = None  # type: ignore[assignment,misc]

    X86_OP_IMM = X86_OP_MEM = 0
    X86_REG_RBP = X86_REG_RSP = 0
    CS_ARCH_X86 = CS_ARCH_ARM = CS_ARCH_ARM64 = 0


# PE Machine -> (capstone arch, capstone mode, bits)
_MACHINE_TO_CAPSTONE: dict[int, tuple[int, int, int]] = {}
if capstone is not None:
    _MACHINE_TO_CAPSTONE = {
        0x014C: (CS_ARCH_X86, capstone.CS_MODE_32, 32),
        0x8664: (CS_ARCH_X86, capstone.CS_MODE_64, 64),
        0x01C0: (CS_ARCH_ARM, capstone.CS_MODE_ARM | capstone.CS_MODE_LITTLE_ENDIAN, 32),
        0x01C4: (CS_ARCH_ARM, capstone.CS_MODE_THUMB | capstone.CS_MODE_LITTLE_ENDIAN, 32),
        0xAA64: (CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN, 64),
    }


def hex_to_int(value: Any) -> int:
    """Parse an int/hex-string address the way the ida tools accepted it."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip(), 0)
        except ValueError:
            try:
                return int(value.strip(), 16)
            except ValueError as exc:
                raise ToolError(f"not an address: {value!r}") from exc
    raise ToolError(f"not an address: {value!r}")


def x86_arg_register(index: int, bits: int) -> str | None:
    """Windows x64 ABI argument register for ``index`` (0-based)."""
    regs = ("rcx", "rdx", "r8", "r9") if bits == 64 else ("esp+",)
    if bits == 32:
        return None  # stack args; handled by callers as unsupported
    return regs[index] if 0 <= index < len(regs) else None


@dataclass
class FunctionInfo:
    """Recovered function entry used by the graph/render tools."""

    address: int
    name: str
    size: int = 0
    source: str = "heuristic"  # export | symbol | prologue | call_target


@dataclass
class LoadedBinary:
    """One target loaded from disk plus everything derived from it."""

    path: Path
    data: bytes
    pe: Any | None
    is_pe: bool
    arch: int
    mode: int
    bits: int
    machine: int
    imagebase: int
    entry_point: int
    key: str

    # -- address translation ------------------------------------------
    def va_to_offset(self, va: int) -> int | None:
        if self.is_pe and self.pe is not None:
            rva = va - self.imagebase
            try:
                off = self.pe.get_offset_from_rva(rva)
            except (ValueError, AttributeError):
                return None
            return off if 0 <= off < len(self.data) else None
        return va if 0 <= va < len(self.data) else None

    def offset_to_va(self, offset: int) -> int:
        if self.is_pe and self.pe is not None:
            try:
                return self.imagebase + self.pe.get_rva_from_offset(offset)
            except (ValueError, AttributeError):
                return offset
        return offset

    def read(self, va: int, size: int) -> bytes:
        """Read ``size`` bytes at VA, applying the session patch overlay."""
        off = self.va_to_offset(va)
        if off is None or size <= 0:
            return b""
        raw = self.data[off:off + size]
        patches = annotations.byte_patches_in_range(self.key, va, size)
        if not patches:
            return raw
        buf = bytearray(raw)
        for patch_va, patch_bytes in patches:
            start = patch_va - va
            for i, b in enumerate(patch_bytes):
                idx = start + i
                if 0 <= idx < len(buf):
                    buf[idx] = b
        return bytes(buf)

    def section_spans(self) -> list[dict[str, Any]]:
        """VA spans of every section (PE) or the whole file (raw)."""
        if not (self.is_pe and self.pe is not None):
            return [{"name": "raw", "va": 0, "size": len(self.data)}]
        spans = []
        for sec in self.pe.sections:
            name = sec.Name.rstrip(b"\x00").decode("latin-1", errors="replace")
            va = self.imagebase + sec.VirtualAddress
            spans.append({
                "name": name,
                "va": va,
                "size": max(sec.Misc_VirtualSize, sec.SizeOfRawData),
                "raw_offset": sec.PointerToRawData,
                "raw_size": sec.SizeOfRawData,
                "characteristics": int(sec.Characteristics),
            })
        return spans

    def executable_spans(self) -> list[dict[str, Any]]:
        """Sections marked executable (IMAGE_SCN_MEM_EXECUTE)."""
        return [s for s in self.section_spans() if s["characteristics"] & 0x20000000]

    def entry_bytes(self, size: int = 64) -> bytes:
        ep = self.entry_point
        return self.read(ep, size) if ep else b""


class _Overlay:
    """Session-scoped annotations and byte patches, keyed by target path.

    Holds exactly what the ida mutation tools persisted in an IDB:
    renames, comments, type overrides, and queued byte patches. In this
    server the state lives for the stdio process lifetime only; tools
    that render functions or bytes apply it on read. All operations take
    an ``RLock`` because the MCP server runs handlers on a thread pool.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._targets: dict[str, dict[str, Any]] = {}

    def _target(self, key: str) -> dict[str, Any]:
        ent = self._targets.get(key)
        if ent is None:
            ent = {
                "names": {},          # func address (int) -> str
                "comments": {},       # any address (int) -> str
                "function_types": {}, # func address (int) -> str prototype
                "variable_renames": {},  # (func addr, old name) -> new name
                "variable_types": {},    # (func addr, var name) -> str
                "patches": {},        # va (int) -> bytes
                "generation": 0,
            }
            self._targets[key] = ent
        return ent

    def rename_function(self, key: str, address: int, new_name: str) -> None:
        with self._lock:
            self._target(key)["names"][address] = new_name

    def function_name(self, key: str, address: int, fallback: str) -> str:
        with self._lock:
            return self._target(key)["names"].get(address, fallback)

    def set_comment(self, key: str, address: int, comment: str) -> None:
        with self._lock:
            self._target(key)["comments"][address] = comment

    def comment(self, key: str, address: int) -> str | None:
        with self._lock:
            return self._target(key)["comments"].get(address)

    def function_extra(self, key: str, address: int) -> dict[str, Any]:
        """Type overrides and variable annotations for one function."""
        with self._lock:
            ent = self._target(key)
            out: dict[str, Any] = {}
            proto = ent["function_types"].get(address)
            if proto:
                out["prototype"] = proto
            renames = {
                old: new
                for (func, old), new in ent["variable_renames"].items()
                if func == address
            }
            if renames:
                out["variable_renames"] = renames
            vtypes = {
                var: ty
                for (func, var), ty in ent["variable_types"].items()
                if func == address
            }
            if vtypes:
                out["variable_types"] = vtypes
            return out

    def set_function_type(self, key: str, address: int, prototype: str) -> None:
        with self._lock:
            self._target(key)["function_types"][address] = prototype

    def rename_variable(self, key: str, func: int, old: str, new: str) -> None:
        with self._lock:
            self._target(key)["variable_renames"][(func, old)] = new

    def set_variable_type(self, key: str, func: int, var: str, ty: str) -> None:
        with self._lock:
            self._target(key)["variable_types"][(func, var)] = ty

    def patch_bytes(self, key: str, va: int, data: bytes) -> None:
        with self._lock:
            self._target(key)["patches"][va] = data
            self._target(key)["generation"] += 1

    def byte_patches_in_range(self, key: str, va: int, size: int) -> list[tuple[int, bytes]]:
        with self._lock:
            patches = self._target(key)["patches"]
            return [
                (pva, pdata)
                for pva, pdata in patches.items()
                if va <= pva < va + size or pva <= va < pva + len(pdata)
            ]

    def bump_generation(self, key: str) -> int:
        with self._lock:
            ent = self._target(key)
            ent["generation"] += 1
            return ent["generation"]

    def generation(self, key: str) -> int:
        with self._lock:
            return self._target(key)["generation"]

    def reset_target(self, key: str) -> None:
        """Drop all session state for one target (:tool:`close_binary`)."""
        with self._lock:
            self._targets.pop(key, None)

    def target_keys(self) -> list[str]:
        with self._lock:
            return list(self._targets)

    def stats(self, key: str) -> dict[str, Any]:
        with self._lock:
            ent = self._target(key)
            return {
                "renamed_functions": len(ent["names"]),
                "comments": len(ent["comments"]),
                "function_types": len(ent["function_types"]),
                "variable_renames": len(ent["variable_renames"]),
                "variable_types": len(ent["variable_types"]),
                "byte_patches": len(ent["patches"]),
                "generation": ent["generation"],
            }


annotations = _Overlay()


def _load_pe(path: Path, data: bytes) -> tuple[Any, int, int, int, int]:
    """Parse the PE; return (pe, machine, imagebase, entry_point, bits)."""
    if pefile is None:
        raise ToolError(
            "pefile is not installed; re-run with the re-analytics extra "
            "(pip install -e '.[re-analytics]')",
        )
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except (ValueError, TypeError, AttributeError, OSError, RuntimeError) as exc:
        raise ToolError(f"cannot parse PE {path.name}: {exc}") from exc
    machine = int(pe.FILE_HEADER.Machine)
    opt = pe.OPTIONAL_HEADER
    imagebase = int(opt.ImageBase)
    entry_point = imagebase + int(opt.AddressOfEntryPoint)
    bits = 64 if opt.Magic == 0x20B else 32
    return pe, machine, imagebase, entry_point, bits


def load_binary(target_path: str) -> LoadedBinary:
    """Load and validate a target file, returning the analysis wrapper."""
    if not target_path:
        raise ToolError("target_path is required (absolute local binary path)")
    path = Path(target_path)
    try:
        path = path.resolve()
    except OSError as exc:
        raise ToolError(f"cannot resolve target_path {target_path!r}: {exc}") from exc
    if not path.is_file():
        raise ToolError(f"target not found: {path}")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ToolError(f"cannot read {path}: {exc}") from exc
    if not data:
        raise ToolError(f"target is empty: {path}")

    is_pe = data[:2] == b"MZ"
    if is_pe:
        pe, machine, imagebase, entry_point, bits = _load_pe(path, data)
        if capstone is None:
            raise ToolError(
                "capstone is not installed; re-run with the re-analytics extra",
            )
        arch_mode = _MACHINE_TO_CAPSTONE.get(machine)
        if arch_mode is None:
            raise ToolError(f"unsupported PE machine type 0x{machine:04x}")
        arch, mode, bits = arch_mode
    else:
        pe, machine, imagebase, entry_point = None, 0, 0, 0
        if capstone is None:
            raise ToolError("capstone is not installed")
        arch, mode, bits = CS_ARCH_X86, capstone.CS_MODE_64, 64

    return LoadedBinary(
        path=path,
        data=data,
        pe=pe,
        is_pe=is_pe,
        arch=arch,
        mode=mode,
        bits=bits,
        machine=machine,
        imagebase=imagebase,
        entry_point=entry_point,
        key=str(path).lower(),
    )


def require_pe(b: LoadedBinary) -> Any:
    """Return the pefile object or raise for non-PE targets."""
    if not (b.is_pe and b.pe is not None):
        raise ToolError(
            f"{b.path.name} is not a PE file; this tool requires a PE target",
        )
    return b.pe


def disasm(b: LoadedBinary, va: int, size: int, *, detail: bool = True) -> list[Any]:
    """Disassemble ``size`` bytes at VA with capstone (empty on failure)."""
    if Cs is None:
        raise ToolError("capstone is not installed")
    code = b.read(va, size)
    if not code:
        return []
    md = Cs(b.arch, b.mode)
    md.detail = detail
    try:
        return list(md.disasm(code, va))
    except capstone.CsError:
        return []


_PROLOGUE_PATTERNS = (
    # x64: push rbp; mov rbp, rsp | sub rsp, imm8 | mov [rsp+imm], imm
    re.compile(rb"\x55\x48\x8b\xec"),
    re.compile(rb"\x48\x89\x5c\x24"),
    re.compile(rb"\x40\x55"),            # x86: push ebp
    re.compile(rb"\x55\x8b\xec"),        # x86: push ebp; mov ebp, esp
    re.compile(rb"\x48\x83\xec"),        # sub rsp, imm8
    re.compile(rb"\x83\xec"),            # x86 sub esp, imm8
)


def iter_function_starts(b: LoadedBinary) -> list[FunctionInfo]:
    """Collect candidate function entries: exports, symbols, thunks.

    Sources, in confidence order: PE exports, COFF symbol table,
    exception-directory RVA list (x64), then call-target/prologue
    heuristics over executable sections. Names from the annotation
    overlay supersede recovered ones at render time.
    """
    seen: dict[int, FunctionInfo] = {}
    if b.is_pe and b.pe is not None:
        pe = b.pe
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.address:
                    va = b.imagebase + exp.address
                    name = exp.name.decode("latin-1", errors="replace") if exp.name else f"export_{va:x}"
                    seen.setdefault(va, FunctionInfo(va, name, source="export"))
        if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
            pass  # debug dir carries no function info
        try:
            for sym in pe.symbols:
                addr = int(getattr(sym, "address", 0) or 0)
                if addr:
                    va = b.imagebase + addr
                    name = getattr(sym, "name", "") or f"sym_{va:x}"
                    if isinstance(name, bytes):
                        name = name.decode("latin-1", errors="replace")
                    seen.setdefault(va, FunctionInfo(va, str(name), source="symbol"))
        except (AttributeError, ValueError):
            pass
        # x64 exception directory: function RVAs are authoritative starts
        try:
            dir_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]  # EXCEPTION
            if dir_entry.Size:
                rva, size = dir_entry.VirtualAddress, dir_entry.Size
                off = pe.get_offset_from_rva(rva)
                n = size // 12
                for i in range(n):
                    rec = pe.__data__[off + i * 12: off + i * 12 + 12]
                    if len(rec) < 12:
                        break
                    func_rva = int.from_bytes(rec[0:4], "little")
                    if func_rva:
                        va = b.imagebase + func_rva
                        seen.setdefault(va, FunctionInfo(va, f"sub_{va:x}", source="pdata"))
        except (ValueError, IndexError, AttributeError):
            pass

    # Call targets from direct E8 calls give good coverage on stripped bins
    for span in b.executable_spans():
        code = b.read(span["va"], span["size"])
        if not code:
            continue
        for m in re.finditer(rb"\xe8(...)", code, re.DOTALL):
            rel = int.from_bytes(m.group(1), "little", signed=True)
            insn_va = span["va"] + m.start()
            tgt = insn_va + 5 + rel
            if span["va"] <= tgt < span["va"] + span["size"]:
                seen.setdefault(tgt, FunctionInfo(tgt, f"sub_{tgt:x}", source="call_target"))

    # Prologue scan fills in compiler-generated helpers
    for span in b.executable_spans():
        code = b.read(span["va"], span["size"])
        for pat in _PROLOGUE_PATTERNS:
            for m in re.finditer(pat, code):
                va = span["va"] + m.start()
                seen.setdefault(va, FunctionInfo(va, f"sub_{va:x}", source="prologue"))

    funcs = sorted(seen.values(), key=lambda f: f.address)
    # Approximate sizes as distance to the next start (capstone-corrected later)
    for i, f in enumerate(funcs):
        nxt = funcs[i + 1].address if i + 1 < len(funcs) else None
        f.size = (nxt - f.address) if nxt else 0
    return funcs


def function_bounds(b: LoadedBinary, start: int, max_insns: int = 4000) -> tuple[int, int, list[Any]]:
    """Recover (start_va, end_va, instructions) for one function.

    Disassembles from ``start`` until two return instructions have been
    followed by non-adjacent code, a jump lands outside a sane window,
    or ``max_insns`` is hit. Bounded and heuristic -- callers state that.
    """
    span = None
    for s in b.executable_spans():
        if s["va"] <= start < s["va"] + s["size"]:
            span = s
            break
    if span is None:
        return start, start, []
    insns = disasm(b, start, min(span["size"] - (start - span["va"]), 64 * 1024))
    if not insns:
        return start, start, []
    out: list[Any] = []
    rets = 0
    for insn in insns:
        out.append(insn)
        if insn.mnemonic in ("ret", "retn", "retf", "int3") and insn.address > start:
            rets += 1
            if rets >= 2:
                break
        if len(out) >= max_insns:
            break
    if not out:
        return start, start, []
    return start, out[-1].address + out[-1].size, out


def build_call_graph(
    b: LoadedBinary, max_funcs: int = 4000,
) -> tuple[dict[int, str], dict[int, set[int]], dict[int, set[int]]]:
    """Build the direct-call graph over executable sections.

    Returns ``(names, callees, callers)`` keyed by function VA. Only
    direct near calls (E8 rel32) are edges; indirect calls through
    registers/IAT are invisible to this graph -- every consumer of this
    data must say so in ``limitations``.
    """
    names: dict[int, str] = {f.address: f.name for f in iter_function_starts(b)[:max_funcs]}
    callees: dict[int, set[int]] = defaultdict(set)
    callers: dict[int, set[int]] = defaultdict(set)
    starts = sorted(names)
    if not starts:
        return names, callees, callers

    def _owner(va: int) -> int | None:
        lo, hi = 0, len(starts) - 1
        owner = None
        while lo <= hi:
            mid = (lo + hi) // 2
            if starts[mid] <= va:
                owner = starts[mid]
                lo = mid + 1
            else:
                hi = mid - 1
        return owner

    for span in b.executable_spans():
        code = b.read(span["va"], span["size"])
        if not code or b.arch != CS_ARCH_X86:
            continue
        for m in re.finditer(rb"\xe8(...)", code, re.DOTALL):
            insn_va = span["va"] + m.start()
            rel = int.from_bytes(m.group(1), "little", signed=True)
            tgt = insn_va + 5 + rel
            src_owner = _owner(insn_va)
            if src_owner is None:
                continue
            names.setdefault(tgt, f"sub_{tgt:x}")
            callees[src_owner].add(tgt)
            callers[tgt].add(src_owner)
    return names, callees, callers


def resolve_function(b: LoadedBinary, address_or_name: str) -> FunctionInfo:
    """Resolve an ida-style ``address_or_name`` to a FunctionInfo."""
    funcs = iter_function_starts(b)
    key = str(address_or_name).strip()
    try:
        va = hex_to_int(key)
    except ToolError:
        va = None
    if va is not None:
        # Nearest start at or below va
        best = None
        for f in funcs:
            if f.address <= va:
                best = f
            else:
                break
        if best is not None and va - best.address < 0x1000:
            return best
        return FunctionInfo(va, annotations.function_name(b.key, va, f"sub_{va:x}"))
    low = key.lower()
    for f in funcs:
        if f.name.lower() == low:
            f.name = annotations.function_name(b.key, f.address, f.name)
            return f
    for f in funcs:
        if low in f.name.lower():
            return f
    raise ToolError(f"function not found: {address_or_name}")


_ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


def extract_strings(b: LoadedBinary, min_length: int = 4) -> list[dict[str, Any]]:
    """Extract ASCII and UTF-16LE strings with VAs, deduped by value.

    Scans raw section bytes (not just the import- referenced set) so the
    behavior matches the agent's expectation from the PE-reader tools:
    broad enumeration first, classification second.
    """
    min_length = max(1, min_length)
    found: dict[tuple[str, str], dict[str, Any]] = {}
    for span in b.section_spans():
        raw = b.data[span["raw_offset"]: span["raw_offset"] + span["raw_size"]]
        for regex, enc in ((_ASCII_RE, "ascii"), (_UTF16_RE, "utf16le")):
            for m in regex.finditer(raw):
                s = m.group()
                if len(s) < min_length and enc == "ascii":
                    continue
                if enc == "utf16le" and (len(s) // 2) < min_length:
                    continue
                va = b.offset_to_va(span["raw_offset"] + m.start())
                try:
                    value = s.decode("utf-16-le" if enc == "utf16le" else "latin-1")
                except UnicodeDecodeError:
                    continue
                key = (enc, value)
                if key not in found:
                    found[key] = {
                        "value": value,
                        "address": f"0x{va:x}",
                        "encoding": enc,
                        "section": span["name"],
                    }
    return sorted(found.values(), key=lambda e: (e["encoding"], e["value"]))


def string_at_va(b: LoadedBinary, va: int, max_length: int, encoding: str) -> tuple[str, str]:
    """Read a null-terminated string at VA; returns (value, canonical_enc)."""
    canonical = "utf16le" if encoding.lower() in ("utf16", "utf-16", "utf-16le", "utf16le") else "ascii"
    step = 2 if canonical == "utf16le" else 1
    out = bytearray()
    for i in range(0, max(0, max_length) * step, step):
        chunk = b.read(va + i, step)
        if len(chunk) < step or chunk == b"\x00" * step:
            break
        out += chunk
    if canonical == "utf16le":
        return out.decode("utf-16-le", errors="replace"), canonical
    return out.decode("latin-1", errors="replace"), canonical


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte; 0 for empty input."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


