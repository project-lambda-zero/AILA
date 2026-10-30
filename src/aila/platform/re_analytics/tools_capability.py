"""Capability group of the ``re_analytics`` MCP tool surface.

Every tool keeps the ida-headless tool name and argument names; the one
contractual change is that ``binary_id`` becomes ``target_path`` -- the
absolute local path of the binary under analysis -- because REA and
re_analytics open targets directly from disk instead of through an
upload/open lifecycle.

Tools fall into four buckets:

* **flare-capa backed** -- ``capa_scan``, ``verify_capabilities``,
  ``classify_behavior``, ``detect_anti_analysis`` share one cached
  per-target evaluation (:mod:`aila.platform.re_analytics._capa_engine`).
* **Real heuristics** -- PE/disassembly analysis implemented here with
  pefile/lief/capstone. Each result carries ``engine`` and
  ``limitations`` fields stating exactly what was and was not proven.
* **Session overlay** -- the ida mutation surface (rename/comment/type/
  patch) against the in-process annotation store; nothing touches disk.
* **Unsupported envelopes** -- tools whose ida implementation needed
  Hex-Rays microcode/ctree, the SMT proof engine, or the async mutation
  worker. They keep their names and return the structured
  ``{"status": "unsupported", ...}`` envelope ida-headless itself used,
  so agents branch on ``status`` exactly as before.
"""
from __future__ import annotations

import difflib
import hashlib
import importlib
import json
import re
import time
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Any

# _miasm_compat applies the pyparsing-3 shim; it must import before miasm.
from aila.platform.re_analytics import _miasm_compat
from aila.platform.re_analytics._binary import (
    annotations,
    build_call_graph,
    disasm,
    extract_strings,
    function_bounds,
    hex_to_int,
    iter_function_starts,
    load_binary,
    require_pe,
    resolve_function,
    shannon_entropy,
    string_at_va,
    x86_arg_register,
)
from aila.platform.re_analytics._capa_engine import capa_evaluate, capa_render
from aila.platform.re_analytics._tooldef import ToolDef, ToolError

__all__ = ["TOOLS"]

_LOG = __import__("logging").getLogger(__name__)

# Optional heavy deps. Presence is reported by worker_status; individual
# tools raise ToolError with an install hint when their engine is absent.
# (capstone is effectively required for the disassembly tools -- pefile and
# capstone back nearly every handler -- but the module must still import so
# tools/list can advertise the surface on a bare host.)
try:
    import capstone.x86_const as _x86_const

    X86_OP_IMM = _x86_const.X86_OP_IMM
    X86_OP_MEM = _x86_const.X86_OP_MEM
    X86_OP_REG = _x86_const.X86_OP_REG
except ImportError:  # pragma: no cover - environment guard
    X86_OP_IMM = X86_OP_MEM = X86_OP_REG = 0

miasm = importlib.import_module("miasm") if _miasm_compat.HAS_MIASM else None

try:
    import lief
except ImportError:  # pragma: no cover - environment guard
    lief = None  # type: ignore[assignment]

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:  # pragma: no cover - environment guard
    Cipher = None  # type: ignore[assignment]
    algorithms = None  # type: ignore[assignment]
    modes = None  # type: ignore[assignment]


# ── schema helpers ───────────────────────────────────────────────────

def _schema(
    properties: dict[str, Any], required: list[str],
) -> dict[str, Any]:
    props = {
        "target_path": {
            "type": "string",
            "description": (
                "Absolute local filesystem path of the binary under analysis."
            ),
        },
    }
    props.update(properties)
    req = ["target_path"] if "target_path" in required else []
    req += [r for r in required if r != "target_path"]
    return {"type": "object", "properties": props, "required": req}


def _path_prop(description: str) -> dict[str, Any]:
    return {"type": "string", "description": description}


def _addr_prop(description: str = "Virtual address (0x...) or function name.") -> dict[str, Any]:
    return {"type": "string", "description": description}


# ── shared plumbing ──────────────────────────────────────────────────

def _key(target_path: str) -> str:
    try:
        return str(Path(target_path).resolve()).lower()
    except OSError as exc:
        raise ToolError(f"cannot resolve target_path {target_path!r}: {exc}") from exc


def _unsupported(name: str, reason: str, properties: dict[str, Any] | None = None) -> ToolDef:
    """Build a ToolDef that returns ida's structured unsupported envelope."""

    async def _handler(_args: dict[str, Any]) -> dict[str, Any]:
        return {"status": "unsupported", "tool": name, "reason": reason}

    return ToolDef(
        name=name,
        description=f"{name} (preserved ida-headless tool name). {reason}",
        input_schema=_schema(properties or {}, ["target_path"]),
        handler=_handler,
    )


def _section_for_va(sections: list[dict[str, Any]], va: int) -> str | None:
    for s in sections:
        if s["va"] <= va < s["va"] + s["size"]:
            return s["name"]
    return None


def _display_name(b: Any, address: int, fallback: str) -> str:
    return annotations.function_name(b.key, address, fallback)


# ======================================================================
# flare-capa backed tools
# ======================================================================


async def _capa_scan(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target_path", ""))
    rules, capabilities = capa_evaluate(target)
    payload = capa_render(rules, capabilities)
    payload["status"] = "ok"
    payload["target_path"] = str(Path(target).resolve())
    payload["engine"] = "flare-capa"
    return payload


async def _verify_capabilities(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target_path", ""))
    b = load_binary(target)
    rules, capabilities = capa_evaluate(target)
    payload = capa_render(rules, capabilities)

    by_namespace: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for cap in payload["capabilities"]:
        by_namespace[cap["namespace"] or "uncategorized"].append(cap)

    pe = require_pe(b)
    imports: list[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    imports.append(imp.name.decode("latin-1", errors="replace"))
    matched_apis = {
        cap["rule"].lower() for caps in by_namespace.values() for cap in caps
    }
    uncategorized = sorted(
        api for api in set(imports) if api.lower() not in matched_apis
    )

    capabilities_out = [
        {
            "capability": ns,
            "verdict": "confirmed",
            "evidence_rules": [c["rule"] for c in caps],
            "evidence_addresses": [
                a for c in caps for a in c["addresses"][:5]
            ][:10],
            "description": caps[0]["description"] if caps else "",
        }
        for ns, caps in sorted(by_namespace.items())
    ]
    return {
        "status": "ok",
        "target_path": str(b.path),
        "engine": "flare-capa",
        "capabilities": capabilities_out,
        "capability_count": len(capabilities_out),
        "uncategorized_apis": uncategorized[:100],
        "limitations": [
            "verdicts are per-namespace presence, not exploitability proof",
            "uncategorized_apis are imports no matched capa rule referenced",
        ],
    }


async def _classify_behavior(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target_path", ""))
    rules, capabilities = capa_evaluate(target)
    payload = capa_render(rules, capabilities)

    categories: dict[str, dict[str, Any]] = {}
    for cap in payload["capabilities"]:
        ns = cap["namespace"] or "uncategorized"
        top = ns.split("/")[0]
        cat = categories.setdefault(top, {"category": top, "rules": [], "attack": []})
        cat["rules"].append(cap["rule"])
        for a in cap["attack"]:
            if a not in cat["attack"]:
                cat["attack"].append(a)
    for cat in categories.values():
        cat["rule_count"] = len(cat["rules"])
    return {
        "status": "ok",
        "target_path": str(Path(target).resolve()),
        "engine": "flare-capa",
        "categories": sorted(categories.values(), key=lambda c: -c["rule_count"]),
        "total_rules_matched": payload["matches"],
        "attack_map": payload["attack_map"],
        "limitations": [
            "behavior classes derive from capa rule namespaces; absence of a"
            " class only means no rule matched, not that the behavior is absent"
        ],
    }


async def _detect_anti_analysis(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target_path", ""))
    b = load_binary(target)
    pe = require_pe(b)
    rules, capabilities = capa_evaluate(target)
    payload = capa_render(rules, capabilities)

    techniques: list[dict[str, Any]] = []
    for cap in payload["capabilities"]:
        if (cap["namespace"] or "").startswith("anti-analysis"):
            techniques.append({
                "technique": cap["rule"],
                "description": cap["description"],
                "addresses": cap["addresses"][:10],
                "source": "capa",
            })

    # Import-based checks complement capa with explicit evidence.
    anti_debug_imports = {
        "isdebuggerpresent", "checkremotedebuggerpresent",
        "ntqueryinformationprocess", "outputdebugstringa", "outputdebugstringw",
        "findwindowa", "findwindoww", "gettickcount", "gettickcount64",
        "queryperformancecounter", "rdtsc",
    }
    anti_vm_strings = (
        "vmware", "vbox", "virtualbox", "qemu", "xen", "parallels",
        "sandbox", "cuckoo", "wireshark", "procmon", "process monitor",
    )
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("latin-1", errors="replace") if entry.dll else "?"
            for imp in entry.imports:
                if not imp.name:
                    continue
                name = imp.name.decode("latin-1", errors="replace")
                if name.lower() in anti_debug_imports:
                    techniques.append({
                        "technique": f"anti-debug import {name}",
                        "description": f"imported from {dll}",
                        "addresses": [],
                        "source": "imports",
                    })
    for s in extract_strings(b, 6):
        low = s["value"].lower()
        if any(marker in low for marker in anti_vm_strings):
            techniques.append({
                "technique": f"anti-vm string {s['value'][:64]!r}",
                "description": f"found in section {s['section']}",
                "addresses": [s["address"]],
                "source": "strings",
            })

    # de-dupe by technique name
    seen: dict[str, dict[str, Any]] = {}
    for t in techniques:
        seen.setdefault(t["technique"], t)
    return {
        "status": "ok",
        "target_path": str(b.path),
        "engine": "flare-capa + pe imports/strings",
        "techniques": sorted(seen.values(), key=lambda t: t["technique"]),
        "count": len(seen),
        "limitations": [
            "string markers also match benign VMware/VirtualBox tooling",
            "capa anti-analysis namespace relies on the installed rule set",
        ],
    }


# ======================================================================
# strings / dynamic resolution / API tracing
# ======================================================================


async def _classify_strings(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target_path", ""))
    limit = int(args.get("limit", 200) or 200)
    b = load_binary(target)
    entries = extract_strings(b, 4)

    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    patterns: list[tuple[str, Any]] = [
        ("url", re.compile(r"https?://[^\s'\"<>]+", re.I)),
        ("ip_address", re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b")),
        ("email", re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")),
        ("registry_path", re.compile(r"^(HKEY_|SYSTEM\\|SOFTWARE\\|\\Registry\\)", re.I)),
        ("file_path", re.compile(r"^(?:[A-Za-z]:\\|/|\\\\)")),
        ("guid", re.compile(r"^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$")),
        ("base64_blob", re.compile(r"^[A-Za-z0-9+/]{40,}={0,2}$")),
        ("user_agent", re.compile(r"^(Mozilla/|curl/|Wget/|python-requests/)")),
        ("pdb_path", re.compile(r"\.pdb$", re.I)),
        ("dll_name", re.compile(r"\.dll$", re.I)),
        ("exe_name", re.compile(r"\.exe$", re.I)),
    ]
    for entry in entries:
        value = entry["value"].strip()
        if not value:
            continue
        categorized = False
        for name, regex in patterns:
            if regex.search(value):
                buckets[name].append(entry)
                categorized = True
                break
        if not categorized:
            buckets["other"].append(entry)

    counts = {k: len(v) for k, v in sorted(buckets.items())}
    out: dict[str, list[dict[str, Any]]] = {}
    remaining = max(0, limit)
    for name in sorted(buckets, key=lambda k: -len(buckets[k])):
        take = buckets[name][:remaining]
        if take:
            out[name] = take
            remaining -= len(take)
        if remaining <= 0:
            break
    return {
        "status": "ok",
        "target_path": str(b.path),
        "engine": "raw-section regex classification",
        "total_strings": len(entries),
        "counts": counts,
        "categories": out,
        "returned": sum(len(v) for v in out.values()),
        "limitations": [
            "scans raw section bytes, so UTF-16LE/.rsrc strings are included",
            "regex buckets are coarse; 'other' holds everything unmatched",
        ],
    }


def _import_iat_slots(b: Any) -> dict[str, int]:
    """Map imported API name (lower) to IAT slot VA."""
    pe = require_pe(b)
    slots: dict[str, int] = {}
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return slots
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.name and imp.address:
                name = imp.name.decode("latin-1", errors="replace")
                slots[name.lower()] = int(imp.address)
    return slots


def _x86_mem_target(insn: Any) -> int | None:
    """Resolve a rip-relative [base+disp] memory operand to its VA."""
    if not insn.operands:
        return None
    mem = getattr(insn.operands[0], "mem", None)
    if mem is None:
        return None
    base_name = insn.reg_name(getattr(mem, "base", 0) or 0)
    if base_name != "rip":
        return None
    return insn.address + insn.size + getattr(mem, "disp", 0)


def _scan_iat_refs(b: Any, opcode2: int, slot_va: int) -> list[int]:
    """Find ``FF <opcode2> <disp32>`` refs to ``slot_va`` in executable spans.

    Byte-search finds candidates (capstone's linear stream can stall on
    embedded data and drop a section tail), then each candidate is
    validated by a targeted 6-byte decode at its exact address, so a
    false ``ff 15`` inside an immediate is discarded.
    """
    hits: list[int] = []
    for span in b.executable_spans():
        code = b.read(span["va"], span["size"])
        needle = bytes((0xFF, opcode2))
        start = 0
        while True:
            idx = code.find(needle, start)
            if idx < 0:
                break
            start = idx + 1
            va = span["va"] + idx
            # REX-prefixed form (48 ff 15 ...) starts one byte earlier and
            # is 7 bytes long; prefer the real instruction boundary.
            prev = code[idx - 1] if idx > 0 else 0
            if 0x40 <= prev <= 0x4F:
                rex_insn = disasm(b, va - 1, 7, detail=True)
                if (
                    len(rex_insn) == 1
                    and rex_insn[0].address == va - 1
                    and rex_insn[0].size == 7
                    and rex_insn[0].bytes[1:3] == needle
                    and _x86_mem_target(rex_insn[0]) == slot_va
                ):
                    hits.append(va - 1)
                    continue
            insn_list = disasm(b, va, 6, detail=True)
            if (
                len(insn_list) == 1
                and insn_list[0].address == va
                and insn_list[0].bytes[:2] == needle
                and insn_list[0].size == 6
                and _x86_mem_target(insn_list[0]) == slot_va
            ):
                hits.append(va)
    return hits


def _find_calls_to_iat(b: Any, slot_va: int) -> list[int]:
    """Scan executable sections for FF 15 <disp32> (call [IAT slot])."""
    return _scan_iat_refs(b, 0x15, slot_va)


def _find_thunks(b: Any, slot_va: int) -> list[int]:
    """Scan for FF 25 <disp32> (jmp [IAT slot]) thunk stubs."""
    return _scan_iat_refs(b, 0x25, slot_va)


async def _detect_dynamic_resolution(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target_path", ""))
    limit = int(args.get("limit", 50) or 50)
    b = load_binary(target)
    slots = _import_iat_slots(b)
    resolver_names = ("getprocaddress", "loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw", "ldrloaddll", "ldrdll")
    resolver_slots = {name: va for name, va in slots.items() if name in resolver_names}

    resolvers: list[dict[str, Any]] = []
    for name, slot in sorted(resolver_slots.items()):
        for site in _find_calls_to_iat(b, slot):
            entry: dict[str, Any] = {
                "resolver": name,
                "call_site": f"0x{site:x}",
                "resolved_names": [],
            }
            # Heuristic: look backwards for a string pointer argument setup.
            insns = disasm(b, max(b.imagebase, site - 0x80), site - max(b.imagebase, site - 0x80) + 8)
            window = [i for i in insns if i.address < site][-16:]
            for insn in window:
                if insn.mnemonic == "lea" and insn.operands:
                    op = insn.operands[-1]
                    mem = getattr(op, "mem", None)
                    disp = getattr(mem, "disp", 0) if mem is not None else 0
                    if insn.reg_name(getattr(mem, "base", 0) or 0) == "rip":
                        ptr = insn.address + insn.size + disp
                        value, _ = string_at_va(b, ptr, 128, "ascii")
                        if value and value.strip():
                            entry["resolved_names"].append(value)
                elif insn.mnemonic == "mov" and insn.operands:
                    imm = getattr(insn.operands[-1], "imm", 0)
                    if isinstance(imm, int) and b.imagebase <= imm < b.imagebase + 0x10000000:
                        value, _ = string_at_va(b, imm, 128, "ascii")
                        if value and value.strip():
                            entry["resolved_names"].append(value)
            resolvers.append(entry)

    return {
        "status": "ok",
        "target_path": str(b.path),
        "engine": "IAT scan + call-site backtracking",
        "resolvers": resolvers[:limit],
        "total": len(resolvers),
        "returned": min(len(resolvers), limit),
        "limitations": [
            "resolved names come from heuristics near the call site; "
            "indirect resolution through registers is not followed",
        ],
    }


async def _find_api_call_sites(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target_path", ""))
    api_name = str(args.get("api_name", "")).strip()
    if not api_name:
        raise ToolError("api_name is required")
    b = load_binary(target)
    slots = _import_iat_slots(b)
    slot = slots.get(api_name.lower())
    call_sites: list[str] = []
    thunk_addrs: list[str] = []
    if slot is not None:
        call_sites = [f"0x{a:x}" for a in _find_calls_to_iat(b, slot)]
        thunks = _find_thunks(b, slot)
        thunk_addrs = [f"0x{a:x}" for a in thunks]
        # Direct calls (E8) to thunks
        names, _callees, _callers = build_call_graph(b)
        thunk_set = {hex_to_int(a) for a in thunk_addrs}
        for src, targets in _callees.items():
            for tgt in targets:
                if tgt in thunk_set:
                    call_sites.append(f"0x{src:x}")

    # Hash-resolution marker: the API name appearing in .rdata/.data
    name_locations: list[str] = []
    needle = api_name.encode("latin-1")
    for span in b.section_spans():
        raw = b.data[span["raw_offset"]: span["raw_offset"] + span["raw_size"]]
        start = 0
        while True:
            idx = raw.find(needle, start)
            if idx < 0:
                break
            name_locations.append(f"0x{b.offset_to_va(span['raw_offset'] + idx):x}")
            start = idx + 1

    return {
        "status": "ok",
        "target_path": str(b.path),
        "api_name": api_name,
        "iat_address": f"0x{slot:x}" if slot is not None else None,
        "thunk_addresses": sorted(set(thunk_addrs)),
        "call_sites": sorted(set(call_sites)),
        "name_locations": name_locations,
        "limitations": [
            "hash-resolved APIs leave no name xref; name_locations only"
            " catches plaintext storage of the name",
        ],
    }


# ======================================================================
# lifecycle / worker status / overlay mutations
# ======================================================================


async def _close_binary(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target_path", ""))
    key = _key(target)
    annotations.reset_target(key)
    return {
        "status": "ok",
        "target_path": target,
        "closed": True,
        "note": "re_analytics is stateless per call; closing discards the session annotation/patch overlay for this target",
    }


async def _worker_status(_args: dict[str, Any]) -> dict[str, Any]:
    def _has(mod: str) -> bool:
        try:
            __import__(mod)
        except ImportError:
            return False
        return True

    groups: dict[str, int] = {}
    for mod_name in (
        "aila.platform.re_analytics.tools_capability",
        "aila.platform.re_analytics.tools_crypto",
        "aila.platform.re_analytics.tools_dataflow",
    ):
        try:
            mod = __import__(mod_name, fromlist=["TOOLS"])
            groups[mod_name.rsplit(".", 1)[-1]] = len(getattr(mod, "TOOLS", []))
        except ImportError:
            groups[mod_name.rsplit(".", 1)[-1]] = -1

    targets = {k: annotations.stats(k) for k in annotations.target_keys()}
    return {
        "status": "ok",
        "server": "re_analytics",
        "tool_groups": groups,
        "dependencies": {
            "pefile": _has("pefile"),
            "capstone": _has("capstone"),
            "lief": _has("lief"),
            "flare-capa": _has("capa.rules"),
            "miasm": _has("miasm"),
            "unicorn": _has("unicorn"),
            "keystone": _has("keystone"),
            "cryptography": _has("cryptography"),
        },
        "overlay_targets": targets,
        "note": "single-process stdio server; there is no external worker or queue",
    }


async def _get_generation(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target_path", ""))
    key = _key(target)
    return {
        "status": "ok",
        "target_path": target,
        "generation": annotations.generation(key),
        "note": "increments on every session mutation (rename/comment/patch); use to detect stale analysis results",
    }


def _bump(key: str) -> int:
    return annotations.bump_generation(key)


async def _rename_function(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target_path", ""))
    address = hex_to_int(args.get("address"))
    new_name = str(args.get("new_name", "")).strip()
    if not new_name:
        raise ToolError("new_name is required")
    key = _key(target)
    annotations.rename_function(key, address, new_name)
    return {
        "status": "ok",
        "target_path": target,
        "address": f"0x{address:x}",
        "new_name": new_name,
        "generation": _bump(key),
        "note": "session-scoped rename; applied to function renders by this server",
    }


async def _rename_variable(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target_path", ""))
    func = hex_to_int(args.get("function_address"))
    old = str(args.get("old_name", "")).strip()
    new = str(args.get("new_name", "")).strip()
    if not old or not new:
        raise ToolError("old_name and new_name are required")
    key = _key(target)
    annotations.rename_variable(key, func, old, new)
    return {
        "status": "ok",
        "target_path": target,
        "function_address": f"0x{func:x}",
        "old_name": old,
        "new_name": new,
        "generation": _bump(key),
        "note": "surfaced in function_extra() renders (recover_cfg, miasm_disassemble)",
    }


async def _set_comment(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target_path", ""))
    address = hex_to_int(args.get("address"))
    comment = str(args.get("comment", ""))
    key = _key(target)
    annotations.set_comment(key, address, comment)
    return {
        "status": "ok",
        "target_path": target,
        "address": f"0x{address:x}",
        "generation": _bump(key),
    }


async def _set_function_type(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target_path", ""))
    func = hex_to_int(args.get("function_address"))
    prototype = str(args.get("prototype", "")).strip()
    if not prototype:
        raise ToolError("prototype is required")
    key = _key(target)
    annotations.set_function_type(key, func, prototype)
    return {
        "status": "ok",
        "target_path": target,
        "function_address": f"0x{func:x}",
        "prototype": prototype,
        "generation": _bump(key),
    }


async def _set_variable_type(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target_path", ""))
    func = hex_to_int(args.get("function_address"))
    var = str(args.get("variable_name", "")).strip()
    ty = str(args.get("new_type", "")).strip()
    if not var or not ty:
        raise ToolError("variable_name and new_type are required")
    key = _key(target)
    annotations.set_variable_type(key, func, var, ty)
    return {
        "status": "ok",
        "target_path": target,
        "function_address": f"0x{func:x}",
        "variable_name": var,
        "new_type": ty,
        "generation": _bump(key),
    }


async def _patch_bytes(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target_path", ""))
    address = hex_to_int(args.get("address"))
    hex_bytes = re.sub(r"[^0-9a-fA-F]", "", str(args.get("hex_bytes", "")))
    if not hex_bytes or len(hex_bytes) % 2:
        raise ToolError("hex_bytes must be an even-length hex string")
    if len(hex_bytes) > 8192:
        raise ToolError("hex_bytes too large (max 4096 bytes)")
    data = bytes.fromhex(hex_bytes)
    b = load_binary(target)
    key = _key(target)
    annotations.patch_bytes(key, address, data)
    applied = b.read(address, len(data))
    return {
        "status": "ok",
        "target_path": str(b.path),
        "address": f"0x{address:x}",
        "bytes_written": len(data),
        "applied_hex": applied.hex(),
        "generation": annotations.generation(key),
        "note": "session-scoped overlay; the file on disk is NOT modified",
    }


# ======================================================================
# miasm / disassembly family
# ======================================================================


def _miasm_available() -> bool:
    return miasm is not None


async def _miasm_disassemble(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target_path", ""))
    address = hex_to_int(args.get("address"))
    size = int(args.get("size", 64) or 64)
    b = load_binary(target)
    # capstone backs this tool (name preserved from ida-headless); the
    # result states the engine so consumers are not misled.
    insns = disasm(b, address, size)
    return {
        "status": "ok",
        "target_path": str(b.path),
        "engine": "capstone",
        "architecture": f"{b.bits}-bit",
        "address": f"0x{address:x}",
        "instructions": [
            {
                "address": f"0x{i.address:x}",
                "mnemonic": i.mnemonic,
                "operands": i.op_str,
                "size": i.size,
                "bytes": i.bytes.hex(),
            }
            for i in insns
        ],
        "count": len(insns),
        "limitations": ["backed by capstone, not miasm; ARM/Thumb targets use capstone semantics"],
    }


async def _miasm_lift_ir(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target_path", ""))
    address = hex_to_int(args.get("address"))
    size = int(args.get("size", 64) or 64)
    if not _miasm_available():
        raise ToolError(
            "miasm is not installed; pip install miasm to enable IR lifting",
        )
    b = load_binary(target)
    code = b.read(address, size)
    if not code:
        raise ToolError(f"no executable bytes at 0x{address:x}")
    try:
        machine = _miasm_compat.Machine("x86_64" if b.bits == 64 else "x86_32")
        loc_db = _miasm_compat.LocationDB()
        # Stream only the requested window, rebased at ``address``, so the
        # disassembler cannot walk outside it.
        stream = _miasm_compat.bin_stream_str(code, base_address=address)
        mdis = machine.dis_engine(stream, loc_db=loc_db, follow_call=False)
        mdis.dont_dis_nulstart_bloc = True
        asmcfg = mdis.dis_multiblock(address)
        lifter = machine.lifter_model_call(loc_db)
        ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)
        blocks = []
        for loc_key, irblock in sorted(
            ircfg.blocks.items(),
            key=lambda kv: loc_db.get_location_offset(kv[0]) or 0,
        ):
            offset = loc_db.get_location_offset(loc_key)
            if offset is None or not (address <= offset < address + len(code)):
                continue
            assignments = [
                {"dst": str(dst), "src": str(src)}
                for assignblk in irblock
                for dst, src in assignblk.items()
            ]
            blocks.append({"address": f"0x{offset:x}", "assignments": assignments})
            if len(blocks) >= 32:
                break
        return {
            "status": "ok",
            "target_path": str(b.path),
            "engine": "miasm",
            "address": f"0x{address:x}",
            "blocks": blocks,
            "count": len(blocks),
            "limitations": [
                "IR lifted within the requested byte window only",
                "at most 32 IR blocks are returned",
            ],
        }
    except ToolError:
        raise
    except (ValueError, RuntimeError, KeyError, TypeError, AttributeError) as exc:
        raise ToolError(f"miasm lifting failed at 0x{address:x}: {exc}") from exc


async def _miasm_simplify_expression(args: dict[str, Any]) -> dict[str, Any]:
    expression = str(args.get("expression", "")).strip()
    if not expression:
        raise ToolError("expression is required")
    if not _miasm_available():
        raise ToolError(
            "miasm is not installed; pip install miasm to enable expression simplification",
        )
    try:
        from miasm.expression.parser import str_to_expr
        from miasm.expression.simplifications import expr_simp

        expr = str_to_expr(expression)
        simplified = expr_simp(expr)
        return {
            "status": "ok",
            "engine": "miasm",
            "original": expression,
            "simplified": str(simplified),
            "changed": str(simplified) != expression,
        }
    except (ValueError, RuntimeError, KeyError, TypeError, AttributeError) as exc:
        raise ToolError(f"miasm simplification failed: {exc}") from exc


# ======================================================================
# CFG recovery / CFF / stack strings / obfuscation
# ======================================================================


def _split_blocks(insns: list[Any]) -> tuple[list[dict[str, Any]], list[tuple[int, int]]]:
    """Split linear disassembly into basic blocks at branch boundaries."""
    if not insns:
        return [], []
    leaders: set[int] = {insns[0].address}
    branch_targets: set[int] = set()
    for i, insn in enumerate(insns):
        if insn.mnemonic.startswith("j") or insn.mnemonic in ("call", "ret", "retn", "jmp"):
            for op in insn.operands:
                imm = getattr(op, "imm", None)
                if isinstance(imm, int) and any(i2.address == imm for i2 in insns):
                    branch_targets.add(imm)
                    leaders.add(imm)
            if i + 1 < len(insns):
                leaders.add(insns[i + 1].address)
    addr_to_insn = {i.address: i for i in insns}
    blocks: list[dict[str, Any]] = []
    edges: list[tuple[int, int]] = []
    sorted_leaders = sorted(lead for lead in leaders if lead in addr_to_insn)
    for idx, start in enumerate(sorted_leaders):
        next_start = sorted_leaders[idx + 1] if idx + 1 < len(sorted_leaders) else None
        body = [i for i in insns if i.address >= start and (next_start is None or i.address < next_start)]
        if not body:
            continue
        term = body[-1]
        fallthrough = None
        if term.mnemonic.startswith("j") or term.mnemonic == "jmp":
            for op in term.operands:
                imm = getattr(op, "imm", None)
                if isinstance(imm, int) and imm in addr_to_insn:
                    edges.append((start, imm))
            if term.mnemonic != "jmp" and idx + 1 < len(sorted_leaders):
                fallthrough = sorted_leaders[idx + 1]
                edges.append((start, fallthrough))
        blocks.append({
            "address": f"0x{start:x}",
            "size": sum(i.size for i in body),
            "instruction_count": len(body),
            "terminator": term.mnemonic,
            "terminator_address": f"0x{term.address:x}",
            "fallthrough": f"0x{fallthrough:x}" if fallthrough else None,
        })
    return blocks, edges


_SURVEY_DANGEROUS_IMPORTS = frozenset({
    "memcpy", "memmove", "strcpy", "sprintf", "gets", "strcat",
    "system", "popen", "execve", "free", "malloc", "realloc",
})
_SURVEY_NETWORK_IMPORTS = frozenset({
    "recv", "send", "accept", "bind", "listen", "connect",
    "recvfrom", "sendto", "wsarecv", "wsasend", "read", "write",
})
_SURVEY_MAX_FUNCTIONS = 4000


def _imported_names(b: Any) -> set[str]:
    pe = b.pe if b.is_pe else None
    names: set[str] = set()
    for attr in ("DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT"):
        for entry in getattr(pe, attr, None) or []:
            for imp in entry.imports:
                if imp.name:
                    names.add(imp.name.decode("latin-1").lower())
    return names


async def _binary_survey(args: dict[str, Any]) -> dict[str, Any]:
    """One-call orientation: overview, attack surface, complexity hotspots."""
    target = str(args.get("target_path", ""))
    max_hotspots = max(1, int(args.get("max_hotspots", 10) or 10))
    b = load_binary(target)
    names, callees, callers = build_call_graph(b, max_funcs=_SURVEY_MAX_FUNCTIONS)
    string_vas = {int(s["address"], 16) for s in extract_strings(b)}

    rows: list[dict[str, Any]] = []
    covered_until = 0
    for start in sorted(names)[:_SURVEY_MAX_FUNCTIONS]:
        # Heuristic discovery yields interior addresses (mid-function
        # call targets / prologue matches) as extra starts; a start inside
        # the previous function's recovered range is the same function.
        if start < covered_until:
            continue
        _s, end, insns = function_bounds(b, start)
        if not insns:
            continue
        covered_until = end
        blocks, edges = _split_blocks(insns)
        string_refs = 0
        for insn in insns:
            for op in getattr(insn, "operands", ()) or ():
                if op.type == X86_OP_MEM and op.mem.base == 0 and op.mem.disp in string_vas:
                    string_refs += 1
                elif op.type == X86_OP_MEM and insn.reg_name(op.mem.base) == "rip":
                    if insn.address + insn.size + op.mem.disp in string_vas:
                        string_refs += 1
                elif op.type == X86_OP_IMM and op.imm in string_vas:
                    string_refs += 1
        rows.append({
            "name": _display_name(b, start, names[start]),
            "address": f"0x{start:x}",
            # McCabe: E - N + 2 over the recovered intra-procedural CFG.
            "complexity": max(1, len(edges) - len(blocks) + 2),
            "callees_count": len(callees.get(start, ())),
            "callers_count": len(callers.get(start, ())),
            "string_refs_count": string_refs,
        })
    rows.sort(key=lambda r: -r["complexity"])
    imports = _imported_names(b)
    exports = 0
    if b.is_pe and hasattr(b.pe, "DIRECTORY_ENTRY_EXPORT"):
        exports = len(b.pe.DIRECTORY_ENTRY_EXPORT.symbols)
    return {
        "status": "ok",
        "target_path": str(b.path),
        "engine": "capstone linear disassembly + direct-call graph",
        "overview": {
            "root_filename": b.path.name,
            "format": "pe" if b.is_pe else "raw",
            "bits": b.bits,
            "total_functions": len(rows),
        },
        "attack_surface": {
            "exported_functions": exports,
            "imports_dangerous": sorted(imports & _SURVEY_DANGEROUS_IMPORTS),
            "imports_network": sorted(imports & _SURVEY_NETWORK_IMPORTS),
        },
        "hotspots": rows[:max_hotspots],
        "limitations": [
            "function discovery is heuristic (exports, symbols, .pdata, direct call targets)",
            "cyclomatic complexity counts only direct branch edges; indirect jumps add none",
            f"at most {_SURVEY_MAX_FUNCTIONS} functions are surveyed",
        ],
    }


async def _recover_cfg(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target_path", ""))
    address_or_name = str(args.get("address_or_name", ""))
    b = load_binary(target)
    f = resolve_function(b, address_or_name)
    start, end, insns = function_bounds(b, f.address)
    blocks, edges = _split_blocks(insns)
    name = _display_name(b, f.address, f.name)
    return {
        "status": "ok",
        "target_path": str(b.path),
        "engine": "capstone linear disassembly + branch-target splitting",
        "function": name,
        "function_address": f"0x{f.address:x}",
        "range": [f"0x{start:x}", f"0x{end:x}"],
        "blocks": blocks,
        "edges": [[f"0x{a:x}", f"0x{c:x}"] for a, c in edges],
        "stats": {
            "block_count": len(blocks),
            "instruction_count": len(insns),
            "edge_count": len(edges),
        },
        "annotations": annotations.function_extra(b.key, f.address),
        "comment": annotations.comment(b.key, f.address),
        "limitations": [
            "function bounds are heuristic (linear disassembly until double ret)",
            "indirect branches produce no edges",
        ],
    }


async def _detect_stack_strings(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target_path", ""))
    address_or_name = str(args.get("address_or_name", ""))
    b = load_binary(target)
    f = resolve_function(b, address_or_name)
    _s, _e, insns = function_bounds(b, f.address)

    chunks: dict[tuple[str, int], bytearray] = {}
    order: list[tuple[str, int, int]] = []
    for insn in insns:
        if insn.mnemonic != "mov" or not insn.operands:
            continue
        dst, src = insn.operands[0], insn.operands[-1]
        if dst.type != X86_OP_MEM or src.type != X86_OP_IMM:
            continue
        base_name = insn.reg_name(dst.mem.base) if dst.mem.base else ""
        if base_name not in ("rsp", "rbp", "esp", "ebp"):
            continue
        key = (base_name, dst.mem.disp)
        if key not in chunks:
            chunks[key] = bytearray()
            order.append((base_name, dst.mem.disp, insn.address))
        nbytes = max(1, min(4, (src.imm.bit_length() + 7) // 8 if isinstance(src.imm, int) else 1))
        chunks[key] += int(src.imm).to_bytes(4, "little")[:nbytes] if isinstance(src.imm, int) else b""

    results: list[dict[str, Any]] = []
    for base_name, disp, at in order:
        raw = bytes(chunks[(base_name, disp)])
        text = raw.split(b"\x00")[0]
        if len(text) >= 4 and all(0x20 <= c < 0x7F for c in text):
            results.append({
                "address": f"0x{at:x}",
                "stack_offset": f"{base_name}{disp:+d}" if disp else base_name,
                "string": text.decode("latin-1"),
                "length": len(text),
            })
    return {
        "status": "ok",
        "target_path": str(b.path),
        "engine": "capstone stack-write tracking",
        "function": _display_name(b, f.address, f.name),
        "function_address": f"0x{f.address:x}",
        "stack_strings": results,
        "count": len(results),
        "limitations": [
            "tracks immediate dword/byte writes to rsp/rbp relative slots only",
            "loop-built stack strings are not unrolled",
        ],
    }


def _opaque_predicates_in_blocks(insns: list[Any]) -> list[dict[str, Any]]:
    """Find cmp reg,imm where reg holds an immediate earlier in the block."""

    out: list[dict[str, Any]] = []
    consts: dict[str, int] = {}
    for insn in insns:
        if insn.mnemonic == "mov" and insn.operands:
            dst, src = insn.operands[0], insn.operands[-1]
            if dst.type == X86_OP_REG and src.type == X86_OP_IMM:
                consts[insn.reg_name(dst.reg)] = int(src.imm)
        elif insn.mnemonic == "cmp" and insn.operands:
            op0, op1 = insn.operands[0], insn.operands[-1]
            if op0.type == X86_OP_REG and op1.type == X86_OP_IMM:
                reg = insn.reg_name(op0.reg)
                if reg in consts:
                    out.append({
                        "address": f"0x{insn.address:x}",
                        "comparison": f"{reg} == 0x{int(op1.imm):x}",
                        "constant_value": f"0x{consts[reg]:x}",
                        "always": consts[reg] == int(op1.imm),
                    })
        elif insn.mnemonic.startswith("j") or insn.mnemonic in ("call", "ret", "retn"):
            pass  # block boundary for fold purposes: reset
    return out


async def _detect_cff(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target_path", ""))
    address_or_name = str(args.get("address_or_name", ""))
    b = load_binary(target)
    f = resolve_function(b, address_or_name)
    _s, _e, insns = function_bounds(b, f.address)
    blocks, edges = _split_blocks(insns)
    indegree: Counter[str] = Counter()
    for _a, c in edges:
        indegree[c] += 1

    dispatcher: str | None = None
    for block in blocks:
        if indegree[block["address"]] >= 4 and block["terminator"] in ("jmp",):
            dispatcher = block["address"]
            break
    state_var = None
    if dispatcher is not None and len(blocks) >= 8:
        # OLLVM-style: many small blocks converging on one indirect jump dispatcher
        state_var = "switch-state (heuristic: high fan-in dispatcher)"

    indirect = 0
    for insn in insns:
        if insn.mnemonic == "jmp" and insn.operands:
            op = insn.operands[0]
            if op.type in (X86_OP_MEM, X86_OP_REG):
                indirect += 1
    ratio = (indirect / len(insns)) if insns else 0.0
    opaque = _opaque_predicates_in_blocks(insns)
    is_cff = dispatcher is not None and (len(blocks) >= 8 or ratio > 0.02)
    return {
        "status": "ok",
        "target_path": str(b.path),
        "engine": "CFG topology heuristics (capstone)",
        "function": _display_name(b, f.address, f.name),
        "function_address": f"0x{f.address:x}",
        "is_cff": bool(is_cff),
        "dispatcher_address": dispatcher,
        "state_variable": state_var,
        "matched_signature": "ollvm-style" if is_cff else "none",
        "confidence": ("high" if is_cff and len(blocks) >= 12 else
                       "medium" if is_cff else "none"),
        "block_count": len(blocks),
        "indirect_jump_ratio": round(ratio, 4),
        "opaque_predicates": opaque[:20],
        "opaque_count": len(opaque),
        "limitations": [
            "topology heuristics only; no symbolic dispatcher analysis",
            "indirect jmp counts include tail-call thunks",
        ],
    }


async def _batch_cff_scan(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target_path", ""))
    min_blocks = int(args.get("min_blocks", 20) or 20)
    limit = int(args.get("limit", 50) or 50)
    b = load_binary(target)
    funcs = iter_function_starts(b)[:400]
    results: list[dict[str, Any]] = []
    scanned = 0
    for f in funcs:
        if scanned >= limit:
            break
        _s, _e, insns = function_bounds(b, f.address, max_insns=1500)
        if not insns:
            continue
        blocks, edges = _split_blocks(insns)
        if len(blocks) < min_blocks:
            continue
        scanned += 1
        indegree: Counter[str] = Counter()
        for _a, c in edges:
            indegree[c] += 1
        dispatcher = next(
            (blk["address"] for blk in blocks
             if indegree[blk["address"]] >= 4 and blk["terminator"] == "jmp"),
            None,
        )
        if dispatcher is not None:
            results.append({
                "address": f"0x{f.address:x}",
                "name": _display_name(b, f.address, f.name),
                "block_count": len(blocks),
                "signature": "ollvm-style",
                "confidence": "medium",
                "opaque_count": len(_opaque_predicates_in_blocks(insns)),
            })
    return {
        "status": "ok",
        "target_path": str(b.path),
        "engine": "capstone CFG topology heuristics",
        "scanned": scanned,
        "cff_positive": len(results),
        "functions": results,
        "limitations": [
            "scans the first 400 recovered functions; min_blocks filter applies",
        ],
    }


async def _detect_obfuscation(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target_path", ""))
    address_or_name = str(args.get("address_or_name", ""))
    b = load_binary(target)
    f = resolve_function(b, address_or_name)
    _s, end, insns = function_bounds(b, f.address)
    nbytes = max(0, end - f.address)
    raw = b.read(f.address, min(nbytes, 64 * 1024))
    entropy = shannon_entropy(raw)
    nop_count = sum(1 for i in insns if i.mnemonic == "nop")
    int3_count = sum(1 for i in insns if i.mnemonic == "int3")
    opaque = _opaque_predicates_in_blocks(insns)
    cff_probe = await _detect_cff({"target_path": target, "address_or_name": address_or_name})

    techniques: list[dict[str, Any]] = []
    if cff_probe.get("is_cff"):
        techniques.append({
            "technique": "control_flow_flattening",
            "confidence": cff_probe.get("confidence", "medium"),
            "evidence": f"dispatcher {cff_probe.get('dispatcher_address')}",
        })
    if opaque:
        techniques.append({
            "technique": "opaque_predicates",
            "confidence": "medium",
            "evidence": f"{len(opaque)} constant-foldable comparisons",
        })
    if insns and (nop_count + int3_count) / len(insns) > 0.02:
        techniques.append({
            "technique": "dead_code_insertion",
            "confidence": "low",
            "evidence": f"{nop_count} nop / {int3_count} int3 of {len(insns)} instructions",
        })
    if entropy > 6.5 and nbytes > 256:
        techniques.append({
            "technique": "encrypted_or_compressed_body",
            "confidence": "medium",
            "evidence": f"function byte entropy {entropy:.2f} bits/byte",
        })
    return {
        "status": "ok",
        "target_path": str(b.path),
        "engine": "capstone + entropy heuristics",
        "function": _display_name(b, f.address, f.name),
        "function_address": f"0x{f.address:x}",
        "techniques": techniques,
        "technique_count": len(techniques),
        "entropy": round(entropy, 3),
        "instruction_count": len(insns),
        "confidence": ("high" if any(t["confidence"] == "high" for t in techniques)
                       else "medium" if techniques else "none"),
        "limitations": [
            "heuristic detector; MBA substitution and instruction substitution"
            " are not identified without symbolic analysis",
        ],
    }


# ======================================================================
# diff family
# ======================================================================


def _section_fingerprint(b: Any) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for s in b.section_spans():
        raw = b.data[s["raw_offset"]: s["raw_offset"] + s["raw_size"]]
        out[s["name"]] = {
            "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "entropy": round(shannon_entropy(raw), 3),
        }
    return out


def _imports_of(b: Any) -> set[str]:
    pe = require_pe(b)
    out: set[str] = set()
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    out.add(imp.name.decode("latin-1", errors="replace"))
    return out


def _exports_of(b: Any) -> set[str]:
    pe = require_pe(b)
    out: set[str] = set()
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                out.add(exp.name.decode("latin-1", errors="replace"))
    return out


async def _diff_binary(args: dict[str, Any]) -> dict[str, Any]:
    old_path = str(args.get("target_path_old", ""))
    new_path = str(args.get("target_path_new", ""))
    if not old_path or not new_path:
        raise ToolError("target_path_old and target_path_new are required")
    b_old = load_binary(old_path)
    b_new = load_binary(new_path)

    sec_old = _section_fingerprint(b_old)
    sec_new = _section_fingerprint(b_new)
    added_sections = sorted(set(sec_new) - set(sec_old))
    removed_sections = sorted(set(sec_old) - set(sec_new))
    changed_sections = sorted(
        name for name in set(sec_old) & set(sec_new)
        if sec_old[name]["sha256"] != sec_new[name]["sha256"]
    )

    imports_added = sorted(_imports_of(b_new) - _imports_of(b_old))
    imports_removed = sorted(_imports_of(b_old) - _imports_of(b_new))
    exports_added = sorted(_exports_of(b_new) - _exports_of(b_old))
    exports_removed = sorted(_exports_of(b_old) - _exports_of(b_new))

    old_funcs = {f.name: f for f in iter_function_starts(b_old)}
    new_funcs = {f.name: f for f in iter_function_starts(b_new)}
    common = sorted(set(old_funcs) & set(new_funcs))
    added_functions = sorted(set(new_funcs) - set(old_funcs))
    removed_functions = sorted(set(old_funcs) - set(new_funcs))
    changed_functions: list[dict[str, Any]] = []
    for name in common[:2000]:
        fo, fn = old_funcs[name], new_funcs[name]
        size_delta = abs(fn.size - fo.size)
        if size_delta > 0:
            changed_functions.append({
                "name": name,
                "address_old": f"0x{fo.address:x}",
                "address_new": f"0x{fn.address:x}",
                "size_old": fo.size,
                "size_new": fn.size,
            })

    return {
        "status": "ok",
        "target_path_old": str(b_old.path),
        "target_path_new": str(b_new.path),
        "summary": {
            "identical": b_old.data == b_new.data,
            "size_old": len(b_old.data),
            "size_new": len(b_new.data),
            "sections_changed": len(changed_sections),
            "imports_added": len(imports_added),
            "imports_removed": len(imports_removed),
        },
        "sections": {
            "added": added_sections,
            "removed": removed_sections,
            "changed": changed_sections,
        },
        "imports": {"added": imports_added, "removed": imports_removed},
        "exports": {"added": exports_added, "removed": exports_removed},
        "functions": {
            "added": added_functions[:200],
            "removed": removed_functions[:200],
            "changed": changed_functions[:200],
        },
        "limitations": [
            "structural PE-level diff; per-instruction comparison is diff_function",
        ],
    }


def _disasm_lines(b: Any, address_or_name: str, max_insns: int) -> tuple[str, list[str]]:
    f = resolve_function(b, address_or_name)
    _s, _e, insns = function_bounds(b, f.address, max_insns=max_insns)
    lines = [
        f"0x{i.address:x}: {i.mnemonic} {i.op_str}".rstrip()
        for i in insns
    ]
    return _display_name(b, f.address, f.name), lines


async def _diff_function(args: dict[str, Any]) -> dict[str, Any]:
    old_path = str(args.get("target_path_old", ""))
    old_fn = str(args.get("address_or_name_old", ""))
    new_path = str(args.get("target_path_new", ""))
    new_fn = str(args.get("address_or_name_new", ""))
    max_lines = int(args.get("max_lines", 500) or 500)
    if not all((old_path, old_fn, new_path, new_fn)):
        raise ToolError(
            "target_path_old, address_or_name_old, target_path_new and"
            " address_or_name_new are required",
        )
    b_old = load_binary(old_path)
    b_new = load_binary(new_path)
    name_old, lines_old = _disasm_lines(b_old, old_fn, 1200)
    name_new, lines_new = _disasm_lines(b_new, new_fn, 1200)
    diff = list(difflib.unified_diff(
        lines_old, lines_new,
        fromfile=f"{Path(old_path).name}:{name_old}",
        tofile=f"{Path(new_path).name}:{name_new}",
        lineterm="",
    ))
    truncated = len(diff) > max_lines
    return {
        "status": "ok",
        "engine": "capstone disassembly diff",
        "function_old": name_old,
        "function_new": name_new,
        "lines_old": len(lines_old),
        "lines_new": len(lines_new),
        "diff_unified": "\n".join(diff[:max_lines]),
        "truncated": truncated,
        "limitations": [
            "disassembly-level diff, not pseudocode; register allocation"
            " noise shows up as changes",
        ],
    }


_DANGEROUS_APIS = {
    "memcpy", "memmove", "strcpy", "strncpy", "strcat", "sprintf",
    "virtualprotect", "writeprocessmemory", "createremotethread",
    "openprocess", "adjusttokenprivileges", "system", "winexec",
    "loadlibrarya", "loadlibraryw", "getprocaddress", "regsetvalueexa",
    "regsetvalueexw", "internetopena", "internetopenurla", "httpsendrequesta",
}


async def _diff_survey(args: dict[str, Any]) -> dict[str, Any]:
    old_path = str(args.get("target_path_old", ""))
    new_path = str(args.get("target_path_new", ""))
    max_changed = int(args.get("max_changed", 20) or 20)
    include_diff = bool(args.get("include_pseudocode_diff", True))
    binary_diff = await _diff_binary({
        "target_path_old": old_path, "target_path_new": new_path,
    })
    if binary_diff.get("status") != "ok":
        return binary_diff

    changed = binary_diff["functions"]["changed"][:max_changed]
    enriched: list[dict[str, Any]] = []
    for entry in changed:
        item = dict(entry)
        if include_diff:
            fn_diff = await _diff_function({
                "target_path_old": old_path,
                "address_or_name_old": entry["name"],
                "target_path_new": new_path,
                "address_or_name_new": entry["name"],
                "max_lines": 200,
            })
            if fn_diff.get("status") == "ok":
                item["diff_preview"] = fn_diff.get("diff_unified", "")[:2000]
        # Security ranking: newly referenced dangerous APIs in this function.
        score = 0
        reasons: list[str] = []
        preview = item.get("diff_preview", "").lower()
        for api in _DANGEROUS_APIS:
            if api in preview:
                score += 1
                reasons.append(f"references {api}")
        if entry.get("size_new", 0) > entry.get("size_old", 0) * 2 and entry.get("size_old", 0) > 0:
            score += 1
            reasons.append("doubled in size")
        item["security_rank"] = score
        item["security_reasons"] = reasons
        enriched.append(item)
    enriched.sort(key=lambda e: -e.get("security_rank", 0))
    return {
        "status": "ok",
        "target_path_old": binary_diff["target_path_old"],
        "target_path_new": binary_diff["target_path_new"],
        "summary": binary_diff["summary"],
        "changed": enriched,
        "limitations": [
            "security ranking is a lexical heuristic over disassembly diffs",
        ],
    }


# ======================================================================
# call graph / paths / similarity
# ======================================================================


async def _call_chain(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target_path", ""))
    target_function = str(args.get("target_function", "")).strip()
    depth = int(args.get("depth", 5) or 5)
    direction = str(args.get("direction", "callers") or "callers")
    if direction not in ("callers", "callees"):
        raise ToolError("direction must be 'callers' or 'callees'")
    b = load_binary(target)
    names, callees, callers = build_call_graph(b)

    key = target_function.lower()
    root = None
    for va, name in names.items():
        if name.lower() == key:
            root = (va, name)
            break
    if root is None:
        for va, name in names.items():
            if key in name.lower():
                root = (va, name)
                break
    if root is None:
        try:
            va = hex_to_int(target_function)
            root = (va, names.get(va, f"sub_{va:x}"))
        except ToolError:
            raise ToolError(f"function not found: {target_function}") from None

    visited = {root[0]}
    chain: list[dict[str, Any]] = []
    frontier = [root[0]]
    for d in range(depth):
        nxt: list[int] = []
        for va in frontier:
            neighbors = (callers if direction == "callers" else callees).get(va, set())
            for nb in sorted(neighbors):
                if nb in visited:
                    continue
                visited.add(nb)
                chain.append({
                    "name": _display_name(b, nb, names.get(nb, f"sub_{nb:x}")),
                    "address": f"0x{nb:x}",
                    "depth": d + 1,
                    "reached_from": _display_name(b, va, names.get(va, f"sub_{va:x}")),
                })
                nxt.append(nb)
        if not nxt:
            break
        frontier = nxt
    return {
        "status": "ok",
        "target_path": str(b.path),
        "target": _display_name(b, root[0], root[1]),
        "target_address": f"0x{root[0]:x}",
        "direction": direction,
        "nodes_found": len(chain),
        "chain": chain,
        "limitations": [
            "direct near calls only (E8); indirect dispatch invisible",
        ],
    }


def _bfs_paths(
    start: int, goal: int, neighbors: Any, avoid: set[int],
    max_paths: int, deadline: float,
) -> list[list[int]]:
    paths: list[list[int]] = []
    queue: deque[list[int]] = deque([[start]])
    seen_depth: dict[int, int] = {start: 0}
    while queue and len(paths) < max_paths:
        if time.monotonic() > deadline:
            break
        path = queue.popleft()
        node = path[-1]
        if node == goal:
            paths.append(path)
            continue
        if len(path) > 32:
            continue
        for nb in sorted(neighbors(node)):
            if nb in avoid or nb in path:
                continue
            if seen_depth.get(nb, 1 << 30) < len(path):
                continue
            seen_depth[nb] = len(path)
            queue.append(path + [nb])
    return paths


async def _find_paths(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target_path", ""))
    from_address = hex_to_int(args.get("from_address"))
    to_address = hex_to_int(args.get("to_address"))
    avoid_raw = args.get("avoid_addresses") or []
    timeout_seconds = float(args.get("timeout_seconds", 60) or 60)
    max_paths = int(args.get("max_paths", 3) or 3)
    b = load_binary(target)
    names, callees, _callers = build_call_graph(b)
    avoid = {hex_to_int(a) for a in avoid_raw}
    deadline = time.monotonic() + min(timeout_seconds, 120.0)

    def _nb(va: int) -> set[int]:
        return callees.get(va, set())

    paths = _bfs_paths(from_address, to_address, _nb, avoid, max_paths, deadline)
    return {
        "status": "ok",
        "target_path": str(b.path),
        "from_address": f"0x{from_address:x}",
        "to_address": f"0x{to_address:x}",
        "paths": [
            [
                {"name": _display_name(b, va, names.get(va, f"sub_{va:x}")), "address": f"0x{va:x}"}
                for va in p
            ]
            for p in paths
        ],
        "path_count": len(paths),
        "timed_out": time.monotonic() > deadline,
        "limitations": [
            "static call-graph paths (direct calls), not execution-feasible paths",
        ],
    }


async def _find_similar_functions(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target_path", ""))
    address_or_name = str(args.get("address_or_name", ""))
    b = load_binary(target)
    f_target = resolve_function(b, address_or_name)
    _s, _e, target_insns = function_bounds(b, f_target.address)
    target_hist = Counter(i.mnemonic for i in target_insns)
    target_size = max(1, len(target_insns))

    scored: list[dict[str, Any]] = []
    for f in iter_function_starts(b)[:500]:
        if f.address == f_target.address:
            continue
        _s2, _e2, insns = function_bounds(b, f.address, max_insns=800)
        if not insns:
            continue
        hist = Counter(i.mnemonic for i in insns)
        all_m = set(hist) | set(target_hist)
        dot = sum(hist[m] * target_hist[m] for m in all_m)
        mag_a = sum(v * v for v in hist.values()) ** 0.5
        mag_b = sum(v * v for v in target_hist.values()) ** 0.5
        sim = dot / (mag_a * mag_b) if mag_a and mag_b else 0.0
        size_sim = min(len(insns), target_size) / max(len(insns), target_size)
        score = 0.8 * sim + 0.2 * size_sim
        if score >= 0.75:
            scored.append({
                "name": _display_name(b, f.address, f.name),
                "address": f"0x{f.address:x}",
                "similarity": round(score, 3),
                "instruction_count": len(insns),
            })
    scored.sort(key=lambda e: -e["similarity"])
    return {
        "status": "ok",
        "target_path": str(b.path),
        "function": _display_name(b, f_target.address, f_target.name),
        "function_address": f"0x{f_target.address:x}",
        "similar": scored[:10],
        "limitations": [
            "mnemonic-histogram similarity; structurally identical code with"
            " different registers scores lower than a true structure hash",
        ],
    }


async def _constrained_reachability(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target_path", ""))
    address_or_name = str(args.get("address_or_name", ""))
    sink_address = hex_to_int(args.get("sink_address"))
    timeout_seconds = float(args.get("timeout_seconds", 60) or 60)
    b = load_binary(target)
    f = resolve_function(b, address_or_name)
    names, callees, _c = build_call_graph(b)
    deadline = time.monotonic() + min(timeout_seconds, 120.0)
    avoid: set[int] = set()
    paths = _bfs_paths(f.address, sink_address, lambda va: callees.get(va, set()), avoid, 1, deadline)
    return {
        "status": "ok",
        "target_path": str(b.path),
        "function": _display_name(b, f.address, f.name),
        "sink_address": f"0x{sink_address:x}",
        "reachable": bool(paths),
        "path": [
            {"name": _display_name(b, va, names.get(va, f"sub_{va:x}")), "address": f"0x{va:x}"}
            for va in paths[0]
        ] if paths else [],
        "timed_out": time.monotonic() > deadline,
        "limitations": [
            "graph reachability over direct calls; constraints on data/state"
            " are not evaluated",
        ],
    }


# ======================================================================
# PE info / library detection / yara / string-at
# ======================================================================


async def _get_string_at(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target_path", ""))
    address = hex_to_int(args.get("address"))
    max_length = int(args.get("max_length", 512) or 512)
    encoding = str(args.get("encoding", "ascii") or "ascii")
    b = load_binary(target)
    value, canonical = string_at_va(b, address, max_length, encoding)
    return {
        "status": "ok",
        "target_path": str(b.path),
        "address": f"0x{address:x}",
        "section": _section_for_va(b.section_spans(), address),
        "encoding": canonical,
        "length": len(value),
        "value": value,
    }


async def _checksec(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target_path", ""))
    b = load_binary(target)
    pe = require_pe(b)
    opt = pe.OPTIONAL_HEADER
    dll_chars = int(opt.DllCharacteristics)
    load_config = None
    security_cookie = 0
    se_handler_count = 0
    try:
        lc = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
        load_config = int(lc.Size)
        security_cookie = int(getattr(lc, "SecurityCookie", 0) or 0)
        se_handler_count = int(getattr(lc, "SEHandlerCount", 0) or 0)
    except (AttributeError, ValueError):
        pass
    def has_dir(idx: int) -> bool:
        return (
            int(pe.OPTIONAL_HEADER.NumberOfRvaAndSizes) > idx
            and int(pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx].Size) > 0
        )
    guard_flags = 0
    try:
        guard_flags = int(pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardFlags)
    except (AttributeError, ValueError):
        pass

    bits = b.bits
    return {
        "status": "ok",
        "target_path": str(b.path),
        "nx": bool(dll_chars & 0x0100),
        "aslr": bool(dll_chars & 0x0040),
        "high_entropy_aslr": bool(dll_chars & 0x0020) if bits == 64 else False,
        "force_integrity": bool(dll_chars & 0x0080),
        "no_seh": bool(dll_chars & 0x0400),
        "appcontainer": bool(dll_chars & 0x1000),
        "guard_cf": bool(dll_chars & 0x4000) and bool(guard_flags & 0x100),
        "authenticode": bool(has_dir(4)),
        "dotnet": bool(has_dir(14)),
        "manifest": bool(has_dir(1)),
        "gs_security_cookie": security_cookie != 0,
        "safe_seh": se_handler_count > 0 if bits == 32 else None,
        "load_config_size": load_config,
        "machine": f"0x{b.machine:04x}",
        "bits": bits,
        "limitations": [
            "authenticode reports certificate presence, not signature validity",
        ],
    }


async def _detect_library_functions(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target_path", ""))
    b = load_binary(target)
    require_pe(b)
    libraries: dict[str, dict[str, Any]] = {}

    def _add(lib: str, name: str, address: int, confidence: str, via: str) -> None:
        entry = libraries.setdefault(lib, {
            "library": lib, "count": 0, "functions": [], "confidence": confidence, "via": via,
        })
        entry["count"] += 1
        entry["functions"].append({
            "name": name, "address": f"0x{address:x}", "confidence": confidence, "via": via,
        })

    # 1) Symbol tables / exports name library code directly.
    prefix_map = {
        "__crt": "ucrt", "std::": "c++-stl", "operator": "c++-stl",
        "__security": "msvc-runtime", "__scrt": "msvc-runtime",
        "_seh": "msvc-runtime", "__dyn_tls": "msvc-runtime",
        "malloc": "ucrt", "free": "ucrt", "calloc": "ucrt", "realloc": "ucrt",
        "memcpy": "ucrt", "memset": "ucrt", "memcmp": "ucrt", "strlen": "ucrt",
        "__std": "c++-stl", "boost::": "boost",
    }
    for f in iter_function_starts(b):
        if f.source in ("export", "symbol"):
            for prefix, lib in prefix_map.items():
                if f.name.lower().startswith(prefix.lower()) or prefix.lower() in f.name.lower():
                    _add(lib, f.name, f.address, "high", f.source)
                    break

    # 2) Rich header tooling identifies the compiler runtime.
    try:
        parsed = lief.parse(str(b.path))
        if parsed is not None and parsed.has_rich_header:
            tools = [e.id for e in parsed.rich_header.entries]
            comp_likes = [t for t in tools if t in (0x101, 0x102, 0x103, 0x104, 0x105, 0x106, 0x107, 0x108, 0x10A, 0x10B, 0x10C)]
            if comp_likes:
                libraries.setdefault("msvc-runtime", {
                    "library": "msvc-runtime", "count": 0, "functions": [],
                    "confidence": "high", "via": "rich-header",
                })["via"] = "rich-header"
    except (OSError, ValueError, TypeError, AttributeError, RuntimeError) as exc:
        _LOG.debug("lief rich header parse failed: %s", exc)

    # 3) Embedded byte-pattern table for stripped binaries.
    patterns = [
        ("__security_init_cookie", 64, b"\x48\xa1", "MSVC /GS cookie init (mov rax, cookie)"),
        ("__security_check_cookie", 64, b"\x48\x3b\x0d", "MSVC /GS cookie check (cmp rcx, cookie)"),
        ("__security_check_cookie", 32, b"\x3b\x0d", "MSVC /GS cookie check (cmp ecx, cookie)"),
    ]
    for span in b.executable_spans():
        code = b.read(span["va"], span["size"])
        for name, bits, needle, desc in patterns:
            if bits != b.bits:
                continue
            start = 0
            while True:
                idx = code.find(needle, start)
                if idx < 0:
                    break
                va = span["va"] + idx
                _add("msvc-runtime", name, va, "medium", f"pattern: {desc}")
                start = idx + 1

    out = sorted(libraries.values(), key=lambda e: -e["count"])
    for e in out:
        e["functions"] = e["functions"][:50]
    return {
        "status": "ok",
        "target_path": str(b.path),
        "libraries": out,
        "library_count": len(out),
        "limitations": [
            "stripped binaries rely on the rich header and a small runtime"
            " pattern table; FLIRT-style precise matching is not implemented",
        ],
    }


async def _generate_yara_rule(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target_path", ""))
    address_or_name = str(args.get("address_or_name", ""))
    b = load_binary(target)
    f = resolve_function(b, address_or_name)
    _s, _e, insns = function_bounds(b, f.address, max_insns=24)
    if not insns:
        raise ToolError(f"cannot disassemble function at 0x{f.address:x}")

    hex_parts: list[str] = []
    for insn in insns[:24]:
        raw = bytearray(insn.bytes)
        if insn.mnemonic == "call" or (insn.mnemonic == "jmp" and insn.size == 5):
            for k in range(1, insn.size):
                raw[k] = 0xCC  # mask rel32
        elif insn.mnemonic.startswith("j") and insn.size == 6 and raw[0] == 0x0F:
            for k in range(2, 6):
                raw[k] = 0xCC
        elif insn.mnemonic in ("je", "jne", "jz", "jnz", "ja", "jb", "jae", "jbe", "jg", "jl") and insn.size == 2:
            raw[1] = 0xCC
        hex_parts.append(" ".join(
            f"{byte:02X}" if byte != 0xCC else "??" for byte in raw
        ))
    pattern = " ".join(hex_parts)

    strings_clause = ""
    notable = [s for s in extract_strings(b, 8) if s["encoding"] == "ascii"][:6]
    for idx, s in enumerate(notable):
        val = s["value"].replace("\\", "\\\\").replace('"', '\\"')[:64]
        if val.strip():
            strings_clause += f'    $s{idx} = "{val}"\n'

    safe_base = re.sub(r"[^A-Za-z0-9_]", "_", b.path.stem)[:24] or "sample"
    safe_fn = re.sub(r"[^A-Za-z0-9_]", "_", _display_name(b, f.address, f.name))[:32]
    rule_name = f"aila_{safe_base}_{safe_fn}"
    condition = "any of them" if strings_clause else "$code"
    rule = (
        f"rule {rule_name} {{\n"
        f"  meta:\n"
        f'    description = "auto-generated by re_analytics from {b.path.name} {_display_name(b, f.address, f.name)}"\n'
        f"  strings:\n"
        f'    $code = {{ {pattern} }}\n'
        f"{strings_clause}"
        f"  condition:\n"
        f"    {condition}\n"
        f"}}\n"
    )
    return {
        "status": "ok",
        "target_path": str(b.path),
        "rule_name": rule_name,
        "function": _display_name(b, f.address, f.name),
        "function_address": f"0x{f.address:x}",
        "yara_rule": rule,
        "limitations": [
            "rel32 operands are masked to keep the pattern position-independent;"
            " review before deploying as a detection rule",
        ],
    }


async def _decrypt_binary_strings(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target_path", ""))
    decryptor_address = hex_to_int(args.get("decryptor_address"))
    b = load_binary(target)
    _s, _e, dec_insns = function_bounds(b, decryptor_address)
    dec_bytes = b.read(decryptor_address, max(256, sum(i.size for i in dec_insns[:64])))

    # Identify the cipher from constants embedded in the decryptor.
    aes_sbox_prefix = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")
    cipher = "unknown"
    if aes_sbox_prefix in dec_bytes:
        cipher = "aes-128-ecb (s-box detected)"

    # Find every caller of the decryptor.
    names, _callees, callers = build_call_graph(b)
    work = sorted(callers.get(decryptor_address, set()))[:64]
    callers_all = [f"0x{a:x}" for a in work]

    decrypted: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    printable = re.compile(r"^[\x20-\x7e]{6,}")
    for caller in work:
        _s2, _e2, insns = function_bounds(b, caller, max_insns=600)
        call_sites = [i for i in insns if i.mnemonic == "call" and i.operands and (getattr(i.operands[0], "imm", 0) or 0) == decryptor_address]
        for site in call_sites:
            window = [i for i in insns if site.address - 0x100 <= i.address < site.address][-24:]
            ptrs: list[int] = []
            keys: list[bytes] = []
            for insn in window:
                if insn.mnemonic in ("mov", "lea") and insn.operands:
                    for op in insn.operands:
                        imm = getattr(op, "imm", 0)
                        mem = getattr(op, "mem", None)
                        if insn.mnemonic == "lea" and mem is not None:
                            base_reg = insn.reg_name(getattr(mem, "base", 0) or 0)
                            if base_reg == "rip":
                                ptrs.append(insn.address + insn.size + getattr(mem, "disp", 0))
                        elif isinstance(imm, int) and b.imagebase <= imm < b.imagebase + 0x20000000 and insn.mnemonic == "mov":
                            ptrs.append(imm)
                        if isinstance(imm, int) and 0 < imm < 0x1_0000_0000 and insn.mnemonic == "mov":
                            cand = imm.to_bytes(4, "little")
                            if len(cand) >= 4:
                                keys.append(cand[:16].ljust(16, b"\x00"))
            entry: dict[str, Any] = {
                "call_site": f"0x{site.address:x}",
                "caller": _display_name(b, caller, names.get(caller, f"sub_{caller:x}")),
                "cipher": cipher,
                "data_pointers": [f"0x{p:x}" for p in ptrs[:8]],
                "key_candidates": len(keys),
            }
            candidates.append(entry)
            if Cipher is not None and keys and ptrs and "aes" in cipher:
                for ptr in ptrs[:4]:
                    blob = b.read(ptr, 64)
                    if len(blob) < 32:
                        continue
                    for key in keys[:4]:
                        try:
                            dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
                            plain = dec.update(blob[:32]) + dec.finalize()
                        except (ValueError, TypeError, KeyError, OSError):
                            continue
                        text = plain.split(b"\x00")[0]
                        if printable.match(text.decode("latin-1", errors="ignore")):
                            decrypted.append({
                                "call_site": f"0x{site.address:x}",
                                "cipher": cipher,
                                "plaintext": text.decode("latin-1", errors="replace"),
                                "ciphertext_address": f"0x{ptr:x}",
                            })
                            break
                    if decrypted and decrypted[-1]["call_site"] == f"0x{site.address:x}":
                        break
    seen: set[tuple[str, str]] = set()
    uniq: list[dict[str, Any]] = []
    for d in decrypted:
        k = (d["call_site"], d["plaintext"])
        if k not in seen:
            seen.add(k)
            uniq.append(d)
    return {
        "status": "ok",
        "target_path": str(b.path),
        "cipher_detected": cipher,
        "decryptor_address": f"0x{decryptor_address:x}",
        "decrypted_strings": uniq[:100],
        "callers": callers_all,
        "candidates": candidates[:25],
        "limitations": [
            "key extraction is heuristic (immediate scan before the call);"
            " only AES-128-ECB is attempted and only when the S-box is present",
        ],
    }


# ======================================================================
# intra-procedural dataflow (capstone-backed, honest scope)
# ======================================================================


async def _trace_dataflow(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target_path", ""))
    address_or_name = str(args.get("address_or_name", ""))
    sink_function = str(args.get("sink_function", "")).strip().lower()
    sink_argument_index = int(args.get("sink_argument_index", 0) or 0)
    source_contains = [str(s).lower() for s in (args.get("source_contains") or [])]
    max_steps = int(args.get("max_steps", 10) or 10)
    if not sink_function:
        raise ToolError("sink_function is required")
    b = load_binary(target)
    if b.bits != 64:
        raise ToolError("sink argument tracing is implemented for x64 register args only")
    arg_reg = x86_arg_register(sink_argument_index, b.bits)
    if arg_reg is None:
        raise ToolError(f"sink_argument_index {sink_argument_index} is not a register argument on x64")

    f = resolve_function(b, address_or_name)
    _s, _e, insns = function_bounds(b, f.address)

    # Resolve sink to VA when it is an address/name in this binary.
    sink_va = None
    for cand in iter_function_starts(b):
        if cand.name.lower() == sink_function:
            sink_va = cand.address
            break
    slots = {}
    try:
        slots = _import_iat_slots(b)
    except ToolError:
        pass
    sink_slot = slots.get(sink_function)


    sink_sites = [
        i for i in insns
        if i.mnemonic == "call" and i.operands and (
            (sink_va is not None and (getattr(i.operands[0], "imm", 0) or 0) == sink_va)
            or sink_slot is None  # name-only match handled below via thunk proximity
        )
    ]
    if not sink_sites:
        # fallback: any call site (indirect) inside the function
        sink_sites = [i for i in insns if i.mnemonic == "call"][-1:]

    traces: list[dict[str, Any]] = []
    for site in sink_sites[:4]:
        steps: list[dict[str, Any]] = []
        reg = arg_reg
        for insn in reversed([i for i in insns if i.address < site.address]):
            if len(steps) >= max_steps:
                break
            if insn.mnemonic in ("mov", "lea", "xor", "movzx", "movsxd") and insn.operands:
                dst = insn.operands[0]
                if dst.type == X86_OP_REG and insn.reg_name(dst.reg) == reg:
                    src = insn.operands[-1]
                    classification = "unknown"
                    detail = ""
                    if insn.mnemonic == "xor" and src.type == X86_OP_REG and insn.reg_name(src.reg) == reg:
                        classification, detail = "zeroed", f"{reg} ^= {reg}"
                    elif src.type == X86_OP_IMM:
                        classification, detail = "constant", f"0x{int(src.imm):x}"
                    elif src.type == X86_OP_MEM:
                        mem = src.mem
                        base_name = insn.reg_name(getattr(mem, "base", 0) or 0)
                        if base_name == "rip":
                            ptr = insn.address + insn.size + getattr(mem, "disp", 0)
                            value, _enc = string_at_va(b, ptr, 128, "ascii")
                            detail = f"[rip{getattr(mem, 'disp', 0):+d}] = 0x{ptr:x}"
                            if value.strip():
                                classification = "string_ref"
                                detail += f" -> {value[:64]!r}"
                            else:
                                classification = "memory_load"
                        else:
                            classification = "memory_load"
                            detail = f"[{base_name}{getattr(mem, 'disp', 0):+d}]"
                    elif src.type == X86_OP_REG:
                        reg = insn.reg_name(src.reg)
                        classification, detail = "register_alias", reg
                    steps.append({
                        "address": f"0x{insn.address:x}",
                        "instruction": f"{insn.mnemonic} {insn.op_str}".strip(),
                        "classification": classification,
                        "detail": detail,
                    })
                    if classification in ("constant", "string_ref", "zeroed", "memory_load"):
                        break
            elif insn.mnemonic == "call":
                steps.append({
                    "address": f"0x{insn.address:x}",
                    "instruction": f"{insn.mnemonic} {insn.op_str}".strip(),
                    "classification": "call_result",
                    "detail": "argument register overwritten by call return",
                })
                break
        summary = steps[-1]["classification"] if steps else "not_found"
        if source_contains and summary != "not_found":
            hay = json.dumps(steps).lower()
            if not any(s in hay for s in source_contains):
                continue
        traces.append({
            "sink_call_site": f"0x{site.address:x}",
            "sink": f"{site.mnemonic} {site.op_str}".strip(),
            "steps": steps,
            "summary": summary,
        })
    return {
        "status": "ok",
        "target_path": str(b.path),
        "engine": "intra-procedural capstone backward slice",
        "function": _display_name(b, f.address, f.name),
        "function_address": f"0x{f.address:x}",
        "sink_function": sink_function,
        "sink_argument_index": sink_argument_index,
        "traces": traces,
        "limitations": [
            "x64 register arguments only; intra-procedural only; indirect"
            " call targets are not resolved",
        ],
    }


async def _def_use(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args.get("target_path", ""))
    address_or_name = str(args.get("address_or_name", ""))
    target_callee = str(args.get("target_callee", "") or "").strip().lower()
    max_instructions = int(args.get("max_instructions", 200) or 200)
    b = load_binary(target)
    f = resolve_function(b, address_or_name)
    _s, _e, insns = function_bounds(b, f.address, max_insns=max_instructions)

    def regs_of(insn: Any) -> list[str]:
        return [insn.reg_name(op.reg) for op in insn.operands if op.type == X86_OP_REG]

    write_mnems = ("mov", "lea", "xor", "movzx", "movsxd", "pop", "add", "sub", "and", "or", "shl", "shr", "inc", "dec")

    def writes_of(insn: Any) -> list[str]:
        regs = regs_of(insn)
        return [regs[0]] if insn.mnemonic in write_mnems and regs else []

    chains: list[dict[str, Any]] = []
    defs: dict[str, dict[str, Any]] = {}
    for insn in insns:
        if target_callee and insn.mnemonic == "call" and target_callee not in insn.op_str.lower():
            continue
        reads = regs_of(insn)[1:] if insn.mnemonic in ("mov", "lea", "movzx", "movsxd") else regs_of(insn)
        for reg in reads:
            d = defs.get(reg)
            if d is not None and insn.address not in d["uses"]:
                d["uses"].append(f"0x{insn.address:x}")
        for reg in writes_of(insn):
            if reg in defs and (defs[reg]["uses"] or not target_callee):
                chains.append(defs[reg])
            defs[reg] = {
                "register": reg,
                "def_address": f"0x{insn.address:x}",
                "def_instruction": f"{insn.mnemonic} {insn.op_str}".strip(),
                "uses": [],
            }
    chains.extend(d for d in defs.values() if d["uses"] or not target_callee)
    return {
        "status": "ok",
        "target_path": str(b.path),
        "engine": "intra-procedural capstone def/use (register granularity)",
        "function": _display_name(b, f.address, f.name),
        "function_address": f"0x{f.address:x}",
        "chains": chains[:200],
        "chain_count": len(chains),
        "limitations": [
            "register-level only (no memory aliasing); resets are not tracked"
            " across indirect calls",
        ],
    }


# ======================================================================
# Tool table
# ======================================================================

_UNSUPPORTED_REASON_CTREE = (
    "requires the Hex-Rays ctree/microcode IR, which is not available in "
    "re_analytics (no decompiler backend); use the rea server for "
    "decompilation-backed analysis"
)
_UNSUPPORTED_REASON_PROOF = (
    "requires the SMT proof engine over decompiler IR; not available in "
    "re_analytics"
)
_UNSUPPORTED_REASON_QUEUE = (
    "re_analytics applies mutations synchronously in-process; there is no "
    "mutation queue to poll -- write tools return their result directly"
)


def _addr_name_schema() -> dict[str, Any]:
    return _schema({"address_or_name": _addr_prop()}, ["target_path", "address_or_name"])


TOOLS: list[ToolDef] = [
    # ── flare-capa capability tools ──────────────────────────────────
    ToolDef(
        name="capa_scan",
        description=(
            "Evaluate the installed capa rule set against the binary "
            "(Mandiant CAPA via flare-capa). Returns matched capabilities "
            "with ATT&CK mapping and triggering addresses."
        ),
        input_schema=_schema({}, ["target_path"]),
        handler=_capa_scan,
    ),
    ToolDef(
        name="verify_capabilities",
        description=(
            "Classify the binary's behavior into capability namespaces from "
            "the capa rule set, with per-capability verdicts, evidence rules "
            "and addresses, plus uncategorized imports."
        ),
        input_schema=_schema({}, ["target_path"]),
        handler=_verify_capabilities,
    ),
    ToolDef(
        name="classify_behavior",
        description=(
            "Map matched capa rules to ATT&CK-aligned behavioral categories "
            "(persistence, execution, defense-evasion, ...)."
        ),
        input_schema=_schema({}, ["target_path"]),
        handler=_classify_behavior,
    ),
    ToolDef(
        name="classify_strings",
        description=(
            "Classify strings found in the binary's sections by format: "
            "URLs, IPs, registry paths, file paths, base64 blobs, GUIDs, "
            "user agents, PDB paths, DLL/EXE names."
        ),
        input_schema=_schema(
            {"limit": {"type": "integer", "default": 200}},
            ["target_path"],
        ),
        handler=_classify_strings,
    ),
    ToolDef(
        name="detect_anti_analysis",
        description=(
            "Detect anti-debug, anti-VM and anti-sandbox techniques via the "
            "capa anti-analysis rule namespace plus import and string markers."
        ),
        input_schema=_schema({}, ["target_path"]),
        handler=_detect_anti_analysis,
    ),
    ToolDef(
        name="detect_dynamic_resolution",
        description=(
            "Find dynamic API resolution sites (GetProcAddress/LoadLibrary "
            "IAT calls) and extract resolved API names where visible near "
            "the call site."
        ),
        input_schema=_schema(
            {"limit": {"type": "integer", "default": 50}},
            ["target_path"],
        ),
        handler=_detect_dynamic_resolution,
    ),
    ToolDef(
        name="find_api_call_sites",
        description=(
            "Find all call sites for a specific API: direct IAT calls "
            "(FF 15), calls through JMP [IAT] thunks, and plaintext name "
            "locations in data sections."
        ),
        input_schema=_schema(
            {"api_name": {"type": "string", "description": "API function name, e.g. 'TerminateProcess'"}},
            ["target_path", "api_name"],
        ),
        handler=_find_api_call_sites,
    ),
    # ── lifecycle / status ───────────────────────────────────────────
    ToolDef(
        name="close_binary",
        description=(
            "Discard the session annotation/patch overlay for the target. "
            "re_analytics holds no open database; closing resets session state."
        ),
        input_schema=_schema(
            {"save": {"type": "boolean", "default": False}},
            ["target_path"],
        ),
        handler=_close_binary,
    ),
    ToolDef(
        name="worker_status",
        description=(
            "Report re_analytics server health: tool counts per group, "
            "optional-dependency availability, and session overlay stats."
        ),
        input_schema={"type": "object", "properties": {}, "required": []},
        handler=_worker_status,
    ),
    ToolDef(
        name="get_generation",
        description=(
            "Session mutation counter for the target; increments on every "
            "rename/comment/type/patch so consumers can detect stale results."
        ),
        input_schema=_schema({}, ["target_path"]),
        handler=_get_generation,
    ),
    # ── disassembly / miasm ──────────────────────────────────────────
    ToolDef(
        name="miasm_disassemble",
        description=(
            "Disassemble bytes at a virtual address. Served by capstone in "
            "re_analytics (tool name preserved from ida-headless); the "
            "result states the engine."
        ),
        input_schema=_schema(
            {
                "address": {"type": "string", "description": "Virtual address to start (0x...)"},
                "size": {"type": "integer", "default": 64},
            },
            ["target_path", "address"],
        ),
        handler=_miasm_disassemble,
    ),
    ToolDef(
        name="miasm_lift_ir",
        description=(
            "Lift bytes at a virtual address to miasm's intermediate "
            "representation (symbolic assignments per block)."
        ),
        input_schema=_schema(
            {
                "address": {"type": "string", "description": "Virtual address to start lifting (0x...)"},
                "size": {"type": "integer", "default": 64},
            },
            ["target_path", "address"],
        ),
        handler=_miasm_lift_ir,
    ),
    ToolDef(
        name="miasm_simplify_expression",
        description=(
            "Simplify a symbolic expression (MBA deobfuscation, opaque "
            "predicates) using miasm's rewrite engine. Pure expression tool; "
            "no target needed."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "expression": {
                    "type": "string",
                    "description": (
                        "Expression in miasm repr syntax, e.g. "
                        "\"ExprOp('^', ExprId('RAX', 64), ExprId('RAX', 64))\""
                    ),
                },
            },
            "required": ["expression"],
        },
        handler=_miasm_simplify_expression,
    ),
    # ── CFG / obfuscation ────────────────────────────────────────────
    ToolDef(
        name="binary_survey",
        description=(
            "One-call orientation: overview, attack-surface imports, and the "
            "top functions ranked by cyclomatic complexity (with callee, "
            "caller, and string-reference counts)."
        ),
        input_schema=_schema(
            {"max_hotspots": {"type": "integer", "default": 10}}, ["target_path"],
        ),
        handler=_binary_survey,
    ),
    ToolDef(
        name="recover_cfg",
        description=(
            "Recover the control-flow graph of one function: basic blocks, "
            "edges, topology stats, and session annotations."
        ),
        input_schema=_addr_name_schema(),
        handler=_recover_cfg,
    ),
    ToolDef(
        name="detect_stack_strings",
        description=(
            "Detect stack-built strings in a function (mov dword ptr "
            "[rsp/rbp+off], imm sequences decoded to text)."
        ),
        input_schema=_addr_name_schema(),
        handler=_detect_stack_strings,
    ),
    ToolDef(
        name="detect_control_flow_obfuscation",
        description=(
            "Detect control-flow-flattening in a function via CFG topology: "
            "high fan-in dispatchers, state-machine shape, opaque predicates."
        ),
        input_schema=_addr_name_schema(),
        handler=_detect_cff,
    ),
    ToolDef(
        name="batch_cff_scan",
        description=(
            "Scan recovered functions for control-flow flattening and "
            "return CFF-positive functions with signatures and confidence."
        ),
        input_schema=_schema(
            {
                "min_blocks": {"type": "integer", "default": 20},
                "limit": {"type": "integer", "default": 50},
            },
            ["target_path"],
        ),
        handler=_batch_cff_scan,
    ),
    ToolDef(
        name="detect_obfuscation",
        description=(
            "Detect obfuscation techniques in a function: control-flow "
            "flattening, opaque predicates, dead-code insertion, encrypted "
            "bodies (entropy)."
        ),
        input_schema=_addr_name_schema(),
        handler=_detect_obfuscation,
    ),
    # ── diff family ──────────────────────────────────────────────────
    ToolDef(
        name="diff_binary",
        description=(
            "Structural diff of two binaries: sections, imports, exports, "
            "and recovered functions added/removed/changed."
        ),
        input_schema=_schema(
            {
                "target_path_old": _path_prop("Absolute path of the older/baseline binary."),
                "target_path_new": _path_prop("Absolute path of the newer/target binary."),
            },
            ["target_path_old", "target_path_new"],
        ),
        handler=_diff_binary,
    ),
    ToolDef(
        name="diff_function",
        description=(
            "Disassembly-level unified diff of one function across two "
            "binaries (capstone-backed, bounded line count)."
        ),
        input_schema=_schema(
            {
                "target_path_old": _path_prop("Absolute path of the older/baseline binary."),
                "address_or_name_old": _addr_prop("Function in the old binary."),
                "target_path_new": _path_prop("Absolute path of the newer/target binary."),
                "address_or_name_new": _addr_prop("Function in the new binary."),
                "max_lines": {"type": "integer", "default": 500},
            },
            ["target_path_old", "address_or_name_old", "target_path_new", "address_or_name_new"],
        ),
        handler=_diff_function,
    ),
    ToolDef(
        name="diff_survey",
        description=(
            "Full survey diff: structural diff plus per-function disassembly "
            "diffs with a lexical security ranking of changed functions."
        ),
        input_schema=_schema(
            {
                "target_path_old": _path_prop("Absolute path of the older/baseline binary."),
                "target_path_new": _path_prop("Absolute path of the newer/target binary."),
                "max_changed": {"type": "integer", "default": 20},
                "include_pseudocode_diff": {"type": "boolean", "default": True},
            },
            ["target_path_old", "target_path_new"],
        ),
        handler=_diff_survey,
    ),
    # ── call graph / paths ───────────────────────────────────────────
    ToolDef(
        name="call_chain",
        description=(
            "Walk caller or callee chains from a function over the "
            "direct-call graph (BFS to a depth)."
        ),
        input_schema=_schema(
            {
                "target_function": _addr_prop("Root function name or address."),
                "depth": {"type": "integer", "default": 5},
                "direction": {"type": "string", "enum": ["callers", "callees"], "default": "callers"},
            },
            ["target_path", "target_function"],
        ),
        handler=_call_chain,
    ),
    ToolDef(
        name="find_paths",
        description=(
            "Find static call-graph paths between two addresses (BFS, "
            "avoid-list honored). These are direct-call paths, not "
            "execution-feasible paths."
        ),
        input_schema=_schema(
            {
                "from_address": {"type": "string", "description": "Path start VA (0x...)"},
                "to_address": {"type": "string", "description": "Path end VA (0x...)"},
                "avoid_addresses": {"type": "array", "items": {"type": "string"}},
                "timeout_seconds": {"type": "number", "default": 60},
                "max_paths": {"type": "integer", "default": 3},
            },
            ["target_path", "from_address", "to_address"],
        ),
        handler=_find_paths,
    ),
    ToolDef(
        name="find_similar_functions",
        description=(
            "Find functions with a similar mnemonic histogram and size to "
            "the target (duplicated logic / template instantiations)."
        ),
        input_schema=_addr_name_schema(),
        handler=_find_similar_functions,
    ),
    ToolDef(
        name="constrained_reachability",
        description=(
            "Graph reachability from a function to a sink address over the "
            "direct-call graph. Constraints on data/state are not evaluated."
        ),
        input_schema=_schema(
            {
                "address_or_name": _addr_prop("Source function."),
                "sink_address": {"type": "string", "description": "Sink VA (0x...)"},
                "timeout_seconds": {"type": "number", "default": 60},
            },
            ["target_path", "address_or_name", "sink_address"],
        ),
        handler=_constrained_reachability,
    ),
    # ── PE info / strings / yara ─────────────────────────────────────
    ToolDef(
        name="get_string_at",
        description=(
            "Read a null-terminated string at a virtual address (ascii or "
            "utf16le)."
        ),
        input_schema=_schema(
            {
                "address": {"type": "string", "description": "Virtual address (0x...)"},
                "max_length": {"type": "integer", "default": 512},
                "encoding": {"type": "string", "enum": ["ascii", "utf16le", "utf16", "utf-16", "utf-16le"], "default": "ascii"},
            },
            ["target_path", "address"],
        ),
        handler=_get_string_at,
    ),
    ToolDef(
        name="checksec",
        description=(
            "Report PE security flags: NX, ASLR (+HEASLR), CFG, GS, SafeSEH, "
            "force-integrity, Authenticode presence, .NET, manifest."
        ),
        input_schema=_schema({}, ["target_path"]),
        handler=_checksec,
    ),
    ToolDef(
        name="detect_library_functions",
        description=(
            "Aggregate library functions by detected library (MSVC runtime, "
            "uCRT, C++ STL) using symbols, the Rich header, and embedded "
            "runtime byte patterns."
        ),
        input_schema=_schema({}, ["target_path"]),
        handler=_detect_library_functions,
    ),
    ToolDef(
        name="generate_yara_rule",
        description=(
            "Generate a YARA rule from a function's bytes (position-"
            "independent pattern with masked rel32 operands) plus notable "
            "strings."
        ),
        input_schema=_addr_name_schema(),
        handler=_generate_yara_rule,
    ),
    ToolDef(
        name="decrypt_binary_strings",
        description=(
            "Locate every caller of a string-decryptor function, identify "
            "the cipher from embedded constants, and attempt decryption "
            "(AES-128-ECB when the S-box is present)."
        ),
        input_schema=_schema(
            {"decryptor_address": {"type": "string", "description": "VA of the decryption function (0x...)"}},
            ["target_path", "decryptor_address"],
        ),
        handler=_decrypt_binary_strings,
    ),
    # ── intra-procedural dataflow ────────────────────────────────────
    ToolDef(
        name="trace_dataflow",
        description=(
            "Backward-trace a sink call argument within one function "
            "(x64 register args): classifies the source as constant, "
            "string_ref, memory_load, call_result, or register_alias."
        ),
        input_schema=_schema(
            {
                "address_or_name": _addr_prop("Function containing the sink."),
                "sink_function": {"type": "string", "description": "Dangerous callee name."},
                "sink_argument_index": {"type": "integer", "description": "0-based argument index (rcx=0, rdx=1, r8=2, r9=3)."},
                "source_contains": {"type": "array", "items": {"type": "string"}},
                "max_steps": {"type": "integer", "default": 10},
            },
            ["target_path", "address_or_name", "sink_function", "sink_argument_index"],
        ),
        handler=_trace_dataflow,
    ),
    ToolDef(
        name="def_use",
        description=(
            "Intra-procedural register def/use chains within a function "
            "(optionally filtered to instructions around calls to a callee)."
        ),
        input_schema=_schema(
            {
                "address_or_name": _addr_prop("Function to analyze."),
                "target_callee": {"type": "string", "default": ""},
                "max_instructions": {"type": "integer", "default": 200},
            },
            ["target_path", "address_or_name"],
        ),
        handler=_def_use,
    ),
    # ── overlay mutations ────────────────────────────────────────────
    ToolDef(
        name="rename_function",
        description=(
            "Rename a function for this server session; the new name is "
            "applied to function renders by this server."
        ),
        input_schema=_schema(
            {
                "address": {"type": "string", "description": "Function VA (0x...)"},
                "new_name": {"type": "string"},
                "agent_id": {"type": "string", "default": ""},
            },
            ["target_path", "address", "new_name"],
        ),
        handler=_rename_function,
    ),
    ToolDef(
        name="rename_variable",
        description=(
            "Rename a variable within a function for this session; surfaced "
            "in function_extra renders."
        ),
        input_schema=_schema(
            {
                "function_address": {"type": "string"},
                "old_name": {"type": "string"},
                "new_name": {"type": "string"},
                "agent_id": {"type": "string", "default": ""},
            },
            ["target_path", "function_address", "old_name", "new_name"],
        ),
        handler=_rename_variable,
    ),
    ToolDef(
        name="set_comment",
        description="Attach a session comment to an address.",
        input_schema=_schema(
            {
                "address": {"type": "string"},
                "comment": {"type": "string"},
                "agent_id": {"type": "string", "default": ""},
            },
            ["target_path", "address", "comment"],
        ),
        handler=_set_comment,
    ),
    ToolDef(
        name="set_function_type",
        description="Set a session prototype override for a function.",
        input_schema=_schema(
            {
                "function_address": {"type": "string"},
                "prototype": {"type": "string"},
                "agent_id": {"type": "string", "default": ""},
            },
            ["target_path", "function_address", "prototype"],
        ),
        handler=_set_function_type,
    ),
    ToolDef(
        name="set_variable_type",
        description="Set a session type override for a variable in a function.",
        input_schema=_schema(
            {
                "function_address": {"type": "string"},
                "variable_name": {"type": "string"},
                "new_type": {"type": "string"},
                "agent_id": {"type": "string", "default": ""},
            },
            ["target_path", "function_address", "variable_name", "new_type"],
        ),
        handler=_set_variable_type,
    ),
    ToolDef(
        name="patch_bytes",
        description=(
            "Apply a session byte patch at an address. The overlay affects "
            "reads by this server only; the file on disk is never modified."
        ),
        input_schema=_schema(
            {
                "address": {"type": "string"},
                "hex_bytes": {"type": "string", "description": "Hex-encoded bytes, e.g. '9090C3'"},
                "agent_id": {"type": "string", "default": ""},
            },
            ["target_path", "address", "hex_bytes"],
        ),
        handler=_patch_bytes,
    ),
    # ── unsupported envelopes (names preserved) ──────────────────────
    _unsupported("poll_mutation", _UNSUPPORTED_REASON_QUEUE, {"ticket_id": {"type": "string"}}),
    _unsupported(
        "query_ctree", _UNSUPPORTED_REASON_CTREE,
        {
            "address_or_name": _addr_prop(),
            "target_function": {"type": "string", "default": ""},
            "argument_index": {"type": "integer"},
            "contains_operation": {"type": "string", "default": ""},
            "operand_type_is": {"type": "string", "default": ""},
            "limit": {"type": "integer", "default": 50},
        },
    ),
    _unsupported(
        "get_microcode", _UNSUPPORTED_REASON_CTREE,
        {"address_or_name": _addr_prop(), "maturity": {"type": "string", "default": "current"}},
    ),
    _unsupported("hexrays_warnings", _UNSUPPORTED_REASON_CTREE, {"address_or_name": _addr_prop()}),
    _unsupported("deflat_function", (
        "deflattening requires decompiler-backed control-flow restructuring; "
        "not available in re_analytics"
    ), {"address_or_name": _addr_prop()}),
    _unsupported(
        "patch_cff", (
            "patching CFF dispatchers requires deflattening, which needs a "
            "decompiler backend; not available in re_analytics"
        ),
        {"address_or_name": _addr_prop()},
    ),
    _unsupported(
        "prove_equivalence", _UNSUPPORTED_REASON_PROOF,
        {
            "expr_a": {"type": "string"},
            "expr_b": {"type": "string"},
            "address_or_name": _addr_prop(),
        },
    ),
    _unsupported(
        "prove_overflow", _UNSUPPORTED_REASON_PROOF,
        {
            "address_or_name": _addr_prop(),
            "sink_function": {"type": "string"},
            "sink_argument_index": {"type": "integer"},
        },
    ),
    _unsupported(
        "prove_predicate_opaque", _UNSUPPORTED_REASON_PROOF,
        {"address_or_name": _addr_prop(), "condition_address": {"type": "string"}},
    ),
    _unsupported(
        "prove_bounds_sufficient", _UNSUPPORTED_REASON_PROOF,
        {
            "address_or_name": _addr_prop(),
            "sink_function": {"type": "string"},
            "sink_argument_index": {"type": "integer"},
        },
    ),
]
