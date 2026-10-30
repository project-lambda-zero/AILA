"""Dataflow, recovery, and mutation tools for the ``re_analytics`` MCP server.

This module implements the ida-headless tools that REA does not provide,
backed by Capstone disassembly, LIEF/PE parsing, Keystone assembly, and
(optionally) angr symbolic execution. Every tool takes ``target_path`` --
the absolute local path of the binary under analysis -- where the legacy
ida-headless surface took an opaque ``binary_id``.

All analyses here are heuristic static analyses over the
disassembly-level IR. Result dicts carry a ``limitations`` list stating
what the analysis did not prove (repo rule: no hidden smartness).

Tool inventory (signatures mirror ida-headless, ``binary_id`` ->
``target_path``):

- ``interprocedural_taint(target_path, sink_function,
  sink_argument_index, source_functions=None, max_depth=5)``
- ``value_ranges(target_path, address_or_name)``
- ``path_feasibility(target_path, source_address, sink_address,
  timeout_seconds=60, max_steps=200000)`` (angr-backed)
- ``assess_exploitability(target_path, address_or_name, sink_function,
  sink_argument_index)``
- ``cross_binary_similarity(target_path_a, target_path_b)``
- ``patch_assemble(target_path, address, assembly)`` (Keystone; returns
  patched bytes and a byte-level diff -- the original file is never
  modified)
- ``recover_class_hierarchy(target_path)`` (MSVC RTTI scan with a
  pointer-array vtable fallback)
- ``detect_protocol_state_machine(target_path, address_or_name)``
- ``pseudocode_slice_view(target_path, address_or_name, focus_callee="",
  focus_address="", context_lines=5, max_slices=10)`` (disassembly
  listing slice; no decompiler AST is available at this layer)
"""
from __future__ import annotations

import hashlib
import re
import threading
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ._tooldef import ToolDef, ToolError

__all__ = ["TOOLS"]


# ---------------------------------------------------------------------------
# Optional heavy dependency (path_feasibility only). Imported lazily inside
# the handler so the rest of the server works without angr installed.
# ---------------------------------------------------------------------------

_ANGR_INSTALL_HINT = (
    "path_feasibility requires the angr symbolic-execution stack; "
    "install it with: pip install angr"
)

# ---------------------------------------------------------------------------
# Binary loading / address mapping
# ---------------------------------------------------------------------------

_MAX_TEXT_INSNS = 400_000
_MAX_FUNCTION_INSNS = 8_000
_SLICE_MAX_HOPS = 60

_HEX_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]+$")
# IDA auto-generated names embed the hex address: sub_140001000.
_AUTONAME_RE = re.compile(r"^(?:sub|loc|unk|byte|word|dword|qword|off)_([0-9a-fA-F]+)$")


@dataclass(slots=True)
class _Section:
    name: str
    va: int          # absolute virtual address of section start
    vsize: int       # virtual size
    raw_off: int     # file offset of section data
    raw_size: int    # raw (on-disk) size
    data: bytes


@dataclass(slots=True)
class _LoadedBinary:
    path: str
    is64: bool
    image_base: int
    entry_va: int
    sections: list[_Section]
    iat: dict[int, str]          # IAT slot VA -> imported function name
    exports_by_name: dict[str, int]  # exported name -> VA
    func_names: dict[int, str] = field(default_factory=dict)

    @property
    def ptr_size(self) -> int:
        return 8 if self.is64 else 4

    @property
    def code_sections(self) -> list[_Section]:
        return [s for s in self.sections if s.name == ".text"]

    @property
    def data_sections(self) -> list[_Section]:
        return [s for s in self.sections if s.name != ".text"]

    def section_for_va(self, va: int) -> _Section | None:
        for sec in self.sections:
            if sec.va <= va < sec.va + max(sec.vsize, sec.raw_size):
                return sec
        return None

    def va_to_offset(self, va: int) -> int | None:
        sec = self.section_for_va(va)
        if sec is None:
            return None
        delta = va - sec.va
        if delta >= sec.raw_size:
            return None
        return sec.raw_off + delta

    def read_va(self, va: int, size: int) -> bytes | None:
        """Read ``size`` bytes starting at absolute VA (single section)."""
        sec = self.section_for_va(va)
        if sec is None:
            return None
        start = va - sec.va
        end = start + size
        if start < 0 or end > len(sec.data):
            return None
        return sec.data[start:end]

    def read_ptr(self, va: int) -> int | None:
        raw = self.read_va(va, self.ptr_size)
        if raw is None or len(raw) != self.ptr_size:
            return None
        return int.from_bytes(raw, "little")

    def read_u32(self, va: int) -> int | None:
        raw = self.read_va(va, 4)
        if raw is None or len(raw) != 4:
            return None
        return int.from_bytes(raw, "little")

    def is_code_va(self, va: int) -> bool:
        return any(s.va <= va < s.va + max(s.vsize, s.raw_size) for s in self.code_sections)


def _load_binary(target_path: Any) -> _LoadedBinary:
    """Parse ``target_path`` as a PE and build the VA mapping."""
    if not isinstance(target_path, str) or not target_path:
        raise ToolError("target_path must be a non-empty string")
    p = Path(target_path)
    if not p.is_file():
        raise ToolError(f"target not found: {target_path}")

    try:
        import lief  # noqa: PLC0415 -- optional dependency, lazy import
    except ImportError as exc:  # pragma: no cover - depends on env
        raise ToolError(
            "re_analytics requires lief for PE parsing; install with: pip install lief",
        ) from exc

    try:
        pe = lief.parse(str(p))
    except (RuntimeError, ValueError, OSError) as exc:
        raise ToolError(f"lief failed to parse {target_path}: {exc}") from exc
    if pe is None or not isinstance(pe, lief.PE.Binary):
        raise ToolError(f"not a PE binary: {target_path}")

    is64 = pe.optional_header.magic == lief.PE.PE_TYPE.PE32_PLUS
    image_base = int(pe.optional_header.imagebase)
    sections = [
        _Section(
            name=sec.name,
            va=image_base + int(sec.virtual_address),
            vsize=int(sec.virtual_size),
            raw_off=int(sec.offset),
            raw_size=int(sec.sizeof_raw_data),
            data=bytes(sec.content),
        )
        for sec in pe.sections
    ]

    iat: dict[int, str] = {}
    for imp in pe.imports or []:
        for entry in imp.entries:
            name = entry.name
            if not name:
                continue
            iat_va = int(entry.iat_address) + image_base
            iat[iat_va] = str(name)

    exports_by_name: dict[str, int] = {}
    for exp in pe.exported_functions or []:
        if exp.name:
            exports_by_name[str(exp.name)] = int(exp.address) + image_base

    entry_va = int(pe.optional_header.addressof_entrypoint) + image_base

    loaded = _LoadedBinary(
        path=str(p),
        is64=is64,
        image_base=image_base,
        entry_va=entry_va,
        sections=sections,
        iat=iat,
        exports_by_name=exports_by_name,
    )
    loaded.func_names = {entry_va: "entry"}
    for name, va in exports_by_name.items():
        loaded.func_names.setdefault(va, name)
    return loaded


def _md_capstone(loaded: _LoadedBinary, detail: bool = True):
    """Build a Capstone disassembler matching the PE architecture."""
    try:
        from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover - depends on env
        raise ToolError(
            "re_analytics requires capstone for disassembly; install with: pip install capstone",
        ) from exc
    mode = CS_MODE_64 if loaded.is64 else CS_MODE_32
    md = Cs(CS_ARCH_X86, mode)
    md.detail = detail
    return md


def _parse_address(value: Any, loaded: _LoadedBinary, arg: str) -> int:
    """Parse an address argument: ``0x...``/hex VA, or RVA if below image base.

    Also accepts IDA auto-generated names (``sub_140001000``) whose hex
    tail is the address itself.
    """
    if isinstance(value, int) and not isinstance(value, bool):
        va = value
    elif isinstance(value, str):
        text = value.strip()
        m = _AUTONAME_RE.match(text)
        if m:
            va = int(m.group(1), 16)
        elif _HEX_RE.match(text):
            va = int(text, 16)
        else:
            raise ToolError(f"{arg} must be a hex address string (got {value!r})")
    else:
        raise ToolError(f"{arg} must be a hex address string (got {value!r})")
    if va < loaded.image_base:
        va += loaded.image_base
    return va


# ---------------------------------------------------------------------------
# Function discovery + disassembly
# ---------------------------------------------------------------------------


def _iter_code_insns(loaded: _LoadedBinary, limit: int = _MAX_TEXT_INSNS):
    """Disassemble all executable sections linearly (yields capstone insns)."""
    md = _md_capstone(loaded)
    count = 0
    for sec in loaded.code_sections:
        for insn in md.disasm(sec.data, sec.va):
            yield insn
            count += 1
            if count >= limit:
                return


def _branch_target(insn) -> int | None:
    """Absolute target of a direct call/jump, else None."""
    from capstone import CS_OP_IMM  # noqa: PLC0415

    if not insn.operands:
        return None
    op = insn.operands[0]
    if op.type == CS_OP_IMM:
        return int(op.imm)
    return None


def _is_terminal(insn) -> bool:
    from capstone import CS_GRP_JUMP, CS_GRP_RET  # noqa: PLC0415

    return insn.group(CS_GRP_JUMP) or insn.group(CS_GRP_RET)


def _function_starts(loaded: _LoadedBinary) -> set[int]:
    """Collect candidate function entry points.

    Sources: entry point, exported RVAs, and targets of direct ``call``
    instructions across the executable sections. This is the standard
    call-target + prologue-free linear-sweep approximation; unnamed
    internal functions are only discovered when some caller targets
    them directly.
    """
    starts = {loaded.entry_va, *loaded.exports_by_name.values()}
    for insn in _iter_code_insns(loaded):
        tgt = _branch_target(insn)
        if tgt is not None and loaded.is_code_va(tgt) and insn.mnemonic == "call":
            starts.add(tgt)
    return starts


def _function_names(loaded: _LoadedBinary, starts: set[int]) -> dict[int, str]:
    """VA -> best-known name (export, or ``sub_<hex>`` placeholder)."""
    names = dict(loaded.func_names)
    for va in sorted(starts):
        names.setdefault(va, f"sub_{va:x}")
    return names


def _disasm_function(loaded: _LoadedBinary, va: int, max_insns: int = _MAX_FUNCTION_INSNS):
    """Linear-sweep disassembly of one function starting at ``va``.

    Stops at the end of the section, on int3 padding, after a return
    when the following bytes are padding, or when ``max_insns`` is hit.
    """
    md = _md_capstone(loaded)
    sec = loaded.section_for_va(va)
    if sec is None or not any(sec is s for s in loaded.code_sections):
        raise ToolError(f"address 0x{va:x} is not inside an executable section")
    off = va - sec.va
    insns: list[Any] = []
    saw_term = False  # last insn was ret or an unconditional jmp
    int3_run = 0
    from capstone import CS_GRP_JUMP, CS_GRP_RET  # noqa: PLC0415

    for insn in md.disasm(sec.data[off:], va):
        if insn.mnemonic == "int3":
            int3_run += 1
            # Two or more consecutive int3s -- or any int3 after a
            # function-ending terminator -- are alignment padding, not
            # code; drop them and end the sweep.
            if int3_run >= 2 or saw_term:
                break
            insns.append(insn)
        else:
            int3_run = 0
            insns.append(insn)
        if insn.group(CS_GRP_RET):
            saw_term = True
            # Terminate when the next instruction would be padding.
            nxt = insn.address + insn.size
            if not loaded.is_code_va(nxt):
                break
            following = loaded.read_va(nxt, 1)
            if following == b"\xcc":
                break
        elif insn.group(CS_GRP_JUMP) and insn.mnemonic == "jmp":
            saw_term = True
        else:
            saw_term = False
        if len(insns) >= max_insns:
            break
    if not insns:
        raise ToolError(f"no instructions decoded at 0x{va:x}")
    return insns


def _resolve_function(loaded: _LoadedBinary, address_or_name: Any) -> tuple[int, str]:
    """Resolve an ``address_or_name`` argument to (VA, name)."""
    starts = _function_starts(loaded)
    names = _function_names(loaded, starts)

    if isinstance(address_or_name, str) and (
        _HEX_RE.match(address_or_name.strip())
        or _AUTONAME_RE.match(address_or_name.strip())
    ):
        va = _parse_address(address_or_name, loaded, "address_or_name")
        if va not in starts:
            raise ToolError(
                f"0x{va:x} is not a known function start "
                f"(entry, export, or direct call target)",
            )
        return va, names.get(va, f"sub_{va:x}")

    if not isinstance(address_or_name, str) or not address_or_name.strip():
        raise ToolError("address_or_name must be a function name or hex address")

    want = address_or_name.strip().lower()
    for name, va in loaded.exports_by_name.items():
        if name.lower() == want:
            return va, name
    for va, name in names.items():
        if name.lower() == want:
            return va, name
    # Substring fallback (agent may give a decorated or truncated name).
    matches = [(va, n) for va, n in names.items() if want in n.lower()]
    if len(matches) == 1:
        return matches[0]
    raise ToolError(f"function not found: {address_or_name!r}")


def _containing_function(starts: list[int], va: int) -> int | None:
    """Largest function start <= va, or None."""
    best = None
    for s in starts:
        if s <= va and (best is None or s > best):
            best = s
    return best


def _resolve_call_target(loaded: _LoadedBinary, insn) -> str | None:
    """Best-effort symbolic name for a call instruction's target.

    Handles: direct ``call imm`` (named function / thunk / IAT slot) and
    x64 ``call qword ptr [rip+disp]`` imports.
    """
    from capstone import CS_OP_IMM, CS_OP_MEM  # noqa: PLC0415

    if not insn.operands:
        return None
    op = insn.operands[0]
    if op.type == CS_OP_IMM:
        tgt = int(op.imm)
        if tgt in loaded.iat:
            return loaded.iat[tgt]
        if tgt in loaded.func_names:
            return loaded.func_names[tgt]
        # One-hop thunk: jmp qword ptr [rip+disp] -> IAT.
        thunk = _disasm_thunk(loaded, tgt)
        if thunk is not None:
            return thunk
        return f"sub_{tgt:x}"
    if op.type == CS_OP_MEM:
        mem_va = insn.address + insn.size + int(op.mem.disp)
        if mem_va in loaded.iat:
            return loaded.iat[mem_va]
        return None
    return None


def _disasm_thunk(loaded: _LoadedBinary, va: int) -> str | None:
    """If ``va`` is a single-jump import thunk, return the import name."""
    md = _md_capstone(loaded)
    sec = loaded.section_for_va(va)
    if sec is None:
        return None
    insns = list(md.disasm(sec.data[va - sec.va:], va, count=1))
    if not insns:
        return None
    insn = insns[0]
    if insn.mnemonic != "jmp":
        return None
    from capstone import CS_OP_MEM  # noqa: PLC0415

    if insn.operands and insn.operands[0].type == CS_OP_MEM:
        mem_va = insn.address + insn.size + int(insn.operands[0].mem.disp)
        if mem_va in loaded.iat:
            return loaded.iat[mem_va]
    return None


# ---------------------------------------------------------------------------
# Register def-use backslice (intraprocedural)
# ---------------------------------------------------------------------------

_X64_ARG_REGS = ["rcx", "rdx", "r8", "r9"]
_X64_RET_REG = "rax"

# Register families for value_ranges: sub-register ids collapse into
# their 64-bit canonical name. Built lazily inside the handler so a
# missing capstone still lets the other tools answer.


def _build_reg_families() -> tuple[tuple[str, tuple[int, ...]], ...]:
    from capstone.x86_const import (  # noqa: PLC0415
        X86_REG_AL,
        X86_REG_AX,
        X86_REG_BL,
        X86_REG_BP,
        X86_REG_BX,
        X86_REG_CL,
        X86_REG_CX,
        X86_REG_DI,
        X86_REG_DL,
        X86_REG_DX,
        X86_REG_EAX,
        X86_REG_EBP,
        X86_REG_EBX,
        X86_REG_ECX,
        X86_REG_EDI,
        X86_REG_EDX,
        X86_REG_ESI,
        X86_REG_ESP,
        X86_REG_R8,
        X86_REG_R8D,
        X86_REG_R9,
        X86_REG_R9D,
        X86_REG_R10,
        X86_REG_R10D,
        X86_REG_R11,
        X86_REG_R11D,
        X86_REG_R12,
        X86_REG_R12D,
        X86_REG_R13,
        X86_REG_R13D,
        X86_REG_R14,
        X86_REG_R14D,
        X86_REG_R15,
        X86_REG_R15D,
        X86_REG_RAX,
        X86_REG_RBP,
        X86_REG_RBX,
        X86_REG_RCX,
        X86_REG_RDI,
        X86_REG_RDX,
        X86_REG_RSI,
        X86_REG_RSP,
        X86_REG_SI,
        X86_REG_SP,
    )

    return (
        ("rax", (X86_REG_RAX, X86_REG_EAX, X86_REG_AX, X86_REG_AL)),
        ("rbx", (X86_REG_RBX, X86_REG_EBX, X86_REG_BX, X86_REG_BL)),
        ("rcx", (X86_REG_RCX, X86_REG_ECX, X86_REG_CX, X86_REG_CL)),
        ("rdx", (X86_REG_RDX, X86_REG_EDX, X86_REG_DX, X86_REG_DL)),
        ("rsi", (X86_REG_RSI, X86_REG_ESI, X86_REG_SI)),
        ("rdi", (X86_REG_RDI, X86_REG_EDI, X86_REG_DI)),
        ("rbp", (X86_REG_RBP, X86_REG_EBP, X86_REG_BP)),
        ("rsp", (X86_REG_RSP, X86_REG_ESP, X86_REG_SP)),
        ("r8", (X86_REG_R8, X86_REG_R8D)),
        ("r9", (X86_REG_R9, X86_REG_R9D)),
        ("r10", (X86_REG_R10, X86_REG_R10D)),
        ("r11", (X86_REG_R11, X86_REG_R11D)),
        ("r12", (X86_REG_R12, X86_REG_R12D)),
        ("r13", (X86_REG_R13, X86_REG_R13D)),
        ("r14", (X86_REG_R14, X86_REG_R14D)),
        ("r15", (X86_REG_R15, X86_REG_R15D)),
    )


def _reg_name(insn, reg_id: int) -> str:
    return insn.reg_name(reg_id).lower()


def _insn_defines(insn) -> set[str]:
    """Registers written by this instruction (capstone detail)."""
    return {_reg_name(insn, r) for r in insn.regs_write}


def _insn_uses(insn) -> set[str]:
    return {_reg_name(insn, r) for r in insn.regs_read}


def _imm_operand(insn) -> int | None:
    from capstone import CS_OP_IMM  # noqa: PLC0415

    for op in insn.operands:
        if op.type == CS_OP_IMM:
            return int(op.imm)
    return None


def _self_clear(insn) -> bool:
    """``xor reg, reg`` / ``sub reg, reg`` / ``and reg, 0`` -> reg is zero."""
    from capstone import CS_OP_IMM, CS_OP_REG  # noqa: PLC0415

    if len(insn.operands) < 2:
        return False
    dst, src = insn.operands[0], insn.operands[1]
    if dst.type != CS_OP_REG:
        return False
    if insn.mnemonic in ("xor", "sub") and src.type == CS_OP_REG:
        return src.reg == dst.reg
    if insn.mnemonic == "and" and src.type == CS_OP_IMM:
        return int(src.imm) == 0
    return False


def _backward_slice(insns: list[Any], start_idx: int, seed_reg: str):
    """Track ``seed_reg`` backward from ``insns[start_idx]`` (inclusive).

    Returns (chain, root_kind, root_info):
      chain      -- [{address, text, role}] defs that feed the seed, oldest first
      root_kind  -- "function_parameter" | "call_result" | "constant"
                    | "global_data" | "unknown"
      root_info  -- human-readable description of where the chain bottoms out
    """
    from capstone import CS_GRP_CALL, CS_GRP_JUMP  # noqa: PLC0415

    wanted: set[str] = {seed_reg.lower()}
    chain: list[dict[str, Any]] = []
    root_kind = "unknown"
    root_info = f"def of {seed_reg} not found in function window"
    top_idx = 0

    idx = start_idx
    for idx in range(start_idx, -1, -1):
        insn = insns[idx]
        defines = _insn_defines(insn)
        hit = defines & wanted
        if not hit:
            continue
        uses = _insn_uses(insn)
        chain.append({
            "address": f"0x{insn.address:x}",
            "text": f"{insn.mnemonic} {insn.op_str}".strip(),
            "role": "def",
        })
        if _self_clear(insn):
            root_kind = "constant"
            root_info = f"self-clearing op at 0x{insn.address:x} (reg = 0)"
            break
        if insn.group(CS_GRP_CALL):
            root_kind = "call_result"
            root_info = f"result of call at 0x{insn.address:x}"
            break
        if insn.group(CS_GRP_JUMP):
            root_kind = "unknown"
            root_info = f"chain crosses jump at 0x{insn.address:x}"
            break
        if "rip" in insn.op_str.lower():
            root_kind = "global_data"
            root_info = f"rip-relative read at 0x{insn.address:x}"
            break
        # Continue tracking: drop the defined register, pick up every
        # register the instruction reads (accumulator-style ops such as
        # ``add rcx, 1`` keep rcx live so the chain reaches the prior def).
        wanted = (wanted - hit) | (uses - hit)
        if not wanted:
            root_kind = "unknown"
            root_info = f"fully resolved at 0x{insn.address:x}"
            break
        if len(chain) >= _SLICE_MAX_HOPS:
            root_info = f"slice truncated after {_SLICE_MAX_HOPS} hops"
            break
    else:
        top_idx = idx  # loop ran to completion without a break

    if root_kind == "unknown" and idx == top_idx == 0 and wanted:
        # Walked to the top of the window with registers still live:
        # on x64 those are function parameters.
        live = wanted & set(_X64_ARG_REGS)
        if live:
            root_kind = "function_parameter"
            root_info = "live at function entry: " + ", ".join(sorted(live))

    chain.reverse()
    return chain, root_kind, root_info


# ---------------------------------------------------------------------------
# CFG construction (basic blocks + edges)
# ---------------------------------------------------------------------------


def _basic_blocks(insns: list[Any]) -> tuple[list[list[Any]], dict[int, list[int]]]:
    """Split a linear insn stream into basic blocks.

    Returns (blocks, edges) where edges maps block index -> successor
    block indexes. Direct branch targets and fall-through edges only;
    indirect branches model as exiting the function (no successor).
    """
    if not insns:
        return [], {}
    addr_to_idx = {insn.address: i for i, insn in enumerate(insns)}
    leaders: set[int] = {insns[0].address}
    from capstone import CS_GRP_JUMP  # noqa: PLC0415

    for i, insn in enumerate(insns):
        if insn.group(CS_GRP_JUMP):
            tgt = _branch_target(insn)
            if tgt is not None and tgt in addr_to_idx:
                leaders.add(tgt)
            fall = i + 1
            if fall < len(insns):
                leaders.add(insns[fall].address)

    sorted_leaders = sorted(leaders)
    blocks: list[list[Any]] = []
    for j, lead in enumerate(sorted_leaders):
        start_i = addr_to_idx[lead]
        if j + 1 < len(sorted_leaders):
            end_i = addr_to_idx[sorted_leaders[j + 1]]
        else:
            end_i = len(insns)
        blocks.append(insns[start_i:end_i])

    block_of = {}
    for bi, block in enumerate(blocks):
        for insn in block:
            block_of[insn.address] = bi
    edges: dict[int, list[int]] = {bi: [] for bi in range(len(blocks))}
    for bi, block in enumerate(blocks):
        last = block[-1]
        from capstone import CS_GRP_JUMP, CS_GRP_RET  # noqa: PLC0415

        if last.group(CS_GRP_RET):
            continue
        tgt = _branch_target(last)
        if last.group(CS_GRP_JUMP):
            if tgt is not None and tgt in block_of:
                edges[bi].append(block_of[tgt])
            if not last.mnemonic.startswith("jmp"):
                # Conditional jump: fall-through edge.
                fall = bi + 1
                if fall < len(blocks):
                    edges[bi].append(fall)
        else:
            fall = bi + 1
            if fall < len(blocks):
                edges[bi].append(fall)
    return blocks, edges


# ---------------------------------------------------------------------------
# Tool: interprocedural_taint
# ---------------------------------------------------------------------------


def _find_sink_call_sites(loaded: _LoadedBinary, sink_function: str) -> list[tuple[int, int]]:
    """(call_insn_address, containing_function_va) for calls to the sink."""
    want = sink_function.strip().lower()
    starts_sorted = sorted(_function_starts(loaded))
    sites: list[tuple[int, int]] = []
    for insn in _iter_code_insns(loaded):
        if insn.mnemonic != "call":
            continue
        name = _resolve_call_target(loaded, insn)
        if name is None or name.lower() != want:
            continue
        caller = _containing_function(starts_sorted, insn.address)
        if caller is None:
            continue
        sites.append((insn.address, caller))
    return sites


def _handler_interprocedural_taint(args: dict[str, Any]) -> dict[str, Any]:
    loaded = _load_binary(args.get("target_path"))
    sink_function = args.get("sink_function")
    if not isinstance(sink_function, str) or not sink_function.strip():
        raise ToolError("sink_function must be a non-empty string")
    sink_function = sink_function.strip()
    arg_idx = args.get("sink_argument_index", 0)
    if not isinstance(arg_idx, int) or isinstance(arg_idx, bool) or arg_idx < 0:
        raise ToolError("sink_argument_index must be a non-negative integer")
    max_depth = args.get("max_depth", 5)
    if not isinstance(max_depth, int) or isinstance(max_depth, bool) or max_depth < 1:
        raise ToolError("max_depth must be a positive integer")
    source_functions = args.get("source_functions") or []
    if not isinstance(source_functions, list):
        raise ToolError("source_functions must be a list of names or null")
    source_l = {str(s).strip().lower() for s in source_functions if str(s).strip()}

    if not loaded.is64:
        raise ToolError(
            "interprocedural_taint currently supports 64-bit PE targets only "
            "(x64 register argument passing); 32-bit stack-argument targets "
            "are not tracked",
        )
    if arg_idx >= len(_X64_ARG_REGS):
        raise ToolError(
            f"sink_argument_index {arg_idx} targets a stack argument; only "
            f"the first {len(_X64_ARG_REGS)} x64 register arguments are tracked",
        )
    seed_reg = _X64_ARG_REGS[arg_idx]

    names = _function_names(loaded, _function_starts(loaded))
    starts_sorted = sorted(_function_starts(loaded))
    # One pass over the executable sections: every direct call site with
    # its containing function. Caller hops and sink-site discovery share
    # this table.
    call_table: list[tuple[int, int, int]] = []  # site_va, caller_va, target_va
    for insn in _iter_code_insns(loaded):
        if insn.mnemonic != "call":
            continue
        tgt = _branch_target(insn)
        if tgt is None:
            continue
        caller = _containing_function(starts_sorted, insn.address)
        if caller is not None:
            call_table.append((insn.address, caller, tgt))

    def _callers_of(fn_va: int) -> list[tuple[int, int]]:
        return [(site, caller) for site, caller, tgt in call_table if tgt == fn_va]

    chains: list[dict[str, Any]] = []
    reached_source = False

    for call_va, caller_va in _find_sink_call_sites(loaded, sink_function):
        insns = _disasm_function(loaded, caller_va)
        idx = next(
            (i for i, ins in enumerate(insns) if ins.address == call_va),
            None,
        )
        if idx is None:
            continue
        chain, root_kind, root_info = _backward_slice(insns, idx - 1, seed_reg)

        hops: list[dict[str, Any]] = list(chain)
        depth = 0
        cursor = caller_va
        # Interprocedural recursion: while the slice bottoms out in a
        # function parameter, hop to callers and re-slice their argument.
        while root_kind == "function_parameter" and depth < max_depth:
            call_sites = _callers_of(cursor)
            if not call_sites:
                root_info = f"no callers found for {names.get(cursor, hex(cursor))}"
                break
            site_va, parent_va = call_sites[0]
            parent_insns = _disasm_function(loaded, parent_va)
            p_idx = next(
                (i for i, ins in enumerate(parent_insns) if ins.address == site_va),
                None,
            )
            if p_idx is None:
                break
            parent_chain, root_kind, root_info = _backward_slice(
                parent_insns, p_idx - 1, seed_reg,
            )
            hops.insert(0, {
                "address": f"0x{site_va:x}",
                "text": f"call {names.get(cursor, hex(cursor))}",
                "role": "call_hop",
                "caller": names.get(parent_va, f"sub_{parent_va:x}"),
            })
            for h in reversed(parent_chain):
                hops.insert(0, h)
            cursor = parent_va
            depth += 1
            if names.get(cursor, "").lower() in source_l:
                reached_source = True
                root_info = f"reached source function {names[cursor]}"
                break

        if names.get(caller_va, "").lower() in source_l:
            reached_source = True
        source_type = root_kind if root_kind in (
            "function_parameter", "call_result", "constant",
        ) else ("file_header_field" if root_kind == "global_data" else root_kind)
        chains.append({
            "sink_call": f"0x{call_va:x}",
            "function": names.get(caller_va, f"sub_{caller_va:x}"),
            "hops": hops,
            "source_type": source_type,
            "root": root_info,
            "reached_source": names.get(caller_va, "").lower() in source_l,
        })

    if not chains:
        raise ToolError(
            f"no call sites for sink {sink_function!r} resolved in {loaded.path}",
        )

    return {
        "status": "ok",
        "sink_function": sink_function,
        "sink_argument_index": arg_idx,
        "chains": chains,
        "reached_source": reached_source,
        "limitations": [
            "Register-level def-use slice on Capstone disassembly; memory "
            "contents and stack slots are not tracked.",
            "x64 register arguments only (first four); stack-passed "
            "arguments are rejected.",
            "Interprocedural hops follow the first caller only at each "
            "level; alternate call paths are not enumerated.",
            "No constraint solving: reachability means 'a def-use chain "
            "exists', not 'reachable under runtime conditions'.",
        ],
    }


# ---------------------------------------------------------------------------
# Tool: value_ranges
# ---------------------------------------------------------------------------


def _handler_value_ranges(args: dict[str, Any]) -> dict[str, Any]:
    loaded = _load_binary(args.get("target_path"))
    va, name = _resolve_function(loaded, args.get("address_or_name"))

    insns = _disasm_function(loaded, va)
    blocks, edges = _basic_blocks(insns)
    if not blocks:
        raise ToolError(f"no basic blocks recovered at 0x{va:x}")

    # Abstract interpretation over registers: reg -> (lo, hi). Widens on
    # merge at join points; memory and flags are not modeled. Sub-register
    # writes collapse into their 64-bit family.
    from capstone import CS_OP_REG  # noqa: PLC0415

    reg_family: dict[int, str] = {}
    for fam_name, ids in _build_reg_families():
        for rid in ids:
            reg_family[rid] = fam_name

    block_state: dict[int, dict[str, tuple[int, int] | None]] = {}
    order = _reverse_postorder(blocks, edges)
    worklist: deque[int] = deque(order)
    visits: dict[int, int] = {bi: 0 for bi in range(len(blocks))}

    def merge(
        old: dict[str, tuple[int, int] | None],
        new: dict[str, tuple[int, int] | None],
    ) -> bool:
        changed = False
        for reg, rng in new.items():
            if reg not in old:
                old[reg] = rng
                changed = True
            elif old[reg] is None and rng is not None:
                old[reg] = rng
                changed = True
            elif old[reg] is not None and rng is None:
                old[reg] = None
                changed = True
            elif old[reg] is not None and rng is not None:
                lo, hi = old[reg]
                nlo, nhi = rng
                if (nlo, nhi) != (lo, hi):
                    old[reg] = (min(lo, nlo), max(hi, nhi))
                    changed = True
        return changed

    def get_reg_name(insn, rid: int) -> str:
        return insn.reg_name(rid).lower()

    annotations: list[dict[str, Any]] = []
    while worklist:
        bi = worklist.popleft()
        visits[bi] += 1
        cur = dict(block_state.get(bi, {}))
        for insn in blocks[bi]:
            mn = insn.mnemonic
            if not insn.operands or insn.operands[0].type != CS_OP_REG:
                continue
            rid = insn.operands[0].reg
            fam_key = reg_family.get(rid)
            if fam_key is None:
                continue
            imm = _imm_operand(insn)
            before = cur.get(fam_key)
            rng: tuple[int, int] | None = None
            note = ""
            if mn == "mov" and imm is not None:
                rng = (imm, imm)
                note = "immediate"
            elif mn in ("xor", "sub") and len(insn.operands) >= 2 and \
                    insn.operands[1].type == CS_OP_REG and \
                    insn.operands[0].reg == insn.operands[1].reg:
                rng = (0, 0)
                note = "self-clear"
            elif mn in ("inc", "dec") and before is not None:
                delta = 1 if mn == "inc" else -1
                rng = (before[0] + delta, before[1] + delta)
                note = mn
            elif mn == "add" and imm is not None and before is not None:
                rng = (before[0] + imm, before[1] + imm)
                note = "add-imm"
            elif mn == "sub" and imm is not None and before is not None:
                rng = (before[0] - imm, before[1] - imm)
                note = "sub-imm"
            elif mn == "and" and imm is not None:
                rng = (0, imm)
                note = "mask"
            elif mn == "movzx":
                width = 0xFF if "byte" in insn.op_str else 0xFFFF
                rng = (0, width)
                note = "zero-extend"
            elif mn in ("shl", "sal") and imm is not None and before is not None:
                cap = (1 << 63) - 1 if loaded.is64 else (1 << 31) - 1
                rng = (min(before[0] << imm, cap), min(before[1] << imm, cap))
                note = "shift-left"
            elif mn == "mov" and insn.operands[1].type == CS_OP_REG:
                src = get_reg_name(insn, insn.operands[1].reg)
                src_fam = reg_family.get(insn.operands[1].reg)
                rng = cur.get(src_fam) if src_fam else None
                note = f"copy {src}"
            if fam_key in cur and cur[fam_key] == rng and not note:
                continue
            cur[fam_key] = rng
            if rng is not None:
                annotations.append({
                    "register": fam_key,
                    "min": rng[0],
                    "max": rng[1],
                    "origin": f"0x{insn.address:x}",
                    "instruction": f"{insn.mnemonic} {insn.op_str}".strip(),
                    "reason": note or mn,
                })
        block_state[bi] = cur
        if visits[bi] > 6:
            # Widening fixpoint guard: stop re-queueing after a bounded
            # number of revisits; ranges at loops are thus over-approximate.
            continue
        for succ in edges.get(bi, []):
            succ_old = block_state.get(succ, {})
            merged = dict(succ_old)
            if merge(merged, cur) and succ_old != merged:
                block_state[succ] = merged
                worklist.append(succ)

    # De-duplicate annotations by (register, origin), keep last value.
    seen: set[tuple[str, str]] = set()
    deduped: list[dict[str, Any]] = []
    for a in reversed(annotations):
        key = (a["register"], a["origin"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(a)
    deduped.reverse()

    return {
        "status": "ok",
        "function": name,
        "address": f"0x{va:x}",
        "ranges": deduped,
        "range_count": len(deduped),
        "limitations": [
            "Register-level ranges only: memory, stack slots, and flags "
            "are not modeled.",
            "Loop back-edges are widened after a bounded number of "
            "revisits; reported loop-carried ranges are over-approximate.",
            "No path constraints: a reported range is the union over all "
            "executions the linear sweep saw, not a per-path proof.",
            "Sub-register writes (al/ax/eax) collapse into the 64-bit "
            "family range.",
        ],
    }


def _reverse_postorder(blocks: list[Any], edges: dict[int, list[int]]) -> list[int]:
    visited: set[int] = set()
    order: list[int] = []

    def dfs(bi: int) -> None:
        if bi in visited:
            return
        visited.add(bi)
        for succ in edges.get(bi, []):
            dfs(succ)
        order.append(bi)

    for bi in range(len(blocks)):
        dfs(bi)
    order.reverse()
    return order


# ---------------------------------------------------------------------------
# Tool: path_feasibility (angr-backed)
# ---------------------------------------------------------------------------


class _BudgetExhaustedError(Exception):
    """Raised by the step hook when time or step budget is spent."""


def _handler_path_feasibility(args: dict[str, Any]) -> dict[str, Any]:
    loaded = _load_binary(args.get("target_path"))
    source_va = _parse_address(args.get("source_address"), loaded, "source_address")
    sink_va = _parse_address(args.get("sink_address"), loaded, "sink_address")
    timeout_s = args.get("timeout_seconds", 60)
    max_steps = args.get("max_steps", 200_000)
    if not isinstance(timeout_s, (int, float)) or timeout_s <= 0:
        raise ToolError("timeout_seconds must be positive")
    if not isinstance(max_steps, int) or max_steps < 1:
        raise ToolError("max_steps must be a positive integer")
    if not loaded.is_code_va(source_va):
        raise ToolError(f"source_address 0x{source_va:x} is not in an executable section")
    if not loaded.is_code_va(sink_va):
        raise ToolError(f"sink_address 0x{sink_va:x} is not in an executable section")

    try:
        import angr  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover - depends on env
        raise ToolError(_ANGR_INSTALL_HINT) from exc

    import time  # noqa: PLC0415

    result_box: dict[str, Any] = {}

    def _explore() -> None:
        try:
            proj = angr.Project(loaded.path, auto_load_libs=False)
            state = proj.factory.blank_state(addr=source_va)
            # Unmodeled imports and uninitialized regions otherwise make
            # angr fabricate symbolic bytes for every read; zero-filling
            # keeps exploration concrete and avoids internal faults on
            # stores of symbolic garbage.
            state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
            state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
            # angr's msvcr __getmainargs SimProcedure stores
            # state.posix.{argc,argv,environ} into caller buffers; a
            # blank state leaves all three None, which faults angr's
            # memory layer. Seed concrete stand-ins.
            import claripy  # noqa: PLC0415

            bits = proj.arch.bits
            state.posix.argc = claripy.BVV(1, bits)
            state.posix.argv = claripy.BVV(0, bits)
            state.posix.environ = claripy.BVV(0, bits)
            simgr = proj.factory.simgr(state)
            deadline = time.monotonic() + float(timeout_s)
            steps = [0]

            def _step_hook(simgr_):
                steps[0] += 1
                if steps[0] > max_steps or time.monotonic() > deadline:
                    raise _BudgetExhaustedError
                return simgr_

            simgr.explore(find=sink_va, num_find=1, step_func=_step_hook)
            if simgr.found:
                path = [hex(a) for a in simgr.found[0].history.bbl_addrs]
                result_box.update({
                    "feasible": True,
                    "path": path,
                    "path_length": len(path),
                    "explored_steps": steps[0],
                    "active_states": len(simgr.active),
                })
            else:
                result_box.update({
                    "feasible": False,
                    "path": [],
                    "path_length": 0,
                    "explored_steps": steps[0],
                    "active_states": len(simgr.active),
                    "deadended_states": len(simgr.deadended),
                })
        except _BudgetExhaustedError:
            result_box.update({
                "feasible": None,
                "path": [],
                "path_length": 0,
                "explored_steps": max_steps,
                "terminated_reason": "step_or_time_budget",
            })
        except (
            angr.errors.SimError,
            claripy.ClaripyError,
            TypeError,
            ValueError,
            AttributeError,
            KeyError,
            IndexError,
            MemoryError,
            OSError,
            RuntimeError,
        ) as exc:
            # angr's own engine faults plus the concrete faults its
            # SimProcedures can throw (we have observed a TypeError from
            # angr's memory layer on Windows CRT code) are surfaced as a
            # structured error rather than crashing the server.
            result_box.update({"angr_error": f"{type(exc).__name__}: {exc}"})

    worker = threading.Thread(target=_explore, daemon=True)
    worker.start()
    worker.join(timeout=float(timeout_s) + 15)
    timed_out = worker.is_alive()
    if timed_out:
        result_box.update({
            "feasible": None,
            "terminated_reason": "wall_clock_timeout",
        })

    feasible = result_box.get("feasible")
    if "angr_error" in result_box:
        raise ToolError(f"angr exploration failed: {result_box['angr_error']}")
    status = (
        "satisfiable" if feasible is True
        else "unsatisfiable" if feasible is False
        else "unknown"
    )
    return {
        "status": "ok",
        "feasibility": status,
        "source_address": f"0x{source_va:x}",
        "sink_address": f"0x{sink_va:x}",
        "feasible": feasible,
        "path": result_box.get("path", []),
        "explored_steps": result_box.get("explored_steps", 0),
        "terminated_reason": result_box.get("terminated_reason", "completed"),
        "limitations": [
            "angr ran with auto_load_libs=False: DLL imports resolve to "
            "angr's default SimProcedures or concrete stubs, not real "
            "library code.",
            "Exploration started from a blank state at source_address; "
            "no calling-convention context or environment constraints "
            "were seeded.",
            "A 'satisfiable' result is a symbolic-witness path; "
            "'unsatisfiable' means no active state reached the sink "
            "within the step/time budget, not a proof of unreachability.",
            "Windows SEH and thread-context switches are not modeled.",
        ],
    }


# ---------------------------------------------------------------------------
# Tool: assess_exploitability
# ---------------------------------------------------------------------------


def _handler_assess_exploitability(args: dict[str, Any]) -> dict[str, Any]:
    loaded = _load_binary(args.get("target_path"))
    va, name = _resolve_function(loaded, args.get("address_or_name"))
    sink_function = args.get("sink_function")
    if not isinstance(sink_function, str) or not sink_function.strip():
        raise ToolError("sink_function must be a non-empty string")
    sink_function = sink_function.strip()
    arg_idx = args.get("sink_argument_index", 0)
    if not isinstance(arg_idx, int) or isinstance(arg_idx, bool) or arg_idx < 0:
        raise ToolError("sink_argument_index must be a non-negative integer")
    if not loaded.is64:
        raise ToolError(
            "assess_exploitability currently supports 64-bit PE targets only",
        )
    if arg_idx >= len(_X64_ARG_REGS):
        raise ToolError(
            f"sink_argument_index {arg_idx} targets a stack argument; only "
            f"the first {len(_X64_ARG_REGS)} x64 register arguments are tracked",
        )
    seed_reg = _X64_ARG_REGS[arg_idx]

    insns = _disasm_function(loaded, va)
    call_idx = None
    for i, insn in enumerate(insns):
        if insn.mnemonic != "call":
            continue
        tgt = _resolve_call_target(loaded, insn)
        if tgt is not None and tgt.lower() == sink_function.lower():
            call_idx = i
            break
    if call_idx is None:
        return {
            "status": "ok",
            "sink_function": sink_function,
            "sink_argument_index": arg_idx,
            "function": name,
            "sink_found": False,
            "verdict": "not_applicable",
            "assignment_chain": [],
            "validation_gates": [],
            "arithmetic_chain": [],
            "source_type": "unknown",
            "sink_expression": "",
            "limitations": [
                "Sink name resolution covers imports, export names, and "
                "single-jump thunks; indirect calls through function "
                "pointers are not matched.",
            ],
        }

    call_insn = insns[call_idx]
    chain, root_kind, root_info = _backward_slice(insns, call_idx - 1, seed_reg)
    chain_vars: set[str] = {seed_reg}
    for item in chain:
        text = item["text"]
        for m in re.findall(r"[a-z0-9]{2,3}", text.lower()):
            chain_vars.add(m)

    arithmetic: list[dict[str, Any]] = []
    for item in chain:
        mn = item["text"].split(" ", 1)[0]
        if mn in ("imul", "mul", "shl", "sal", "add", "sub", "lea"):
            arithmetic.append(item)
    has_mul = any(
        item["text"].split(" ", 1)[0] in ("imul", "mul")
        for item in chain
    ) or any(
        re.search(r"\bshl\b|\bsal\b", item["text"]) for item in chain
    )

    # Validation gates: cmp/test feeding a conditional jump located
    # between the earliest chain def and the sink call.
    chain_addrs = [int(item["address"], 16) for item in chain if item.get("address")]
    window_lo = min(chain_addrs) if chain_addrs else insns[0].address
    gates: list[dict[str, Any]] = []
    for i, insn in enumerate(insns):
        if not (window_lo <= insn.address <= call_insn.address):
            continue
        if insn.mnemonic not in ("cmp", "test"):
            continue
        for j in range(i + 1, min(i + 3, len(insns))):
            nxt = insns[j]
            if nxt.mnemonic.startswith("j") and nxt.mnemonic not in ("jmp",):
                gates.append({
                    "address": f"0x{insn.address:x}",
                    "instruction": f"{insn.mnemonic} {insn.op_str}".strip(),
                    "branch": f"0x{nxt.address:x} {nxt.mnemonic} {nxt.op_str}",
                })
                break

    source_type = (
        "function_parameter" if root_kind == "function_parameter"
        else "call_result" if root_kind == "call_result"
        else "constant" if root_kind == "constant"
        else "file_header_field" if root_kind == "global_data"
        else "unknown"
    )
    tainted = source_type in ("function_parameter", "file_header_field", "call_result")

    if not tainted:
        verdict = "low_risk"
    elif has_mul and not gates:
        verdict = "likely_exploitable"
    elif gates:
        verdict = "defended"
    else:
        verdict = "needs_review"

    return {
        "status": "ok",
        "sink_function": sink_function,
        "sink_argument_index": arg_idx,
        "function": name,
        "sink_found": True,
        "sink_call": f"0x{call_insn.address:x}",
        "sink_expression": f"{seed_reg} (register argument {arg_idx})",
        "source_type": source_type,
        "root": root_info,
        "has_multiplication": has_mul,
        "assignment_chain": chain,
        "arithmetic_chain": arithmetic,
        "validation_gates": gates,
        "verdict": verdict,
        "limitations": [
            "Assessment is heuristic over a register back-slice on "
            "Capstone disassembly; no SMT solving was performed.",
            "Only the first four x64 register arguments are traceable; "
            "stack-passed sizes/flags are invisible to the slice.",
            "'defended' means at least one conditional gate references "
            "the chain between source and sink; it is not a proof that "
            "the gate blocks exploitation.",
            "Indirect call sites (function pointers) are not matched as "
            "sinks.",
        ],
    }


# ---------------------------------------------------------------------------
# Tool: cross_binary_similarity
# ---------------------------------------------------------------------------


def _structure_hash(insns: list[Any]) -> str | None:
    """CFG-structure hash over a function's instructions.

    Canonical form: block count + per-block (size, terminator) +
    sorted out-degree sequence. Instruction bytes and addresses are
    normalized away so same-shape functions collide.
    """
    blocks, edges = _basic_blocks(insns)
    if len(blocks) < 1:
        return None
    parts: list[str] = [f"nb={len(blocks)}"]
    for bi, block in enumerate(blocks):
        term = block[-1].mnemonic
        parts.append(f"b{bi}:{len(block)}:{term}")
    deg = sorted(len(edges.get(bi, [])) for bi in range(len(blocks)))
    parts.append("deg=" + ",".join(str(d) for d in deg))
    return hashlib.sha1("|".join(parts).encode()).hexdigest()[:16]


def _index_functions(loaded: _LoadedBinary) -> list[dict[str, Any]]:
    """Per-function structural index for similarity matching."""
    entries: list[dict[str, Any]] = []
    names = _function_names(loaded, _function_starts(loaded))
    for va in sorted(_function_starts(loaded)):
        try:
            insns = _disasm_function(loaded, va, max_insns=2000)
        except ToolError:
            continue
        if len(insns) < 2:
            continue
        size = sum(i.size for i in insns)
        if size < 16:
            continue
        # Thunks: a single unconditional jump (optionally after an int3
        # padding prefix) carry no structure.
        real = [i for i in insns if i.mnemonic != "int3"]
        if len(real) == 1 and real[0].mnemonic == "jmp":
            continue
        h = _structure_hash(insns)
        if not h:
            continue
        entries.append({
            "name": names.get(va, f"sub_{va:x}"),
            "address": va,
            "size_bytes": size,
            "structure_hash": h,
        })
    return entries


def _handler_cross_binary_similarity(args: dict[str, Any]) -> dict[str, Any]:
    path_a = args.get("target_path_a")
    path_b = args.get("target_path_b")
    bin_a = _load_binary(path_a)
    bin_b = _load_binary(path_b)

    idx_a = _index_functions(bin_a)
    idx_b = _index_functions(bin_b)

    by_hash: dict[str, list[dict[str, Any]]] = {}
    for e in idx_a:
        by_hash.setdefault(e["structure_hash"], []).append(e)

    matches: list[dict[str, Any]] = []
    for e_b in idx_b:
        peers = by_hash.get(e_b["structure_hash"])
        if not peers:
            continue
        for e_a in peers:
            matches.append({
                "hash": e_b["structure_hash"],
                "binary_a": {
                    "name": e_a["name"],
                    "address": f"0x{e_a['address']:x}",
                    "size_bytes": e_a["size_bytes"],
                },
                "binary_b": {
                    "name": e_b["name"],
                    "address": f"0x{e_b['address']:x}",
                    "size_bytes": e_b["size_bytes"],
                },
            })

    return {
        "status": "ok",
        "binary_a": bin_a.path,
        "binary_b": bin_b.path,
        "indexed_functions_a": len(idx_a),
        "indexed_functions_b": len(idx_b),
        "matches": matches,
        "total_matches": len(matches),
        "limitations": [
            "Similarity is a normalized CFG-shape hash (block counts, "
            "terminators, out-degree sequence); same-shape functions "
            "with different bodies collide.",
            "Only directly-called, exported, or entry functions are "
            "indexed; functions reached solely via indirect calls are "
            "absent from both indexes.",
            "Constants, strings, and operand values are normalized away "
            "-- matched pairs are structural siblings, not semantic "
            "clones.",
        ],
    }


# ---------------------------------------------------------------------------
# Tool: patch_assemble (Keystone; never writes the original file)
# ---------------------------------------------------------------------------


def _handler_patch_assemble(args: dict[str, Any]) -> dict[str, Any]:
    loaded = _load_binary(args.get("target_path"))
    address = args.get("address")
    assembly = args.get("assembly")
    if not isinstance(assembly, str) or not assembly.strip():
        raise ToolError("assembly must be a non-empty instruction string")
    va = _parse_address(address, loaded, "address")

    try:
        import keystone  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover - depends on env
        raise ToolError(
            "patch_assemble requires keystone; install with: pip install keystone-engine",
        ) from exc

    ks_mode = keystone.KS_MODE_64 if loaded.is64 else keystone.KS_MODE_32
    ks = keystone.Ks(keystone.KS_ARCH_X86, ks_mode)
    try:
        encoding, count = ks.asm(assembly, addr=va)
    except keystone.KsError as exc:
        raise ToolError(f"keystone failed to assemble {assembly!r}: {exc}") from exc
    patched = bytes(encoding)

    original = loaded.read_va(va, len(patched))
    if original is None:
        raise ToolError(
            f"cannot read {len(patched)} byte(s) at 0x{va:x} (outside mapped sections)",
        )

    # Byte-level diff.
    diff = []
    for off, (ob, pb) in enumerate(zip(original, patched)):
        if ob != pb:
            diff.append({
                "address": f"0x{va + off:x}",
                "offset": off,
                "original": f"0x{ob:02x}",
                "patched": f"0x{pb:02x}",
            })

    # Re-disassemble the patched bytes so the caller sees the effect.
    md = _md_capstone(loaded)
    patched_disasm = [
        f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}".strip()
        for insn in md.disasm(patched, va)
    ]

    return {
        "status": "ok",
        "address": f"0x{va:x}",
        "assembly": assembly,
        "instruction_count": count,
        "original_bytes": original.hex(),
        "patched_bytes": patched.hex(),
        "byte_diff": diff,
        "patched_disassembly": patched_disasm,
        "file_written": False,
        "limitations": [
            "The original file on disk was NOT modified; apply the "
            "patched_bytes to a copy yourself.",
            "Assembly is one-shot at the given address; relocations "
            "against external symbols are not rebased.",
            "Patched length may differ from the original instruction "
            "stream; the byte_diff covers exactly the assembled span.",
        ],
    }


# ---------------------------------------------------------------------------
# Tool: recover_class_hierarchy (MSVC RTTI + vtable pointer-array scan)
# ---------------------------------------------------------------------------

def _td_name_offset(loaded: _LoadedBinary) -> int:
    """TypeDescriptor name field offset: two pointers precede ``char[]``."""
    return 0x10 if loaded.is64 else 0x08


def _read_c_string(loaded: _LoadedBinary, va: int, max_len: int = 256) -> str | None:
    raw = loaded.read_va(va, max_len)
    if raw is None:
        return None
    end = raw.find(b"\x00")
    if end < 0:
        return None
    # errors="replace" makes decode total; no exception path to swallow.
    return raw[:end].decode("ascii", errors="replace")


def _demangle_msvc(name: str) -> str:
    """``.?AVFoo@@`` -> ``Foo``; pass through anything else."""
    m = re.match(r"^\.\?AV(.+)@@$", name)
    if m:
        return m.group(1)
    return name


def _scan_vtables(loaded: _LoadedBinary) -> list[dict[str, Any]]:
    """Find vtable candidates: runs of >=2 consecutive code pointers in data."""
    ptr = loaded.ptr_size
    vtables: list[dict[str, Any]] = []
    seen: set[int] = set()
    for sec in loaded.data_sections:
        data = sec.data
        base_va = sec.va
        count = len(data) // ptr
        i = 0
        while i < count - 1:
            slot_va = base_va + i * ptr
            val = int.from_bytes(data[i * ptr:(i + 1) * ptr], "little")
            if not loaded.is_code_va(val):
                i += 1
                continue
            # Extend forward while entries keep pointing into code.
            entries: list[int] = [val]
            j = i + 1
            while j < count:
                nxt = int.from_bytes(
                    data[j * ptr:(j + 1) * ptr], "little",
                )
                if not loaded.is_code_va(nxt):
                    break
                entries.append(nxt)
                j += 1
            if len(entries) >= 2 and slot_va not in seen:
                seen.add(slot_va)
                vtables.append({"address": slot_va, "entries": entries})
                i = j  # consumed; continue after this array
                continue
            i += 1
    return vtables


def _parse_rtti(loaded: _LoadedBinary, vtable_va: int) -> dict[str, Any] | None:
    """Parse the MSVC CompleteObjectLocator that owns a vtable.

    MSVC places the ``_RTTICompleteObjectLocator`` record immediately
    before the vftable in ``.rdata``; the pointer to it lives at
    ``vtable[-1]``. Returns {class_name, bases:[{name, mdisp, pdisp,
    vdisp}]} or None when RTTI is absent/stripped.
    """
    ptr = loaded.ptr_size
    col_ref_va = vtable_va - ptr
    col_va = loaded.read_ptr(col_ref_va)
    if col_va is None:
        return None
    sig = loaded.read_u32(col_va)
    if sig != 0:
        return None
    td_off = 0x10 if loaded.is64 else 0x0C
    chd_off = 0x18 if loaded.is64 else 0x10
    td_va = loaded.read_ptr(col_va + td_off)
    chd_va = loaded.read_ptr(col_va + chd_off)
    if td_va is None or chd_va is None:
        return None
    name = _read_c_string(loaded, td_va + _td_name_offset(loaded))
    if name is None or not name.startswith(".?A"):
        return None
    class_name = _demangle_msvc(name)

    num_bases = loaded.read_u32(chd_va + 8)
    bca_off = 0x10 if loaded.is64 else 0x0C
    bca_va = loaded.read_ptr(chd_va + bca_off)
    bases: list[dict[str, Any]] = []
    if num_bases and bca_va is not None and 0 < num_bases < 64:
        for k in range(num_bases):
            bcd_va = loaded.read_ptr(bca_va + k * ptr)
            if bcd_va is None:
                break
            btd = loaded.read_ptr(bcd_va)
            bname = None
            if btd is not None:
                bname = _read_c_string(loaded, btd + _td_name_offset(loaded))
            disp_off = 0x0C if loaded.is64 else 0x08
            bases.append({
                "name": _demangle_msvc(bname) if bname else f"base_{k}",
                "mdisp": loaded.read_u32(bcd_va + disp_off),
                "pdisp": loaded.read_u32(bcd_va + disp_off + 4),
                "vdisp": loaded.read_u32(bcd_va + disp_off + 8),
            })
    return {"class_name": class_name, "bases": bases}


def _handler_recover_class_hierarchy(args: dict[str, Any]) -> dict[str, Any]:
    loaded = _load_binary(args.get("target_path"))
    vtables = _scan_vtables(loaded)
    if not vtables:
        return {
            "status": "ok",
            "classes": [],
            "hierarchy_edges": [],
            "rtti_present": False,
            "limitations": [
                "No pointer arrays into executable code were found in "
                "data sections; the target may be C code, stripped, or "
                "packed.",
            ],
        }

    func_names = _function_names(loaded, _function_starts(loaded))

    classes: list[dict[str, Any]] = []
    edges: list[dict[str, str]] = []
    rtti_seen = False

    for vt in vtables:
        va = vt["address"]
        methods = [func_names.get(e, f"sub_{e:x}") for e in vt["entries"]]
        rtti = _parse_rtti(loaded, va)
        if rtti is not None:
            rtti_seen = True
            class_name = rtti["class_name"]
            for base in rtti["bases"]:
                if base["name"] != class_name:
                    edges.append({
                        "base": base["name"],
                        "derived": class_name,
                        "kind": "rtti",
                    })
            classes.append({
                "class_name": class_name,
                "vtable_address": f"0x{va:x}",
                "method_count": len(methods),
                "methods": methods,
                "source": "rtti",
            })
        else:
            classes.append({
                "class_name": f"vtable_{va:x}",
                "vtable_address": f"0x{va:x}",
                "method_count": len(methods),
                "methods": methods,
                "source": "heuristic",
            })

    # Heuristic edges when RTTI is absent: if class A's method list is a
    # strict prefix of class B's, A is a plausible base of B.
    if not rtti_seen:
        for a in classes:
            ma = a["methods"]
            if len(ma) < 2:
                continue
            for b in classes:
                if a is b:
                    continue
                mb = b["methods"]
                if len(mb) > len(ma) and mb[:len(ma)] == ma:
                    edges.append({
                        "base": a["class_name"],
                        "derived": b["class_name"],
                        "kind": "prefix_heuristic",
                    })

    return {
        "status": "ok",
        "classes": classes,
        "class_count": len(classes),
        "hierarchy_edges": edges,
        "rtti_present": rtti_seen,
        "limitations": (
            [
                "Class names and base classes come from MSVC RTTI "
                "metadata; targets built without RTTI (/GR-) or with "
                "stripped .rdata fall back to the pointer-array "
                "heuristic.",
                "Heuristic classes are named by vtable address; prefix "
                "edges are structural guesses (a derived vtable shares "
                "its base's initial method sequence).",
                "Virtual inheritance offsets (vdisp) are reported raw "
                "from the BCD but not validated.",
            ]
        ),
    }


# ---------------------------------------------------------------------------
# Tool: detect_protocol_state_machine
# ---------------------------------------------------------------------------

_RAW_SOCKET_APIS = {
    "recv", "recvfrom", "wsarecv", "send", "sendto", "wsasend",
    "read", "write", "connect", "accept", "listen", "bind",
    "socket", "closesocket", "shutdown",
}
_WINHTTP_APIS = {
    "winhttpreaddata", "winhttpsendrequest", "winhttpreceiveresponse",
    "winhttpopen", "winhttpconnect", "winhttpopenrequest",
}
_WININET_APIS = {
    "internetreadfile", "internetreadfileex",
    "httpsendrequesta", "httpsendrequestw",
    "internetopena", "internetopenw",
    "internetconnecta", "internetconnectw",
    "httpopenrequesta", "httpopenrequestw",
}
_URLMON_APIS = {"urldownloadtofilea", "urldownloadtofilew"}
_BUFFER_OPS = {
    "memcpy", "memmove", "memset", "malloc", "realloc",
    "ntohs", "ntohl", "htons", "htonl",
}


def _handler_detect_protocol_state_machine(args: dict[str, Any]) -> dict[str, Any]:
    loaded = _load_binary(args.get("target_path"))
    va, name = _resolve_function(loaded, args.get("address_or_name"))
    insns = _disasm_function(loaded, va)

    callees: list[str] = []
    for insn in insns:
        if insn.mnemonic != "call":
            continue
        tgt = _resolve_call_target(loaded, insn)
        if tgt:
            callees.append(tgt.lower())
    callees_lower = set(callees)

    raw_hits = callees_lower & _RAW_SOCKET_APIS
    winhttp_hits = callees_lower & _WINHTTP_APIS
    wininet_hits = callees_lower & _WININET_APIS
    urlmon_hits = callees_lower & _URLMON_APIS
    net_callees = callees_lower & (
        _RAW_SOCKET_APIS | _WINHTTP_APIS | _WININET_APIS | _URLMON_APIS
    )
    has_network = bool(net_callees)

    types_present = [
        t for t, hits in (
            ("raw_socket", raw_hits),
            ("winhttp", winhttp_hits),
            ("wininet", wininet_hits),
            ("urlmon", urlmon_hits),
        ) if hits
    ]
    if not types_present:
        protocol_type = "none"
    elif len(types_present) > 1:
        protocol_type = "mixed"
    else:
        protocol_type = types_present[0]

    http_open = (winhttp_hits & {"winhttpopen"}) | (
        wininet_hits & {"internetopena", "internetopenw"}
    )
    http_connect = (winhttp_hits & {"winhttpconnect"}) | (
        wininet_hits & {"internetconnecta", "internetconnectw"}
    )
    http_request = (winhttp_hits & {"winhttpopenrequest"}) | (
        wininet_hits & {"httpopenrequesta", "httpopenrequestw"}
    )
    http_send = (winhttp_hits & {"winhttpsendrequest"}) | (
        wininet_hits & {"httpsendrequesta", "httpsendrequestw"}
    )
    http_read = (winhttp_hits & {"winhttpreaddata", "winhttpreceiveresponse"}) | (
        wininet_hits & {"internetreadfile", "internetreadfileex"}
    )
    http_op_count = sum(1 for s in (http_open, http_connect, http_request, http_send, http_read) if s)
    if urlmon_hits:
        http_op_count = max(http_op_count, 3)
    has_http_stack = bool(winhttp_hits or wininet_hits or urlmon_hits)
    is_http_protocol = has_http_stack and http_op_count >= 2

    has_buffer_ops = bool(callees_lower & _BUFFER_OPS)

    # State machine recovery: indirect jumps with a preceding bounded
    # comparison. Extract case targets from the jump table.
    states: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    dispatch_addrs: set[int] = set()
    for i, insn in enumerate(insns):
        if insn.mnemonic != "jmp":
            continue
        from capstone import CS_OP_MEM, CS_OP_REG  # noqa: PLC0415

        op = insn.operands[0] if insn.operands else None
        if op is None or op.type not in (CS_OP_MEM, CS_OP_REG):
            continue
        # Look back a few instructions for `cmp reg, imm` bounding the
        # dispatch (classic jump-table dispatcher shape).
        case_count: int | None = None
        for j in range(max(0, i - 8), i):
            prev = insns[j]
            if prev.mnemonic == "cmp":
                imm = _imm_operand(prev)
                if imm is not None and 1 < imm <= 256:
                    case_count = imm + 1
                    break
        if case_count is None:
            continue
        table_va: int | None = None
        if op.type == CS_OP_MEM:
            table_va = insn.address + insn.size + int(op.mem.disp)
        else:
            # mov reg, [rip+disp] feeding the indirect jmp.
            for j in range(max(0, i - 6), i):
                prev = insns[j]
                if prev.mnemonic.startswith("mov") and prev.operands:
                    p0 = prev.operands[0]
                    p1 = prev.operands[-1]
                    if (
                        p1.type == CS_OP_MEM
                        and prev.reg_name(p0.reg) == insn.reg_name(op.reg)
                    ):
                        table_va = prev.address + prev.size + int(p1.mem.disp)
                        break
        if table_va is None:
            continue
        ptr = loaded.ptr_size
        raw = loaded.read_va(table_va, case_count * ptr)
        if raw is None:
            continue
        targets = [
            int.from_bytes(raw[k * ptr:(k + 1) * ptr], "little")
            for k in range(case_count)
        ]
        valid = [t for t in targets if loaded.is_code_va(t)]
        if len(valid) < 2:
            continue
        dispatcher = f"0x{insn.address:x}"
        dispatch_addrs.add(insn.address)
        for case_i, tgt in enumerate(valid):
            states.append({
                "case": case_i,
                "address": f"0x{tgt:x}",
                "dispatcher": dispatcher,
            })
            edges.append({
                "from": dispatcher,
                "to": f"0x{tgt:x}",
                "kind": "dispatch",
            })

    has_switch = bool(states)
    case_count = len(states)
    raw_is_protocol = bool(raw_hits) and (has_switch or has_buffer_ops)
    is_protocol = raw_is_protocol or is_http_protocol

    if is_protocol and case_count >= 3:
        confidence = "high"
    elif is_protocol:
        confidence = "medium"
    elif has_network:
        confidence = "low"
    else:
        confidence = "none"

    # State-variable candidates: registers compared against several
    # distinct small constants across the function (cmp reg, N patterns).
    from capstone import CS_OP_REG  # noqa: PLC0415

    cmp_counts: dict[str, set[int]] = {}
    for insn in insns:
        if insn.mnemonic != "cmp" or not insn.operands:
            continue
        if insn.operands[0].type != CS_OP_REG:
            continue
        imm = _imm_operand(insn)
        if imm is None or imm > 0xFFFF:
            continue
        reg = insn.reg_name(insn.operands[0].reg).lower()
        cmp_counts.setdefault(reg, set()).add(imm)
    state_variables = sorted(
        reg for reg, vals in cmp_counts.items() if len(vals) >= 3
    )[:5]

    return {
        "status": "ok",
        "function": name,
        "is_protocol_handler": is_protocol,
        "protocol_type": protocol_type,
        "confidence": confidence,
        "network_apis": sorted(net_callees),
        "has_command_dispatch": has_switch and case_count >= 2,
        "command_count": case_count,
        "state_variables": state_variables,
        "has_buffer_parsing": has_buffer_ops,
        "states": states,
        "state_edges": edges,
        "has_state_machine": has_switch,
        "limitations": [
            "Callee names resolve through the import table, exports, "
            "and single-jump thunks; indirect calls are anonymous.",
            "States are recovered from jump-table dispatchers only; "
            "if/else state ladders without an indirect jump are not "
            "classified as a state machine.",
            "State-edge targets are the case entries; transitions the "
            "cases make back to the dispatcher are not re-joined into "
            "edges.",
        ],
    }


# ---------------------------------------------------------------------------
# Tool: pseudocode_slice_view (disassembly-listing slice)
# ---------------------------------------------------------------------------


def _handler_pseudocode_slice_view(args: dict[str, Any]) -> dict[str, Any]:
    loaded = _load_binary(args.get("target_path"))
    va, name = _resolve_function(loaded, args.get("address_or_name"))
    focus_callee = str(args.get("focus_callee") or "")
    focus_address = str(args.get("focus_address") or "")
    context_lines = args.get("context_lines", 5)
    max_slices = args.get("max_slices", 10)
    if not isinstance(context_lines, int) or isinstance(context_lines, bool) or context_lines < 0:
        raise ToolError("context_lines must be a non-negative integer")
    if not isinstance(max_slices, int) or isinstance(max_slices, bool) or max_slices < 1:
        raise ToolError("max_slices must be a positive integer")

    insns = _disasm_function(loaded, va)
    blocks, _edges = _basic_blocks(insns)

    # Render a pseudo-listing: one line per instruction, blank line at
    # each basic-block boundary. Call sites render as their resolved
    # import/export name when known.
    block_leaders = {block[0].address for block in blocks}
    lines: list[str] = []
    for insn in insns:
        if insn.address in block_leaders and lines:
            lines.append("")
        text = f"{insn.mnemonic} {insn.op_str}".strip()
        if insn.mnemonic == "call":
            tgt = _resolve_call_target(loaded, insn)
            if tgt and not tgt.startswith("sub_"):
                text = f"call {tgt}"
        lines.append(f"0x{insn.address:x}: {text}")

    focus_callee_l = focus_callee.strip().lower()
    focus_address_s = focus_address.strip().lower()
    slices: list[dict[str, Any]] = []
    match_count = 0
    if focus_callee_l or focus_address_s:
        for lineno, line in enumerate(lines, start=1):
            anchor: str | None = None
            if focus_callee_l and focus_callee_l in line.lower():
                anchor = focus_callee.strip()
            elif focus_address_s and focus_address_s in line.lower():
                anchor = focus_address.strip()
            if anchor is None:
                continue
            match_count += 1
            start = max(1, lineno - context_lines)
            end = min(len(lines), lineno + context_lines)
            slices.append({
                "anchor": anchor,
                "start_line": start,
                "lines": lines[start - 1:end],
            })
            if len(slices) >= max_slices:
                break
    else:
        window = lines[: 2 * context_lines + 1]
        slices.append({"anchor": "", "start_line": 1, "lines": window})

    truncated = match_count > len(slices)
    text_blocks = []
    for s in slices:
        header = (
            f"@ {s['anchor']} (line {s['start_line']}):"
            if s["anchor"]
            else f"(line {s['start_line']}):"
        )
        text_blocks.append(header + "\n" + "\n".join(s["lines"]))

    return {
        "status": "ok",
        "function": name,
        "listing_lines": len(lines),
        "slices": slices,
        "match_count": match_count,
        "truncated": truncated,
        "text": "\n\n".join(text_blocks),
        "limitations": [
            "The listing is Capstone disassembly, not decompiler "
            "pseudocode; there is no typed AST at this layer.",
            "Slices are line windows around textual anchors; dataflow "
            "between sliced lines is not tracked.",
            "Block boundaries come from a linear sweep; functions with "
            "interleaved data or obfuscated control flow may render "
            "out of order.",
        ],
    }


# ---------------------------------------------------------------------------
# Tool table
# ---------------------------------------------------------------------------

_STR = {"type": "string"}
_INT = {"type": "integer"}
_ARR = {"type": "array", "items": {"type": "string"}}

_TOOLS: list[ToolDef] = [
    ToolDef(
        name="interprocedural_taint",
        description=(
            "Trace data flow into a dangerous sink argument backward "
            "across function boundaries on Capstone disassembly. "
            "Register-level def-use slice with interprocedural caller "
            "hops; x64 register arguments only."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target_path": {**_STR, "description": "Absolute local path of the PE binary"},
                "sink_function": {**_STR, "description": "Dangerous sink to trace from (e.g. 'memcpy')"},
                "sink_argument_index": {**_INT, "description": "0-based argument index of the sink (0-3 on x64)"},
                "source_functions": {**_ARR, "description": "Optional names that terminate the trace"},
                "max_depth": {**_INT, "description": "Maximum call-chain hops (default 5)"},
            },
            "required": ["target_path", "sink_function", "sink_argument_index"],
        },
        handler=_handler_interprocedural_taint,
    ),
    ToolDef(
        name="value_ranges",
        description=(
            "Abstract-interpretation value-range annotations for a "
            "function's registers over the recovered basic blocks."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target_path": {**_STR, "description": "Absolute local path of the PE binary"},
                "address_or_name": {**_STR, "description": "Function address (0x...) or name"},
            },
            "required": ["target_path", "address_or_name"],
        },
        handler=_handler_value_ranges,
    ),
    ToolDef(
        name="path_feasibility",
        description=(
            "Check whether a source-to-sink path exists using angr "
            "symbolic execution over the PE."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target_path": {**_STR, "description": "Absolute local path of the PE binary"},
                "source_address": {**_STR, "description": "Start address (0x...)"},
                "sink_address": {**_STR, "description": "Target address (0x...)"},
                "timeout_seconds": {**_INT, "description": "Wall-clock budget (default 60)"},
                "max_steps": {**_INT, "description": "Exploration step budget (default 200000)"},
            },
            "required": ["target_path", "source_address", "sink_address"],
        },
        handler=_handler_path_feasibility,
    ),
    ToolDef(
        name="assess_exploitability",
        description=(
            "Heuristic exploitability assessment for a sink call in a "
            "function: taint source classification, arithmetic chain, "
            "and validation-gate detection over a register back-slice."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target_path": {**_STR, "description": "Absolute local path of the PE binary"},
                "address_or_name": {**_STR, "description": "Function containing the sink call"},
                "sink_function": {**_STR, "description": "Dangerous callee (e.g. 'memmove')"},
                "sink_argument_index": {**_INT, "description": "0-based argument index to assess"},
            },
            "required": ["target_path", "address_or_name", "sink_function", "sink_argument_index"],
        },
        handler=_handler_assess_exploitability,
    ),
    ToolDef(
        name="cross_binary_similarity",
        description=(
            "Match functions across two binaries by normalized "
            "CFG-structure hashing."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target_path_a": {**_STR, "description": "Absolute local path of the first PE binary"},
                "target_path_b": {**_STR, "description": "Absolute local path of the second PE binary"},
            },
            "required": ["target_path_a", "target_path_b"],
        },
        handler=_handler_cross_binary_similarity,
    ),
    ToolDef(
        name="patch_assemble",
        description=(
            "Assemble instructions with Keystone at an address and "
            "return the patched bytes plus a byte-level diff. The "
            "original file is NEVER modified."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target_path": {**_STR, "description": "Absolute local path of the PE binary"},
                "address": {**_STR, "description": "Patch address (0x...)"},
                "assembly": {**_STR, "description": "Instruction text, e.g. \"nop; nop; ret\""},
            },
            "required": ["target_path", "address", "assembly"],
        },
        handler=_handler_patch_assemble,
    ),
    ToolDef(
        name="recover_class_hierarchy",
        description=(
            "Recover C++ class hierarchy from MSVC RTTI when present, "
            "else from vtable pointer-array prefix heuristics."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target_path": {**_STR, "description": "Absolute local path of the PE binary"},
            },
            "required": ["target_path"],
        },
        handler=_handler_recover_class_hierarchy,
    ),
    ToolDef(
        name="detect_protocol_state_machine",
        description=(
            "Detect network-protocol handling and recover jump-table "
            "state machines in a function."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target_path": {**_STR, "description": "Absolute local path of the PE binary"},
                "address_or_name": {**_STR, "description": "Function to analyze"},
            },
            "required": ["target_path", "address_or_name"],
        },
        handler=_handler_detect_protocol_state_machine,
    ),
    ToolDef(
        name="pseudocode_slice_view",
        description=(
            "Slice focused windows out of a function's disassembly "
            "listing around a callee or address anchor."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target_path": {**_STR, "description": "Absolute local path of the PE binary"},
                "address_or_name": {**_STR, "description": "Function to slice"},
                "focus_callee": {**_STR, "description": "Optional callee to focus on"},
                "focus_address": {**_STR, "description": "Optional address to focus on"},
                "context_lines": {**_INT, "description": "Lines of context (default 5)"},
                "max_slices": {**_INT, "description": "Maximum slices (default 10)"},
            },
            "required": ["target_path", "address_or_name"],
        },
        handler=_handler_pseudocode_slice_view,
    ),
]

TOOLS: list[ToolDef] = _TOOLS
