"""Crypto, API-hash, string-decryption, and emulation tools.

Re-implementation of the archived ida-headless crypto/emu tool family on
top of pefile / capstone / unicorn, with miasm driving the symbolic path
of :func:`miasm_emulate` when it is importable. Argument names match the
old ida-headless catalog exactly; the opaque ``binary_id`` handle is
replaced by ``target_path`` (absolute local path of the binary under
analysis), which the AILA bridge injects server-side per the REA cutover
contract.

Real-analysis contract: every heuristic here reports what it actually
proved. A constant-table hit names the table entry and the section it
was found in; nothing upgrades constant presence into "the sample
encrypts with X". Empty scans return ``"found": false`` and empty lists,
never fabricated positives. Heuristic tools carry a ``limitations`` list
stating what the analysis did not prove.
"""
from __future__ import annotations

import json
import logging
import re
import struct
import warnings
import zlib
from importlib import resources
from pathlib import Path
from typing import Any

# _miasm_compat applies the pyparsing-3 shim; it must import before miasm.
from aila.platform.re_analytics._miasm_compat import HAS_MIASM as _HAS_MIASM
from aila.platform.re_analytics._miasm_compat import (
    LocationDB,
    Machine,
    SymbolicExecutionEngine,
    bin_stream_str,
)
from aila.platform.re_analytics._tooldef import ToolDef, ToolError

__all__ = ["TOOLS"]

_log = logging.getLogger(__name__)

# Optional analysis dependencies. The re_analytics server is importable
# without the ``re-analytics`` extra so the platform module graph stays
# loadable on hosts that never analyse binaries; a missing library
# surfaces as an honest ToolError naming the extra to install, not a
# transport fault. Imports stay top-level (repo ruff rule PLC0415).
try:
    import pefile
except ImportError:  # pragma: no cover - environment without extra
    pefile = None  # type: ignore[assignment]

try:
    import capstone as _capstone_mod
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
    from capstone.x86 import X86_REG_ESP, X86_REG_RIP, X86_REG_RSP
except ImportError:  # pragma: no cover - environment without extra
    _capstone_mod = None
    Cs = None  # type: ignore[assignment]
    CS_ARCH_X86 = CS_MODE_32 = CS_MODE_64 = 0
    X86_REG_RIP = X86_REG_RSP = X86_REG_ESP = 0

try:
    import unicorn.x86_const as _uc_x86
    from unicorn import (
        UC_ARCH_X86,
        UC_HOOK_CODE,
        UC_HOOK_MEM_WRITE,
        UC_MODE_32,
        UC_MODE_64,
        UC_PROT_ALL,
        Uc,
        UcError,
    )

    _HAS_UNICORN = True
except ImportError:  # pragma: no cover - environment without extra
    _uc_x86 = None
    UC_ARCH_X86 = UC_HOOK_CODE = UC_HOOK_MEM_WRITE = 0
    UC_MODE_32 = UC_MODE_64 = UC_PROT_ALL = 0
    Uc = None  # type: ignore[assignment]
    UcError = RuntimeError  # type: ignore[assignment,misc]
    _HAS_UNICORN = False

try:
    # ARC4 is deprecated upstream because RC4 is broken as an encryption
    # primitive; here it is analysis-only input for decrypting strings
    # malware encoded with it, which is exactly the recovery use case.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        from Crypto.Cipher import AES, ARC4, CAST, Blowfish

    _HAS_CRYPTO = True
except ImportError:  # pragma: no cover - environment without extra
    AES = ARC4 = Blowfish = CAST = None  # type: ignore[assignment]
    _HAS_CRYPTO = False


# ── shared PE view ───────────────────────────────────────────────────

_IMAGE_SCN_MEM_EXECUTE = 0x20000000
_MAX_TARGET_BYTES = 512 * 1024 * 1024


class _PeView:
    """Minimal PE section view shared by every tool in this module.

    Wraps pefile with fast_load (headers + section table only, no data
    directory walk); every tool here reasons about raw bytes and section
    layout, not imports or resources.
    """

    def __init__(self, data: bytes) -> None:
        if pefile is None:
            raise ToolError(
                "pefile is not installed; pip install 'aila[re-analytics]'",
            )
        self.data = data
        try:
            self._pe = pefile.PE(data=data, fast_load=True)
        except ValueError as exc:
            raise ToolError(f"not a parseable PE: {exc}") from exc
        self.image_base = int(self._pe.OPTIONAL_HEADER.ImageBase)
        self.machine = int(self._pe.FILE_HEADER.Machine)
        self.is64 = self.machine == 0x8664
        self.sections: list[dict[str, Any]] = []
        for sec in self._pe.sections:
            name = sec.Name.rstrip(b"\x00").decode("ascii", "replace")
            self.sections.append(
                {
                    "name": name,
                    "va": self.image_base + int(sec.VirtualAddress),
                    "raw_size": int(sec.SizeOfRawData),
                    "raw_off": int(sec.PointerToRawData),
                    "virt_size": int(sec.Misc_VirtualSize),
                    "chars": int(sec.Characteristics),
                },
            )
        self._pe.close()

    def region(self, sec: dict[str, Any]) -> bytes:
        return self.data[sec["raw_off"]:sec["raw_off"] + sec["raw_size"]]

    def va_to_offset(self, va: int) -> int | None:
        for sec in self.sections:
            span = max(sec["raw_size"], sec["virt_size"])
            if sec["va"] <= va < sec["va"] + span:
                off = sec["raw_off"] + (va - sec["va"])
                if 0 <= off < len(self.data):
                    return off
        return None

    def read_va(self, va: int, size: int) -> bytes | None:
        """Read up to ``size`` bytes starting at ``va`` within one section."""
        for sec in self.sections:
            span = max(sec["raw_size"], sec["virt_size"])
            if sec["va"] <= va < sec["va"] + span:
                off = sec["raw_off"] + (va - sec["va"])
                end = min(off + size, sec["raw_off"] + sec["raw_size"], len(self.data))
                if end > off:
                    return self.data[off:end]
                return None
        return None

    def exec_section(self) -> dict[str, Any]:
        for sec in self.sections:
            if sec["chars"] & _IMAGE_SCN_MEM_EXECUTE:
                return sec
        if not self.sections:
            raise ToolError("PE has no sections")
        return self.sections[0]


def _target_bytes(args: dict[str, Any]) -> tuple[Path, bytes]:
    raw = args.get("target_path")
    if not isinstance(raw, str) or not raw:
        raise ToolError("target_path must be a non-empty string")
    path = Path(raw)
    if not path.is_absolute():
        raise ToolError(f"target_path must be an absolute path, got {raw!r}")
    if not path.is_file():
        raise ToolError(f"target not found: {path}")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ToolError(f"cannot read {path}: {exc}") from exc
    if not data:
        raise ToolError(f"target is empty: {path}")
    if len(data) > _MAX_TARGET_BYTES:
        raise ToolError(f"target too large ({len(data)} bytes)")
    return path, data


_ADDR_RE = re.compile(r"^0[xX][0-9a-fA-F]+$|^[0-9]+$")


def _parse_address(value: Any, name: str) -> int:
    if isinstance(value, bool) or value is None:
        raise ToolError(f"{name} is required (0x... hex string or integer)")
    if isinstance(value, int):
        if value < 0:
            raise ToolError(f"{name} must be non-negative")
        return value
    if isinstance(value, str) and _ADDR_RE.match(value.strip()):
        text = value.strip()
        return int(text, 16) if text.lower().startswith("0x") else int(text, 10)
    raise ToolError(f"{name} must be a 0x... hex string or integer, got {value!r}")


def _clamp_int(value: Any, name: str, lo: int, hi: int, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise ToolError(f"{name} must be an integer")
    if not lo <= value <= hi:
        raise ToolError(f"{name} must be within [{lo}, {hi}], got {value}")
    return value


def _require_capstone() -> None:
    if Cs is None:
        raise ToolError(
            "capstone is not installed; pip install 'aila[re-analytics]'",
        )


def _require_crypto() -> None:
    if not _HAS_CRYPTO:
        raise ToolError(
            "pycryptodome is not installed; pip install 'aila[re-analytics]'",
        )


# ── crypto constant tables ───────────────────────────────────────────

# Embedded constant table. ``bytes`` is the signature prefix (matched up
# to 16 bytes); ``word_size`` groups bytes for the endian swap when the
# table stores an array of machine words; ``endian`` "le" means the
# listed hex is the big-endian textual form of little-endian in-memory
# dwords (the common x86 case for SHA/MD5/CRC tables) so the swapped
# form is searched. Provenance: the archived ida-headless
# data/crypto_sigs.json table, extended with round constants the old
# find_crypto_constants docs promised (S-boxes, round constants, sigma
# constants, padding constants).
_CRYPTO_SIGS: tuple[dict[str, Any], ...] = (
    {"name": "AES_S_box", "algo": "AES", "bytes": "637c777bf26b6fc53001672bfed7ab76", "word_size": 1},
    {"name": "AES_inv_S_box", "algo": "AES", "bytes": "52096ad53036a538bf40a39e81f3d7fb", "word_size": 1},
    {"name": "AES_Rcon", "algo": "AES", "bytes": "01020408102040801b36"},
    {"name": "SHA256_K", "algo": "SHA-256", "bytes": "428a2f9871374491b5c0fbcfe9b5dba5", "endian": "le"},
    {"name": "SHA256_H0", "algo": "SHA-256", "bytes": "6a09e667bb67ae853c6ef372a54ff53a", "endian": "le"},
    {"name": "SHA1_H0", "algo": "SHA-1", "bytes": "67452301efcdab8998badcfe10325476c3d2e1f0"},
    {"name": "SHA512_K", "algo": "SHA-512", "bytes": "428a2f98d728ae227137449123ef65cd", "word_size": 8},
    {"name": "MD5_T", "algo": "MD5", "bytes": "d76aa478e8c7b756242070dbc1bdceee", "endian": "le"},
    {"name": "MD5_H0", "algo": "MD5", "bytes": "67452301efcdab8998badcfe10325476", "endian": "le"},
    {"name": "DES_IP", "algo": "DES", "bytes": "3a32222a121a020a3c34242c141c040c", "word_size": 1},
    {"name": "DES_FP", "algo": "DES", "bytes": "2800200818100800", "word_size": 1},
    {"name": "DES_S1", "algo": "DES", "bytes": "0e0004000f0207010d06000b02000e0b", "word_size": 1},
    {"name": "Blowfish_P", "algo": "Blowfish", "bytes": "243f6a8885a308d313198a2e03707344", "endian": "le"},
    {"name": "Blowfish_S0", "algo": "Blowfish", "bytes": "d1310ba698dfb5ac2ffd72dbd01adfb7", "endian": "le"},
    {"name": "RC4_identity_permutation", "algo": "RC4", "bytes": "000102030405060708090a0b0c0d0e0f", "word_size": 1},
    {"name": "CRC32_table_std", "algo": "CRC32", "bytes": "0000000077073096ee0e612c990951ba", "endian": "le"},
    {"name": "CRC32_poly_EDB88320", "algo": "CRC32", "bytes": "edb88320", "endian": "le"},
    {"name": "CRC32_poly_04C11DB7", "algo": "CRC32", "bytes": "04c11db7", "endian": "le"},
    {"name": "Camellia_SIGMA1", "algo": "Camellia", "bytes": "a09e667f3bcc908b", "word_size": 8},
    {"name": "Camellia_SP1", "algo": "Camellia", "bytes": "70707000", "confidence": "low"},
    {"name": "CAST_S1", "algo": "CAST-128", "bytes": "30fb40d49fa0ff0b6beccd2f3f258c7a"},
    {"name": "Twofish_MDS", "algo": "Twofish", "bytes": "bcbc3275ecec21f3202043c6b1b1a83e"},
    {"name": "SEED_KC", "algo": "SEED", "bytes": "9e3779b9", "endian": "le"},
    {"name": "Serpent_phi", "algo": "Serpent", "bytes": "9e3779b9", "endian": "le"},
    {"name": "TEA_XTEA_delta", "algo": "TEA/XTEA", "bytes": "9e3779b9"},
    {"name": "Whirlpool_C0", "algo": "Whirlpool", "bytes": "18186018c07830d8", "word_size": 8},
    {"name": "RIPEMD160_H0", "algo": "RIPEMD-160", "bytes": "67452301efcdab8998badcfe10325476c3d2e1f0"},
    {"name": "ChaCha20_sigma", "algo": "ChaCha20", "bytes": "61707865332073746279746573203332", "word_size": 1},
    {"name": "ChaCha20_tau", "algo": "ChaCha20", "bytes": "61707865332073746279746573203136"},
    {"name": "Salsa20_sigma", "algo": "Salsa20", "bytes": "61707865332073746279746573203332", "word_size": 1},
    {"name": "SM4_SBOX", "algo": "SM4", "bytes": "d690e9fecce13db716b614c228fb2c05"},
    {"name": "GOST_S_CryptoPro", "algo": "GOST", "bytes": "0a090d060e0b040500070c020108030f"},
    {"name": "Keccak_RC", "algo": "Keccak/SHA-3", "bytes": "0100000000000000", "word_size": 8, "confidence": "medium"},
    {"name": "Adler32_mod_65521", "algo": "Adler-32", "bytes": "f1ff0000"},
    {"name": "zlib_magic", "algo": "zlib", "bytes": "789c"},
    {"name": "GZip_magic", "algo": "GZip", "bytes": "1f8b"},
    {"name": "ARIA_S1", "algo": "ARIA", "bytes": "63007c007700", "confidence": "low"},
    {"name": "Base64_alphabet_std", "algo": "Base64", "bytes": "4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738392b2f", "word_size": 1},
    {"name": "Base64_alphabet_url", "algo": "Base64", "bytes": "4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738392d5f", "word_size": 1},
    {"name": "Murmur3_fmix", "algo": "Murmur3", "bytes": "85ebca6b", "endian": "le"},
)

# Code-immediate sweep for detect_crypto_primitives: distinctive round
# constants that appear as dword immediates inside crypto routines. Value
# is the canonical (big-endian textual) form; both in-memory orders are
# tried. These are hints only: the same constants show up in PRNGs and
# hash-tables, hence confidence "low".
_CODE_CONSTANTS: tuple[tuple[str, str, int], ...] = (
    ("TEA_XTEA_SEED_Serpent_delta", "TEA/XTEA/SEED/Serpent", 0x9E3779B9),
    ("MD5_T0", "MD5", 0xD76AA478),
    ("SHA256_K0", "SHA-256", 0x428A2F98),
    ("Murmur3_fmix_constant", "Murmur3", 0x85EBCA6B),
    ("Murmur3_c1", "Murmur3", 0xCC9E2D51),
    ("ChaCha_const_expa", "ChaCha20", 0x61707865),
    ("ChaCha_const_nd_3", "ChaCha20", 0x33206E64),
    ("Adler32_modulus_65521", "Adler-32", 0xFFF1),
)

_SIG_PREFIX_LEN = 16
_SIG_SCAN_CAP_PER_SECTION = 8
_TOTAL_MATCH_CAP = 256


def _endian_swap(data: bytes, word_size: int) -> bytes:
    """Reverse byte order within each ``word_size`` group."""
    if word_size <= 1:
        return data
    result = bytearray()
    for i in range(0, len(data), word_size):
        result.extend(data[i:i + word_size][::-1])
    return bytes(result)


def _sig_candidates(sig: dict[str, Any]) -> tuple[bytes, ...]:
    pattern = bytes.fromhex(sig["bytes"][: _SIG_PREFIX_LEN * 2])
    if not pattern:
        return ()
    word_size = int(sig.get("word_size", 4))
    endian = sig.get("endian", "")
    if endian == "le":
        return (_endian_swap(pattern, word_size),)
    if endian == "be":
        return (pattern,)
    swapped = _endian_swap(pattern, word_size)
    return (pattern, swapped) if swapped != pattern else (pattern,)


def _confidence(sig: dict[str, Any], matched_len: int) -> str:
    """Table entries may pin a ceiling for byte patterns that are long
    but structurally weak (long runs of zero or repeated bytes)."""
    override = sig.get("confidence")
    if isinstance(override, str):
        return override
    if matched_len >= 8:
        return "high"
    if matched_len >= 4:
        return "medium"
    return "low"


def _scan_region_all_sigs(
    region: bytes,
    base_va: int,
    sigs: tuple[dict[str, Any], ...],
    cap_per_sig: int,
) -> list[dict[str, Any]]:
    """Every occurrence of every signature inside one section region."""
    hits: list[dict[str, Any]] = []
    for sig in sigs:
        for candidate in _sig_candidates(sig):
            start = 0
            count = 0
            while count < cap_per_sig:
                idx = region.find(candidate, start)
                if idx < 0:
                    break
                hits.append(
                    {
                        "name": sig["name"],
                        "algorithm": sig["algo"],
                        "va": base_va + idx,
                        "length": len(candidate),
                        "sig": sig,
                    },
                )
                start = idx + 1
                count += 1
    return hits


# ── detect_crypto_primitives / find_crypto_constants ─────────────────


def _detect_crypto_primitives(args: dict[str, Any]) -> dict[str, Any]:
    path, data = _target_bytes(args)
    view = _PeView(data)
    primitives: list[dict[str, Any]] = []
    scanned_sections: list[str] = []
    seen: set[tuple[str, str]] = set()

    for sec in view.sections:
        region = view.region(sec)
        if not region:
            continue
        scanned_sections.append(sec["name"])
        if sec["chars"] & _IMAGE_SCN_MEM_EXECUTE:
            continue  # code handled by the immediate sweep below
        for hit in _scan_region_all_sigs(
            region, sec["va"], _CRYPTO_SIGS, cap_per_sig=1,
        ):
            key = (hit["name"], sec["name"])
            if key in seen:
                continue
            seen.add(key)
            primitives.append(
                {
                    "type": hit["name"],
                    "algorithm": hit["algorithm"],
                    "address": f"0x{hit['va']:x}",
                    "section": sec["name"],
                    "confidence": _confidence(hit["sig"], hit["length"]),
                },
            )

    code_hints: list[dict[str, Any]] = []
    exec_sec = view.exec_section()
    code_region = view.region(exec_sec)
    for const_name, algo, value in _CODE_CONSTANTS:
        for needle in (struct.pack("<I", value), struct.pack(">I", value)):
            idx = code_region.find(needle)
            if idx >= 0:
                code_hints.append(
                    {
                        "type": const_name,
                        "algorithm": algo,
                        "address": f"0x{exec_sec['va'] + idx:x}",
                        "confidence": "low",
                    },
                )
                break

    return {
        "status": "ok",
        "target_path": str(path),
        "primitives": primitives,
        "code_hints": code_hints,
        "scanned_sections": scanned_sections,
        "limitations": [
            "A data-section constant proves the table is embedded, not that reachable code uses it.",
            "code_hints are raw dword-constant matches inside the executable section; the same values appear in PRNGs and hash tables.",
            "No decompiler correlation is available in this server; the archived tool cross-checked pseudocode, this port cannot.",
            "Signatures of 4 bytes or fewer are coincidence-prone and reported at medium/low confidence.",
        ],
    }


def _find_crypto_constants(args: dict[str, Any]) -> dict[str, Any]:
    path, data = _target_bytes(args)
    view = _PeView(data)
    matches: list[dict[str, Any]] = []
    scanned_sections: list[str] = []

    for sec in view.sections:
        region = view.region(sec)
        if not region:
            continue
        scanned_sections.append(sec["name"])
        hits = _scan_region_all_sigs(
            region, sec["va"], _CRYPTO_SIGS, cap_per_sig=_SIG_SCAN_CAP_PER_SECTION,
        )
        hits.sort(key=lambda h: h["va"])
        for hit in hits[:_SIG_SCAN_CAP_PER_SECTION]:
            matches.append(
                {
                    "name": hit["name"],
                    "algorithm": hit["algorithm"],
                    "address": f"0x{hit['va']:x}",
                    "section": sec["name"],
                    "matched_bytes": hit["length"],
                    "confidence": _confidence(hit["sig"], hit["length"]),
                },
            )
        if len(matches) >= _TOTAL_MATCH_CAP:
            matches = matches[:_TOTAL_MATCH_CAP]
            break

    by_algorithm: dict[str, int] = {}
    for m in matches:
        by_algorithm[m["algorithm"]] = by_algorithm.get(m["algorithm"], 0) + 1

    return {
        "status": "ok",
        "target_path": str(path),
        "total_matches": len(matches),
        "matches": matches,
        "by_algorithm": by_algorithm,
        "scanned_sections": scanned_sections,
        "limitations": [
            "Binary-wide aggregate scan over every section; a hit names an embedded constant table entry, not a call path.",
            "Short signatures (2-4 bytes: TEA delta, SEED KC, CRC polynomials, Murmur fmix, zlib/GZip magic) match by chance on large binaries; weigh them only with corroborating evidence.",
            f"Per-signature per-section results are capped at {_SIG_SCAN_CAP_PER_SECTION} locations and total results at {_TOTAL_MATCH_CAP}.",
        ],
    }


# ── API hash engine ──────────────────────────────────────────────────

_MASK32 = 0xFFFFFFFF
_MASK64 = 0xFFFFFFFFFFFFFFFF


def _rol32(value: int, count: int) -> int:
    return ((value << count) | (value >> (32 - count))) & _MASK32


def _ror32(value: int, count: int) -> int:
    return ((value >> count) | (value << (32 - count))) & _MASK32


def _h_ror13(data: bytes) -> int:
    h = 0
    for byte in data:
        h = (_ror32(h, 13) + byte) & _MASK32
    return h


def _h_add_ror13(data: bytes) -> int:
    h = 0
    for byte in data:
        h = _ror32((h + byte) & _MASK32, 13)
    return h


def _h_crc32(data: bytes) -> int:
    return zlib.crc32(data) & _MASK32


def _h_djb2(data: bytes) -> int:
    h = 5381
    for byte in data:
        h = ((h * 33) + byte) & _MASK32
    return h


def _h_djb2a(data: bytes) -> int:
    h = 5381
    for byte in data:
        h = ((h * 33) ^ byte) & _MASK32
    return h


def _h_djb2_upper(data: bytes) -> int:
    return _h_djb2(data.upper())


def _h_sdbm(data: bytes) -> int:
    h = 0
    for byte in data:
        h = (byte + (h << 6) + (h << 16) - h) & _MASK32
    return h


def _h_fnv1_32(data: bytes) -> int:
    h = 0x811C9DC5
    for byte in data:
        h = (h * 0x01000193) & _MASK32
        h ^= byte
    return h


def _h_fnv1a_32(data: bytes) -> int:
    h = 0x811C9DC5
    for byte in data:
        h ^= byte
        h = (h * 0x01000193) & _MASK32
    return h


def _h_fnv1_64(data: bytes) -> int:
    h = 0xCBF29CE484222325
    for byte in data:
        h = (h * 0x100000001B3) & _MASK64
        h ^= byte
    return h


def _h_fnv1a_64(data: bytes) -> int:
    h = 0xCBF29CE484222325
    for byte in data:
        h ^= byte
        h = (h * 0x100000001B3) & _MASK64
    return h


def _h_joaat(data: bytes) -> int:
    h = 0
    for byte in data:
        h = (h + byte) & _MASK32
        h = (h + (h << 10)) & _MASK32
        h ^= h >> 6
    h = (h + (h << 3)) & _MASK32
    h ^= h >> 11
    h = (h + (h << 15)) & _MASK32
    return h


def _h_joaat_lower(data: bytes) -> int:
    return _h_joaat(data.lower())


def _h_bkdr(data: bytes) -> int:
    h = 0
    for byte in data:
        h = ((h * 131) + byte) & _MASK32
    return h


def _h_rs(data: bytes) -> int:
    a = 63689
    b = 378551
    h = 0
    for byte in data:
        h = (h * a + byte) & _MASK32
        a = (a * b) & _MASK32
    return h


def _h_js(data: bytes) -> int:
    h = 1315423911
    for byte in data:
        h ^= ((h << 5) + byte + (h >> 2)) & _MASK32
    return h


def _h_ap(data: bytes) -> int:
    h = 0xAAAAAAAA
    for i, byte in enumerate(data):
        if i & 1 == 0:
            h ^= ((h << 7) ^ byte * (h >> 3)) & _MASK32
        else:
            h ^= (~((h << 11) + byte ^ (h >> 5))) & _MASK32
    return h & _MASK32


def _h_pjw(data: bytes) -> int:
    high_bits = (_MASK32 << 4) & _MASK32
    h = 0
    for byte in data:
        h = ((h << 4) + byte) & _MASK32
        test = h & high_bits
        if test:
            h = ((h ^ (test >> 24)) & (~high_bits & _MASK32)) & _MASK32
    return h


def _h_murmur3_32(data: bytes, seed: int = 0) -> int:
    length = len(data)
    h = seed & _MASK32
    nblocks = length // 4
    for i in range(nblocks):
        k = struct.unpack_from("<I", data, i * 4)[0]
        k = (k * 0xCC9E2D51) & _MASK32
        k = _rol32(k, 15)
        k = (k * 0x1B873593) & _MASK32
        h ^= k
        h = _rol32(h, 13)
        h = (h * 5 + 0xE6546B64) & _MASK32
    tail = data[nblocks * 4:]
    if len(tail) == 3:
        h ^= tail[2] << 16
    if len(tail) >= 2:
        h ^= tail[1] << 8
    if len(tail) >= 1:
        h ^= tail[0]
        h = (h * 0xCC9E2D51) & _MASK32
        h = _rol32(h, 15)
        h = (h * 0x1B873593) & _MASK32
    h ^= length
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & _MASK32
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & _MASK32
    h ^= h >> 16
    return h


_HASH_ALGOS_32: dict[str, tuple[str, Any]] = {
    "ror13": ("ROR13 add (Metasploit)", _h_ror13),
    "add_ror13": ("add then ROR13", _h_add_ror13),
    "crc32": ("CRC-32 (zlib/IEEE)", _h_crc32),
    "djb2": ("DJB2", _h_djb2),
    "djb2a": ("DJB2a (xor variant)", _h_djb2a),
    "djb2_upper": ("DJB2 over uppercased name", _h_djb2_upper),
    "sdbm": ("SDBM", _h_sdbm),
    "fnv1_32": ("FNV-1 32-bit", _h_fnv1_32),
    "fnv1a_32": ("FNV-1a 32-bit", _h_fnv1a_32),
    "joaat": ("Jenkins one-at-a-time", _h_joaat),
    "joaat_lower": ("Jenkins OAAT over lowercased name", _h_joaat_lower),
    "bkdr": ("BKDR (131)", _h_bkdr),
    "rs": ("RS hash", _h_rs),
    "js": ("JS hash", _h_js),
    "ap": ("AP hash", _h_ap),
    "pjw": ("PJW / ELF hash", _h_pjw),
    "murmur3_32": ("MurmurHash3 x86 32-bit (seed 0)", _h_murmur3_32),
}

_HASH_ALGOS_64: dict[str, tuple[str, Any]] = {
    "fnv1_64": ("FNV-1 64-bit", _h_fnv1_64),
    "fnv1a_64": ("FNV-1a 64-bit", _h_fnv1a_64),
}

_HASHDB_INVALID = 0xFFFFFFFE
_MIN_DWELL_CONSTANT = 0xFFFF
_MAX_MATCHES_PER_ALGO = 50
_MIN_MATCHES_TO_REPORT = 3
_MAX_ALGOS_REPORTED = 5


def _iter_dword_constants(view: _PeView) -> tuple[set[int], set[int]]:
    """Every aligned 4/8-byte value across all sections (PE header skipped)."""
    c32: set[int] = set()
    c64: set[int] = set()
    for sec in view.sections:
        region = view.region(sec)
        n = len(region)
        for i in range(0, n - 4, 4):
            value = struct.unpack_from("<I", region, i)[0]
            if value > _MIN_DWELL_CONSTANT:
                c32.add(value)
        for i in range(0, n - 8, 8):
            value = struct.unpack_from("<Q", region, i)[0]
            if value > _MASK32:
                c64.add(value)
    return c32, c64


def _rank_hash_algorithms(
    view: _PeView,
    corpus: frozenset[str],
) -> list[dict[str, Any]]:
    """Score every algorithm by how many corpus hashes appear as constants."""
    c32, c64 = _iter_dword_constants(view)
    ranked: list[dict[str, Any]] = []
    for algo_name, (description, func) in sorted(_HASH_ALGOS_32.items()):
        matches: list[dict[str, str]] = []
        for api in corpus:
            value = func(api.encode("ascii", "replace"))
            if value <= _MIN_DWELL_CONSTANT or value == _HASHDB_INVALID:
                continue
            if value in c32:
                matches.append({"api": api, "hash": f"0x{value:08x}"})
                if len(matches) >= _MAX_MATCHES_PER_ALGO:
                    break
        if len(matches) >= _MIN_MATCHES_TO_REPORT:
            ranked.append(
                {
                    "algorithm": algo_name,
                    "description": description,
                    "match_count": len(matches),
                    "sample_matches": matches[:10],
                },
            )
    for algo_name, (description, func) in sorted(_HASH_ALGOS_64.items()):
        matches = []
        for api in corpus:
            value = func(api.encode("ascii", "replace"))
            if value <= _MASK32 or value == _HASHDB_INVALID:
                continue
            if value in c64:
                matches.append({"api": api, "hash": f"0x{value:016x}"})
                if len(matches) >= _MAX_MATCHES_PER_ALGO:
                    break
        if len(matches) >= _MIN_MATCHES_TO_REPORT:
            ranked.append(
                {
                    "algorithm": algo_name,
                    "description": description,
                    "match_count": len(matches),
                    "sample_matches": matches[:10],
                },
            )
    ranked.sort(key=lambda r: r["match_count"], reverse=True)
    return ranked


# Ranking is a pure function of file content; resolve_api_hashes and
# trace_hash_xrefs both need it, and hashing the 13k-name corpus under
# every algorithm costs seconds on large binaries. Cache keyed by
# (path, mtime_ns, size) so an edited file is re-ranked.
_RANK_CACHE: dict[tuple[str, int, int], list[dict[str, Any]]] = {}
_RANK_CACHE_CAP = 16


def _rank_hash_algorithms_cached(path: Path, view: _PeView) -> list[dict[str, Any]]:
    try:
        stat = path.stat()
    except OSError:
        return _rank_hash_algorithms(view, _api_names())
    key = (str(path), stat.st_mtime_ns, stat.st_size)
    cached = _RANK_CACHE.get(key)
    if cached is not None:
        return cached
    ranked = _rank_hash_algorithms(view, _api_names())
    if len(_RANK_CACHE) >= _RANK_CACHE_CAP:
        _RANK_CACHE.pop(next(iter(_RANK_CACHE)))
    _RANK_CACHE[key] = ranked
    return ranked


def _resolve_api_hashes(args: dict[str, Any]) -> dict[str, Any]:
    path, data = _target_bytes(args)
    view = _PeView(data)
    ranked = _rank_hash_algorithms_cached(path, view)
    return {
        "status": "ok",
        "target_path": str(path),
        "resolved": bool(ranked),
        "algorithms": ranked[:_MAX_ALGOS_REPORTED],
        "corpus_size": len(_api_names()),
        "algorithms_implemented": len(_HASH_ALGOS_32) + len(_HASH_ALGOS_64),
        "limitations": [
            "Generic algorithms only; per-implant custom schemes (Conti, LockBit, emotet variants, etc.) are not in the implemented set.",
            "A match means hash(name) equals a constant embedded in the binary; it does not prove the constant is used as an API hash.",
            "Resolution rate under one algorithm is the signal: 3+ matches on a 13k-name corpus is unlikely by chance, one match is not.",
        ],
    }


# ── trace_hash_xrefs ─────────────────────────────────────────────────

_LEA_SCAN_MODES = (0x18, 0x10, 0x20, 0x08)


def _find_lea_refs(
    region: bytes,
    base_va: int,
    is64: bool,
    lo: int,
    hi: int,
) -> list[dict[str, str]]:
    """LEA instructions whose target falls in [lo, hi] (capstone-driven)."""
    _require_capstone()
    mode = CS_MODE_64 if is64 else CS_MODE_32
    md = Cs(CS_ARCH_X86, mode)
    md.detail = True
    refs: list[dict[str, str]] = []
    for insn in md.disasm(region, base_va):
        if insn.mnemonic != "lea" or len(insn.operands) < 2:
            continue
        mem = insn.operands[1].mem
        if is64:
            if mem.base != X86_REG_RIP:
                continue
            target = insn.address + insn.size + mem.disp
        else:
            if mem.base != 0 or mem.index != 0:
                continue
            target = mem.disp & _MASK32
        if lo <= target <= hi:
            refs.append(
                {"instruction": f"0x{insn.address:x}", "target": f"0x{target:x}"},
            )
    return refs


def _trace_hash_xrefs(args: dict[str, Any]) -> dict[str, Any]:
    path, data = _target_bytes(args)
    api = args.get("api_name")
    if not isinstance(api, str) or not api.strip():
        raise ToolError("api_name must be a non-empty string")
    api = api.strip()
    view = _PeView(data)
    ranked = _rank_hash_algorithms_cached(path, view)
    candidate_algos = [r["algorithm"] for r in ranked]
    if not candidate_algos:
        return {
            "status": "ok",
            "target_path": str(path),
            "api": api,
            "found": False,
            "hash": None,
            "hash_algorithm": None,
            "hash_locations": [],
            "table_refs": [],
            "table_ref_count": 0,
            "limitations": [
                "No hash algorithm reached the 3-match confidence floor against the bundled corpus; the binary may not hash-resolve APIs, or uses a custom scheme.",
            ],
        }

    # Compute the API's hash under every candidate algorithm and locate
    # the value in non-executable sections.
    needles: list[tuple[str, int, bytes]] = []
    for algo_name in candidate_algos:
        if algo_name in _HASH_ALGOS_32:
            value = _HASH_ALGOS_32[algo_name][1](api.encode("ascii", "replace"))
            needles.append((algo_name, value, struct.pack("<I", value)))
        elif algo_name in _HASH_ALGOS_64:
            value = _HASH_ALGOS_64[algo_name][1](api.encode("ascii", "replace"))
            needles.append((algo_name, value, struct.pack("<Q", value)))

    chosen: tuple[str, int, list[int]] | None = None
    for algo_name, value, needle in needles:
        locations: list[int] = []
        for sec in view.sections:
            if sec["chars"] & _IMAGE_SCN_MEM_EXECUTE:
                continue
            region = view.region(sec)
            start = 0
            while True:
                idx = region.find(needle, start)
                if idx < 0:
                    break
                locations.append(sec["va"] + idx)
                start = idx + 1
        if locations:
            chosen = (algo_name, value, locations)
            break

    if chosen is None:
        algo_name, value, _ = needles[0]
        return {
            "status": "ok",
            "target_path": str(path),
            "api": api,
            "found": False,
            "hash": f"0x{value:08x}",
            "hash_algorithm": algo_name,
            "hash_locations": [],
            "table_refs": [],
            "table_ref_count": 0,
            "auto_detected_algorithms": candidate_algos,
            "limitations": [
                "The auto-detected algorithm's hash of this API does not appear in the binary's data sections; either the API is not hash-resolved or a different scheme covers it.",
            ],
        }

    algo_name, value, locations = chosen
    locations.sort()

    # Detect the containing table: walk backwards from the first hit at
    # common structure strides while dwords look like hashes (> 0x10000).
    table_base_va: int | None = None
    table_stride = 0
    first_off = view.va_to_offset(locations[0])
    if first_off is not None:
        for stride in _LEA_SCAN_MODES:
            prev = first_off - stride
            if 0 <= prev < len(data) - 4:
                prior = struct.unpack_from("<I", data, prev)[0]
                if prior > 0x10000:
                    table_stride = stride
                    pos = first_off
                    while pos - stride >= 0:
                        if struct.unpack_from("<I", data, pos - stride)[0] < 0x10000:
                            break
                        pos -= stride
                    for sec in view.sections:
                        if sec["raw_off"] <= pos < sec["raw_off"] + sec["raw_size"]:
                            table_base_va = sec["va"] + (pos - sec["raw_off"])
                            break
                    break

    table_refs: list[dict[str, str]] = []
    if table_base_va is not None:
        exec_sec = view.exec_section()
        code_region = view.region(exec_sec)
        table_end = locations[-1] + 0x200
        table_refs = _find_lea_refs(
            code_region, exec_sec["va"], view.is64, table_base_va, table_end,
        )

    width = 16 if algo_name in _HASH_ALGOS_64 else 8
    return {
        "status": "ok",
        "target_path": str(path),
        "api": api,
        "found": True,
        "hash": f"0x{value:0{width}x}",
        "hash_algorithm": algo_name,
        "hash_locations": [f"0x{v:x}" for v in locations],
        "table_base": f"0x{table_base_va:x}" if table_base_va is not None else None,
        "table_stride": table_stride,
        "table_refs": table_refs,
        "table_ref_count": len(table_refs),
        "auto_detected_algorithms": candidate_algos,
        "limitations": [
            "The hash algorithm is auto-detected by global corpus match rate; a sample mixing schemes may hash this API differently.",
            "table_refs are LEA instructions targeting the table region; on x86-32 absolute addressing is used, on x86-64 RIP-relative only.",
            "A located hash constant proves the value is embedded, not that it is consumed as an API hash.",
        ],
    }


# ── decrypt_function_strings ─────────────────────────────────────────

# (name, kind, pycryptodome module, key sizes, block size). RC4 is
# analysis-only input for decrypting malware-encoded strings. XOR is a
# repeating-key XOR handled inline (no library).
_CIPHERS: tuple[tuple[str, str, Any, tuple[int, ...], int], ...] = (
    ("CAST-128", "block", CAST, (16, 12, 10, 8, 5), 8),
    ("AES-128-ECB", "block", AES, (16,), 16),
    ("Blowfish-ECB", "block", Blowfish, (16,), 8),
    ("RC4", "stream", ARC4, (16, 8, 5), 1),
    ("XOR", "xor", None, (16, 12, 8, 4, 1), 1),
)

_CT_READ_BYTES = 512
_MAX_CT_BLOCKS = 64
_KEY_WINDOW_BYTES = 16384
_BACKTRACK_INSNS = 60
_PROLOGUE_INSNS = 64


def _find_e8_calls(region: bytes, base_va: int, target_va: int) -> list[int]:
    """Every E8 rel32 CALL inside ``region`` that lands on ``target_va``."""
    calls: list[int] = []
    for i in range(len(region) - 5):
        if region[i] == 0xE8:
            rel = struct.unpack_from("<i", region, i + 1)[0]
            if base_va + i + 5 + rel == target_va:
                calls.append(base_va + i)
    return calls


def _disasm_linear(
    region: bytes,
    base_va: int,
    start_va: int,
    max_instructions: int,
    is64: bool,
) -> list[Any]:
    _require_capstone()
    mode = CS_MODE_64 if is64 else CS_MODE_32
    md = Cs(CS_ARCH_X86, mode)
    md.detail = True
    start_off = start_va - base_va
    if start_off < 0 or start_off >= len(region):
        return []
    insns: list[Any] = []
    for insn in md.disasm(region[start_off:], start_va):
        insns.append(insn)
        if len(insns) >= max_instructions:
            break
    return insns


def _collect_prologue_keys(insns: list[Any], is64: bool) -> dict[int, int]:
    """MOV byte ptr [rsp+N], imm8 writes: scattered key material."""
    rsp_reg = X86_REG_RSP if is64 else X86_REG_ESP
    keys: dict[int, int] = {}
    for insn in insns[:_PROLOGUE_INSNS]:
        if insn.mnemonic != "mov" or len(insn.operands) < 2:
            continue
        mem, imm = insn.operands[0], insn.operands[1]
        if mem.type != _capstone_mod.CS_OP_MEM or imm.type != _capstone_mod.CS_OP_IMM:
            continue
        if mem.mem.base != rsp_reg or mem.mem.disp < 0:
            continue
        keys[int(mem.mem.disp)] = int(imm.imm) & 0xFF
    return keys


def _backtrack_call_ctx(
    insns: list[Any],
    call_va: int,
    is64: bool,
) -> tuple[int | None, int | None, dict[int, int]]:
    """Walk backwards from a call: RIP-relative LEA (ciphertext), stack
    LEA (key offset), and a tiny concrete register tracker for the four
    x64 argument registers."""
    ct_va: int | None = None
    key_off: int | None = None
    regs: dict[str, int] = {}
    seen = 0
    for insn in reversed(insns):
        if insn.address >= call_va:
            continue
        seen += 1
        if seen > _BACKTRACK_INSNS or call_va - insn.address > 200:
            break
        if insn.mnemonic == "lea" and len(insn.operands) == 2:
            dst, mem = insn.operands
            if mem.type == _capstone_mod.CS_OP_MEM:
                target = insn.address + insn.size + mem.mem.disp
                if is64 and mem.mem.base == X86_REG_RIP and ct_va is None:
                    ct_va = target
                elif ((is64 and mem.mem.base == X86_REG_RSP or
                       not is64 and mem.mem.base == X86_REG_ESP)
                      and key_off is None and mem.mem.disp >= 0):
                    key_off = int(mem.mem.disp)
                if dst.type == _capstone_mod.CS_OP_REG:
                    regs[insn.reg_name(dst.reg).upper()] = target
        elif insn.mnemonic == "mov" and len(insn.operands) == 2:
            dst, src = insn.operands
            if dst.type == _capstone_mod.CS_OP_REG and src.type == _capstone_mod.CS_OP_IMM:
                regs[insn.reg_name(dst.reg).upper()] = int(src.imm)
    for reg in ("R8", "RDX", "RCX", "R9") if is64 else ("EDX", "ECX"):
        value = regs.get(reg)
        if value is not None and value > 0x10000:
            return ct_va if ct_va is not None else value, key_off, regs
    return ct_va, key_off, regs


def _raw_key_and_ct(
    region: bytes,
    base_va: int,
    call_va: int,
) -> tuple[dict[int, int], int | None]:
    """Fallback byte-pattern scan (ported from the archived tool): the
    last 4C 8D 05 LEA before the call is the ciphertext pointer; C6 44 24
    / C6 84 24 writes are key bytes."""
    off = call_va - base_va
    ct_va: int | None = None
    ct_start = max(0, off - 200)
    chunk = region[ct_start:off]
    for j in range(len(chunk) - 7, -1, -1):
        if chunk[j:j + 3] == b"\x4c\x8d\x05":
            disp = struct.unpack_from("<i", chunk, j + 3)[0]
            ct_va = base_va + ct_start + j + 7 + disp
            break
    key_bytes: dict[int, int] = {}
    key_start = max(0, off - min(_KEY_WINDOW_BYTES, len(region)))
    key_chunk = region[key_start:off]
    for j in range(len(key_chunk) - 5):
        if (key_chunk[j] == 0xC6 and key_chunk[j + 1] == 0x44
                and key_chunk[j + 2] == 0x24):
            key_bytes[key_chunk[j + 3]] = key_chunk[j + 4]
        elif (j + 7 < len(key_chunk) and key_chunk[j] == 0xC6
              and key_chunk[j + 1] == 0x84 and key_chunk[j + 2] == 0x24):
            koff = struct.unpack_from("<I", key_chunk, j + 3)[0]
            if koff < 0x1000:
                key_bytes[koff] = key_chunk[j + 7]
    return key_bytes, ct_va


def _build_key(key_bytes: dict[int, int], key_size: int) -> bytes | None:
    """Contiguous ``key_size`` run inside the scattered stack writes."""
    if len(key_bytes) < key_size:
        return None
    for base in sorted(key_bytes):
        if all(base + k in key_bytes for k in range(key_size)):
            return bytes(key_bytes[base + k] for k in range(key_size))
    return None


def _looks_printable(text: str) -> bool:
    # U+FFFD means the bytes were not valid text for the encoding; a
    # "plaintext" full of replacement characters is a false-positive
    # decrypt of random-looking ciphertext, not recovered text.
    if len(text) < 2 or "\ufffd" in text:
        return False
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\r\t ")
    return printable > len(text) * 0.75


def _try_block_cipher(
    ct_data: bytes,
    key: bytes,
    module: Any,
    block_size: int,
) -> str | None:
    try:
        cipher = module.new(key, module.MODE_ECB)
    except (ValueError, KeyError) as exc:
        _log.debug("block cipher rejected key size %d: %s", len(key), exc)
        return None
    pt = b""
    max_blocks = min(_MAX_CT_BLOCKS, len(ct_data) // block_size)
    for i in range(max_blocks):
        block = ct_data[i * block_size:(i + 1) * block_size]
        if len(block) < block_size:
            break
        dec = cipher.decrypt(block)
        pad = dec[-1]
        if 1 <= pad <= block_size and all(b == pad for b in dec[-pad:]):
            pt += dec[:-pad]
            break
        if b"\x00" in dec:
            pt += dec[:dec.index(b"\x00")]
            break
        pt += dec
    if not pt:
        return None
    # errors="replace" means decode cannot raise; the printable gate below
    # rejects outputs full of U+FFFD replacement characters.
    text = pt.decode("utf-8", "replace").rstrip("\x00")
    return text if _looks_printable(text) else None


def _try_stream_cipher(ct_data: bytes, key: bytes, module: Any) -> str | None:
    try:
        dec = module.new(key).decrypt(ct_data[:_MAX_CT_BLOCKS * 8])
    except (ValueError, KeyError) as exc:
        _log.debug("stream cipher rejected key size %d: %s", len(key), exc)
        return None
    cut = dec.find(b"\x00")
    if cut >= 0:
        dec = dec[:cut]
    if not dec:
        return None
    text = dec.decode("utf-8", "replace").rstrip("\x00")
    return text if _looks_printable(text) else None


def _try_xor(ct_data: bytes, key: bytes) -> str | None:
    sample = ct_data[:_MAX_CT_BLOCKS * 8]
    dec = bytes(b ^ key[i % len(key)] for i, b in enumerate(sample))
    cut = dec.find(b"\x00")
    if cut >= 0:
        dec = dec[:cut]
    if not dec:
        return None
    text = dec.decode("utf-8", "replace").rstrip("\x00")
    return text if _looks_printable(text) else None


def _decrypt_function_strings(args: dict[str, Any]) -> dict[str, Any]:
    _require_crypto()
    path, data = _target_bytes(args)
    decryptor_va = _parse_address(args.get("decryptor_address"), "decryptor_address")
    func_va = _parse_address(args.get("caller_address"), "caller_address")
    _clamp_int(args.get("max_instructions"), "max_instructions", 1, 100000, 500)

    view = _PeView(data)
    exec_sec = view.exec_section()
    code_region = view.region(exec_sec)
    text_base = exec_sec["va"]
    code_end = text_base + len(code_region)
    if not text_base <= decryptor_va < code_end:
        raise ToolError(
            f"decryptor_address 0x{decryptor_va:x} is outside the executable section",
        )
    if not text_base <= func_va < code_end:
        raise ToolError(
            f"caller_address 0x{func_va:x} is outside the executable section",
        )

    all_calls = _find_e8_calls(code_region, text_base, decryptor_va)
    insns = _disasm_linear(code_region, text_base, func_va, 4096, view.is64)
    if insns:
        span_end = insns[-1].address + insns[-1].size
        func_calls = [va for va in all_calls if func_va <= va < span_end]
    else:
        span_end = func_va
        func_calls = []

    if not func_calls:
        return {
            "status": "ok",
            "target_path": str(path),
            "function": f"0x{func_va:x}",
            "decryptor": f"0x{decryptor_va:x}",
            "cipher_detected": None,
            "call_sites": 0,
            "unique_ciphertexts": 0,
            "decrypted": 0,
            "strings": [],
            "limitations": [
                "No call to the decryptor was found inside the linearly disassembled range of the caller; the archived tool used full CFG recovery, this port uses linear disassembly, so calls behind non-return branches may be missed.",
            ],
        }

    prologue_keys = _collect_prologue_keys(insns, view.is64)
    results: list[dict[str, Any]] = []
    seen_ct: set[int] = set()
    cipher_used: str | None = None

    for call_va in func_calls:
        key_bytes = dict(prologue_keys)
        ct_va, key_off, _regs = _backtrack_call_ctx(insns, call_va, view.is64)
        if key_off is not None and prologue_keys:
            window = {k: v for k, v in prologue_keys.items() if key_off <= k < key_off + 32}
            if window:
                key_bytes = window
        if ct_va is None:
            raw_keys, raw_ct = _raw_key_and_ct(code_region, text_base, call_va)
            if raw_keys:
                key_bytes = raw_keys
            ct_va = raw_ct
        if ct_va is None or ct_va in seen_ct:
            continue
        seen_ct.add(ct_va)
        ct_off = view.va_to_offset(ct_va)
        if ct_off is None or ct_off >= len(data):
            continue
        ct_data = data[ct_off:ct_off + _CT_READ_BYTES]

        decrypted = False
        for cname, kind, module, key_sizes, block_size in _CIPHERS:
            for ksz in key_sizes:
                key = _build_key(key_bytes, ksz)
                if key is None:
                    continue
                if kind == "block":
                    text = _try_block_cipher(ct_data, key, module, block_size)
                elif kind == "stream":
                    text = _try_stream_cipher(ct_data, key, module)
                else:
                    text = _try_xor(ct_data, key)
                if text is not None:
                    results.append(
                        {
                            "call_address": f"0x{call_va:x}",
                            "ciphertext_address": f"0x{ct_va:x}",
                            "cipher": cname,
                            "key_size": ksz,
                            "plaintext": text,
                        },
                    )
                    if cipher_used is None:
                        cipher_used = cname
                    decrypted = True
                    break
            if decrypted:
                break

    return {
        "status": "ok",
        "target_path": str(path),
        "function": f"0x{func_va:x}",
        "decryptor": f"0x{decryptor_va:x}",
        "cipher_detected": cipher_used,
        "call_sites": len(func_calls),
        "unique_ciphertexts": len(seen_ct),
        "decrypted": len(results),
        "strings": results,
        "limitations": [
            "Keys are recovered only from MOV byte ptr [rsp+N], imm writes in the function prologue; keys built by other means (globals, loops, expanded schedules) are missed.",
            "Cipher set is CAST-128/AES-ECB/Blowfish-ECB/RC4/repeating-XOR; custom or stream ciphers outside this set will not decrypt.",
            "Linear disassembly approximates the caller's CFG; calls behind opaque branches may be missed.",
        ],
    }


# ── emulation ────────────────────────────────────────────────────────

_UC_REGS_64 = (
    "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "RIP",
)
_UC_REGS_32 = ("EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP")
_MAX_MEM_WRITES_RECORDED = 256
_MAX_EMU_INSTRUCTIONS_HARD = 1_000_000


def _unicorn_arch(view: _PeView) -> str:
    if view.machine == 0x8664:
        return "x86_64"
    if view.machine == 0x14C:
        return "x86_32"
    raise ToolError(f"unsupported architecture (PE machine 0x{view.machine:04x})")


def _init_unicorn(view: _PeView) -> tuple[Any, int]:
    if not _HAS_UNICORN or Uc is None:
        raise ToolError(
            "unicorn is not installed; pip install 'aila[re-analytics]'",
        )
    mode = UC_MODE_64 if view.is64 else UC_MODE_32
    uc = Uc(UC_ARCH_X86, mode)
    highest_end = 0
    for sec in view.sections:
        region = view.region(sec)
        if not region:
            continue
        base = sec["va"] & ~0xFFF
        end = sec["va"] + len(region)
        highest_end = max(highest_end, end)
        size = (end - base + 0xFFF) & ~0xFFF
        try:
            uc.mem_map(base, size, UC_PROT_ALL)
        except UcError:
            pass  # adjacent sections share an aligned page
        uc.mem_write(sec["va"], region)
    # Entry-point code writes through RSP immediately; map an 8 MiB stack
    # above the image with 1 MiB of headroom and report its top so the
    # caller can seed RSP/EBP. Caller-supplied register seeds win.
    stack_size = 8 * 1024 * 1024
    stack_base = ((highest_end + 0xFFF) & ~0xFFF) + 0x100000
    uc.mem_map(stack_base, stack_size, UC_PROT_ALL)
    stack_top = stack_base + stack_size - 0x100
    return uc, stack_top


def _reg_const(name: str) -> int:
    if _uc_x86 is None:
        raise ToolError(
            "unicorn is not installed; pip install 'aila[re-analytics]'",
        )
    return int(getattr(_uc_x86, f"UC_X86_REG_{name}"))


def _parse_register_seed(
    raw: Any,
    view_is64: bool,
) -> dict[str, int]:
    valid = _UC_REGS_64 if view_is64 else _UC_REGS_32
    if raw in (None, ""):
        return {}
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ToolError(f"initial_registers is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ToolError("initial_registers must be a JSON object of register-name -> int")
    seed: dict[str, int] = {}
    for name, value in raw.items():
        reg = str(name).upper()
        if reg not in valid:
            raise ToolError(
                f"unknown register {name!r} for {'x64' if view_is64 else 'x86'}; "
                f"valid: {', '.join(valid)}",
            )
        if isinstance(value, bool) or not isinstance(value, int):
            raise ToolError(f"register {name!r} value must be an integer")
        seed[reg] = value
    return seed


def _parse_memory_seed(raw: Any) -> dict[int, bytes]:
    if raw in (None, ""):
        return {}
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ToolError(f"initial_memory is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ToolError(
            "initial_memory must be a JSON object of hex-address -> hex-byte-string",
        )
    seed: dict[int, bytes] = {}
    for addr, hex_bytes in raw.items():
        try:
            va = int(str(addr), 16)
        except ValueError as exc:
            raise ToolError(f"initial_memory address {addr!r} is not hex") from exc
        if not isinstance(hex_bytes, str):
            raise ToolError(f"initial_memory value for {addr!r} must be a hex string")
        try:
            seed[va] = bytes.fromhex(hex_bytes)
        except ValueError as exc:
            raise ToolError(f"initial_memory value for {addr!r} is not hex") from exc
    return seed


def _seed_memory(uc: Any, seed: dict[int, bytes]) -> None:
    for va, payload in seed.items():
        base = va & ~0xFFF
        end = va + max(len(payload), 1)
        size = (end - base + 0xFFF) & ~0xFFF
        try:
            uc.mem_write(va, payload)
        except UcError:
            try:
                uc.mem_map(base, size, UC_PROT_ALL)
            except UcError:
                pass
            uc.mem_write(va, payload)


def _run_unicorn(
    view: _PeView,
    start_va: int,
    max_instructions: int,
    reg_seed: dict[str, int],
    mem_seed: dict[int, bytes],
) -> dict[str, Any]:
    """Concrete x86/x64 execution via unicorn; sections are mapped at
    their image VAs. OS services are not modeled: code that calls
    imported APIs faults and the abort reason is reported."""
    uc, stack_top = _init_unicorn(view)
    arch = _unicorn_arch(view)
    uc.reg_write(_reg_const("RSP" if view.is64 else "ESP"), stack_top)
    uc.reg_write(_reg_const("RBP" if view.is64 else "EBP"), stack_top)
    _seed_memory(uc, mem_seed)
    for reg, value in reg_seed.items():
        uc.reg_write(_reg_const(reg), value & _MASK64 if view.is64 else value & _MASK32)

    state = {"count": 0, "rip": start_va}

    def _hook_code(uc_: Any, addr: int, _size: int, _user: Any) -> None:
        state["count"] += 1
        state["rip"] = addr
        if state["count"] >= max_instructions:
            uc_.emu_stop()

    writes: list[dict[str, Any]] = []

    def _hook_write(_uc: Any, _access: int, addr: int, size: int, value: int, _user: Any) -> None:
        if len(writes) < _MAX_MEM_WRITES_RECORDED:
            writes.append(
                {"address": f"0x{addr:x}", "size": size, "value": f"0x{value:x}"},
            )

    uc.hook_add(UC_HOOK_CODE, _hook_code)
    uc.hook_add(UC_HOOK_MEM_WRITE, _hook_write)

    aborted: str | None = None
    try:
        uc.emu_start(start_va, until=0, count=max_instructions)
    except UcError as exc:
        aborted = str(exc)

    regs = _UC_REGS_64 if view.is64 else _UC_REGS_32
    final: dict[str, Any] = {}
    for reg in regs:
        value = uc.reg_read(_reg_const(reg))
        final[reg] = {"hex": f"0x{value:x}", "int": value}

    return {
        "arch": arch,
        "start_address": f"0x{start_va:x}",
        "instructions_run": state["count"],
        "next_address": f"0x{state['rip']:x}" if state["rip"] else None,
        "aborted_reason": aborted,
        "final_registers": final,
        "memory_writes": writes,
    }


def _miasm_arch_name(view: _PeView) -> str:
    if view.machine == 0x8664:
        return "x86_64"
    if view.machine == 0x14C:
        return "x86_32"
    raise ToolError(f"miasm path supports x86 only (PE machine 0x{view.machine:04x})")


def _run_miasm_symbolic(
    view: _PeView,
    address: int,
    size: int,
    arch: str,
) -> dict[str, Any]:
    if not _HAS_MIASM or Machine is None or bin_stream_str is None:
        raise ToolError("miasm is not importable")
    raw = view.read_va(address, size)
    if not raw:
        raise ToolError(f"cannot read {size} bytes at 0x{address:x}")
    machine = Machine(arch)
    loc_db = LocationDB()
    bs = bin_stream_str(raw, base_address=address)
    mdis = machine.dis_engine(bs, loc_db=loc_db)
    mdis.follow_call = False
    mdis.dontdis_retcall = True
    lifter = machine.lifter_model_call(loc_db)
    ircfg = lifter.new_ircfg()
    block = mdis.dis_block(address)
    lifter.add_asmblock_to_ircfg(block, ircfg)
    sb = SymbolicExecutionEngine(lifter)
    loc_key = loc_db.get_offset_location(address)
    next_addr = sb.run_block_at(ircfg, loc_key)
    modified = {str(sym): str(val) for sym, val in sb.modified()}
    return {
        "arch": arch,
        "start_address": f"0x{address:x}",
        "next_address": str(next_addr) if next_addr else None,
        "modified_count": len(modified),
        "modified_state": modified,
    }


def _miasm_emulate(args: dict[str, Any]) -> dict[str, Any]:
    path, data = _target_bytes(args)
    address = _parse_address(args.get("address"), "address")
    size = _clamp_int(args.get("size"), "size", 16, 65536, 256)
    max_instructions = _clamp_int(args.get("max_instructions"), "max_instructions", 1, _MAX_EMU_INSTRUCTIONS_HARD, 100)
    view = _PeView(data)
    arch = _miasm_arch_name(view)

    symbolic_error: str | None = None
    if _HAS_MIASM:
        try:
            result = _run_miasm_symbolic(view, address, size, arch)
            result["engine"] = "miasm(symbolic)"
            result["target_path"] = str(path)
            result["status"] = "ok"
            result["max_instructions"] = max_instructions
            return result
        except ToolError:
            raise
        except (ValueError, RuntimeError, KeyError, AttributeError, NotImplementedError) as exc:
            symbolic_error = str(exc)
    else:
        symbolic_error = "miasm is not installed"

    result = _run_unicorn(view, address, max_instructions, {}, {})
    result["engine"] = "unicorn(concrete)"
    result["target_path"] = str(path)
    result["status"] = "ok"
    result["limitations"] = [
        f"miasm symbolic path unavailable ({symbolic_error}); this result is concrete execution, not symbolic state.",
        "Calls are followed only within mapped sections; imported APIs and OS services are not modeled.",
    ]
    return result


def _emulate_concrete(args: dict[str, Any]) -> dict[str, Any]:
    path, data = _target_bytes(args)
    address = _parse_address(args.get("address"), "address")
    max_instructions = _clamp_int(
        args.get("max_instructions"), "max_instructions", 1, _MAX_EMU_INSTRUCTIONS_HARD, 100,
    )
    view = _PeView(data)
    reg_seed = _parse_register_seed(args.get("initial_registers"), view.is64)
    mem_seed = _parse_memory_seed(args.get("initial_memory"))

    exec_sec = view.exec_section()
    if not exec_sec["va"] <= address < exec_sec["va"] + max(exec_sec["raw_size"], exec_sec["virt_size"]):
        raise ToolError(
            f"address 0x{address:x} is not inside the executable section",
        )

    result = _run_unicorn(view, address, max_instructions, reg_seed, mem_seed)
    result["engine"] = "unicorn"
    result["target_path"] = str(path)
    result["status"] = "ok"
    result["limitations"] = [
        "Sections are mapped at their image VAs but no loader runs: the IAT is not populated, no TEB/PEB exists, and TLS callbacks do not fire.",
        "Code that calls an imported API or issues a syscall faults; aborted_reason carries the fault.",
        "Rep-string instructions count as one instruction each.",
    ]
    return result


# ── API name corpus ──────────────────────────────────────────────────

# Bundled Windows-API export-name corpus: data/api_names.txt inside this
# package (one name per line, sorted). Provenance: the archived
# ida-headless data/api_names.txt system-DLL export corpus, mangled C++
# symbols dropped.
_API_NAMES_CACHE: frozenset[str] | None = None


def _api_names() -> frozenset[str]:
    """Load the bundled export-name corpus from package data (lazy).

    resolve_api_hashes and trace_hash_xrefs hash every name here under
    each implemented algorithm and look the values up in the binary's
    constants. Loaded lazily via importlib.resources so importing this
    module stays cheap and the data ships inside the wheel.
    """
    global _API_NAMES_CACHE
    if _API_NAMES_CACHE is None:
        try:
            text = (
                resources.files("aila.platform.re_analytics")
                .joinpath("data")
                .joinpath("api_names.txt")
                .read_text(encoding="utf-8")
            )
        except (FileNotFoundError, NotADirectoryError, ModuleNotFoundError) as exc:
            raise ToolError(
                "re_analytics package data is missing (data/api_names.txt); "
                "reinstall the package",
            ) from exc
        _API_NAMES_CACHE = frozenset(text.split())
    return _API_NAMES_CACHE




# ── tool catalog ─────────────────────────────────────────────────────

_TARGET_PROP: dict[str, Any] = {
    "type": "string",
    "description": "Absolute local filesystem path of the PE binary under analysis.",
}
_ADDRESS_PROP: dict[str, Any] = {
    "type": ["string", "integer"],
    "description": "Virtual address as a 0x... hex string or an integer.",
}


def _object_schema(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {"target_path": _TARGET_PROP, **properties},
        "required": ["target_path", *required],
        "additionalProperties": False,
    }


TOOLS: list[ToolDef] = [
    ToolDef(
        name="detect_crypto_primitives",
        description=(
            "Detect known cryptographic constants and patterns in the binary. "
            "Scans data sections for AES S-box, SHA-256/SHA-1 constants, CRC32 "
            "polynomials, Base64 alphabets, ChaCha/Salsa sigma constants, and "
            "round constants as code immediates. Returns detected primitives "
            "with addresses and confidence."
        ),
        input_schema=_object_schema({}, []),
        handler=_detect_crypto_primitives,
    ),
    ToolDef(
        name="find_crypto_constants",
        description=(
            "Aggregate scan of the binary for known crypto constants (S-boxes, "
            "round constants, sigma constants, padding constants). High signal "
            "for AES / ChaCha / DES / RC4 / SHA / MD family attribution. Reports "
            "every table hit with its location; short constants carry "
            "false-positive caveats."
        ),
        input_schema=_object_schema({}, []),
        handler=_find_crypto_constants,
    ),
    ToolDef(
        name="resolve_api_hashes",
        description=(
            "Resolve hash-imported API names. Scans the binary for 4/8-byte "
            "constants, hashes a bundled Windows-API export corpus under 19 "
            "generic algorithms (ROR13, CRC32, DJB2, SDBM, FNV-1a, Jenkins "
            "OAAT, Murmur3, ...), and ranks algorithms by match count. A high "
            "resolution rate under one algorithm names the hashing scheme."
        ),
        input_schema=_object_schema({}, []),
        handler=_resolve_api_hashes,
    ),
    ToolDef(
        name="trace_hash_xrefs",
        description=(
            "Find which functions reference a hash constant for a dynamically "
            "resolved API. Auto-detects the hash algorithm, computes the API's "
            "hash, locates it in the binary's data sections, and scans the code "
            "for LEA references to the containing table."
        ),
        input_schema=_object_schema(
            {"api_name": {"type": "string", "description": "API function name to trace."}},
            ["api_name"],
        ),
        handler=_trace_hash_xrefs,
    ),
    ToolDef(
        name="decrypt_function_strings",
        description=(
            "Decrypt all encrypted strings in a single function. Finds every "
            "call to the decryptor, extracts the key from stack-prologue byte "
            "writes and the ciphertext pointer from RIP-relative LEAs, then "
            "tries CAST-128 / AES-ECB / Blowfish-ECB / RC4 / repeating-XOR. "
            "Reports per-call plaintext."
        ),
        input_schema=_object_schema(
            {
                "decryptor_address": _ADDRESS_PROP,
                "caller_address": _ADDRESS_PROP,
                "max_instructions": {
                    "type": "integer",
                    "description": "Kept for API compatibility with the archived tool; linear disassembly is bounded internally.",
                },
            },
            ["decryptor_address", "caller_address"],
        ),
        handler=_decrypt_function_strings,
    ),
    ToolDef(
        name="miasm_emulate",
        description=(
            "Symbolically execute a code snippet starting at an address. Uses "
            "the miasm symbolic engine when importable and falls back to "
            "concrete unicorn execution otherwise; the active engine is named "
            "in the result. Tracks register and memory modifications through "
            "the block."
        ),
        input_schema=_object_schema(
            {
                "address": _ADDRESS_PROP,
                "size": {
                    "type": "integer",
                    "description": "Maximum bytes to read for the symbolic block (16-65536, default 256).",
                },
                "max_instructions": {
                    "type": "integer",
                    "description": "Instruction budget for the concrete fallback (default 100).",
                },
            },
            ["address"],
        ),
        handler=_miasm_emulate,
    ),
    ToolDef(
        name="emulate_concrete",
        description=(
            "Concrete emulation with seeded register and memory values (unicorn "
            "CPU emulator). Feeds real values to get real outputs: hash "
            "verification, crypto identification, opaque-predicate evaluation. "
            "initial_registers maps register names to ints; initial_memory maps "
            "hex addresses to hex byte strings. No OS services are modeled; the "
            "abort reason is reported."
        ),
        input_schema=_object_schema(
            {
                "address": _ADDRESS_PROP,
                "max_instructions": {
                    "type": "integer",
                    "description": "Stop after this many instructions (default 100, hard cap 1000000).",
                },
                "initial_registers": {
                    "type": ["string", "object"],
                    "description": "JSON object mapping register names to int values, e.g. {\"RAX\": 0, \"RCX\": 4919384}.",
                },
                "initial_memory": {
                    "type": ["string", "object"],
                    "description": "JSON object mapping hex addresses to hex byte strings, e.g. {\"0x140000000\": \"4b45524e454c33322e444c4c00\"}.",
                },
            },
            ["address"],
        ),
        handler=_emulate_concrete,
    ),
]
