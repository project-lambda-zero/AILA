"""Canonical crash stack-hash for the VR fuzz subsystem (#174).

Before this module existed there were three independent stack-hash
implementations across the fuzz call sites -- the sidecar
(:mod:`aila_fuzz_reporter.base`), the agent's crash-triage tool
(:mod:`aila.modules.vr.tools.crash_triage`), and the scraper
fallbacks. They produced different hashes for the same crash, so a
crash registered by the sidecar could not be correlated by the
triage tool and vice versa, defeating the ``(campaign_id,
stack_hash)`` dedup key on ``vr_fuzz_crashes``.

This module holds the single authoritative algorithm. Every crash
signature written by any part of the fuzz subsystem MUST go through
:func:`canonical_stack_hash` (or :func:`stack_hash_from_trace` when
only a raw stack-trace text is available). The algorithm is:

  1. Frames are normalised to ``function@module`` (module omitted when
     empty). Raw hex addresses are collapsed to ``0x?`` so ASLR bases
     and load offsets do not split otherwise-identical crashes into
     separate buckets.
  2. Only the first (top) 5 frames participate; deeper frames vary
     between engines and inflate the hash without discriminating.
  3. The canonical form is ``<crash_type>|<frame0>|<frame1>|...``
     (crash type prefix chosen per the reviewer note -- it separates
     an OOB read from an OOB write that ends at the same function).
  4. SHA-256 hex digest.

Pure stdlib; no aila dependencies -- so the sidecar (a standalone
tool package under ``tools/aila_fuzz_reporter``) can import this
module without pulling in the rest of the platform.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from typing import Any

__all__ = [
    "canonical_stack_hash",
    "normalize_frame",
    "parse_frames_from_trace",
    "stack_hash_from_trace",
]

# Any run of hex digits following ``0x`` collapses to ``0x?`` so the
# same virtual-address inside a randomly-based binary is folded across
# runs. Matches ``0x1234abcd``, ``0X00``, etc.
_HEX_ADDR_RE = re.compile(r"0[xX][0-9a-fA-F]+")

# Frame regex for the common ``#N 0xADDR in symbol module`` shape
# emitted by ASAN, GDB, and the LLVM sanitizers.
_ASAN_FRAME_RE = re.compile(
    r"#\d+\s+0[xX][0-9a-fA-F]+\s+in\s+(?P<sym>\S+)(?:\s+(?P<mod>\S+))?",
)


def normalize_frame(raw: Any) -> str:
    """Normalise one frame to ``function[@module]`` with hex addrs stripped.

    Accepts either a raw string (any engine format) or a dict shaped
    like ``{"function": ..., "module": ...}`` (the shape emitted by
    :meth:`CrashTriageTool.parse_asan`). Returns an empty string for
    inputs that carry no function name.
    """
    if isinstance(raw, dict):
        fn = str(raw.get("function") or "").strip()
        mod = str(raw.get("module") or "").strip()
        token = f"{fn}@{mod}" if mod else fn
    else:
        token = str(raw or "").strip()
    token = _HEX_ADDR_RE.sub("0x?", token)
    return token


def parse_frames_from_trace(stack_trace: str) -> list[str]:
    """Extract normalised frame tokens from a raw stack-trace string.

    Frame lines matching the standard sanitizer/GDB shape
    ``#N 0xADDR in symbol [module]`` are captured directly. Lines
    that do not look like a frame (ASAN header, ``WRITE of size…``,
    ``SUMMARY:…``, blank lines) are dropped -- otherwise the header
    prose would end up in the hash and split identical crashes into
    different buckets. Returns the frames in top-first order; the
    caller is responsible for the top-5 truncation.

    Frame lines that carry no leading ``#N`` prefix but still contain
    the GDB-style ``... in symbol …`` marker are accepted as a
    fallback so custom engine outputs still hash. A line without an
    ``in`` marker AND without a ``#N`` prefix is treated as a bare
    symbol token when it consists of a single non-whitespace word --
    otherwise it is dropped as prose.
    """
    if not stack_trace:
        return []
    frames: list[str] = []
    for raw_line in stack_trace.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        m = _ASAN_FRAME_RE.match(line)
        if m is not None:
            fn = m.group("sym") or ""
            mod = (m.group("mod") or "").strip()
            token = f"{fn}@{mod}" if mod else fn
        elif " in " in line:
            # GDB-style ``… in symbol …``. Trim trailing paren args
            # so ``foo(int, int)`` and ``foo()`` collapse.
            token = line.split(" in ", 1)[1]
            if "(" in token:
                token = token.split("(", 1)[0]
            token = token.strip()
        elif " " not in line and line:
            # Bare symbol on its own line (a few minimised engine
            # formats). Anything with embedded spaces is prose and
            # is discarded.
            token = line
        else:
            continue
        token = _HEX_ADDR_RE.sub("0x?", token)
        if token:
            frames.append(token)
    return frames


def canonical_stack_hash(
    crash_type: str,
    frames: Iterable[Any],
    *,
    top_n: int = 5,
) -> str:
    """SHA-256 hex digest of the canonical crash signature (#174).

    Args:
        crash_type: The crash category (e.g. ``"heap-buffer-overflow"``
            or the platform's :class:`CrashType` value). Empty string
            is allowed but discouraged; it disables the crash_type
            discriminator.
        frames: Iterable of frames (strings or ``{"function", "module"}``
            dicts). Only the first ``top_n`` non-empty normalised
            frames participate.
        top_n: Number of top frames included in the hash. Defaults to 5.

    Returns:
        Lowercase hex SHA-256 digest of the canonical signature. Empty
        input still produces a stable hash (of ``crash_type + "|"``),
        so callers never have to special-case empty crashes.
    """
    normalized: list[str] = []
    for raw in frames:
        token = normalize_frame(raw)
        if token:
            normalized.append(token)
        if len(normalized) >= top_n:
            break
    canonical = (crash_type or "") + "|" + "|".join(normalized)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def stack_hash_from_trace(stack_trace: str, crash_type: str = "") -> str:
    """Compute :func:`canonical_stack_hash` from a raw trace string.

    Convenience helper for call sites that only have the engine's raw
    stack-trace text (the sidecar path). Parses frames via
    :func:`parse_frames_from_trace`, then delegates to the canonical
    hasher so all fuzz-subsystem dedup keys stay byte-identical.
    """
    frames = parse_frames_from_trace(stack_trace)
    return canonical_stack_hash(crash_type, frames)
