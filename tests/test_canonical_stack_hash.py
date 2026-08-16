"""Parity tests for :func:`aila.modules.vr.services.stack_hash.canonical_stack_hash` (#174).

Before the unification the fuzz subsystem carried three
incompatible stack-hash algorithms:

* ``tools/aila_fuzz_reporter/base.py::stack_hash_of`` -- sidecar
  path, SHA-256 of top-5 bare function names joined by newline.
* ``src/aila/modules/vr/tools/crash_triage.py::CrashTriageTool
  .compute_signature`` -- agent path, SHA-256 of
  ``crash_type + "|" + "|".join(frames)``.
* Scraper fallbacks -- SHA-256 of the reproducer filename (fallback
  when no stack trace is available; a strictly different signal).

Every stack-trace-based call site now routes through
:mod:`aila.modules.vr.services.stack_hash`. This test pins both
call sites against a fixed ASAN sample so a future edit that
diverges either implementation loses the DB-side dedup key
``(campaign_id, stack_hash)`` on ``vr_fuzz_crashes``.
"""
from __future__ import annotations

import sys
from pathlib import Path

# The sidecar lives under tools/, not src/. Add it to sys.path so
# the test can import it without a package install (mirrors the
# pattern in tests/test_aila_fuzz_reporter_scrapers.py).
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "tools"))

from aila.modules.vr.services.stack_hash import (  # noqa: E402,I001
    canonical_stack_hash,
    stack_hash_from_trace,
)
from aila.modules.vr.tools.crash_triage import CrashTriageTool  # noqa: E402,I001
from aila_fuzz_reporter.base import stack_hash_of  # noqa: E402,I001


# Fixed ASAN heap-buffer-overflow sample. Represents the shape the
# libFuzzer / afl-cov / clang-ASAN engines commonly print for a
# stack-buffer-overflow inside a parser.
_ASAN_SAMPLE = """
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000eff0 at pc 0x00010001a4c8 bp 0x7fff5fbff550 sp 0x7fff5fbff548
WRITE of size 4 at 0x60200000eff0 thread T0
    #0 0x10001a4c7 in parse_frame /src/parser.c:212:9
    #1 0x10001b1a2 in handle_packet /src/parser.c:340:5
    #2 0x100019d34 in dispatch /src/main.c:88:3
    #3 0x100019a10 in main /src/main.c:15:5
    #4 0x7fff8ce6c234 in start (libdyld.dylib+0x1234)
""".strip()


def test_canonical_hash_is_stable_across_sidecar_and_triage_tool() -> None:
    """A canonical hash of a fixed ASAN sample matches on both sides.

    The sidecar's :func:`stack_hash_of` only ever sees the raw trace
    text; the triage tool sees a pre-parsed structured
    ``{function, module}`` frame list produced by
    :meth:`CrashTriageTool.parse_asan`. Both paths MUST end at the
    same SHA-256 digest, otherwise the DB unique constraint
    ``(campaign_id, stack_hash)`` splits the same crash into two rows.
    """
    triage = CrashTriageTool()

    parsed = triage.parse_asan(_ASAN_SAMPLE)
    assert parsed["status"] == "ready"
    crash_type = parsed["crash_type"]
    assert crash_type == "overflow_heap"

    # Agent-side signature (via CrashTriageTool). Uses the structured
    # frame dicts from parse_asan.
    sig_agent = triage.compute_signature(
        crash_type=crash_type,
        frames=parsed["stack_frames"],
    )
    assert sig_agent["status"] == "ready"
    hash_agent = sig_agent["signature_hash"]

    # Sidecar-side hash. Takes the raw ASAN text plus the crash_type
    # so the crash_type discriminator matches the agent's input.
    hash_sidecar = stack_hash_of(_ASAN_SAMPLE, crash_type=crash_type)

    # Direct canonical form -- the source of truth both sides delegate
    # to. All three MUST agree.
    hash_direct = canonical_stack_hash(
        crash_type, parsed["stack_frames"],
    )
    hash_from_trace = stack_hash_from_trace(_ASAN_SAMPLE, crash_type)

    assert hash_agent == hash_sidecar == hash_direct == hash_from_trace, (
        f"stack_hash mismatch across call sites:\n"
        f"  agent    = {hash_agent}\n"
        f"  sidecar  = {hash_sidecar}\n"
        f"  direct   = {hash_direct}\n"
        f"  fromtrace= {hash_from_trace}"
    )
    # Sanity: it's a real SHA-256 hex digest, not an empty-input stub.
    assert len(hash_agent) == 64
    assert set(hash_agent) <= set("0123456789abcdef")


def test_canonical_hash_only_top_five_frames_participate() -> None:
    """Frames beyond the fifth do not perturb the hash (D-33 dedup)."""
    frames_5 = [f"fn_{i}" for i in range(5)]
    frames_10 = frames_5 + [f"tail_{i}" for i in range(5)]
    assert (
        canonical_stack_hash("heap-buffer-overflow", frames_5)
        == canonical_stack_hash("heap-buffer-overflow", frames_10)
    )


def test_canonical_hash_normalises_hex_addresses() -> None:
    """Raw addresses inside frame tokens fold to ``0x?`` so ASLR
    bases and load offsets do not split otherwise-identical crashes.
    """
    frames_a = ["parse_frame+0x1234", "handle_packet+0xdeadbeef"]
    frames_b = ["parse_frame+0x5678", "handle_packet+0xcafebabe"]
    assert (
        canonical_stack_hash("overflow_heap", frames_a)
        == canonical_stack_hash("overflow_heap", frames_b)
    )


def test_canonical_hash_crash_type_is_a_discriminator() -> None:
    """Same frames + different crash types → different hashes.

    Motivates the crash_type prefix in the canonical form: an OOB
    read and an OOB write ending at the same function are distinct
    findings and MUST NOT collapse into a single dedup row.
    """
    frames = ["parse_frame", "handle_packet"]
    assert (
        canonical_stack_hash("overflow_heap", frames)
        != canonical_stack_hash("uaf", frames)
    )
