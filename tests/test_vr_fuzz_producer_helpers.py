"""Unit tests for the producer-side helpers added to fuzz_service.

Covers the §1.5 / §1.6 closure (08_FRONTEND_UX.md):
- _read_reproducer_head — tolerates missing path, returns hex + size
- _compose_crash_summary — one-line summary derived from crash_type +
  top stack frame

The _record_telemetry_snapshot helper is exercised end-to-end by the
existing register_crash + patch_campaign integration tests; this
module just covers the pure functions.
"""
from __future__ import annotations

from pathlib import Path

from aila.modules.vr.services.fuzz_service import (
    _compose_crash_summary,
    _read_reproducer_head,
)

__all__ = [
    "test_read_reproducer_head_missing_path",
    "test_read_reproducer_head_nonexistent",
    "test_read_reproducer_head_truncates_to_limit",
    "test_compose_crash_summary_full",
    "test_compose_crash_summary_only_type",
    "test_compose_crash_summary_only_frame",
    "test_compose_crash_summary_empty",
]


def test_read_reproducer_head_missing_path() -> None:
    """A None / empty path returns (None, None) without raising."""
    assert _read_reproducer_head(None) == (None, None)
    assert _read_reproducer_head("") == (None, None)


def test_read_reproducer_head_nonexistent() -> None:
    """A path that does not exist surfaces as (None, None)."""
    assert _read_reproducer_head("/no/such/file.bin") == (None, None)


def test_read_reproducer_head_truncates_to_limit(tmp_path: Path) -> None:
    """Files larger than the limit are truncated; smaller files read fully."""
    small = tmp_path / "small.bin"
    small.write_bytes(b"\x41\x42\x43\x44")
    hex_str, size = _read_reproducer_head(str(small))
    assert hex_str == "41424344"
    assert size == 4

    big = tmp_path / "big.bin"
    big.write_bytes(b"\xff" * 8192)
    hex_str, size = _read_reproducer_head(str(big))
    assert hex_str is not None
    # Bytes read for hex preview is capped at 4096 → 8192 hex chars.
    assert len(hex_str) == 4096 * 2
    # `size` reports the actual file size (truncated_size on the column).
    assert size == 8192


def test_compose_crash_summary_full() -> None:
    """Combines crash_type with the first non-empty stack frame."""
    summary = _compose_crash_summary(
        "heap-buffer-overflow",
        "    #0 0xabcd in ParseHeader /src/parser.c:42\n"
        "    #1 0xef01 in main /src/main.c:1",
    )
    assert summary.startswith("heap-buffer-overflow at ")
    assert "ParseHeader" in summary


def test_compose_crash_summary_only_type() -> None:
    """When the stack trace is empty, returns the crash type alone."""
    assert _compose_crash_summary("stack-buffer-overflow", "") == (
        "stack-buffer-overflow"
    )
    assert _compose_crash_summary("uaf", None) == "uaf"


def test_compose_crash_summary_only_frame() -> None:
    """When the crash type is missing, returns the top frame alone."""
    assert _compose_crash_summary(None, "  frame_a\n  frame_b").startswith(
        "frame_a",
    )


def test_compose_crash_summary_empty() -> None:
    """No inputs returns empty string (column is nullable but never crashes)."""
    assert _compose_crash_summary(None, None) == ""
    assert _compose_crash_summary("", "") == ""
