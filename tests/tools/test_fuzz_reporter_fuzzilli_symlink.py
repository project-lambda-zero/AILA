"""Tests for finding 58-4 (`.run/designs/DESIGN_injection_evidence.md` section 3.4).

Contract
--------
The fuzz-reporter Fuzzilli scraper reads crash reproducer files out of
``<storagePath>/crashes/`` (or ``distinct_crashes/``) and pushes their
contents as ``payload_preview`` into the AILA server. A symlink placed
inside that directory that points OUTSIDE the storage root would
otherwise be dereferenced and its target's bytes (up to 64 KB) would
leak into the reported payload -- an exfiltration primitive over an
untrusted fuzz output tree.

``tools/aila_fuzz_reporter/scrapers/fuzzilli.py::_safe_crash_files``
gates every entry through two orthogonal guards:

1. ``lstat`` + ``S_ISLNK`` -- drop symlinks before ``resolve()``
   follows them.
2. ``resolve()`` + ``is_relative_to(root)`` -- belt-and-suspenders
   containment check so a non-symlink entry that somehow escapes the
   root (mount, hardlink into another volume, filesystem quirk) is
   still refused.

Tests
-----
These tests exercise ``_safe_crash_files`` and ``discover_crashes``
directly. No live fuzzer is required; the symlink primitive is
constructed in ``tmp_path``. On Windows the standard library refuses
to create a symlink without the appropriate privilege; those tests
are skipped there.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# The sidecar lives under tools/, not src/. Mirror the sys.path shim
# used by tests/test_aila_fuzz_reporter_scrapers.py so the module
# resolves without a package install.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT / "tools"))

from aila_fuzz_reporter.scrapers.fuzzilli import (  # noqa: E402  (sys.path mutated above)
    _MAX_REPRODUCER_HARD_CAP,
    FuzzilliScraper,
    _safe_crash_files,
)

_WINDOWS = sys.platform.startswith("win")


def _can_symlink(tmp_path: Path) -> bool:
    """Return True when the current process can create a symlink in ``tmp_path``.

    Windows requires either developer mode + SeCreateSymbolicLinkPrivilege
    or an admin process; without those the standard library raises
    ``OSError`` on ``symlink_to()``. Skipping there keeps CI green
    without lying about the guarantee.
    """
    if not _WINDOWS:
        return True
    probe = tmp_path / "_probe_target.txt"
    probe.write_text("probe", encoding="utf-8")
    probe_link = tmp_path / "_probe_link.txt"
    try:
        probe_link.symlink_to(probe)
    except (OSError, NotImplementedError):
        return False
    finally:
        try:
            probe_link.unlink()
        except OSError:
            pass
        try:
            probe.unlink()
        except OSError:
            pass
    return True


@pytest.fixture()
def _fuzz_root(tmp_path: Path) -> Path:
    """Create a Fuzzilli-shaped storage root with an empty crashes dir."""
    root = tmp_path / "fuzz_storage"
    (root / "crashes").mkdir(parents=True)
    return root


def test_safe_crash_files_accepts_regular_file_inside_root(_fuzz_root: Path) -> None:
    """A regular file that lives inside the crash dir is accepted.

    Sanity guard: the guard must not accidentally reject the happy path.
    """
    crashes = _fuzz_root / "crashes"
    good = crashes / "crash-abc123.js"
    good.write_bytes(b"crash reproducer bytes")

    result = _safe_crash_files(crashes)

    assert result == [good]


def test_safe_crash_files_rejects_symlink_escaping_root(
    _fuzz_root: Path, tmp_path: Path
) -> None:
    """A symlink in crashes/ that points OUTSIDE the storage root is rejected.

    The primitive finding 58-4 names: a symlink whose target is
    ``/etc/passwd`` (or any operator-visible file the fuzz process
    happens to have read access to) would leak up to 64 KB into the
    ``payload_preview`` reported to the AILA server. The lstat guard
    catches this at step 1; the containment guard catches it at step 2.
    Together they guarantee no read on the escaping target.
    """
    if not _can_symlink(tmp_path):
        pytest.skip("current process cannot create symlinks (Windows privilege)")

    # Sensitive-target stand-in: a file outside the fuzz storage root
    # that a well-meaning operator would never intend to expose.
    outside = tmp_path / "sensitive_secret.txt"
    outside.write_bytes(b"top-secret host content the fuzzer must not read")

    crashes = _fuzz_root / "crashes"
    escaping = crashes / "crash-escape.js"
    escaping.symlink_to(outside)

    result = _safe_crash_files(crashes)

    # The symlink MUST NOT appear in the accepted list. That single
    # assertion is the whole finding-58-4 primitive: a symlink whose
    # target is outside the storage root is refused, so its bytes
    # never enter the ``payload_preview`` string reported upstream.
    assert result == []


def test_safe_crash_files_rejects_symlink_that_points_back_inside_root(
    _fuzz_root: Path, tmp_path: Path
) -> None:
    """A symlink is refused even when its target is inside the storage root.

    The gate is applied by KIND, not by containment alone: a symlink
    that happens to point back into the root is still a symlink, and
    the fuzz-scrape path treats them uniformly. This keeps the guard
    simple to reason about -- ``S_ISLNK`` is the whole test at step 1
    -- and prevents a future ``resolve()`` implementation change from
    accidentally admitting them.
    """
    if not _can_symlink(tmp_path):
        pytest.skip("current process cannot create symlinks (Windows privilege)")

    crashes = _fuzz_root / "crashes"
    real = crashes / "crash-real.js"
    real.write_bytes(b"real reproducer bytes")
    link = crashes / "crash-link.js"
    link.symlink_to(real)

    result = _safe_crash_files(crashes)

    # Only the real file is accepted; the symlink -- even though its
    # target is inside the root -- is rejected at step 1.
    assert result == [real]


def test_safe_crash_files_rejects_hard_size_cap_overrun(_fuzz_root: Path) -> None:
    """A regular file above the hard cap is rejected before any read.

    Complementary size guard already present in the module. The cap is
    1 MB (16 x the 64 KB preview limit); a fuzzer that dumps a
    multi-megabyte reproducer is refused so a single bad file cannot
    OOM the sidecar.
    """
    crashes = _fuzz_root / "crashes"

    fat = crashes / "crash-fat.js"
    # Write cap + 1 bytes so the guard fires by 1.
    fat.write_bytes(b"x" * (_MAX_REPRODUCER_HARD_CAP + 1))

    result = _safe_crash_files(crashes)

    assert result == []


def test_discover_crashes_ignores_escaping_symlink_end_to_end(
    _fuzz_root: Path, tmp_path: Path
) -> None:
    """End-to-end: an escaping symlink never appears in ``discover_crashes`` output.

    This exercises the whole scraper path (``discover_crashes`` calls
    ``_safe_crash_files`` for both ``crashes/`` and
    ``distinct_crashes/``, then reads the accepted files with an
    ``O_NOFOLLOW`` open). A CrashRecord for the escaping symlink would
    carry ``payload_preview`` with sensitive host bytes; asserting the
    escape is absent from the output is the operator-facing guarantee.
    """
    if not _can_symlink(tmp_path):
        pytest.skip("current process cannot create symlinks (Windows privilege)")

    outside = tmp_path / "sensitive_secret.txt"
    outside.write_bytes(b"host bytes fuzzer must not push upstream")

    crashes = _fuzz_root / "crashes"
    (crashes / "crash-real.js").write_bytes(b"legitimate reproducer bytes")
    (crashes / "crash-escape.js").symlink_to(outside)

    scraper = FuzzilliScraper(storage_path=_fuzz_root)
    records = scraper.discover_crashes()

    # Exactly one record -- the legitimate reproducer. The escaping
    # symlink was dropped upstream in _safe_crash_files.
    assert len(records) == 1
    assert records[0].crash_signature == "crash-real.js"
    # Preview carries the legitimate bytes; the sensitive host bytes
    # never appear.
    assert "legitimate reproducer" in records[0].extra["payload_preview"]
    assert "host bytes" not in records[0].extra["payload_preview"]


def test_discover_crashes_stack_hash_stable_across_runs(_fuzz_root: Path) -> None:
    """Same filename -> same stack_hash (rerun dedup guarantee).

    Fuzzilli-minimised crashes are identified by filename signature.
    ``stack_hash`` = sha256(filename), so two invocations across the
    same directory produce the same dedup key. Guards against a future
    edit that stops hashing the filename and thus fills the AILA
    server with duplicate crash rows.
    """
    crashes = _fuzz_root / "crashes"
    (crashes / "crash-abc.js").write_bytes(b"payload")

    first = FuzzilliScraper(storage_path=_fuzz_root).discover_crashes()
    second = FuzzilliScraper(storage_path=_fuzz_root).discover_crashes()

    assert len(first) == len(second) == 1
    assert first[0].stack_hash == second[0].stack_hash
