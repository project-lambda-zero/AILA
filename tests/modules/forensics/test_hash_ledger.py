"""Tests for finding 58-2 (`.run/designs/DESIGN_injection_evidence.md` section 3.2).

Contract change
---------------
``file_retriever._run_script_and_pull`` used to trust the ``sha256``
value the analyzer-side extraction script reported in its
``##AILA-RETRIEVE##`` header and return it as the authoritative hash
of the pulled file. The forensics threat model treats the analyzer
host as untrusted, so a compromised or buggy analyzer could report a
digest that did NOT match the bytes actually delivered -- either to
hide tampering, evade deduplication, or plant a chain-of-custody
signature no later auditor could reproduce.

The fix moves the compute + compare into a reusable
:mod:`aila.modules.forensics.services.hash_ledger` module:

* ``verify_or_raise(local_bytes, claimed_sha256)`` recomputes the
  SHA-256 over the pulled bytes and returns the locally-computed
  digest on match.
* On mismatch it raises :class:`HashMismatchError` carrying both the
  claimed and computed digests plus ``size_bytes`` for the log path.
* A malformed ``claimed_sha256`` (wrong length or non-hex) raises
  ``ValueError`` at the boundary so a garbled claim is not
  misdiagnosed as tampering.

These tests exercise the compute + verify core directly with byte /
file fixtures -- no live SSH, no real analyzer host -- so the
integrity guarantee is locked in isolation of the retrieval plumbing.

Companion caller-side change
----------------------------
``file_retriever._run_script_and_pull`` calls
:func:`verify_file_or_raise` in a worker thread after the SFTP pull,
quarantines the local copy on mismatch, wraps the exception in
``FileRetrievalError`` for a caller-facing message, and returns the
locally-recomputed digest thereafter. That composition is covered by
the existing forensics retrieval integration path; the isolated
compute contract lives here.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from aila.modules.forensics.services.hash_ledger import (
    HashMismatchError,
    compute_sha256_file,
    verify_file_or_raise,
    verify_or_raise,
)
from aila.platform.exceptions import AILAError

# ---------------------------------------------------------------------------
# Fixtures -- byte payloads with known SHA-256 digests. Values below are the
# reference outputs of hashlib.sha256 on the empty bytes and a 5 MB pattern
# buffer. Locking them literally means a future edit that silently swaps the
# hash algorithm (e.g. sha1) fails the test at parse time.
# ---------------------------------------------------------------------------

_EMPTY_BYTES: bytes = b""
_EMPTY_SHA256: str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

_SHORT_BYTES: bytes = b"aila hash ledger fixture bytes"
_SHORT_SHA256: str = hashlib.sha256(_SHORT_BYTES).hexdigest()

# 5 MB of a repeating 4-byte pattern -- crosses the 1 MB stream chunk
# boundary five times in verify_file_or_raise so the streamed compute
# is genuinely exercised.
_LARGE_BYTES: bytes = (b"\xde\xad\xbe\xef" * (5 * 1024 * 1024 // 4))
_LARGE_SHA256: str = hashlib.sha256(_LARGE_BYTES).hexdigest()


# ---------------------------------------------------------------------------
# compute_sha256_file -- streamed digest of a real file on disk
# ---------------------------------------------------------------------------


def test_compute_sha256_file_streams_multiple_chunks(tmp_path: Path) -> None:
    """Streamed file compute matches hashlib on a payload that crosses chunks.

    Uses a 5 MB payload so the stream loop iterates through multiple
    ``_STREAM_CHUNK_BYTES`` (1 MB) reads. A future edit that broke the
    loop (e.g. dropped the final short-read chunk) would produce a
    different digest and fail here. Cross-checked against
    :func:`hashlib.sha256` on the full byte payload so an accidental
    swap of the algorithm inside the streamed helper surfaces too.
    """
    fp = tmp_path / "large.bin"
    fp.write_bytes(_LARGE_BYTES)
    assert compute_sha256_file(fp) == _LARGE_SHA256
    assert compute_sha256_file(fp) == hashlib.sha256(_LARGE_BYTES).hexdigest()


# ---------------------------------------------------------------------------
# verify_or_raise -- happy path
# ---------------------------------------------------------------------------


def test_verify_or_raise_returns_locally_computed_hash_on_match() -> None:
    """Match path returns the LOCAL recomputation (not the caller's claim).

    Even when the caller passes the correct value, the return is the
    freshly-computed digest; callers can rely on the return being the
    ground truth without re-hashing.
    """
    result = verify_or_raise(_SHORT_BYTES, _SHORT_SHA256)
    assert result == _SHORT_SHA256
    assert result == hashlib.sha256(_SHORT_BYTES).hexdigest()


def test_verify_or_raise_accepts_uppercase_and_whitespace_in_claim() -> None:
    """Comparison is case-insensitive and tolerates leading/trailing whitespace.

    Analyzers occasionally emit uppercase hex; a strict lowercase
    compare would raise a false mismatch and quarantine the file for
    the wrong reason.
    """
    claim = f"  {_SHORT_SHA256.upper()}\n"
    assert verify_or_raise(_SHORT_BYTES, claim) == _SHORT_SHA256


def test_verify_or_raise_handles_empty_bytes() -> None:
    """Empty payload has a known digest; edge case that hashlib supports."""
    assert verify_or_raise(_EMPTY_BYTES, _EMPTY_SHA256) == _EMPTY_SHA256


# ---------------------------------------------------------------------------
# verify_or_raise -- fail-closed mismatch path
# ---------------------------------------------------------------------------


def test_verify_or_raise_raises_on_mismatch_and_does_not_return() -> None:
    """A wrong claim MUST raise HashMismatchError, NEVER return the claim.

    This is the core of finding 58-2: the pre-fix code returned the
    unverified header value, so a compromised analyzer could report any
    digest and downstream storage would treat it as ground truth. The
    fix fails closed on mismatch; the function has no return path for
    a mismatched claim.
    """
    wrong_claim = "0" * 64
    with pytest.raises(HashMismatchError) as excinfo:
        verify_or_raise(_SHORT_BYTES, wrong_claim)
    err = excinfo.value
    assert err.claimed_sha256 == wrong_claim
    assert err.computed_sha256 == _SHORT_SHA256
    assert err.size_bytes == len(_SHORT_BYTES)


def test_hash_mismatch_error_is_ailaerror_subclass() -> None:
    """HashMismatchError is catchable via the platform base class.

    Callers that already handle AILAError generically (e.g. the
    forensics retrieval path's ``except AILAError`` cleanup block on
    SFTP failures) must be able to catch a hash mismatch too.
    """
    assert issubclass(HashMismatchError, AILAError)


def test_hash_mismatch_error_message_includes_both_digests() -> None:
    """Error string carries a truncated form of both digests for logs.

    Trimming to 16 hex chars keeps log lines readable while retaining
    enough entropy to correlate a mismatch to a specific tampered
    payload after the fact.
    """
    wrong_claim = "1" * 64
    with pytest.raises(HashMismatchError) as excinfo:
        verify_or_raise(_SHORT_BYTES, wrong_claim, source="/tmp/analyzer-tmp.bin")
    msg = str(excinfo.value)
    assert wrong_claim[:16] in msg
    assert _SHORT_SHA256[:16] in msg
    assert "/tmp/analyzer-tmp.bin" in msg
    assert excinfo.value.source == "/tmp/analyzer-tmp.bin"


# ---------------------------------------------------------------------------
# verify_or_raise -- garbled input rejected BEFORE compare
# ---------------------------------------------------------------------------


def test_verify_or_raise_rejects_wrong_length_claim_with_value_error() -> None:
    """A too-short claim raises ValueError, NOT HashMismatchError.

    Distinguishing "the analyzer sent garbage" from "the analyzer sent a
    valid digest that does not match" matters for operator triage: the
    former is an analyzer bug or transport corruption, the latter is a
    potential tamper.
    """
    with pytest.raises(ValueError, match="64-char hex digest"):
        verify_or_raise(_SHORT_BYTES, "deadbeef")


def test_verify_or_raise_rejects_non_hex_claim_with_value_error() -> None:
    """A 64-char string with non-hex characters is not a valid claim."""
    bogus = "z" * 64
    with pytest.raises(ValueError, match="non-hex"):
        verify_or_raise(_SHORT_BYTES, bogus)


# ---------------------------------------------------------------------------
# verify_file_or_raise -- file-based streamed variant used by file_retriever
# ---------------------------------------------------------------------------


def test_verify_file_or_raise_returns_hash_on_match(tmp_path: Path) -> None:
    """Streamed variant on a real file returns the local digest on match."""
    fp = tmp_path / "match.bin"
    fp.write_bytes(_LARGE_BYTES)
    assert verify_file_or_raise(fp, _LARGE_SHA256) == _LARGE_SHA256


def test_verify_file_or_raise_raises_on_mismatch_with_size(tmp_path: Path) -> None:
    """Mismatch on a file also carries the file's stat size in the error.

    ``file_retriever`` logs ``size_bytes`` in the quarantine WARN line so
    the operator can correlate the mismatch to the header's declared
    ``size`` at triage time (a size mismatch alongside a hash mismatch
    is a stronger tamper signal than either alone).
    """
    fp = tmp_path / "mismatch.bin"
    fp.write_bytes(_LARGE_BYTES)
    wrong_claim = "a" * 64
    with pytest.raises(HashMismatchError) as excinfo:
        verify_file_or_raise(fp, wrong_claim, source=str(fp))
    err = excinfo.value
    assert err.computed_sha256 == _LARGE_SHA256
    assert err.claimed_sha256 == wrong_claim
    assert err.size_bytes == len(_LARGE_BYTES)
    assert err.source == str(fp)


def test_verify_file_or_raise_rejects_garbled_claim_before_reading_file(
    tmp_path: Path,
) -> None:
    """A garbled claim short-circuits before any file I/O.

    The claim is validated first; if it is not a well-formed digest the
    function raises without opening the file. Reading a multi-GB
    acquisition just to fail on a claim we already know is invalid is
    wasted work.
    """
    fp = tmp_path / "unused.bin"
    fp.write_bytes(b"never read")
    with pytest.raises(ValueError):
        verify_file_or_raise(fp, "not-a-real-hash")
