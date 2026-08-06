"""Local hash re-verification helpers (finding 58-2).

Reusable SHA-256 compute + verify helpers used by the forensics
retrieval path (``file_retriever._run_script_and_pull``) to
recompute the hash of file bytes pulled from an analyzer over
SSH/SFTP and compare it to the value the analyzer-side extraction
script reported in its ``##AILA-RETRIEVE##`` header.

Threat model
------------
The forensics threat model treats the analyzer host as untrusted
(see the ``file_retriever`` module docstring). Returning the
header-supplied ``sha256`` verbatim lets a compromised or buggy
analyzer report a value that does not match the bytes actually
delivered -- either to hide tampering, to evade deduplication, or
to plant a chain-of-custody signature that a later auditor cannot
reproduce.

Contract
--------
``verify_or_raise(local_bytes, claimed_sha256)`` recomputes the
SHA-256 over the pulled bytes and returns the locally-computed
hex digest when it matches; on mismatch it raises
:class:`HashMismatchError`. ``verify_file_or_raise(local_path,
claimed_sha256)`` performs the same check with a streamed 1 MB
chunk read so a multi-GB acquisition does not need to sit in
memory. Neither helper touches the DB or the network -- they are
pure compute over bytes / a local file.

Follow-up (not shipped here)
----------------------------
Design section 3.2 proposes an AppendJournal ``retrieval_hash_verified``
event so an auditor can prove after the fact which retrievals were
verified and which mismatched. That path depends on issue #52
(AppendJournal DDL). See ``.run/designs/DESIGN_injection_evidence.md``
issue #58 finding 58-2 for the full write-up. Migration is out of
scope for this module; the compute + fail-closed core lives here
and the caller (``file_retriever``) already emits a WARN log on
mismatch which the operator's run log captures.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from aila.platform.exceptions import AILAError

__all__ = [
    "HashMismatchError",
    "compute_sha256_file",
    "verify_file_or_raise",
    "verify_or_raise",
]


# Stream 1 MB at a time when hashing a file on disk. Bounded memory
# use regardless of acquisition size (a 500 MB forensic pull stays
# within a single chunk-buffer footprint).
_STREAM_CHUNK_BYTES: int = 1024 * 1024


class HashMismatchError(AILAError):
    """Raised when a locally-recomputed SHA-256 does not match a claimed value.

    Carries both the claimed and computed digests on the instance so
    callers can log or re-emit both without re-hashing. Subclass of
    :class:`AILAError` so the API error envelope maps it to 500 by
    default; the retrieval path re-wraps it into ``FileRetrievalError``
    for a caller-facing message that names the quarantine action.
    """

    def __init__(
        self,
        *,
        claimed_sha256: str,
        computed_sha256: str,
        size_bytes: int | None = None,
        source: str | None = None,
    ) -> None:
        self.claimed_sha256 = claimed_sha256.lower()
        self.computed_sha256 = computed_sha256.lower()
        self.size_bytes = size_bytes
        self.source = source
        size_str = f", size={size_bytes}" if size_bytes is not None else ""
        src_str = f" source={source!r}" if source else ""
        super().__init__(
            f"hash mismatch{src_str}: claimed={self.claimed_sha256[:16]}..., "
            f"computed={self.computed_sha256[:16]}...{size_str}"
        )


def _normalize_hex(value: str) -> str:
    """Lowercase and strip whitespace; validate hex-only content.

    Raises :class:`ValueError` when ``value`` is not a valid 64-char
    SHA-256 hex digest. Called from the verify helpers so a garbled
    claim fails at the boundary instead of silently mis-comparing.
    A silent normalization on non-hex input would let a buggy analyzer
    report ``"deadbeef" * 8 + "xx"`` and get a mismatch that looks like
    a genuine tamper flag; explicit ValueError makes the diagnosis
    obvious.
    """
    cleaned = value.strip().lower()
    if len(cleaned) != 64:
        raise ValueError(
            f"claimed_sha256 must be a 64-char hex digest, got length={len(cleaned)}"
        )
    try:
        int(cleaned, 16)
    except ValueError as exc:
        raise ValueError("claimed_sha256 contains non-hex characters") from exc
    return cleaned


def compute_sha256_file(path: Path) -> str:
    """Return the streamed SHA-256 hex digest of the file at ``path``.

    Reads the file in :data:`_STREAM_CHUNK_BYTES` chunks. Bounded memory
    regardless of file size. The caller is responsible for keeping
    ``path`` stable for the duration of the read (a swap between the
    analyzer download and this compute would silently produce a hash
    of the swapped bytes; the whole point of the caller-side
    ``asyncio.to_thread`` wrap is to run this immediately after the
    SFTP pull completes, with no interleaved awaits).
    """
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(_STREAM_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def verify_or_raise(
    local_bytes: bytes,
    claimed_sha256: str,
    *,
    source: str | None = None,
) -> str:
    """Return the locally-computed SHA-256 of ``local_bytes`` on match, else raise.

    ``claimed_sha256`` is the value the untrusted producer (an analyzer
    over SSH, an upload endpoint, an MCP bridge) reported. Comparison
    is case-insensitive; leading/trailing whitespace is stripped. On
    mismatch, :class:`HashMismatchError` is raised carrying both the
    claimed and computed digests plus ``size_bytes`` and optional
    ``source`` for the log/journal path. A malformed ``claimed_sha256``
    (wrong length or non-hex) raises :class:`ValueError` BEFORE the
    compare so callers do not treat a garbled claim as evidence of
    tampering.

    The returned value is the caller's authoritative hash from this
    point on -- the untrusted claim is discarded on the happy path
    just as it is on the fail-closed path. This lets callers do
    ``sha256 = verify_or_raise(...)`` and never handle the header
    value again.
    """
    normalized_claim = _normalize_hex(claimed_sha256)
    computed = hashlib.sha256(local_bytes).hexdigest()
    if computed != normalized_claim:
        raise HashMismatchError(
            claimed_sha256=normalized_claim,
            computed_sha256=computed,
            size_bytes=len(local_bytes),
            source=source,
        )
    return computed


def verify_file_or_raise(
    local_path: Path,
    claimed_sha256: str,
    *,
    source: str | None = None,
) -> str:
    """Return the locally-computed SHA-256 of ``local_path`` on match, else raise.

    Streams the file in 1 MB chunks; a multi-GB forensic pull does not
    consume memory. Same raise contract as :func:`verify_or_raise`.
    """
    normalized_claim = _normalize_hex(claimed_sha256)
    computed = compute_sha256_file(local_path)
    if computed != normalized_claim:
        try:
            size = local_path.stat().st_size
        except OSError:
            size = None
        raise HashMismatchError(
            claimed_sha256=normalized_claim,
            computed_sha256=computed,
            size_bytes=size,
            source=source,
        )
    return computed
