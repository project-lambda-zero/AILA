"""Integration test for finding 58-2 (`.run/designs/DESIGN_injection_evidence.md` section 3.2).

Contract
--------
``file_retriever._run_script_and_pull`` MUST re-hash the bytes pulled
from the analyzer over SFTP and compare that against the analyzer-side
``sha256`` reported in the extraction script's ``##AILA-RETRIEVE##``
header. On mismatch the local copy is quarantined (unlinked) and a
:class:`FileRetrievalError` is raised carrying the truncated claimed +
computed digests. The forensics threat model treats the analyzer host
as untrusted (see the file_retriever module docstring): a compromised
analyzer that reports a hash matching bytes it never delivered would
otherwise launder a chain-of-custody break through the retriever.

Unit-level `verify_or_raise` / `verify_file_or_raise` coverage lives in
``tests/modules/forensics/test_hash_ledger.py``. This file wires the
retrieval path end-to-end (script tool + SSH SFTP layer both patched)
so the fail-closed guarantee is exercised where it actually protects
the operator, not just at the primitive level.

Mocking strategy
----------------
* ``ScriptExecutorTool`` is patched to return a canned script result
  whose ``##AILA-RETRIEVE##`` header claims a bogus SHA-256 while the
  local temp file the SSH layer drops actually contains different
  bytes with a different digest.
* ``get_ssh_service`` is patched so ``download_file`` writes a known
  payload to the caller-chosen local path (no real SFTP round-trip).
* ``run_command`` (the analyzer-side cleanup after the pull) is
  stubbed to a no-op so the finally-branch does not raise.
* ``run_blocking_io`` is patched to call its function synchronously so
  the streamed re-hash executes inline in the test's event loop.
"""
from __future__ import annotations

import hashlib
import json
import os
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from aila.modules.forensics.services.file_retriever import (
    FileRetrievalError,
    _run_script_and_pull,
)
from aila.modules.forensics.services.hash_ledger import HashMismatchError

_BYTES_ON_DISK: bytes = b"forensic-payload-that-does-not-match-claim"
_REAL_SHA256: str = hashlib.sha256(_BYTES_ON_DISK).hexdigest()
# Deliberately a well-formed 64-char lowercase-hex digest that IS NOT
# _REAL_SHA256. Using a legitimate-looking claim ensures the mismatch
# path (not the "garbled claim" ValueError path) is what raises.
_BOGUS_CLAIM: str = "deadbeef" * 8


def _canned_script_stdout(claim: str, tmp_path_on_analyzer: str, size: int) -> str:
    """Build the ``##AILA-RETRIEVE##`` header a happy script would emit."""
    header = {
        "ok": True,
        "kind": "file",
        "tmp_path": tmp_path_on_analyzer,
        "size": size,
        "sha256": claim,
        "resolved": "/mnt/image/Users/opr/evidence.bin",
    }
    return f"##AILA-RETRIEVE## {json.dumps(header)}\n"


def _make_ssh_mock(local_bytes: bytes) -> AsyncMock:
    """Stub SSH: ``download_file`` writes ``local_bytes`` at the requested path."""
    ssh = AsyncMock()

    async def _download(_integration, _remote, local_path, timeout_seconds=None):
        del _integration, _remote, timeout_seconds
        Path(local_path).write_bytes(local_bytes)
        return None

    ssh.download_file = AsyncMock(side_effect=_download)
    # Cleanup command (rm -f / del /q) on the analyzer -- no-op.
    ssh.run_command = AsyncMock(return_value="")
    return ssh


def _canned_tool_result(claim: str) -> dict:
    """Build the dict shape ScriptExecutorTool.forward returns."""
    return {
        "stdout": _canned_script_stdout(
            claim=claim,
            tmp_path_on_analyzer="/tmp/aila_retrieve_bogus.bin",
            size=len(_BYTES_ON_DISK),
        ),
        "stderr": "",
        "exit_code": 0,
        "script_hash": "deadbeefcafebabe",
        "ok": True,
        "error": None,
    }


def _patch_retriever_deps(ssh: AsyncMock, tool_result: dict):
    """Bundle every patch _run_script_and_pull touches into one context manager stack."""
    stack = ExitStack()
    mock_tool_cls = stack.enter_context(patch(
        "aila.modules.forensics.services.file_retriever.ScriptExecutorTool",
    ))
    stack.enter_context(patch(
        "aila.modules.forensics.services.file_retriever.get_ssh_service",
        new=AsyncMock(return_value=ssh),
    ))
    stack.enter_context(patch(
        "aila.modules.forensics.services.file_retriever.run_blocking_io",
        new=AsyncMock(side_effect=lambda fn, *a, **kw: fn(*a, **kw)),
    ))
    mock_tool_cls.return_value.forward = AsyncMock(return_value=tool_result)
    return stack


async def test_run_script_and_pull_raises_and_quarantines_on_hash_mismatch() -> None:
    """Analyzer-reported hash does not match locally-recomputed hash -> raise.

    The retriever MUST reject the file (not return it) so downstream
    evidence-pack builders and report writers never touch bytes whose
    chain-of-custody was broken between the analyzer script and the
    API host.
    """
    ssh = _make_ssh_mock(local_bytes=_BYTES_ON_DISK)
    tool_result = _canned_tool_result(claim=_BOGUS_CLAIM)

    with _patch_retriever_deps(ssh, tool_result):
        with pytest.raises(FileRetrievalError) as excinfo:
            await _run_script_and_pull(
                settings=None,
                integration={"host": "analyzer", "username": "opr"},
                analyzer_os="linux",
                script="# canned",
                not_found_message="unused",
                max_bytes=1 * 1024 * 1024,
            )

    msg = str(excinfo.value)
    # Both digest fragments appear so the operator log correlates the
    # mismatched pull to a specific tamper attempt.
    assert "hash mismatch" in msg
    assert _BOGUS_CLAIM[:16] in msg
    assert _REAL_SHA256[:16] in msg
    # Cause chain preserves the underlying HashMismatchError from the
    # ledger primitive so an ``except HashMismatchError`` sink still
    # fires without knowing about FileRetrievalError.
    assert isinstance(excinfo.value.__cause__, HashMismatchError)


async def test_run_script_and_pull_quarantines_local_copy_on_mismatch() -> None:
    """On mismatch the retriever unlinks the local temp copy before raising.

    A mismatched acquisition MUST NOT survive on disk: leaving the
    file would let a later code path pick it up thinking the earlier
    call succeeded, or a report writer bundle the bytes into a report
    the operator has no way to know is tainted. The retriever unlinks
    before propagating.
    """
    ssh = _make_ssh_mock(local_bytes=_BYTES_ON_DISK)
    tool_result = _canned_tool_result(claim=_BOGUS_CLAIM)

    captured_local: list[str] = []

    async def _download(_integration, _remote, local_path, timeout_seconds=None):
        del _integration, _remote, timeout_seconds
        Path(local_path).write_bytes(_BYTES_ON_DISK)
        captured_local.append(str(local_path))

    ssh.download_file = AsyncMock(side_effect=_download)

    with _patch_retriever_deps(ssh, tool_result):
        with pytest.raises(FileRetrievalError):
            await _run_script_and_pull(
                settings=None,
                integration={"host": "analyzer", "username": "opr"},
                analyzer_os="linux",
                script="# canned",
                not_found_message="unused",
                max_bytes=1 * 1024 * 1024,
            )

    # The retriever created exactly one local temp file, then unlinked
    # it on the mismatch path before propagating.
    assert len(captured_local) == 1
    assert not os.path.exists(captured_local[0]), (
        f"quarantine leaked: local temp {captured_local[0]!r} still exists"
    )


async def test_run_script_and_pull_returns_hash_on_match() -> None:
    """Happy path -- claim matches local recompute -> returns the local digest.

    Sanity guard against a fix that accidentally makes every pull fail
    closed. The returned sha256 is the LOCAL recomputation (the claim
    is intentionally discarded from the return path so downstream code
    never handles the untrusted value again).
    """
    ssh = _make_ssh_mock(local_bytes=_BYTES_ON_DISK)
    tool_result = _canned_tool_result(claim=_REAL_SHA256)

    with _patch_retriever_deps(ssh, tool_result):
        local_path, size, sha256_hex, kind = await _run_script_and_pull(
            settings=None,
            integration={"host": "analyzer", "username": "opr"},
            analyzer_os="linux",
            script="# canned",
            not_found_message="unused",
            max_bytes=1 * 1024 * 1024,
        )

    try:
        assert sha256_hex == _REAL_SHA256
        assert size == len(_BYTES_ON_DISK)
        assert kind == "file"
        assert local_path.exists()
        assert local_path.read_bytes() == _BYTES_ON_DISK
    finally:
        # Retriever leaves cleanup to the caller on the happy path.
        try:
            local_path.unlink()
        except OSError:
            pass
