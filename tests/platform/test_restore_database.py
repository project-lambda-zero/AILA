"""Behavioral tests for ``restore_database``.

Covers the pg_restore argv construction (``--clean --if-exists --no-owner``
plus a driver-stripped libpq URL), the success return value, the
``UpstreamError`` translation on a non-zero exit, and the
``FileNotFoundError`` guard on a missing dump path.

The pg_restore subprocess is stubbed out via ``monkeypatch.setattr`` on
``subprocess.run`` so the tests do not require a live PostgreSQL server.
"""
from __future__ import annotations

import subprocess

import pytest

from aila.platform.exceptions import UpstreamError
from aila.storage import database as db


class _Settings:
    """Minimal DatabaseSettings-shaped stand-in."""

    database_url = "postgresql+asyncpg://user:pw@localhost:5432/aila"


class _FakeCompletedProcess:
    def __init__(self, returncode: int = 0, stderr: str = "") -> None:
        self.returncode = returncode
        self.stderr = stderr


async def test_restore_database_builds_pg_restore_argv_and_returns_source(
    monkeypatch, tmp_path,
) -> None:
    """Argv includes --clean/--if-exists/--no-owner, the +asyncpg prefix is
    stripped from the URL passed to --dbname, and the source path is echoed
    back on a zero-exit run."""
    recorded: dict[str, object] = {}

    def fake_run(*args, **kwargs):
        recorded["argv"] = args[0]
        return _FakeCompletedProcess(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    source = tmp_path / "aila.dump"
    source.write_bytes(b"pg_dump payload")

    out = await db.restore_database(source=source, settings=_Settings())

    assert out == source
    argv = recorded["argv"]
    assert argv[0] == "pg_restore"
    assert "--clean" in argv
    assert "--if-exists" in argv
    assert "--no-owner" in argv
    # pg_restore receives a libpq URL (no +asyncpg driver prefix).
    assert "--dbname=postgresql://user:pw@localhost:5432/aila" in argv
    # The archive path is the final positional arg.
    assert argv[-1] == str(source)


async def test_restore_database_raises_upstream_error_on_nonzero_returncode(
    monkeypatch, tmp_path,
) -> None:
    """A non-zero pg_restore exit is surfaced as UpstreamError carrying stderr."""
    def fake_run(*args, **kwargs):
        return _FakeCompletedProcess(returncode=1, stderr="pg_restore: role does not exist")

    monkeypatch.setattr(subprocess, "run", fake_run)

    source = tmp_path / "aila.dump"
    source.write_bytes(b"pg_dump payload")

    with pytest.raises(UpstreamError) as excinfo:
        await db.restore_database(source=source, settings=_Settings())
    assert "pg_restore failed" in str(excinfo.value)
    assert "role does not exist" in str(excinfo.value)


async def test_restore_database_raises_file_not_found_for_missing_source(
    tmp_path,
) -> None:
    """A source path that does not exist must fail fast before pg_restore runs."""
    missing = tmp_path / "does-not-exist.dump"
    assert not missing.exists()

    with pytest.raises(FileNotFoundError):
        await db.restore_database(source=missing, settings=_Settings())
