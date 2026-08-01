"""Retention-sweep tests for on-disk report artifacts (report_store.py).

``purge_expired_report_files`` walks the top-level of ``settings.report_dir``
and unlinks every regular file whose mtime is older than the retention
cutoff. These tests seed a tmp report dir with two files at different
mtimes, monkeypatch ``aila.config.get_settings`` so the purge points at
the tmp dir instead of the real ``reports/`` under the project root, and
assert only the aged file is removed.

Contract defended (matches acceptance criteria):
- old-only deletion: file with mtime strictly older than cutoff is
  removed; recent file with mtime after cutoff is kept.
- return value equals the count actually unlinked.
- empty / missing directory returns 0 without raising.
- retention_days=0 sweeps everything (cutoff = now).

No DB fixture is used -- the sweep is pure filesystem.
"""
from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from aila.storage.report_store import purge_expired_report_files


def _touch(path: Path, mtime_epoch: float) -> None:
    """Create ``path`` (empty file) and set its mtime to ``mtime_epoch``."""
    path.write_bytes(b"")
    os.utime(path, (mtime_epoch, mtime_epoch))


@pytest.fixture
def report_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point ``aila.config.get_settings`` at a tmp report_dir.

    ``purge_expired_report_files`` reads ``get_settings().report_dir`` via
    a local import. Replacing the callable with one that returns a
    ``SimpleNamespace(report_dir=tmp_path)`` avoids constructing a real
    ``Settings`` (which would resolve AILA_DATABASE_URL and other env
    vars the filesystem test doesn't care about).
    """
    fake = SimpleNamespace(report_dir=tmp_path)
    monkeypatch.setattr("aila.config.get_settings", lambda: fake)
    return tmp_path


async def test_purge_deletes_only_files_older_than_cutoff(report_dir: Path) -> None:
    """A file older than ``retention_days`` is unlinked; a fresh one is kept."""
    import time

    now = time.time()
    old = report_dir / "run-old.csv"
    fresh = report_dir / "run-fresh.csv"
    _touch(old, now - (100 * 86400))       # 100 days old -- past the 90d default
    _touch(fresh, now - (10 * 86400))       # 10 days old -- inside the window

    deleted = await purge_expired_report_files()

    assert deleted == 1
    assert not old.exists()
    assert fresh.exists()


async def test_purge_return_matches_deleted_count(report_dir: Path) -> None:
    """Return value equals the exact number of files removed."""
    import time

    now = time.time()
    for i in range(4):
        _touch(report_dir / f"aged-{i}.csv", now - (200 * 86400))
    for i in range(2):
        _touch(report_dir / f"recent-{i}.summary.json", now - (5 * 86400))

    deleted = await purge_expired_report_files()

    assert deleted == 4
    remaining = sorted(p.name for p in report_dir.iterdir())
    assert remaining == ["recent-0.summary.json", "recent-1.summary.json"]


async def test_purge_missing_report_dir_returns_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Directory absent from disk -> 0 return, no raise."""
    missing = tmp_path / "does-not-exist"
    fake = SimpleNamespace(report_dir=missing)
    monkeypatch.setattr("aila.config.get_settings", lambda: fake)

    deleted = await purge_expired_report_files()

    assert deleted == 0


async def test_purge_custom_retention_window_zero_sweeps_everything(
    report_dir: Path,
) -> None:
    """``retention_days=0`` sets the cutoff at now, sweeping every file
    (mtimes are strictly less than the cutoff since mkdir + touch
    happen before the call).
    """
    import time

    now = time.time()
    for i in range(3):
        _touch(report_dir / f"any-{i}.csv", now - 60)  # 1 minute old

    deleted = await purge_expired_report_files(retention_days=0)

    assert deleted == 3
    assert list(report_dir.iterdir()) == []


async def test_purge_leaves_subdirectories_alone(report_dir: Path) -> None:
    """Subdirectories are operator-owned; the shallow walk skips them
    even when older than the cutoff (``is_file()`` returns False on
    directories).
    """
    import time

    now = time.time()
    subdir = report_dir / "operator-owned"
    subdir.mkdir()
    os.utime(subdir, (now - (200 * 86400), now - (200 * 86400)))
    _touch(report_dir / "top-level-old.csv", now - (200 * 86400))

    deleted = await purge_expired_report_files()

    assert deleted == 1
    assert subdir.exists() and subdir.is_dir()


async def test_purge_empty_directory_returns_zero(report_dir: Path) -> None:
    """No files -> 0 return, no side effect."""
    deleted = await purge_expired_report_files()

    assert deleted == 0
    assert list(report_dir.iterdir()) == []
