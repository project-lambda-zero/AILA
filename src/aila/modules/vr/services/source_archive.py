"""Safely extract uploaded source archives into a shared staging volume."""
from __future__ import annotations

import os
import shutil
import stat
import tarfile
import tempfile
import zipfile
import zlib
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import IO

__all__ = [
    "SourceArchiveError",
    "extract_source_archive",
    "is_supported_source_archive",
]

_COPY_CHUNK_BYTES = 1024 * 1024
_TAR_SUFFIXES = (".tar.gz", ".tgz", ".tar")


class SourceArchiveError(ValueError):
    """An uploaded source archive is unsupported, unsafe, or malformed."""


def is_supported_source_archive(file_name: str) -> bool:
    """Return whether ``file_name`` has a supported source archive extension."""
    lower_name = file_name.lower()
    return lower_name.endswith(".zip") or lower_name.endswith(_TAR_SUFFIXES)


def _member_path(member_name: str) -> Path:
    """Return a safe relative output path for a ZIP or tar member name."""
    if not member_name or "\x00" in member_name:
        raise SourceArchiveError("Archive contains an empty or invalid member path.")
    normalized = member_name.replace("\\", "/")
    windows_path = PureWindowsPath(member_name)
    if normalized.startswith("/") or windows_path.is_absolute() or windows_path.drive:
        raise SourceArchiveError(
            f"Archive member {member_name!r} uses an absolute path.",
        )
    posix_path = PurePosixPath(normalized)
    if ".." in posix_path.parts:
        raise SourceArchiveError(
            f"Archive member {member_name!r} contains '..' path traversal.",
        )
    parts = [part for part in posix_path.parts if part not in ("", ".")]
    if not parts:
        # A plain ``.`` or ``./`` tar directory denotes the extraction root.
        return Path()
    return Path(*parts)


def _check_limits(
    member_name: str,
    member_size: int,
    member_count: int,
    total_bytes: int,
    *,
    max_members: int,
    max_uncompressed_bytes: int,
) -> None:
    if member_count > max_members:
        raise SourceArchiveError(
            f"Source archive exceeds the {max_members:,}-member limit.",
        )
    if member_size < 0:
        raise SourceArchiveError(
            f"Archive member {member_name!r} has an invalid negative size.",
        )
    if total_bytes + member_size > max_uncompressed_bytes:
        raise SourceArchiveError(
            "Source archive exceeds the "
            f"{max_uncompressed_bytes:,}-byte uncompressed-size limit.",
        )


def _copy_member(source: IO[bytes], destination: Path, member_size: int) -> None:
    """Write exactly the declared member size without unbounded buffering."""
    remaining = member_size
    with destination.open("wb") as output:
        while remaining:
            chunk = source.read(min(_COPY_CHUNK_BYTES, remaining))
            if not chunk:
                raise SourceArchiveError(
                    f"Archive member {destination.name!r} ended unexpectedly.",
                )
            output.write(chunk)
            remaining -= len(chunk)


def _extract_zip(
    archive_path: Path,
    work_dir: Path,
    *,
    max_members: int,
    max_uncompressed_bytes: int,
) -> None:
    with zipfile.ZipFile(archive_path) as archive:
        total_bytes = 0
        for count, member in enumerate(archive.infolist(), start=1):
            relative_path = _member_path(member.filename)
            mode = (member.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                raise SourceArchiveError(
                    f"Archive member {member.filename!r} is a symlink; links are not allowed.",
                )
            file_type = stat.S_IFMT(mode)
            if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise SourceArchiveError(
                    f"Archive member {member.filename!r} has an unsupported file type.",
                )
            member_size = 0 if member.is_dir() else member.file_size
            _check_limits(
                member.filename,
                member_size,
                count,
                total_bytes,
                max_members=max_members,
                max_uncompressed_bytes=max_uncompressed_bytes,
            )
            total_bytes += member_size

            destination = work_dir / relative_path
            if member.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member, "r") as source:
                _copy_member(source, destination, member.file_size)


def _extract_tar(
    archive_path: Path,
    work_dir: Path,
    *,
    max_members: int,
    max_uncompressed_bytes: int,
) -> None:
    mode = "r:gz" if archive_path.name.lower().endswith((".tar.gz", ".tgz")) else "r"
    with tarfile.open(archive_path, mode=mode) as archive:
        total_bytes = 0
        for count, member in enumerate(archive, start=1):
            relative_path = _member_path(member.name)
            if member.issym() or member.islnk():
                raise SourceArchiveError(
                    f"Archive member {member.name!r} is a symlink or hardlink; "
                    "links are not allowed.",
                )
            if not member.isdir() and not member.isreg():
                raise SourceArchiveError(
                    f"Archive member {member.name!r} has an unsupported file type.",
                )
            member_size = 0 if member.isdir() else member.size
            _check_limits(
                member.name,
                member_size,
                count,
                total_bytes,
                max_members=max_members,
                max_uncompressed_bytes=max_uncompressed_bytes,
            )
            total_bytes += member_size

            destination = work_dir / relative_path
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            source = archive.extractfile(member)
            if source is None:
                raise SourceArchiveError(
                    f"Archive member {member.name!r} has no readable file data.",
                )
            destination.parent.mkdir(parents=True, exist_ok=True)
            with source:
                _copy_member(source, destination, member.size)


def _make_world_readable(root: Path) -> None:
    root.chmod(0o755)
    for dirpath, dirnames, filenames in os.walk(root):
        for dirname in dirnames:
            (Path(dirpath) / dirname).chmod(0o755)
        for filename in filenames:
            (Path(dirpath) / filename).chmod(0o644)


def extract_source_archive(
    archive_path: Path,
    extraction_dir: Path,
    *,
    max_uncompressed_bytes: int,
    max_members: int,
) -> Path:
    """Extract an uploaded archive and return its effective source root.

    Extraction happens in a fresh sibling temporary directory. The requested
    destination is replaced only after every member has passed validation and
    extraction has completed. A single top-level directory is unwrapped.
    """
    archive_path = Path(archive_path)
    extraction_dir = Path(extraction_dir)
    if max_uncompressed_bytes < 1 or max_members < 1:
        raise ValueError("Source archive limits must be positive.")

    if not is_supported_source_archive(archive_path.name):
        raise SourceArchiveError(
            "Source archive must be a .zip, .tar.gz, .tgz, or .tar file.",
        )
    is_zip = archive_path.name.lower().endswith(".zip")
    if extraction_dir.is_symlink():
        raise SourceArchiveError("Source extraction destination must not be a symlink.")
    if extraction_dir.exists() and not extraction_dir.is_dir():
        raise SourceArchiveError("Source extraction destination must be a directory.")

    extraction_dir.parent.mkdir(parents=True, exist_ok=True)
    work_dir = Path(tempfile.mkdtemp(
        prefix=f".{extraction_dir.name}-extract-",
        dir=extraction_dir.parent,
    ))
    try:
        if is_zip:
            _extract_zip(
                archive_path,
                work_dir,
                max_members=max_members,
                max_uncompressed_bytes=max_uncompressed_bytes,
            )
        else:
            _extract_tar(
                archive_path,
                work_dir,
                max_members=max_members,
                max_uncompressed_bytes=max_uncompressed_bytes,
            )
        _make_world_readable(work_dir)

        entries = list(work_dir.iterdir())
        relative_root = (
            Path(entries[0].name)
            if len(entries) == 1 and entries[0].is_dir()
            else Path()
        )
        if extraction_dir.exists():
            shutil.rmtree(extraction_dir)
        work_dir.replace(extraction_dir)
    except SourceArchiveError:
        shutil.rmtree(work_dir, ignore_errors=True)
        raise
    except (
        EOFError,
        NotImplementedError,
        RuntimeError,
        zlib.error,
        zipfile.BadZipFile,
        tarfile.TarError,
    ) as exc:
        shutil.rmtree(work_dir, ignore_errors=True)
        raise SourceArchiveError(f"Failed to extract source archive: {exc}") from exc
    except OSError:
        # Disk or permission failures are server-side; let the caller map them.
        shutil.rmtree(work_dir, ignore_errors=True)
        raise
    return extraction_dir / relative_root
