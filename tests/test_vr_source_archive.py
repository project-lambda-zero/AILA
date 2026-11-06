"""Source-archive extraction for VR source_repo uploads."""

from __future__ import annotations

import io
import stat
import tarfile
import zipfile
from pathlib import Path

import pytest

from aila.modules.vr.services.source_archive import (
    SourceArchiveError,
    extract_source_archive,
    is_supported_source_archive,
)

_LIMITS = {"max_uncompressed_bytes": 1024 * 1024, "max_members": 1000}


def _write_zip(path: Path, members: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return path


def _write_tar_gz(path: Path, members: dict[str, bytes]) -> Path:
    with tarfile.open(path, "w:gz") as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return path


def test_supported_extensions() -> None:
    assert is_supported_source_archive("repo.zip")
    assert is_supported_source_archive("REPO.ZIP")
    assert is_supported_source_archive("repo.tar.gz")
    assert is_supported_source_archive("repo.tgz")
    assert is_supported_source_archive("repo.tar")
    assert not is_supported_source_archive("repo.rar")
    assert not is_supported_source_archive("repo.7z")


def test_zip_with_single_top_level_directory_unwraps_to_it(tmp_path: Path) -> None:
    archive = _write_zip(
        tmp_path / "proj.zip",
        {"proj/src/main.c": b"int main(){}", "proj/README": b"hi"},
    )
    root = extract_source_archive(archive, tmp_path / "out", **_LIMITS)
    assert root == tmp_path / "out" / "proj"
    assert (root / "src" / "main.c").read_bytes() == b"int main(){}"
    assert (root / "README").read_bytes() == b"hi"


def test_zip_with_several_top_level_entries_uses_extraction_root(tmp_path: Path) -> None:
    archive = _write_zip(tmp_path / "a.zip", {"a/x.c": b"x", "b/y.c": b"y"})
    root = extract_source_archive(archive, tmp_path / "out", **_LIMITS)
    assert root == tmp_path / "out"
    assert (root / "a" / "x.c").is_file()
    assert (root / "b" / "y.c").is_file()


def test_tar_gz_extracts(tmp_path: Path) -> None:
    archive = _write_tar_gz(tmp_path / "p.tar.gz", {"p/lib.c": b"lib"})
    root = extract_source_archive(archive, tmp_path / "out", **_LIMITS)
    assert (root / "lib.c").read_bytes() == b"lib"


def test_plain_tar_extracts(tmp_path: Path) -> None:
    archive = tmp_path / "p.tar"
    with tarfile.open(archive, "w") as tar:
        info = tarfile.TarInfo("p/main.rs")
        info.size = 2
        tar.addfile(info, io.BytesIO(b"fn"))
    root = extract_source_archive(archive, tmp_path / "out", **_LIMITS)
    assert (root / "main.rs").read_bytes() == b"fn"


def test_reupload_replaces_previous_extraction(tmp_path: Path) -> None:
    dest = tmp_path / "out"
    first = _write_zip(tmp_path / "one.zip", {"old/stale.c": b"stale"})
    extract_source_archive(first, dest, **_LIMITS)
    second = _write_zip(tmp_path / "two.zip", {"new/fresh.c": b"fresh"})
    root = extract_source_archive(second, dest, **_LIMITS)
    assert (root / "fresh.c").is_file()
    assert not (dest / "old").exists()


def test_rejects_path_traversal(tmp_path: Path) -> None:
    archive = _write_zip(tmp_path / "evil.zip", {"../escape.txt": b"x"})
    dest = tmp_path / "out"
    with pytest.raises(SourceArchiveError, match="path traversal"):
        extract_source_archive(archive, dest, **_LIMITS)
    assert not dest.exists()
    assert not (tmp_path / "escape.txt").exists()


def test_rejects_absolute_member_path(tmp_path: Path) -> None:
    archive = _write_zip(tmp_path / "abs.zip", {"/etc/passwd": b"x"})
    with pytest.raises(SourceArchiveError, match="absolute path"):
        extract_source_archive(archive, tmp_path / "out", **_LIMITS)


def test_rejects_symlink_member(tmp_path: Path) -> None:
    archive = tmp_path / "link.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        info = zipfile.ZipInfo("repo/link")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(info, "/etc/passwd")
    dest = tmp_path / "out"
    with pytest.raises(SourceArchiveError, match="symlink"):
        extract_source_archive(archive, dest, **_LIMITS)
    assert not dest.exists()


def test_rejects_tar_symlink_member(tmp_path: Path) -> None:
    archive = tmp_path / "link.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        info = tarfile.TarInfo("repo/link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tar.addfile(info)
    with pytest.raises(SourceArchiveError, match="symlink or hardlink"):
        extract_source_archive(archive, tmp_path / "out", **_LIMITS)


def test_rejects_member_count_over_limit(tmp_path: Path) -> None:
    archive = _write_zip(tmp_path / "many.zip", {f"r/f{i}": b"x" for i in range(5)})
    with pytest.raises(SourceArchiveError, match="member limit"):
        extract_source_archive(
            archive, tmp_path / "out", max_uncompressed_bytes=1024 * 1024, max_members=3,
        )


def test_rejects_uncompressed_size_over_limit(tmp_path: Path) -> None:
    archive = _write_zip(tmp_path / "big.zip", {"r/big.bin": b"x" * 4096})
    dest = tmp_path / "out"
    with pytest.raises(SourceArchiveError, match="uncompressed-size limit"):
        extract_source_archive(
            archive, dest, max_uncompressed_bytes=1024, max_members=100,
        )
    assert not dest.exists()


def test_rejects_corrupt_zip(tmp_path: Path) -> None:
    archive = tmp_path / "corrupt.zip"
    archive.write_bytes(b"this is not a zip file at all")
    with pytest.raises(SourceArchiveError, match="Failed to extract"):
        extract_source_archive(archive, tmp_path / "out", **_LIMITS)


def test_rejects_unsupported_extension(tmp_path: Path) -> None:
    archive = tmp_path / "repo.rar"
    archive.write_bytes(b"Rar!")
    with pytest.raises(SourceArchiveError, match=r"must be a \.zip, \.tar\.gz"):
        extract_source_archive(archive, tmp_path / "out", **_LIMITS)


def test_rejects_non_positive_limits(tmp_path: Path) -> None:
    archive = _write_zip(tmp_path / "a.zip", {"r/a": b"x"})
    with pytest.raises(ValueError, match="must be positive"):
        extract_source_archive(
            archive, tmp_path / "out", max_uncompressed_bytes=0, max_members=1,
        )
