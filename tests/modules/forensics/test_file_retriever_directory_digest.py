"""Directory retrieval reports the digest of the archive that is pulled.

Both extraction scripts (dissect-backed and raw filesystem) zip a
directory into a temp archive and report a ``sha256`` in their
``##AILA-RETRIEVE##`` header. ``_run_script_and_pull`` re-hashes the
pulled bytes and rejects any mismatch, so the header digest has to cover
the archive bytes. Each case renders the real script, executes it
in-process against a temp tree of synthetic files, and feeds its stdout
and archive through ``_run_script_and_pull`` with the script tool and
SFTP layer replaced by local fakes. ``dissect.target`` is replaced by a
fake whose filesystem is the temp tree.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import shutil
import sys
import types
import zipfile
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from aila.modules.forensics.services.file_retriever import (
    _build_extraction_script,
    _build_raw_extraction_script,
    _run_script_and_pull,
)

_MEMBERS: dict[str, bytes] = {
    "notes.txt": b"plain text evidence\n",
    "nested/blob.bin": bytes(range(256)) * 4,
}


def _make_tree(root: Path) -> Path:
    tree = root / "evidence_dir"
    for rel, data in _MEMBERS.items():
        path = tree / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return tree


def _fake_dissect(fs_root: Path) -> dict[str, types.ModuleType]:
    class _Fs:
        def path(self, candidate: str) -> Path:
            return fs_root / candidate.lstrip("/")

    class _Target:
        fs = _Fs()

        @classmethod
        def open(cls, _image: str) -> _Target:
            return cls()

    pkg = types.ModuleType("dissect")
    mod = types.ModuleType("dissect.target")
    mod.Target = _Target
    pkg.target = mod
    return {"dissect": pkg, "dissect.target": mod}


def _render(kind: str, tmp_path: Path, rel: str) -> tuple[str, dict[str, types.ModuleType]]:
    if kind == "raw":
        script = _build_raw_extraction_script(
            target_path=str(tmp_path / rel), max_bytes=10 * 1024 * 1024, analyzer_os="linux",
        )
        return script, {}
    script = _build_extraction_script(
        disk_image_path="disk.E01", virtual_path=rel,
        max_bytes=10 * 1024 * 1024, analyzer_os="linux",
    )
    return script, _fake_dissect(tmp_path)


def _exec_script(script: str, modules: dict[str, types.ModuleType]) -> str:
    out = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    with patch.dict(sys.modules, modules), contextlib.redirect_stdout(out):
        try:
            exec(compile(script, "<retrieve>", "exec"), {"__name__": "__retrieve__"})
        except SystemExit as exc:
            assert exc.code in (0, None), f"script exited {exc.code}"
    out.flush()
    return out.buffer.getvalue().decode("utf-8")


def _header(stdout: str) -> dict:
    needle = "##AILA-RETRIEVE## "
    return json.loads(stdout[stdout.rfind(needle) + len(needle):].splitlines()[0])


async def _pull(stdout: str) -> tuple[Path, int, str, str]:
    async def _download(_integration, remote, local_path, timeout_seconds=None):
        del _integration, timeout_seconds
        shutil.copyfile(remote, local_path)

    ssh = AsyncMock()
    ssh.download_file = AsyncMock(side_effect=_download)
    ssh.run_command = AsyncMock(return_value="")
    with ExitStack() as stack:
        tool_cls = stack.enter_context(
            patch("aila.modules.forensics.services.file_retriever.ScriptExecutorTool"),
        )
        tool_cls.return_value.forward = AsyncMock(
            return_value={"stdout": stdout, "stderr": "", "exit_code": 0},
        )
        stack.enter_context(patch(
            "aila.modules.forensics.services.file_retriever.get_ssh_service",
            new=AsyncMock(return_value=ssh),
        ))
        stack.enter_context(patch(
            "aila.modules.forensics.services.file_retriever.run_blocking_io",
            new=AsyncMock(side_effect=lambda fn, *a, **kw: fn(*a, **kw)),
        ))
        return await _run_script_and_pull(
            settings=None,
            integration={"host": "analyzer.invalid"},
            analyzer_os="linux",
            script="# rendered above",
            not_found_message="not found",
            max_bytes=10 * 1024 * 1024,
        )


@pytest.mark.parametrize("kind", ["raw", "dissect"])
async def test_directory_pull_verifies_against_archive_digest(kind: str, tmp_path: Path) -> None:
    _make_tree(tmp_path)
    script, modules = _render(kind, tmp_path, "evidence_dir")
    stdout = _exec_script(script, modules)
    header = _header(stdout)
    archive = Path(header["tmp_path"])
    try:
        assert header["kind"] == "dir"
        assert header["file_count"] == len(_MEMBERS)
        assert header["sha256"] == hashlib.sha256(archive.read_bytes()).hexdigest()
        with zipfile.ZipFile(archive) as zf:
            assert {n: zf.read(n) for n in zf.namelist()} == {
                f"evidence_dir/{rel}": data for rel, data in _MEMBERS.items()
            }

        local_path, size, sha256_hex, pulled_kind = await _pull(stdout)
        try:
            assert pulled_kind == "dir"
            assert sha256_hex == header["sha256"]
            assert size == archive.stat().st_size
            assert local_path.read_bytes() == archive.read_bytes()
        finally:
            local_path.unlink(missing_ok=True)
    finally:
        archive.unlink(missing_ok=True)


@pytest.mark.parametrize("kind", ["raw", "dissect"])
async def test_single_file_pull_verifies_against_file_digest(kind: str, tmp_path: Path) -> None:
    _make_tree(tmp_path)
    script, modules = _render(kind, tmp_path, "evidence_dir/notes.txt")
    stdout = _exec_script(script, modules)
    header = _header(stdout)
    staged = Path(header["tmp_path"])
    try:
        assert header["kind"] == "file"
        assert header["sha256"] == hashlib.sha256(_MEMBERS["notes.txt"]).hexdigest()

        local_path, _size, sha256_hex, pulled_kind = await _pull(stdout)
        try:
            assert pulled_kind == "file"
            assert sha256_hex == header["sha256"]
            assert local_path.read_bytes() == _MEMBERS["notes.txt"]
        finally:
            local_path.unlink(missing_ok=True)
    finally:
        staged.unlink(missing_ok=True)
