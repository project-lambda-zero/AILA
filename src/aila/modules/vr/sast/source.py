"""Bounded, repository-root-confined source access for the SAST workbench."""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from .contracts import SastDiagnostic, SastSourceFile, SastSourceFileEntry, SastSourceTree
from .diagnostics import normalize_diagnostic_path

__all__ = ["SastSourceService", "SourcePathError", "language_for_path"]

_log = logging.getLogger(__name__)

_MAX_BYTES = 1024 * 1024
_MAX_LINES = 20_000
_MAX_FILES = 10_000
_IGNORED = {".git", "node_modules", "dist", "build", ".venv", "venv", "__pycache__"}
_LANGUAGES = {
    ".c": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".h": "c",
    ".hh": "cpp", ".hpp": "cpp", ".cs": "csharp", ".css": "css",
    ".go": "go", ".graphql": "graphql", ".html": "html", ".java": "java",
    ".js": "javascript", ".jsx": "javascript", ".json": "json",
    ".kt": "kotlin", ".kts": "kotlin", ".lua": "lua", ".md": "markdown",
    ".php": "php", ".py": "python", ".rb": "ruby", ".rs": "rust",
    ".scala": "scala", ".sh": "shell", ".sql": "sql", ".swift": "swift",
    ".toml": "toml", ".ts": "typescript", ".tsx": "typescript",
    ".vue": "html", ".xml": "xml", ".yaml": "yaml", ".yml": "yaml",
}
_FILENAMES = {"dockerfile": "dockerfile", "makefile": "makefile"}


class SourcePathError(ValueError):
    """A requested path is not a safe relative file below the repository root."""


def language_for_path(path: str) -> str:
    candidate = Path(path)
    return _LANGUAGES.get(candidate.suffix.lower()) or _FILENAMES.get(candidate.name.lower()) or "plaintext"


def _local_root(mcp_path: str | None) -> Path | None:
    if not mcp_path:
        return None
    try:
        root = Path(mcp_path).resolve(strict=True)
    except (OSError, RuntimeError):
        _log.debug("SAST repository root %r is not mounted locally; using audit-mcp", mcp_path, exc_info=True)
        return None
    return root if root.is_dir() else None


class SastSourceService:
    def __init__(self, *, mcp_path: str | None, index_id: str | None, bridge: Any = None) -> None:
        self._root = _local_root(mcp_path)
        self._index_id = index_id
        self._bridge = bridge

    def list_files(self, diagnostics: list[SastDiagnostic]) -> SastSourceTree:
        counts: dict[str, int] = {}
        for diagnostic in diagnostics:
            if diagnostic.path:
                counts[diagnostic.path] = counts.get(diagnostic.path, 0) + 1
        paths = set(counts)
        complete = self._root is not None
        if self._root is not None:
            for root, dirs, files in os.walk(self._root, followlinks=False):
                dirs[:] = sorted(
                    name for name in dirs
                    if name not in _IGNORED and not (Path(root) / name).is_symlink()
                )
                for name in sorted(files):
                    candidate = Path(root) / name
                    if candidate.is_symlink():
                        continue
                    try:
                        path = candidate.relative_to(self._root).as_posix()
                    except ValueError:
                        continue
                    paths.add(path)
                    if len(paths) >= _MAX_FILES:
                        complete = False
                        break
                if not complete:
                    break
        return SastSourceTree(
            files=[
                SastSourceFileEntry(
                    path=path,
                    language=language_for_path(path),
                    diagnostic_count=counts.get(path, 0),
                )
                for path in sorted(paths)[:_MAX_FILES]
            ],
            complete=complete,
        )

    async def read_file(self, requested_path: str) -> SastSourceFile:
        path = normalize_diagnostic_path(requested_path)
        if path is None:
            raise SourcePathError("Source path must be a safe repository-relative file path.")
        if self._root is not None:
            return self._read_local(path)
        return await self._read_remote(path)

    def _read_local(self, path: str) -> SastSourceFile:
        if self._root is None:
            raise RuntimeError("local source read requires a resolved repository root")
        try:
            candidate = (self._root / path).resolve(strict=True)
            candidate.relative_to(self._root)
        except (OSError, RuntimeError, ValueError) as exc:
            raise SourcePathError("Source file is not below the indexed repository root.") from exc
        if not candidate.is_file():
            raise SourcePathError("Source path is not a regular file.")
        with candidate.open("rb") as stream:
            raw = stream.read(_MAX_BYTES + 1)
        truncated = len(raw) > _MAX_BYTES
        raw = raw[:_MAX_BYTES]
        text = raw.decode("utf-8", errors="replace")
        lines = text.splitlines(keepends=True)
        total_lines = len(lines)
        if len(lines) > _MAX_LINES:
            lines = lines[:_MAX_LINES]
            truncated = True
        content = "".join(lines)
        return SastSourceFile(
            path=path,
            content=content,
            language=language_for_path(path),
            total_lines=total_lines,
            truncated=truncated,
        )

    async def _read_remote(self, path: str) -> SastSourceFile:
        if not self._index_id or self._bridge is None:
            raise FileNotFoundError("Indexed source is not accessible from the API host.")
        response = await self._bridge.forward(
            action="read_lines", index_id=self._index_id, file_path=path,
            start=1, end=_MAX_LINES,
        )
        if not isinstance(response, dict) or response.get("status") == "error":
            raise FileNotFoundError(f"audit-mcp could not read {path}.")
        nested_data = response.get("data")
        data: dict[str, Any] = nested_data if isinstance(nested_data, dict) else response
        content = data.get("content") or data.get("text") or data.get("pseudocode") or ""
        if not isinstance(content, str):
            raise FileNotFoundError(f"audit-mcp returned no source text for {path}.")
        raw = content.encode("utf-8")
        truncated = len(raw) > _MAX_BYTES
        content = raw[:_MAX_BYTES].decode("utf-8", errors="replace")
        lines = content.splitlines(keepends=True)[:_MAX_LINES]
        total = data.get("total_lines_in_file")
        total_lines = total if isinstance(total, int) and total >= 0 else len(lines)
        truncated = truncated or total_lines > len(lines)
        return SastSourceFile(
            path=path,
            content="".join(lines),
            language=language_for_path(path),
            total_lines=total_lines,
            truncated=truncated,
        )
