"""Idempotent installer for the unified ``.agents/`` layout (issue #5).

Cal.com's cal.diy pattern: ``.agents/`` at the repo root is the canonical,
tool-neutral home for prompts, agents, commands, rules, and skills. Every
supported AI coding harness (Claude Code, OpenCode, Codex, Cursor, Gemini
CLI, Aider, ...) reads its config from a tool-specific hidden directory;
this script wires each of those directories' shared subcategories back to
``.agents/<category>`` via directory links so there is a single source of
truth.

Run any number of times; the script is safe to re-invoke:

    python scripts/setup_agent_links.py            # default tools + categories
    python scripts/setup_agent_links.py --dry-run  # preview only
    python scripts/setup_agent_links.py --tools .claude .codex .opencode
    python scripts/setup_agent_links.py --create-missing-tools

For every ``(tool, category)`` pair it:
    * ensures ``.agents/<category>/`` exists;
    * if ``<tool>/<category>/`` is already the correct link, does nothing;
    * if it exists as a real directory, moves each entry into the canonical
      location -- byte-identical duplicates are silently deduplicated,
      divergent entries are left in place and reported instead of clobbered
      -- then replaces the drained directory with a link;
    * if the path is missing, creates the link directly.

Links are directory junctions on Windows (``mklink /J``) and symlinks on
POSIX (``os.symlink(..., target_is_directory=True)``). Junctions do not
require Administrator privileges; symlinks on POSIX do not either. Nothing
outside the categorised subdirs is touched, so tool-local runtime state
(``.claude/CLAUDE.md``, ``.claude/settings.json``, ``.claude/memory.db*``,
``.codex/config.toml``, ``.codex/hooks.json``, ...) survives untouched.
"""
from __future__ import annotations

import argparse
import filecmp
import os
import shutil
import subprocess
import sys
from pathlib import Path

__all__ = ["main"]

REPO_ROOT = Path(__file__).resolve().parent.parent
CANONICAL = REPO_ROOT / ".agents"
SHARED_CATEGORIES: tuple[str, ...] = ("agents", "commands", "rules", "skills")
DEFAULT_TOOL_DIRS: tuple[str, ...] = (
    ".claude",
    ".codex",
    ".opencode",
    ".cursor",
    ".gemini",
    ".aider",
)


def _is_windows() -> bool:
    return os.name == "nt"


def _is_link(path: Path) -> bool:
    """True for POSIX symlinks and Windows junctions/symlinks."""
    if path.is_symlink():
        return True
    if not _is_windows() or not path.exists():
        return False
    try:
        os.readlink(path)
        return True
    except OSError:
        return False


def _remove_link(link: Path) -> None:
    """Remove a directory link (junction or symlink) portably."""
    try:
        link.unlink()
        return
    except (IsADirectoryError, PermissionError, OSError):
        os.rmdir(link)


def _make_dir_link(link: Path, target: Path, *, dry_run: bool) -> None:
    """Create a directory link at ``link`` pointing at ``target``."""
    if dry_run:
        print(f"    [dry-run] link {link} -> {target}")
        return
    link.parent.mkdir(parents=True, exist_ok=True)
    if _is_windows():
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            check=True,
            stdout=subprocess.DEVNULL,
        )
    else:
        rel = os.path.relpath(target, start=link.parent)
        os.symlink(rel, link, target_is_directory=True)


def _merge_dir(src: Path, dst: Path, *, dry_run: bool) -> list[str]:
    """Move ``src/*`` into ``dst/``; skip byte-identical dupes, report diverges.

    Recursively merges subdirectories. Never overwrites; a genuine conflict
    is appended to the returned list so the caller can decide whether to
    proceed with the link. Empty source subdirs are removed after their
    contents have been drained.
    """
    conflicts: list[str] = []
    dst.mkdir(parents=True, exist_ok=True)
    for entry in sorted(src.iterdir()):
        target = dst / entry.name
        if not target.exists():
            if dry_run:
                print(f"    [dry-run] move {entry} -> {target}")
            else:
                shutil.move(str(entry), str(target))
            continue
        if entry.is_file() and target.is_file():
            if filecmp.cmp(entry, target, shallow=False):
                if not dry_run:
                    entry.unlink()
                continue
            conflicts.append(f"file diverges: {entry} vs {target}")
            continue
        if entry.is_dir() and target.is_dir():
            conflicts.extend(_merge_dir(entry, target, dry_run=dry_run))
            if not dry_run:
                try:
                    entry.rmdir()
                except OSError:
                    pass
            continue
        conflicts.append(f"type mismatch: {entry} vs {target}")
    return conflicts


def _install_category(tool_dir: Path, category: str, *, dry_run: bool) -> str:
    """Wire ``<tool_dir>/<category>`` to ``.agents/<category>``; return status."""
    canonical = CANONICAL / category
    canonical.mkdir(parents=True, exist_ok=True)
    link = tool_dir / category

    if _is_link(link):
        try:
            actual = link.resolve(strict=False)
        except OSError:
            actual = None
        if actual == canonical.resolve():
            return f"ok        {link} -> {canonical}"
        if not dry_run:
            _remove_link(link)
        _make_dir_link(link, canonical, dry_run=dry_run)
        return f"relinked  {link} -> {canonical}"

    if link.exists():
        if not link.is_dir():
            return f"skip      {link} (exists as non-dir; refusing to replace)"
        conflicts = _merge_dir(link, canonical, dry_run=dry_run)
        for msg in conflicts:
            print(f"    conflict: {msg}", file=sys.stderr)
        if conflicts:
            return f"skip      {link} (unresolved conflicts; not linked)"
        if not dry_run:
            try:
                link.rmdir()
            except OSError:
                return f"skip      {link} (dir not empty after merge)"
        _make_dir_link(link, canonical, dry_run=dry_run)
        return f"migrated  {link} -> {canonical}"

    _make_dir_link(link, canonical, dry_run=dry_run)
    return f"created   {link} -> {canonical}"


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Set up the unified .agents/ pattern (issue #5).",
    )
    parser.add_argument(
        "--tools",
        nargs="+",
        default=list(DEFAULT_TOOL_DIRS),
        help="Per-tool hidden dirs to wire (default: %(default)s).",
    )
    parser.add_argument(
        "--categories",
        nargs="+",
        default=list(SHARED_CATEGORIES),
        help="Shared category subdirs (default: %(default)s).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print planned actions without touching the filesystem.",
    )
    parser.add_argument(
        "--create-missing-tools",
        action="store_true",
        help="Create per-tool directories that do not exist yet.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    for category in args.categories:
        canonical = CANONICAL / category
        if not canonical.exists() and not args.dry_run:
            canonical.mkdir(parents=True, exist_ok=True)
    print(f"canonical: {CANONICAL}")
    for tool in args.tools:
        tool_dir = REPO_ROOT / tool
        print(f"tool: {tool_dir}")
        if not tool_dir.exists():
            if not args.create_missing_tools:
                print(f"    skip      (absent; pass --create-missing-tools to opt in)")
                continue
            if not args.dry_run:
                tool_dir.mkdir(parents=True, exist_ok=True)
            print(f"    created   {tool_dir}")
        for category in args.categories:
            print(f"    {_install_category(tool_dir, category, dry_run=args.dry_run)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
