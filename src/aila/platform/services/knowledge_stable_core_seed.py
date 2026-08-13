"""Startup seeder for the ``platform:stable_core:*`` knowledge namespace.

RFC-12 criterion 5 (CAG stable core) shipped a router path, a preload
cache, and a retrieval overlay, but no writer -- so every classified
stable-core query returned an empty list. This module fills that gap by
reading a small, versioned set of policy / rubric / checklist markdown
files under :data:`SEED_DIR` and upserting each into the platform
knowledge store under ``platform:stable_core:<file-stem>``. Re-running
the seeder is idempotent: :meth:`KnowledgeService.store` dedups on the
``(namespace, dedup_key)`` pair (the dedup key is the file stem), so a
second call updates the row in place instead of inserting a duplicate.
The stable-core CAG cache is invalidated after the batch commits so the
next stable-core query pays a fresh SELECT and picks up the seeded rows.

Each seed file MUST open with an HTML comment naming the source
artifact the content was extracted from::

    <!-- source: src/aila/platform/... -->

The seeder rejects a file whose first non-blank line does not match that
shape, so operator-added seeds cannot ship anonymous prose into the
stable core. The comment stays inside the stored content so a retrieval
caller sees the provenance in-band.

Failure posture matches :mod:`aila.platform.automation.seed_schedules`:
a DB / IO / classification fault is logged and swallowed so a bad seed
row cannot abort API startup. The stable-core cache is a strict
optimisation over the hybrid retrieval path; a fault degrades the CAG
to empty, not the whole retrieval subsystem.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING

import sqlalchemy.exc

from . import knowledge as knowledge_mod
from .knowledge import KnowledgeService
from .knowledge_stable_core import STABLE_CORE_NAMESPACE_PREFIX

if TYPE_CHECKING:
    from collections.abc import Iterable

__all__ = [
    "SEED_DIR",
    "SEED_ERRORS",
    "SOURCE_COMMENT_RE",
    "seed_stable_core_knowledge",
]

_log = logging.getLogger(__name__)


# Directory holding the versioned stable-core seed files. Resolved once
# at import time relative to this module so the path survives a working
# directory change (the API worker spawns from its own cwd on Windows).
# ``services/`` is a sibling of ``knowledge/`` under ``platform/``, so
# two ``.parent`` hops land at ``platform/`` and one more descends into
# ``knowledge/stable_core``.
SEED_DIR: Path = Path(__file__).resolve().parent.parent / "knowledge" / "stable_core"


# The first non-blank line of every seed file MUST match this pattern:
# an HTML comment naming the source artifact. The regex is anchored so a
# stray leading ``#`` heading does not accidentally satisfy the contract.
SOURCE_COMMENT_RE: re.Pattern[str] = re.compile(
    r"^\s*<!--\s*source\s*:\s*(?P<source>.+?)\s*-->\s*$",
)


# Isolation tuple for the seeder's failure modes. Mirrors the posture of
# ``seed_default_automation_schedules``: every realistic DB / IO fault is
# captured, logged, and swallowed so a bad row cannot abort API startup.
# Bare ``except Exception`` is banned by honesty audit rule 33.
SEED_ERRORS: tuple[type[BaseException], ...] = (
    sqlalchemy.exc.SQLAlchemyError,
    OSError,
    RuntimeError,
    ValueError,
    TypeError,
    LookupError,
    ConnectionError,
    TimeoutError,
)


def _discover_seed_files(seed_dir: Path) -> list[Path]:
    """Return the sorted ``.md`` seed files under ``seed_dir``.

    Sorted lexically so the write order is deterministic across
    platforms (Windows and Linux disagree on ``Path.iterdir`` order),
    which in turn stabilises test assertions on the seeded set.
    Returns an empty list when the directory is absent or contains no
    markdown files -- a no-op seeder is the documented empty-directory
    behaviour.
    """
    if not seed_dir.is_dir():
        return []
    return sorted(p for p in seed_dir.iterdir() if p.is_file() and p.suffix == ".md")


def _parse_seed_file(path: Path) -> tuple[str, str] | None:
    """Return ``(subkey, content)`` for a valid seed file, else ``None``.

    ``subkey`` is the file stem (used both as the namespace suffix and
    as the store dedup key). ``content`` is the full file text. The
    file is rejected -- and a warning logged -- when its first
    non-blank line is not a ``<!-- source: ... -->`` comment, so an
    operator-added seed cannot ship anonymous prose into the stable
    core.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        _log.warning(
            "stable_core seed unreadable: %s (%s)", path, type(exc).__name__,
        )
        return None
    stripped = text.lstrip()
    first_line = stripped.split("\n", 1)[0] if stripped else ""
    if not SOURCE_COMMENT_RE.match(first_line):
        _log.warning(
            "stable_core seed missing source comment on first line: %s", path,
        )
        return None
    return path.stem, text


async def seed_stable_core_knowledge(
    *,
    seed_dir: Path | None = None,
    service: KnowledgeService | None = None,
) -> int:
    """Upsert every seed file under ``seed_dir`` into the stable core.

    Idempotent: each ``(namespace, dedup_key)`` pair either inserts on
    first run or updates in place on re-run (see
    :meth:`KnowledgeService.store`). Returns the count of files
    actually written (both inserts and updates); an empty ``seed_dir``
    returns 0 without touching the DB.

    ``service`` defaults to a fresh :class:`KnowledgeService` -- the
    optional argument exists so tests can inject a service backed by a
    stub embedding provider (the default provider loads a real model
    which is unnecessary in unit tests).

    A DB / IO / classification fault on any single seed is logged and
    swallowed; the seeder skips that file and moves on so one bad row
    cannot block the rest. On any successfully-committed write the
    process-shared stable-core CAG cache is invalidated so the next
    stable-core query reloads from the DB and picks up the seeded set.
    """
    directory = seed_dir if seed_dir is not None else SEED_DIR
    seed_files: Iterable[Path] = _discover_seed_files(directory)
    seed_files = list(seed_files)
    if not seed_files:
        return 0

    writer = service if service is not None else KnowledgeService()

    written = 0
    for path in seed_files:
        parsed = _parse_seed_file(path)
        if parsed is None:
            continue
        subkey, content = parsed
        namespace = f"{STABLE_CORE_NAMESPACE_PREFIX}{subkey}"
        try:
            await writer.store(
                namespace=namespace,
                content=content,
                dedup_key=subkey,
            )
        except SEED_ERRORS as exc:
            _log.warning(
                "stable_core seed write failed: %s (%s: %s)",
                path, type(exc).__name__, exc,
            )
            continue
        written += 1

    if written:
        # Drop the process-shared CAG cache so the next stable-core
        # query reloads from the DB and picks up the seeded rows.
        knowledge_mod._STABLE_CORE_CACHE.invalidate()
    return written
