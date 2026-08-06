"""KnowledgeIngestor -- content-aware chunker for knowledge-store ingestion (RFC-12).

Splits long inputs on structural boundaries (function/class heads for source,
markdown heading rows for prose) so each chunk lands as its own row in the
knowledge base. Boundary-aligned chunks embed cleanly, keep retrieval
precise, and stop a 20 KB blob from producing a single averaged vector that
dilutes every query it participates in.

The chunker is regex-based (no AST). One code path serves Python, Go, Rust,
Java, Kotlin, C/C++, JavaScript, TypeScript, and similar languages by
matching the shared leading tokens (``def``, ``async def``, ``class``,
``func``, ``fn``, ``function``, and the Java-family access modifiers). Every
method is pure text-in / list-of-strings-out -- no I/O, no DB, no model
calls -- so the chunker is trivially unit-testable and safe to reuse across
threads and workers.

``KnowledgeService.store()`` opts into chunked ingestion via ``chunked=True``
plus a ``kind`` hint; the default (non-chunked) store path is unchanged for
existing callers.
"""

from __future__ import annotations

import re
from typing import Literal

__all__ = [
    "DEFAULT_MAX_CHARS",
    "Kind",
    "KnowledgeIngestor",
]

Kind = Literal["code", "document"]

DEFAULT_MAX_CHARS: int = 2000

# Leading-token boundary for common language declarations. Anchored to line
# start (MULTILINE) so the same keywords appearing mid-expression inside a
# docstring or a longer signature line do not split the source. Trailing
# whitespace after the token keeps the match on genuine declaration heads
# such as `def foo(`, `class Bar:`, `async def baz(`, `func Qux()`, and
# `function make()`.
_CODE_BOUNDARY_RE = re.compile(
    r"^[ \t]*"
    r"(?:async[ \t]+def|def|class|func|fn|function"
    r"|public|private|protected|internal)"
    r"[ \t]+",
    re.MULTILINE,
)

# Markdown heading rows -- one to six ``#`` characters followed by whitespace
# at the start of a line. Matches ATX-style headings (``# H1`` ... ``###### H6``).
_HEADING_RE = re.compile(r"^#{1,6}[ \t]+", re.MULTILINE)


class KnowledgeIngestor:
    """Content-aware chunker for the knowledge-store ingestion path.

    Instances hold no state; a single shared instance is safe to reuse
    across threads and workers. Methods raise ``ValueError`` on
    non-positive ``max_chars`` and on an unknown ``kind`` in :meth:`chunk`.
    """

    def chunk_code(self, text: str, *, max_chars: int = DEFAULT_MAX_CHARS) -> list[str]:
        """Split source text on function/class boundaries, then hard-cap by size.

        Boundaries are recognised by leading-line declaration tokens
        (``def`` / ``class`` / ``async def`` / ``func`` / ``fn`` /
        ``function`` and the Java-family access modifiers). Any single unit
        exceeding ``max_chars`` is hard-split into ``max_chars`` slices so no
        emitted chunk ever violates the ceiling. Empty or whitespace-only
        input yields an empty list.
        """
        if max_chars <= 0:
            raise ValueError("max_chars must be positive")
        if not text or not text.strip():
            return []
        units = self._split_by_regex(text, _CODE_BOUNDARY_RE)
        return self._pack_units(units, max_chars=max_chars)

    def chunk_document(self, text: str, *, max_chars: int = DEFAULT_MAX_CHARS) -> list[str]:
        """Split markdown text on heading rows, then hard-cap by size.

        Any heading level (``#`` through ``######``) starts a new unit; any
        content preceding the first heading is emitted as its own leading
        unit. Oversize units are hard-split into ``max_chars`` slices so no
        emitted chunk exceeds the ceiling.
        """
        if max_chars <= 0:
            raise ValueError("max_chars must be positive")
        if not text or not text.strip():
            return []
        units = self._split_by_regex(text, _HEADING_RE)
        return self._pack_units(units, max_chars=max_chars)

    def chunk(
        self,
        text: str,
        *,
        kind: Kind,
        max_chars: int = DEFAULT_MAX_CHARS,
    ) -> list[str]:
        """Dispatch to :meth:`chunk_code` or :meth:`chunk_document` by ``kind``.

        Raises ``ValueError`` when ``kind`` is neither ``"code"`` nor
        ``"document"``. ``max_chars`` flows through unchanged.
        """
        if kind == "code":
            return self.chunk_code(text, max_chars=max_chars)
        if kind == "document":
            return self.chunk_document(text, max_chars=max_chars)
        raise ValueError(
            f"unknown kind: {kind!r}; expected 'code' or 'document'",
        )

    @staticmethod
    def _split_by_regex(text: str, pattern: re.Pattern[str]) -> list[str]:
        """Return ``text`` split on boundaries matched by ``pattern``.

        Each match starts a new unit; content before the first match is
        emitted as its own leading unit (dropped when empty/whitespace).
        The matched line stays as the first line of its unit so the
        declaration head or heading row travels with its body.
        """
        boundaries = [m.start() for m in pattern.finditer(text)]
        if not boundaries:
            return [text]
        units: list[str] = []
        prev = 0
        for start in boundaries:
            if start > prev:
                head = text[prev:start]
                if head.strip():
                    units.append(head)
            prev = start
        tail = text[prev:]
        if tail.strip():
            units.append(tail)
        return units

    @staticmethod
    def _pack_units(units: list[str], *, max_chars: int) -> list[str]:
        """Emit each unit as a chunk; hard-split any unit exceeding ``max_chars``.

        Units are NOT combined -- boundary alignment is the whole point of
        the chunker, so packing multiple small units into a single bigger
        chunk would smear boundaries. Sub-cap units flow through untouched;
        leading and trailing newlines are trimmed so the emitted chunk
        starts on the declaration head or heading row.
        """
        chunks: list[str] = []
        for unit in units:
            stripped = unit.strip("\r\n")
            if not stripped:
                continue
            if len(stripped) <= max_chars:
                chunks.append(stripped)
                continue
            for start in range(0, len(stripped), max_chars):
                slice_text = stripped[start : start + max_chars]
                if slice_text.strip():
                    chunks.append(slice_text)
        return chunks
