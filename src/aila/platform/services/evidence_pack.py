"""Bounded evidence pack for LLM reasoning turns.

Manages what the LLM sees per reasoning turn with explicit size bounds,
priority-based eviction, and truncation markers. Generic across modules:
forensics may use it for investigation context, VR for crash analysis, etc.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from aila.platform.contracts import utc_now

from .journal import JournalEntry, append

__all__ = ["BoundedEvidencePack", "EvidencePackSealedError", "EvidenceSection"]


class EvidencePackSealedError(RuntimeError):
    """Raised when a sealed evidence pack is mutated (C2 evidence sealing)."""


def _merkle_root(hashes: list[str]) -> str:
    """Merkle root over ordered leaf hashes. Order-sensitive: a reordering or
    any content change alters the root, so a sealed pack is tamper-evident."""
    if not hashes:
        return hashlib.sha256(b"").hexdigest()
    layer = list(hashes)
    while len(layer) > 1:
        nxt: list[str] = []
        for i in range(0, len(layer), 2):
            left = layer[i]
            right = layer[i + 1] if i + 1 < len(layer) else layer[i]
            nxt.append(hashlib.sha256((left + right).encode("utf-8")).hexdigest())
        layer = nxt
    return layer[0]


def _truncate_to(content: str, original_chars: int, target_chars: int) -> str:
    """Truncate ``content`` so the result (with marker) fits in ~target_chars."""
    suffix = f"\n[truncated, {original_chars} chars total]"
    keep = max(0, target_chars - len(suffix))
    return content[:keep] + suffix


class EvidenceSection(BaseModel):
    """One labeled piece of evidence shown to the LLM. ``char_count`` is
    auto-computed from ``content``; any value passed in is overwritten."""

    title: str
    content: str
    source: str
    priority: int = 50
    char_count: int = 0
    truncated: bool = False

    def model_post_init(self, __context: Any) -> None:
        self.char_count = len(self.content)


class BoundedEvidencePack(BaseModel):
    """Bounded collection of evidence sections for one reasoning turn.

    Sections live in priority order (lower number = more important). Bounds:
    per-section ``max_chars_per_section`` truncates incoming content with a
    ``[truncated, N chars total]`` marker; ``max_sections`` evicts the
    lowest-priority existing section iff the new section is strictly higher
    priority; ``max_total_chars`` truncates (or drops) the longest strictly
    lower-priority section to make room. Dropped/evicted titles are recorded
    in ``self.dropped`` so the LLM can be told what is missing."""

    hypothesis: str = ""
    sections: list[EvidenceSection] = Field(default_factory=list)
    max_sections: int = 20
    max_chars_per_section: int = 4000
    max_total_chars: int = 60000
    dropped: list[str] = Field(default_factory=list)
    sealed: bool = False
    sealed_at: datetime | None = None
    seal_digest: str | None = None

    @property
    def total_chars(self) -> int:
        return sum(s.char_count for s in self.sections)

    @property
    def remaining_capacity(self) -> int:
        return max(0, self.max_total_chars - self.total_chars)

    def add(self, section: EvidenceSection) -> bool:
        """Add ``section`` honoring all bounds. Returns False if dropped."""
        if self.sealed:
            raise EvidencePackSealedError("cannot add to a sealed evidence pack")
        candidate = self._cap_section_chars(section)

        if len(self.sections) >= self.max_sections and not self._evict_lowest_below(candidate.priority):
            self.dropped.append(candidate.title)
            return False

        if not self._make_char_room(candidate):
            self.dropped.append(candidate.title)
            return False

        # Insert in priority order; equal priority keeps FIFO (first added wins).
        insert_at = len(self.sections)
        for i, existing in enumerate(self.sections):
            if existing.priority > candidate.priority:
                insert_at = i
                break
        self.sections.insert(insert_at, candidate)
        return True

    def render(self) -> str:
        """Format sections as a single prompt string with a dropped-tag tail."""
        total = len(self.sections)
        blocks: list[str] = []
        for idx, section in enumerate(self.sections, start=1):
            blocks.append(
                f"--- [{idx}/{total}] {section.title} "
                f"(source: {section.source}) ---\n{section.content}"
            )
        rendered = "\n\n".join(blocks)
        if self.dropped:
            tag = f"[{len(self.dropped)} sections excluded: {', '.join(self.dropped)}]"
            rendered = f"{rendered}\n\n{tag}" if rendered else tag
        return rendered

    def _section_hashes(self) -> list[str]:
        """Canonical SHA-256 of each section, in order."""
        return [
            hashlib.sha256(
                json.dumps(
                    {
                        "title": s.title,
                        "content": s.content,
                        "source": s.source,
                        "priority": s.priority,
                        "char_count": s.char_count,
                        "truncated": s.truncated,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                    default=str,
                ).encode("utf-8")
            ).hexdigest()
            for s in self.sections
        ]

    def seal(self) -> str:
        """Freeze the pack against further adds and compute a merkle digest over
        the ordered section hashes. Returns the seal digest."""
        self.seal_digest = _merkle_root(self._section_hashes())
        self.sealed = True
        self.sealed_at = utc_now()
        return self.seal_digest

    def verify(self) -> bool:
        """Return True if the current sections still match ``seal_digest``."""
        if self.seal_digest is None:
            return False
        return _merkle_root(self._section_hashes()) == self.seal_digest

    async def seal_and_journal(
        self,
        session: Any,
        *,
        investigation_id: str | None = None,
        run_id: str | None = None,
        branch_id: str | None = None,
        turn_number: int | None = None,
        team_id: str | None = None,
    ) -> str:
        """Seal the pack and append one ``evidence_added`` journal row per
        section plus a final ``evidence_sealed`` row carrying the digest (C2).

        The section content itself is referenced by ``content_hash``; the row
        stays small. Returns the seal digest.
        """
        section_hashes = self._section_hashes()
        for section, content_hash in zip(self.sections, section_hashes, strict=True):
            await append(
                session,
                entry=JournalEntry(
                    kind="evidence_added",
                    source="platform.evidence_pack",
                    action="evidence.add",
                    payload={
                        "title": section.title,
                        "source": section.source,
                        "priority": section.priority,
                        "char_count": section.char_count,
                        "truncated": section.truncated,
                        "content_hash": content_hash,
                    },
                    investigation_id=investigation_id,
                    run_id=run_id,
                    branch_id=branch_id,
                    turn_number=turn_number,
                ),
                team_id=team_id,
            )
        digest = self.seal()
        await append(
            session,
            entry=JournalEntry(
                kind="evidence_sealed",
                source="platform.evidence_pack",
                action="evidence.seal",
                payload={
                    "section_count": len(self.sections),
                    "dropped_titles": list(self.dropped),
                    "total_chars": self.total_chars,
                    "seal_digest": digest,
                    "section_hashes": section_hashes,
                },
                investigation_id=investigation_id,
                run_id=run_id,
                branch_id=branch_id,
                turn_number=turn_number,
            ),
            team_id=team_id,
        )
        return digest

    def _cap_section_chars(self, section: EvidenceSection) -> EvidenceSection:
        if section.char_count <= self.max_chars_per_section:
            return section
        original = section.char_count
        new_content = _truncate_to(section.content, original, self.max_chars_per_section)
        return EvidenceSection(
            title=section.title,
            content=new_content,
            source=section.source,
            priority=section.priority,
            truncated=True,
        )

    def _evict_lowest_below(self, priority: int) -> bool:
        """Evict the lowest-priority section iff its priority > ``priority``."""
        worst_idx = -1
        worst_priority = priority
        for i, s in enumerate(self.sections):
            if s.priority > worst_priority:
                worst_priority = s.priority
                worst_idx = i
        if worst_idx < 0:
            return False
        victim = self.sections.pop(worst_idx)
        self.dropped.append(victim.title)
        return True

    def _make_char_room(self, candidate: EvidenceSection) -> bool:
        """Truncate or drop low-priority sections until ``candidate`` fits."""
        if candidate.char_count > self.max_total_chars:
            return False
        while self.total_chars + candidate.char_count > self.max_total_chars:
            truncatable = [
                (i, s) for i, s in enumerate(self.sections)
                if s.priority > candidate.priority
            ]
            if not truncatable:
                return False
            idx, victim = max(truncatable, key=lambda pair: pair[1].char_count)
            excess = (self.total_chars + candidate.char_count) - self.max_total_chars
            target = max(0, victim.char_count - excess)
            suffix = f"\n[truncated, {victim.char_count} chars total]"
            if target <= len(suffix) + 32:
                self.sections.pop(idx)
                self.dropped.append(victim.title)
            else:
                victim.content = victim.content[: target - len(suffix)] + suffix
                victim.char_count = len(victim.content)
                victim.truncated = True
        return True
