"""Bounded evidence pack for LLM reasoning turns.

Manages what the LLM sees per reasoning turn with explicit size bounds,
priority-based eviction, and truncation markers. Generic across modules:
forensics may use it for investigation context, VR for crash analysis, etc.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

__all__ = ["BoundedEvidencePack", "EvidenceSection"]


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

    @property
    def total_chars(self) -> int:
        return sum(s.char_count for s in self.sections)

    @property
    def remaining_capacity(self) -> int:
        return max(0, self.max_total_chars - self.total_chars)

    def add(self, section: EvidenceSection) -> bool:
        """Add ``section`` honoring all bounds. Returns False if dropped."""
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
