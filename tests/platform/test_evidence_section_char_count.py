"""#52 evidence-pack char_count is derived, not writable.

Prior to the fix an evidence section carried a mutable ``char_count``
field. A caller who wanted to slip a 60KB section past the pack's
``max_total_chars`` budget could construct the section, stamp
``char_count = 0`` after ``__init__``, and the pack's budget sum
(``sum(s.char_count for s in sections)``) would think the section
occupied zero space. That was the direct bypass the audit called
out.

char_count is now a Pydantic ``@computed_field`` derived from
``len(content)`` on every access. Assigning to it fails at the
model boundary, and the budget path can't be tricked: the pack
truncates or drops the section as if the caller had never lied.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from aila.platform.services.evidence_pack import (
    BoundedEvidencePack,
    EvidenceSection,
)


def test_char_count_matches_content_length_on_construction() -> None:
    section = EvidenceSection(title="t", content="hello world", source="s")
    assert section.char_count == len("hello world")


def test_char_count_field_is_not_accepted_by_constructor() -> None:
    # Pydantic rejects assignments to a computed field via the constructor.
    # A caller trying to preseed ``char_count`` no longer succeeds.
    with pytest.raises(ValidationError):
        EvidenceSection(
            title="t",
            content="x" * 5000,
            source="s",
            char_count=0,  # type: ignore[call-arg]
        )


def test_char_count_cannot_be_overwritten_after_init() -> None:
    section = EvidenceSection(title="t", content="alpha", source="s")
    # Pydantic raises when a caller tries to assign to a computed field.
    with pytest.raises((AttributeError, ValidationError)):
        section.char_count = 0  # type: ignore[misc]
    # And the derived value stays truthful.
    assert section.char_count == len("alpha")


def test_char_count_follows_content_mutation() -> None:
    # Internal truncation in _make_char_room mutates content directly and
    # relies on char_count re-deriving. Confirm that contract holds.
    section = EvidenceSection(title="t", content="alpha", source="s")
    section.content = "shortened"
    assert section.char_count == len("shortened")


def test_budget_sum_uses_actual_content_length() -> None:
    # This is the audit's residual: a caller stamping char_count=0 to hide
    # a huge section from the ``max_total_chars`` accounting is no longer
    # possible, so the pack's budget check reflects real bytes.
    pack = BoundedEvidencePack(max_total_chars=1000, max_chars_per_section=10_000)
    section = EvidenceSection(title="t", content="x" * 500, source="s")
    # Direct read of the accounting the pack uses.
    assert section.char_count == 500
    added = pack.add(section)
    assert added is True
    assert pack.total_chars == 500


def test_lying_at_construction_is_not_possible() -> None:
    # A hypothetical bypass -- pass char_count=0 to a 5000-char section --
    # is prevented at construction time. Even if it were somehow
    # constructed with a stale value, the budget path sees the real length.
    real_section = EvidenceSection(
        title="fits", content="tiny", source="s", priority=10
    )
    pack = BoundedEvidencePack(
        max_total_chars=50, max_chars_per_section=100
    )
    pack.add(real_section)
    # A big section with the same priority should NOT be admitted intact --
    # _make_char_room needs strictly lower priority victims to truncate,
    # so a same-priority overflow is dropped.
    big = EvidenceSection(
        title="big", content="y" * 400, source="s", priority=10
    )
    assert big.char_count == 400
    admitted = pack.add(big)
    assert admitted is False
    assert "big" in pack.dropped
    assert pack.total_chars == 4  # only the tiny section survives.


def test_computed_field_serializes_in_model_dump() -> None:
    # Downstream code (e.g. _section_hashes JSON canonicalization) relies
    # on char_count appearing in serialization. Confirm computed_field is
    # emitted so section hashes remain deterministic.
    section = EvidenceSection(title="t", content="alpha", source="s")
    dumped = section.model_dump()
    assert dumped.get("char_count") == 5
