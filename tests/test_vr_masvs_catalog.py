"""C-2 — MASVS catalog completeness invariants.

Single-function test required by ``.run/ralph/apk-masvs/IMPLEMENTATION_PLAN.md``
task C-2: assert the catalog populated by C-1a..C-1i meets the floor the
batch dispatcher (D-1) relies on before fanning out one child VR
investigation per L1 control.

Invariants enforced here:

1. **L1 count floor** — ≥35 entries at :class:`MasvsLevel.L1`. The PRD's
   north star is "one independent VR investigation per OWASP MASVS L1
   control (~40 investigations)"; the 35 floor leaves headroom for
   future spec revisions while still proving the catalog is not empty
   and not half-loaded.
2. **No duplicate ids** — every catalogued control id is unique across
   the full :data:`MASVS_CONTROLS` tuple (not just L1). Duplicates would
   double-dispatch a child investigation and skew the aggregate.
3. **All fields populated** — every control carries non-empty title,
   description, ``verification_steps``, ``relevant_apis``, and
   ``evidence_hints``; the per-row strings inside those tuples are
   themselves non-blank. ``MasvsSeedBuilder`` (S-2) consumes these
   directly into the child ``initial_question``, so a blank row would
   silently degrade the prompt the scout persona receives.
"""
from __future__ import annotations

from collections import Counter

from aila.modules.vr.masvs.catalog import MASVS_CONTROLS
from aila.modules.vr.masvs.models import MasvsControl, MasvsLevel

_L1_FLOOR = 35


def test_l1_complete() -> None:
    l1_controls: tuple[MasvsControl, ...] = tuple(
        c for c in MASVS_CONTROLS if c.level == MasvsLevel.L1
    )

    # Invariant 1 — L1 count floor.
    assert len(l1_controls) >= _L1_FLOOR, (
        f"MASVS_CONTROLS only carries {len(l1_controls)} L1 entries; "
        f"D-1 dispatcher floor is ≥{_L1_FLOOR}. "
        "Check that every C-1b..C-1i group tuple is spliced into "
        "MASVS_CONTROLS at the bottom of catalog.py."
    )

    # Invariant 2 — id uniqueness across the full catalog (not just L1).
    id_counts = Counter(c.id for c in MASVS_CONTROLS)
    duplicates = {cid: n for cid, n in id_counts.items() if n > 1}
    assert not duplicates, (
        f"MASVS catalog has duplicate ids: {duplicates}. "
        "Each id maps 1:1 to a child VR investigation; duplicates would "
        "double-dispatch."
    )

    # Invariant 3 — every field is populated (non-empty tuple, non-blank
    # strings throughout). Iterate per-control and accumulate failures so
    # one run flags every offending row rather than failing on the first.
    field_failures: list[str] = []
    for c in MASVS_CONTROLS:
        if not c.id.strip():
            field_failures.append(f"{c!r}: blank id")
        if not c.title.strip():
            field_failures.append(f"{c.id}: blank title")
        if not c.description.strip():
            field_failures.append(f"{c.id}: blank description")
        if not c.verification_steps:
            field_failures.append(f"{c.id}: empty verification_steps")
        if not c.relevant_apis:
            field_failures.append(f"{c.id}: empty relevant_apis")
        if not c.evidence_hints:
            field_failures.append(f"{c.id}: empty evidence_hints")
        for idx, step in enumerate(c.verification_steps):
            if not step.strip():
                field_failures.append(
                    f"{c.id}: verification_steps[{idx}] is blank"
                )
        for idx, api in enumerate(c.relevant_apis):
            if not api.strip():
                field_failures.append(f"{c.id}: relevant_apis[{idx}] is blank")
        for idx, hint in enumerate(c.evidence_hints):
            if not hint.strip():
                field_failures.append(f"{c.id}: evidence_hints[{idx}] is blank")
    assert not field_failures, (
        "MASVS catalog has unpopulated fields:\n  - "
        + "\n  - ".join(field_failures)
    )
