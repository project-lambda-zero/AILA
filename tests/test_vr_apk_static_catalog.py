"""APK static-analysis catalog completeness + shape invariants.

Assert the catalog the dispatcher fans out from meets the floor and shape
its consumers rely on:

1. **STATIC count floor** -- the dispatcher fans one child investigation
   per :attr:`ApkStaticMode.STATIC` check; a half-loaded catalog would
   silently under-audit. Floor is set below the shipped count to leave
   headroom for future revisions while still proving the catalog is not
   empty or half-assembled.
2. **No duplicate ids** -- every check id is unique across the full
   catalog. Duplicates would double-dispatch a child and skew results.
3. **All fields populated** -- non-blank id / title / description and a
   non-empty ``verification_steps`` on every check (the seed builder
   consumes these into the child prompt). ``cwe`` entries are shaped
   ``CWE-*`` and ``masvs_refs`` entries ``MASVS-*`` so downstream
   traceability tooling can parse them.
4. **Mode invariant** -- every check is STATIC or EXTRACTOR, and at
   least one EXTRACTOR check is present (the roadmap tier is catalogued,
   not silently dropped).
"""
from __future__ import annotations

from collections import Counter

from aila.modules.vr.apk_static.catalog import APK_STATIC_CHECKS
from aila.modules.vr.apk_static.models import (
    ApkStaticCheck,
    ApkStaticGroup,
    ApkStaticMode,
)

_STATIC_FLOOR = 60


def test_static_count_floor() -> None:
    static_checks: tuple[ApkStaticCheck, ...] = tuple(
        c for c in APK_STATIC_CHECKS if c.mode == ApkStaticMode.STATIC
    )
    assert len(static_checks) >= _STATIC_FLOOR, (
        f"APK_STATIC_CHECKS only carries {len(static_checks)} STATIC "
        f"entries; the dispatcher floor is >={_STATIC_FLOOR}. Check that "
        "every _checks_*.py cluster is spliced into APK_STATIC_CHECKS."
    )


def test_no_duplicate_ids() -> None:
    id_counts = Counter(c.id for c in APK_STATIC_CHECKS)
    duplicates = {cid: n for cid, n in id_counts.items() if n > 1}
    assert not duplicates, (
        f"APK static catalog has duplicate ids: {duplicates}. Each id "
        "maps 1:1 to a child investigation; duplicates double-dispatch."
    )


def test_at_least_one_extractor_check_catalogued() -> None:
    extractor = [
        c for c in APK_STATIC_CHECKS if c.mode == ApkStaticMode.EXTRACTOR
    ]
    assert extractor, (
        "The roadmap (EXTRACTOR) tier must stay catalogued so it is "
        "documented, not silently dropped. Found zero EXTRACTOR checks."
    )


def test_every_field_populated_and_well_shaped() -> None:
    failures: list[str] = []
    for c in APK_STATIC_CHECKS:
        if not c.id.strip():
            failures.append(f"{c!r}: blank id")
        if not c.id.startswith("APK-"):
            failures.append(f"{c.id}: id must start with 'APK-'")
        if not isinstance(c.group, ApkStaticGroup):
            failures.append(f"{c.id}: group is not an ApkStaticGroup")
        if not isinstance(c.mode, ApkStaticMode):
            failures.append(f"{c.id}: mode is not an ApkStaticMode")
        if not c.title.strip():
            failures.append(f"{c.id}: blank title")
        if not c.description.strip():
            failures.append(f"{c.id}: blank description")
        if not c.verification_steps:
            failures.append(f"{c.id}: empty verification_steps")
        for idx, step in enumerate(c.verification_steps):
            if not step.strip():
                failures.append(f"{c.id}: verification_steps[{idx}] blank")
        for w in c.cwe:
            if not w.startswith("CWE-"):
                failures.append(f"{c.id}: malformed cwe {w!r}")
        for m in c.masvs_refs:
            if not m.startswith("MASVS-"):
                failures.append(f"{c.id}: malformed masvs_ref {m!r}")
    assert not failures, (
        "APK static catalog has malformed rows:\n  - "
        + "\n  - ".join(failures)
    )
