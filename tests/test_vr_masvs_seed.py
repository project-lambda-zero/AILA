"""S-2 -- :class:`MasvsSeedBuilder` produces a faithful per-control prompt.

The aggregator at S-4 reads child investigation outcomes verbatim; the
scout that produces those outcomes reads ``initial_question`` verbatim.
This test pins the contract for that string:

1. **Mandatory** (per ``IMPLEMENTATION_PLAN.md`` S-2): every catalogued
   :attr:`MasvsControl.verification_steps` entry appears unmodified in
   the rendered prompt. A silently-dropped step would let the scout
   skip a verification path the aggregator expects to have been
   walked.
2. Control metadata (id, title, description, group, level) round-trip
   through the prompt.
3. Catalogued ``relevant_apis`` and ``evidence_hints`` appear in the
   prompt so the scout can use them as seed queries against the
   audit_mcp index.
4. The APK context (package, version, sha-256, audit_mcp index id,
   decompiled directory, jadx class count) is interpolated correctly
   from the parent :class:`VRTargetSummary`'s ``apk_overview``.
5. Missing or partial ``apk_overview`` payloads degrade to
   ``"<unknown>"`` markers rather than raising -- the dispatcher
   dry-run path passes ``None`` when previewing the prompt.
6. The prompt body is non-trivial for every catalogued control (catch
   silent template-key explosions on rare entries).
"""
from __future__ import annotations

from aila.modules.vr.masvs.catalog import MASVS_CONTROLS
from aila.modules.vr.masvs.models import MasvsControl, MasvsLevel
from aila.modules.vr.masvs.seed import MasvsSeedBuilder

_APK_OVERVIEW = {
    "sha256": (
        "9228be90bf0bc3c4248431d2f2acb96e222a5b85c0a07ff19adf7c1e93de3bc4"
    ),
    "decoded_dir": "/cache/9228be90/decoded",
    "decompiled_dir": "/cache/9228be90/jadx",
    "jadx_root": "/cache/9228be90/jadx/sources",
    "jadx_class_count": 18432,
    "audit_mcp_index_id": "android_apk__9228be90bf0bc3c4",
    "audit_mcp_indexed_at": "2026-06-07T12:00:00Z",
    "static_summary": {
        "package": "com.examplecorp.selfservis",
        "version_name": "19.4.0",
        "version_code": 19040000,
        "permissions": [],
        "native_libs": [],
    },
    "mobsf_scan": {"skipped": True, "reason": "no_api_key"},
}


def _first_l1() -> MasvsControl:
    for c in MASVS_CONTROLS:
        if c.level == MasvsLevel.L1:
            return c
    raise AssertionError(
        "MASVS catalog has no L1 entries -- test_l1_complete (C-2) "
        "should fail before this test runs"
    )


def test_build_includes_every_verification_step_verbatim() -> None:
    """The mandatory invariant from IMPLEMENTATION_PLAN.md S-2.

    Runs across the full catalog (not just one control) so a per-row
    bug -- e.g. a step containing characters the renderer trims -- is
    caught against every entry, not just whichever one happens to be
    first.
    """
    for control in MASVS_CONTROLS:
        prompt = MasvsSeedBuilder.build(control, _APK_OVERVIEW)
        for idx, step in enumerate(control.verification_steps):
            assert step in prompt, (
                f"{control.id}: verification_steps[{idx}] missing from "
                f"prompt; expected verbatim substring not found:\n{step!r}"
            )


def test_build_includes_control_metadata() -> None:
    control = _first_l1()
    prompt = MasvsSeedBuilder.build(control, _APK_OVERVIEW)
    assert control.id in prompt
    assert control.title.strip() in prompt
    assert control.description.strip() in prompt
    assert control.group.value in prompt
    assert control.level.value in prompt


def test_build_includes_evidence_hints_and_relevant_apis() -> None:
    control = _first_l1()
    prompt = MasvsSeedBuilder.build(control, _APK_OVERVIEW)
    for hint in control.evidence_hints:
        assert hint in prompt, f"missing evidence hint: {hint!r}"
    for api in control.relevant_apis:
        assert api in prompt, f"missing relevant api: {api!r}"


def test_build_includes_apk_context() -> None:
    control = _first_l1()
    prompt = MasvsSeedBuilder.build(control, _APK_OVERVIEW)
    assert "com.examplecorp.selfservis" in prompt
    assert "19.4.0" in prompt
    assert "19040000" in prompt
    assert "android_apk__9228be90bf0bc3c4" in prompt
    assert "/cache/9228be90/jadx" in prompt
    assert "18432" in prompt
    # The sha-256 hex is rendered in full; assert on the prefix
    # operators reference in logs to confirm the full value lands.
    assert "9228be90bf0bc3c4" in prompt


def test_build_tolerates_missing_apk_overview() -> None:
    """The dispatcher dry-run path passes ``None`` when previewing."""
    control = _first_l1()
    prompt = MasvsSeedBuilder.build(control, None)
    # Control body still renders.
    assert control.id in prompt
    for step in control.verification_steps:
        assert step in prompt
    # Every apk-context field collapses to the <unknown> sentinel.
    assert "<unknown>" in prompt


def test_build_tolerates_missing_static_summary() -> None:
    """Catch the mid-pipeline case where only the early stages ran."""
    control = _first_l1()
    partial = {
        "sha256": "deadbeefcafebabe",
        "audit_mcp_index_id": "idx-xyz",
        # static_summary / decompiled_dir / jadx_class_count absent.
    }
    prompt = MasvsSeedBuilder.build(control, partial)
    assert "deadbeefcafebabe" in prompt
    assert "idx-xyz" in prompt
    # Package, versionName, versionCode, decompiled tree, class count
    # all fall back to the sentinel.
    assert "<unknown>" in prompt


def test_build_renders_substantial_body_for_every_control() -> None:
    """A silent template-key explosion would leave a one-line prompt.

    The threshold (>=500 chars) is well below every catalogued entry's
    actual rendered size and well above the size of any plausible
    accidental-empty case.
    """
    for control in MASVS_CONTROLS:
        prompt = MasvsSeedBuilder.build(control, _APK_OVERVIEW)
        assert prompt.strip(), f"{control.id}: empty prompt"
        assert len(prompt) >= 500, (
            f"{control.id}: suspiciously short prompt ({len(prompt)} chars)"
        )


def test_build_lists_steps_as_a_numbered_block() -> None:
    """The scout's audit-only system prompt expects ordered steps."""
    control = _first_l1()
    prompt = MasvsSeedBuilder.build(control, _APK_OVERVIEW)
    # Every step is rendered as ``N. <step>`` (1-indexed).
    for idx, step in enumerate(control.verification_steps, start=1):
        assert f"{idx}. {step}" in prompt, (
            f"{control.id}: step {idx} not rendered as a numbered list "
            f"entry; expected substring '{idx}. {step}'"
        )
