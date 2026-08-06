"""`ApkStaticSeedBuilder` produces a faithful per-check prompt.

The child investigation's ``initial_question`` is built verbatim from one
:class:`ApkStaticCheck` plus the parent target's ``apk_overview``. These
tests pin the contract the audit persona relies on: every verification
step appears, the check metadata + evidence hints + APIs + CWE/MASVS
mapping are embedded, the APK context cells render, and a missing overview
degrades to ``<unknown>`` rather than crashing.
"""
from __future__ import annotations

from typing import Any

from aila.modules.vr.apk_static.catalog import APK_STATIC_CHECKS
from aila.modules.vr.apk_static.models import ApkStaticCheck, ApkStaticMode
from aila.modules.vr.apk_static.seed import ApkStaticSeedBuilder

_APK_OVERVIEW: dict[str, Any] = {
    "sha256": "9228be90bf0bc3c4248431d2f2acb96e222a5b85",
    "audit_mcp_index_id": "sampleapp@9228be90",
    "jadx_class_count": 1234,
    "static_summary": {
        "package": "com.example.sampleapp",
        "version_name": "3.2.1",
        "version_code": "3210",
    },
}


def _first_static() -> ApkStaticCheck:
    for c in APK_STATIC_CHECKS:
        if c.mode == ApkStaticMode.STATIC:
            return c
    raise AssertionError("catalog has no STATIC checks")


def test_build_includes_every_verification_step_verbatim() -> None:
    for check in APK_STATIC_CHECKS:
        if check.mode != ApkStaticMode.STATIC:
            continue
        prompt = ApkStaticSeedBuilder.build(check, _APK_OVERVIEW)
        for step in check.verification_steps:
            assert step in prompt, (
                f"{check.id}: verification step missing from prompt: "
                f"{step!r}"
            )


def test_build_includes_check_metadata() -> None:
    check = _first_static()
    prompt = ApkStaticSeedBuilder.build(check, _APK_OVERVIEW)
    assert check.id in prompt
    assert check.group.value in prompt
    assert check.title.strip() in prompt


def test_build_includes_evidence_hints_and_apis() -> None:
    check = _first_static()
    prompt = ApkStaticSeedBuilder.build(check, _APK_OVERVIEW)
    for hint in check.evidence_hints:
        assert hint in prompt, f"missing evidence hint: {hint!r}"
    for api in check.relevant_apis:
        assert api in prompt, f"missing relevant api: {api!r}"


def test_build_includes_cwe_and_masvs_refs() -> None:
    # Pick a check that actually carries a CWE + MASVS mapping so the
    # assertion proves the mapping section renders, not just the "(none)"
    # fallback.
    check = next(
        c for c in APK_STATIC_CHECKS
        if c.mode == ApkStaticMode.STATIC and c.cwe and c.masvs_refs
    )
    prompt = ApkStaticSeedBuilder.build(check, _APK_OVERVIEW)
    for w in check.cwe:
        assert w in prompt, f"missing cwe: {w!r}"
    for m in check.masvs_refs:
        assert m in prompt, f"missing masvs ref: {m!r}"


def test_build_includes_apk_context() -> None:
    check = _first_static()
    prompt = ApkStaticSeedBuilder.build(check, _APK_OVERVIEW)
    assert "com.example.sampleapp" in prompt
    assert "3.2.1" in prompt
    assert "sampleapp@9228be90" in prompt
    assert "1234" in prompt
    # sha is truncated to 16 chars in the seed
    assert "9228be90bf0bc3c4" in prompt


def test_build_tolerates_missing_apk_overview() -> None:
    check = _first_static()
    prompt = ApkStaticSeedBuilder.build(check, None)
    assert "<unknown>" in prompt


def test_build_tolerates_missing_static_summary() -> None:
    check = _first_static()
    prompt = ApkStaticSeedBuilder.build(check, {"sha256": "abcd"})
    assert "<unknown>" in prompt


def test_build_lists_steps_as_a_numbered_block() -> None:
    check = _first_static()
    prompt = ApkStaticSeedBuilder.build(check, _APK_OVERVIEW)
    assert "1. " + check.verification_steps[0] in prompt
