"""Roadmap EXTRACTOR check: Flutter Dart-AOT.

Catalogued for traceability but NOT dispatched by the current pipeline.
The Flutter lift (Blutter / reFlutter over libapp.so) is owned by the
android_mcp side and postponed there; the native-library and SBOM checks
that used to live here are now STATIC (see ``_checks_native_sbom.py``),
and the Play data-safety check was dropped.
"""
from __future__ import annotations

from aila.modules.vr.apk_static.models import (
    ApkStaticCheck,
    ApkStaticGroup,
    ApkStaticMode,
)

CHECKS: tuple[ApkStaticCheck, ...] = (
    ApkStaticCheck(
        id="APK-FLUTTER-AOT-ANALYSIS",
        group=ApkStaticGroup.FLUTTER,
        mode=ApkStaticMode.EXTRACTOR,
        title=(
            "Secrets, endpoints, and business logic hidden inside a Dart "
            "AOT snapshot (libapp.so)."
        ),
        description=(
            "A Flutter release build compiles all Dart code to an AOT "
            "snapshot at lib/<abi>/libapp.so, and the jadx tree contains "
            "only the FlutterActivity bootstrap -- no application logic, no "
            "endpoints, no keys. Lifting libapp.so with Blutter or "
            "reFlutter and indexing the recovered Dart sources is owned by "
            "the android_mcp side and postponed there; until that lands, a "
            "Flutter app's Dart logic is not reachable by the static audit "
            "(the STATIC APK-FLUTTER-BUNDLE-DETECT check flags when this "
            "gap applies)."
        ),
        verification_steps=(
            "android_mcp stage (postponed): detect a Flutter build "
            "(flutter_assets/ present, or libflutter.so + libapp.so under "
            "lib/<abi>/) and run Blutter or reFlutter against libapp.so to "
            "lift the Dart AOT snapshot to readable Dart source.",
            "Register the recovered Dart tree as an audit_mcp index under "
            "the same target so semantic_search / search_functions reach it.",
            "Auditor searches the Dart source for hard-coded endpoints, "
            "embedded api keys, jwt secrets, and business-logic checks.",
            "Read the surrounding Dart class to confirm a string is a live "
            "configuration value before reporting it.",
        ),
        relevant_apis=(
            "FlutterActivity", "FlutterEngine", "libapp.so", "libflutter.so",
            "flutter_assets/AssetManifest.json",
        ),
        evidence_hints=(
            "libapp.so", "libflutter.so", "flutter_assets",
            "kDartVmSnapshotData", "kDartIsolateSnapshotData",
        ),
        cwe=("CWE-540", "CWE-798"),
        masvs_refs=(),
    ),
)
