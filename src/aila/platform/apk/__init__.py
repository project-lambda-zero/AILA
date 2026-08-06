"""Pure, in-repo APK static extractors shared across modules.

These helpers derive an APK static summary from artifacts already on
disk -- apktool's decoded ``AndroidManifest.xml``, the APK signing
block, the bundled native ``.so`` libraries, and a bundled-component
inventory. They shell out to nothing and call no external analysis
service, so any module that ingests an ``android_apk`` target composes
the same summary shape without depending on another module.

Public functions:
    parse_manifest(decoded_dir)      -> manifest facts (package, sdk,
                                        permissions, exported components,
                                        network posture, deep links)
    parse_signing(apk_path)          -> signing scheme + certificates
    analyze_apk_natives(apk_path)    -> native hardening + JNI surface
    build_sbom(apk_path, native)     -> bundled-component inventory
"""

from __future__ import annotations

from aila.platform.apk.apk_manifest import parse_manifest
from aila.platform.apk.apk_signing import parse_signing
from aila.platform.apk.native_analysis import analyze_apk_natives
from aila.platform.apk.sbom import build_sbom

__all__ = [
    "analyze_apk_natives",
    "build_sbom",
    "parse_manifest",
    "parse_signing",
]
