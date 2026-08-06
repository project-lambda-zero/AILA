"""Static software bill of materials for the components bundled in an APK.

Produces a real, evidence-backed component inventory from the parts of an
APK that carry machine-readable provenance, without decompiling or
running anything:

- ``META-INF/*.version`` -- the version marker files Gradle writes for
  each dependency (e.g. ``androidx.core_core.version``), the single most
  reliable static source of dependency-version pairs in a release APK.
- ``META-INF/maven/**/pom.properties`` -- groupId / artifactId / version
  for Maven-packaged dependencies.
- ``META-INF/*.kotlin_module`` -- Kotlin module markers.
- native ``lib/<abi>/*.so`` sonames and version hints, taken from the
  companion native-analysis result so the ELF is parsed once.
- framework fingerprints from asset paths (Flutter, React Native,
  Cordova / Ionic, Unity, Xamarin).

This is not a CycloneDX / SPDX serializer -- it is the inventory an
auditor and a downstream SCA tool reason over. The output feeds the
APK-SBOM check and cross-references the native CVE check.
"""
from __future__ import annotations

import zipfile
from typing import Any

__all__ = [
    "build_sbom",
]

_MAX_COMPONENTS = 200

# Asset-path fingerprints for cross-platform frameworks. First match per
# framework is enough to record it.
_FRAMEWORK_MARKERS: tuple[tuple[str, str], ...] = (
    ("Flutter", "assets/flutter_assets/"),
    ("React Native", "assets/index.android.bundle"),
    ("Cordova/Ionic", "assets/www/"),
    ("Unity", "assets/bin/Data/"),
    ("Xamarin", "assemblies/"),
    ("Kotlin Multiplatform", "META-INF/"),
)


def _parse_version_file(name: str, content: bytes) -> dict[str, Any] | None:
    """A ``META-INF/<coordinate>.version`` marker -> component record."""
    base = name.rsplit("/", 1)[-1]
    if not base.endswith(".version"):
        return None
    coord = base[: -len(".version")]
    text = content.decode("utf-8", "replace").strip()
    ver = text.split("\n", 1)[0].strip()
    if not ver:
        return None
    return {
        "name": coord.replace("_", ":", 1),
        "version": ver,
        "type": "java",
        "source": "META-INF/*.version",
    }


def _parse_pom_properties(content: bytes) -> dict[str, Any] | None:
    """A ``META-INF/maven/**/pom.properties`` -> component record."""
    props: dict[str, str] = {}
    for line in content.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        props[k.strip()] = v.strip()
    group = props.get("groupId", "")
    artifact = props.get("artifactId", "")
    ver = props.get("version", "")
    if not artifact or not ver:
        return None
    coord = f"{group}:{artifact}" if group else artifact
    return {
        "name": coord,
        "version": ver,
        "type": "java",
        "source": "META-INF/maven",
    }


def build_sbom(
    apk_path: str,
    native_analysis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble a static component inventory for one APK.

    ``native_analysis`` is the companion
    :func:`aila.platform.apk.native_analysis.analyze_apk_natives`
    result; when supplied, native sonames and version hints are folded in
    without re-parsing the ELFs. Never raises on a malformed member.
    """
    components: list[dict[str, Any]] = []
    frameworks: set[str] = set()
    seen: set[tuple[str, str]] = set()

    def _add(rec: dict[str, Any] | None) -> None:
        if rec is None:
            return
        key = (rec["name"], rec.get("version", ""))
        if key in seen:
            return
        seen.add(key)
        components.append(rec)

    try:
        with zipfile.ZipFile(apk_path) as zf:
            names = zf.namelist()
            for framework, marker in _FRAMEWORK_MARKERS:
                if framework == "Kotlin Multiplatform":
                    continue  # META-INF is too broad to fingerprint a framework
                if any(n.startswith(marker) or n == marker for n in names):
                    frameworks.add(framework)
            for info in zf.infolist():
                n = info.filename
                if n.endswith(".version") and n.startswith("META-INF/"):
                    _add(_parse_version_file(n, zf.read(info)))
                elif n.startswith("META-INF/maven/") and n.endswith(
                    "pom.properties",
                ):
                    _add(_parse_pom_properties(zf.read(info)))
                elif n.endswith(".kotlin_module") and n.startswith("META-INF/"):
                    mod = n.split("/")[-1][: -len(".kotlin_module")]
                    _add({
                        "name": mod, "version": "", "type": "kotlin-module",
                        "source": "META-INF/*.kotlin_module",
                    })
    except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
        return {
            "component_count": 0,
            "components": [],
            "frameworks": [],
            "truncated": False,
            "error": f"apk_unreadable: {type(exc).__name__}",
        }

    # Fold native libraries in from the companion analysis.
    if native_analysis and native_analysis.get("present"):
        for lib in native_analysis.get("libraries", []):
            if "error" in lib:
                continue
            soname = lib["path"].split("/")[-1]
            hints = lib.get("version_hints") or {}
            if hints:
                for libname, ver in hints.items():
                    _add({
                        "name": libname, "version": ver, "type": "native",
                        "source": lib["path"],
                    })
            else:
                _add({
                    "name": soname, "version": "", "type": "native",
                    "source": lib["path"],
                })

    total = len(components)
    return {
        "component_count": total,
        "components": components[:_MAX_COMPONENTS],
        "frameworks": sorted(frameworks),
        "truncated": total > _MAX_COMPONENTS,
    }
