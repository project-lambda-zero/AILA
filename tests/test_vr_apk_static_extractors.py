"""Unit tests for the in-repo APK static extractors (manifest, signing, native, SBOM).

Covers the classification logic of the native analyzer (pure over a stub
LIEF binary), the SBOM inventory over a synthetic APK zip, and the
graceful-degradation contract of every extractor on bad input. These
defend the observable contracts the ``static_summary`` composition and
the NATIVE / SBOM checks rely on.
"""
from __future__ import annotations

import zipfile
from pathlib import Path
from types import SimpleNamespace

from aila.platform.apk.native_analysis import (
    analyze_apk_natives,
    classify_binary,
)
from aila.platform.apk.sbom import build_sbom


class _Seg:
    def __init__(self, seg_type: str, flags: int) -> None:
        self.type = seg_type
        self.flags = flags


class _Dyn:
    def __init__(self, tag: str, value: int = 0) -> None:
        self.tag = tag
        self.value = value


class _Sect:
    def __init__(self, name: str) -> None:
        self.name = name


def _stub_binary(
    *,
    imports: list[str],
    exports: list[str],
    segments: list[_Seg],
    dyn: list[_Dyn],
    sections: list[str],
    is_pie: bool,
) -> SimpleNamespace:
    return SimpleNamespace(
        imported_functions=imports,
        exported_functions=exports,
        segments=segments,
        dynamic_entries=dyn,
        sections=[_Sect(n) for n in sections],
        is_pie=is_pie,
        header=SimpleNamespace(machine_type="ARCH.AARCH64"),
    )


def test_classify_hardened_binary() -> None:
    b = _stub_binary(
        imports=["__stack_chk_fail", "__memcpy_chk", "GetStringUTFChars"],
        exports=["Java_com_x_Y_run"],
        segments=[_Seg("SEGMENT_TYPES.GNU_STACK", 0x6), _Seg("SEGMENT_TYPES.GNU_RELRO", 0x4)],
        dyn=[_Dyn("DYNAMIC_TAGS.BIND_NOW")],
        sections=[".text", ".symtab"],
        is_pie=True,
    )
    rec = classify_binary(b, b"OpenSSL 1.1.1k  25 Mar 2021")
    assert rec["nx"] is True          # GNU_STACK without PF_X (0x1)
    assert rec["pie"] is True
    assert rec["relro"] == "full"     # GNU_RELRO + BIND_NOW
    assert rec["stack_canary"] is True
    assert rec["fortify"] is True     # *_chk import
    assert rec["stripped"] is False   # .symtab present
    assert rec["jni_export_count"] == 1
    assert "GetStringUTFChars" in rec["jni_env_calls"]
    assert rec["version_hints"].get("openssl") == "1.1.1k"


def test_classify_unhardened_binary() -> None:
    b = _stub_binary(
        imports=["memcpy", "strcpy", "malloc"],
        exports=["some_internal_fn"],
        segments=[_Seg("SEGMENT_TYPES.GNU_STACK", 0x7)],  # PF_X set -> NX off
        dyn=[],
        sections=[".text"],  # no .symtab -> stripped
        is_pie=False,
    )
    rec = classify_binary(b, b"no version strings here")
    assert rec["nx"] is False
    assert rec["pie"] is False
    assert rec["relro"] == "none"     # no GNU_RELRO segment
    assert rec["stack_canary"] is False
    assert rec["fortify"] is False
    assert rec["stripped"] is True
    assert rec["jni_export_count"] == 0
    assert "memcpy" in rec["unsafe_libc_imports"]
    assert "strcpy" in rec["unsafe_libc_imports"]


def test_classify_partial_relro() -> None:
    b = _stub_binary(
        imports=[],
        exports=[],
        segments=[_Seg("SEGMENT_TYPES.GNU_RELRO", 0x4)],  # relro but no BIND_NOW
        dyn=[_Dyn("DYNAMIC_TAGS.FLAGS", 0x0)],
        sections=[".symtab"],
        is_pie=True,
    )
    rec = classify_binary(b, b"")
    assert rec["relro"] == "partial"


def test_analyze_apk_natives_bad_path() -> None:
    out = analyze_apk_natives("/does/not/exist.apk")
    assert out["present"] is False
    assert out["lib_count"] == 0
    assert "error" in out


def test_build_sbom_inventory(tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("META-INF/androidx.core_core.version", b"1.12.0\n")
        z.writestr(
            "META-INF/maven/com.squareup.okhttp3/okhttp/pom.properties",
            b"groupId=com.squareup.okhttp3\nartifactId=okhttp\nversion=4.9.0\n",
        )
        z.writestr("assets/flutter_assets/AssetManifest.json", b"{}")
    native = {
        "present": True,
        "libraries": [
            {"path": "lib/arm64-v8a/libssl.so",
             "version_hints": {"openssl": "1.1.1k"}},
        ],
    }
    sbom = build_sbom(str(apk), native)
    names = {c["name"]: c for c in sbom["components"]}
    assert "androidx.core:core" in names
    assert names["androidx.core:core"]["version"] == "1.12.0"
    assert "com.squareup.okhttp3:okhttp" in names
    assert names["com.squareup.okhttp3:okhttp"]["version"] == "4.9.0"
    assert "openssl" in names            # folded from native version hints
    assert "Flutter" in sbom["frameworks"]


def test_build_sbom_bad_path() -> None:
    out = build_sbom("/does/not/exist.apk")
    assert out["component_count"] == 0
    assert "error" in out
