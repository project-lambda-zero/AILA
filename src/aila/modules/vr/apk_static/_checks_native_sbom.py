"""STATIC native-library and SBOM checks.

These were the roadmap NATIVE / SBOM entries. The ingestion pipeline now
runs a LIEF pass over every bundled ``lib/<abi>/*.so`` and builds a
static component inventory, both composed into the target's static
summary. The seed builder renders that ``native_analysis`` /
``sbom`` evidence directly into each child prompt, so these checks audit
real extracted facts and dispatch as STATIC.

Deep native dataflow (resolving a memcpy's argument back to a JNI
parameter through disassembly) is out of scope here -- that belongs to a
future native deep-analysis stage. These checks reason over the hardening
posture, symbol/JNI surface, unsafe-primitive presence, and version
fingerprints LIEF can extract without disassembly.
"""
from __future__ import annotations

from aila.modules.vr.apk_static.models import (
    ApkStaticCheck,
    ApkStaticGroup,
    ApkStaticMode,
)

CHECKS: tuple[ApkStaticCheck, ...] = (
    ApkStaticCheck(
        id="APK-NATIVE-HARDENING",
        group=ApkStaticGroup.NATIVE,
        mode=ApkStaticMode.STATIC,
        title=(
            "Bundled native library missing NX / PIE / RELRO / stack canary "
            "/ FORTIFY hardening."
        ),
        description=(
            "A native library shipped without NX, PIE, full RELRO, stack "
            "canaries, or FORTIFY lets a memory-corruption bug reach code "
            "execution far more cheaply than a fully hardened binary. The "
            "ingestion pipeline records each flag per library via LIEF."
        ),
        verification_steps=(
            "Read the Native analysis block in this prompt: it lists every "
            "lib/<abi>/*.so with nx / pie / relro / canary / fortify / "
            "stripped already resolved, plus a 'hardening gaps' summary.",
            "Flag any first-party library missing NX, PIE, full RELRO "
            "(relro != full), a stack canary, or FORTIFY.",
            "Confirm the library is genuinely first-party (not a vendored "
            "dependency the developer cannot rebuild) before treating a "
            "missing flag as a finding; note vendored libraries separately.",
            "If no native libraries are present, this is a clean negative.",
        ),
        relevant_apis=(
            "GNU_STACK", "GNU_RELRO", "DT_BIND_NOW", "__stack_chk_fail",
            "__memcpy_chk",
        ),
        evidence_hints=(
            "native_analysis.hardening_gaps", "relro", "nx", "pie",
            "__stack_chk_fail",
        ),
        cwe=("CWE-693",),
        masvs_refs=(),
    ),
    ApkStaticCheck(
        id="APK-NATIVE-STRIPPED-SYMBOLS",
        group=ApkStaticGroup.NATIVE,
        mode=ApkStaticMode.STATIC,
        title="Debug symbols left in bundled native .so files.",
        description=(
            "An unstripped native library ships function names (and "
            "sometimes build paths) that make reverse engineering trivial "
            "and can leak internal identifiers. The pipeline records a "
            "stripped verdict per library from the presence of a .symtab "
            "section."
        ),
        verification_steps=(
            "Read the Native analysis block: each library carries a "
            "'stripped' boolean derived from whether a .symtab section is "
            "present.",
            "Flag any first-party library reported as stripped=False.",
            "Note whether retained symbols include obviously internal names "
            "(build helpers, class-like prefixes) that raise the "
            "information-disclosure impact.",
            "A release build should ship stripped libraries; a stripped=True "
            "result across all first-party libraries is a clean negative.",
        ),
        relevant_apis=(".symtab", ".strtab", ".debug_info", "SHT_SYMTAB"),
        evidence_hints=("native_analysis", "stripped", ".symtab"),
        cwe=("CWE-215",),
        masvs_refs=(),
    ),
    ApkStaticCheck(
        id="APK-NATIVE-JNI-SURFACE",
        group=ApkStaticGroup.NATIVE,
        mode=ApkStaticMode.STATIC,
        title=(
            "JNI entry points (Java_* exports) crossing untrusted data into "
            "native memory."
        ),
        description=(
            "Every Java_* export and JNIEnv accessor (GetStringUTFChars, "
            "GetByteArrayElements, and similar) is a boundary where managed "
            "data crosses into native code. The pipeline enumerates the JNI "
            "export surface and the JNIEnv accessors each library imports."
        ),
        verification_steps=(
            "Read the Native analysis block: it lists each library's "
            "jni_exports count, sample Java_* export names, and the "
            "jni_env accessors it imports (GetStringUTFChars, "
            "GetByteArrayElements, and similar).",
            "For each library with a JNI surface, correlate the exported "
            "Java_* symbols with their declaring Java class in the jadx "
            "tree via semantic_search / search_functions.",
            "Flag entry points whose Java caller populates the argument "
            "from untrusted input (intent extra, network payload, exported "
            "IPC) as a surface warranting deeper native review.",
            "A library with zero Java_* exports is not a JNI surface; record "
            "the negative.",
        ),
        relevant_apis=(
            "RegisterNatives", "GetStringUTFChars", "GetByteArrayElements",
            "GetDirectBufferAddress", "JNIEnv",
        ),
        evidence_hints=(
            "native_analysis", "jni_exports", "Java_", "GetStringUTFChars",
        ),
        cwe=("CWE-111",),
        masvs_refs=(),
    ),
    ApkStaticCheck(
        id="APK-NATIVE-MEMSAFETY",
        group=ApkStaticGroup.NATIVE,
        mode=ApkStaticMode.STATIC,
        title=(
            "Native library importing unsafe memory primitives alongside a "
            "JNI surface."
        ),
        description=(
            "A native library that imports memcpy / strcpy / strcat / "
            "sprintf / gets and also exposes JNI entry points is a candidate "
            "for out-of-bounds read or write when a JNI-supplied length or "
            "pointer reaches one of those primitives. This is a heuristic "
            "surface signal from the import table -- a confirmed bug needs "
            "the deeper native dataflow analysis a later stage will add."
        ),
        verification_steps=(
            "Read the Native analysis block: each library lists its "
            "unsafe_libc imports (memcpy, strcpy, sprintf, gets, and "
            "similar) and whether it exposes a JNI surface.",
            "Flag libraries that BOTH import an unsafe primitive AND export "
            "Java_* symbols as warranting deeper native review.",
            "Correlate the JNI export with its Java caller and confirm an "
            "untrusted-input-derived length or buffer reaches the boundary "
            "before raising severity above a surface note.",
            "State explicitly that argument-level dataflow was not resolved "
            "(no disassembly); keep the confidence caveated accordingly.",
        ),
        relevant_apis=("memcpy", "strcpy", "sprintf", "GetArrayLength"),
        evidence_hints=(
            "native_analysis", "unsafe_libc_imports", "memcpy", "jni_exports",
        ),
        cwe=("CWE-119", "CWE-787"),
        masvs_refs=(),
    ),
    ApkStaticCheck(
        id="APK-NATIVE-VULN-LIB",
        group=ApkStaticGroup.NATIVE,
        mode=ApkStaticMode.STATIC,
        title=(
            "Bundled native library (openssl / sqlite / ffmpeg / libpng / "
            "webp) at a version with a known CVE."
        ),
        description=(
            "Apps commonly bundle their own openssl / sqlite / ffmpeg / "
            "libpng / libwebp and ship whatever version was current at "
            "build time, inheriting any CVE against that version. The "
            "pipeline fingerprints each library's version from embedded "
            "version strings."
        ),
        verification_steps=(
            "Read the Native analysis block: each library carries "
            "version_hints resolving the vendored library and version "
            "(for example openssl=1.1.1k).",
            "For each resolved (library, version) pair, check known CVEs "
            "against that version using the platform CVE intelligence.",
            "Confirm the vulnerable code path is reachable from the app's "
            "JNI surface, not dead code in an unused plugin, before "
            "treating a CVE match as exploitable.",
            "A library with no resolved version hint is inconclusive, not a "
            "negative; note it for manual fingerprinting.",
        ),
        relevant_apis=(
            "SSLeay_version", "OpenSSL_version", "sqlite3_libversion",
            "av_version_info", "png_get_libpng_ver",
        ),
        evidence_hints=(
            "native_analysis", "version_hints", "OpenSSL", "sqlite3_libversion",
        ),
        cwe=("CWE-1104", "CWE-1035"),
        masvs_refs=("MASVS-CODE-3",),
    ),
    ApkStaticCheck(
        id="APK-SBOM-INVENTORY",
        group=ApkStaticGroup.SBOM,
        mode=ApkStaticMode.STATIC,
        title=(
            "Bundled-component inventory (SBOM) for the APK's dependencies."
        ),
        description=(
            "A meaningful SCA pass needs an inventory of the components the "
            "APK ships. The pipeline builds one statically from Gradle "
            "version markers (META-INF/*.version), Maven pom.properties, "
            "Kotlin module markers, native library sonames + versions, and "
            "framework fingerprints (Flutter, React Native, and similar)."
        ),
        verification_steps=(
            "Read the Component inventory block: it lists each detected "
            "component with type, name, resolved version, and detection "
            "source, plus any cross-platform frameworks in use.",
            "Review the inventory against the component-approval policy and "
            "feed the (name, version) pairs to the platform CVE "
            "intelligence to derive the CVE surface.",
            "Flag components at versions with known CVEs; confirm each is "
            "genuinely bundled (not a stale META-INF leftover) before "
            "treating an SCA hit as a finding.",
            "An empty inventory on an app that clearly bundles dependencies "
            "is a detection gap, not a clean negative -- note it.",
        ),
        relevant_apis=(
            "META-INF/*.version", "META-INF/maven", "pom.properties",
            "lib/<abi>/", "flutter_assets",
        ),
        evidence_hints=(
            "sbom", "component inventory", "META-INF", "pom.properties",
        ),
        cwe=("CWE-1104",),
        masvs_refs=("MASVS-CODE-3",),
    ),
)
