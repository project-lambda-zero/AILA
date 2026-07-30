"""Roadmap EXTRACTOR checks: NATIVE, FLUTTER, SBOM, PRIVACY (Play listing).

These checks are catalogued for traceability but NOT dispatched by the
current APK static pipeline. Each entry names the extractor stage that
must be built before the check can be answered.
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
        mode=ApkStaticMode.EXTRACTOR,
        title=(
            "Bundled native library missing NX / PIE / RELRO / stack canary "
            "/ FORTIFY_SOURCE hardening."
        ),
        description=(
            "An ELF shipped without NX, PIE, full RELRO, stack canaries, or "
            "FORTIFY_SOURCE lets any memory-corruption bug reach code "
            "execution far more cheaply than a fully hardened binary. "
            "Requires a native-hardening extractor stage that enumerates "
            "every lib/*/*.so in the APK and runs checksec (or the "
            "equivalent readelf / ida-headless probe) against each file, "
            "recording the state of each hardening flag."
        ),
        verification_steps=(
            "Extractor stage: enumerate lib/<abi>/*.so for every ABI in the "
            "APK and feed each ELF to checksec (or the equivalent readelf / "
            "ida-headless probe).",
            "Persist a per-library record of {NX, PIE, RELRO, stack canary, "
            "FORTIFY_SOURCE, Fortifiable count / Fortified count} keyed by "
            "(abi, library).",
            "Auditor reviews the resulting table and flags any first-party "
            "library missing NX, PIE, full RELRO, stack canaries, or "
            "FORTIFY_SOURCE.",
            "Confirm the library is genuinely bundled by this app (not a "
            "vendored dependency the operator cannot rebuild) before "
            "treating a missing flag as a finding.",
        ),
        relevant_apis=(
            "GNU_STACK",
            "GNU_RELRO",
            "DT_BIND_NOW",
            "__stack_chk_fail",
            "__memcpy_chk",
        ),
        evidence_hints=(
            "checksec",
            "readelf -d",
            "GNU_STACK",
            "__stack_chk_fail",
            "_chk",
        ),
        cwe=("CWE-693",),
        masvs_refs=(),
    ),
    ApkStaticCheck(
        id="APK-NATIVE-STRIPPED-SYMBOLS",
        group=ApkStaticGroup.NATIVE,
        mode=ApkStaticMode.EXTRACTOR,
        title="Debug symbols left in bundled native .so files.",
        description=(
            "Unstripped native libraries ship function names, build paths, "
            "and sometimes DWARF debug sections that make reverse "
            "engineering trivial and can leak internal directory layout "
            "and developer identifiers. Requires a native-symbols extractor "
            "stage that runs readelf / nm against each bundled .so and "
            "records the presence of .symtab / .debug_* sections."
        ),
        verification_steps=(
            "Extractor stage: iterate lib/<abi>/*.so and capture, per file, "
            "the presence and size of .symtab, .strtab, and any .debug_* "
            "sections plus a sample of retained symbol names.",
            "Persist the report keyed by (abi, library) with a boolean "
            "'stripped' verdict and the list of retained debug sections.",
            "Auditor reviews the report and flags first-party libraries "
            "that retain .symtab or any .debug_* section.",
            "Inspect the retained strings for absolute build paths or "
            "internal usernames before treating the finding as an "
            "information-disclosure issue.",
        ),
        relevant_apis=(
            ".symtab",
            ".strtab",
            ".debug_info",
            ".debug_line",
            "SHT_SYMTAB",
        ),
        evidence_hints=(
            "readelf -S",
            "nm -D",
            ".debug_info",
            ".symtab",
            "not stripped",
        ),
        cwe=("CWE-215",),
        masvs_refs=(),
    ),
    ApkStaticCheck(
        id="APK-NATIVE-JNI-SURFACE",
        group=ApkStaticGroup.NATIVE,
        mode=ApkStaticMode.EXTRACTOR,
        title=(
            "JNI entry points (RegisterNatives / Java_* exports) accepting "
            "untrusted arguments."
        ),
        description=(
            "Every RegisterNatives table entry and every Java_* export is a "
            "boundary where managed data (String, byte[], int lengths) "
            "crosses into native memory. Requires a JNI-surface extractor "
            "stage that runs ida-headless against each bundled .so, "
            "resolves the JNI export table, and produces a "
            "(java signature -> native symbol -> xrefs) index that an "
            "auditor can walk to review each entry."
        ),
        verification_steps=(
            "Extractor stage: run ida-headless per bundled .so, enumerate "
            "Java_* symbol exports and RegisterNatives / "
            "jniRegisterNativeMethods call sites, and resolve each entry "
            "into (java class, java method, native symbol, argument "
            "signature).",
            "Attach a callgraph slice per entry so the auditor can see the "
            "first ~3 levels of native code reached from the JNI border.",
            "Auditor reviews entries whose signature accepts String, "
            "byte[], ByteBuffer, or an int length paired with a pointer, "
            "and correlates each with its calling Java class in the jadx "
            "tree.",
            "Confirm that a Java caller populates the argument from "
            "untrusted input (intent extra, network payload, exported IPC) "
            "before treating the entry as a live sink.",
        ),
        relevant_apis=(
            "RegisterNatives",
            "jniRegisterNativeMethods",
            "GetStringUTFChars",
            "GetByteArrayElements",
            "GetDirectBufferAddress",
        ),
        evidence_hints=(
            "RegisterNatives",
            "Java_",
            "JNIEnv",
            "GetStringUTFChars",
            "GetByteArrayElements",
        ),
        cwe=("CWE-111",),
        masvs_refs=(),
    ),
    ApkStaticCheck(
        id="APK-NATIVE-MEMSAFETY",
        group=ApkStaticGroup.NATIVE,
        mode=ApkStaticMode.EXTRACTOR,
        title=(
            "Native memory-safety hotspots: unchecked memcpy / strcpy / "
            "length arithmetic on JNI inputs."
        ),
        description=(
            "Native code invoked across the JNI boundary that copies a "
            "caller-supplied length or pointer through memcpy, strcpy, "
            "strcat, sprintf, gets, or memmove is a candidate for "
            "out-of-bounds read or write. Requires a native memory-safety "
            "extractor stage that runs ida-headless per bundled .so, walks "
            "the callgraph from each JNI export to unsafe libc sinks, and "
            "tags paths where length arithmetic is derived from a JNI "
            "argument."
        ),
        verification_steps=(
            "Extractor stage: per bundled .so, enumerate JNI entry symbols "
            "and walk the callgraph forward to memcpy / memmove / strcpy / "
            "strncpy / strcat / sprintf / snprintf / gets call sites.",
            "For each reached sink, record the argument-flow slice that "
            "shows whether the destination pointer, source pointer, or "
            "length integer traces back to a JNI parameter (or to an "
            "arithmetic expression combining JNI-derived values).",
            "Auditor reads each tagged slice and confirms the sink is "
            "reachable from an exported JNI symbol with input-derived "
            "length or pointer, not from a purely internal helper.",
            "Cross-reference the corresponding Java caller and verify the "
            "argument originates from untrusted input before reporting.",
        ),
        relevant_apis=(
            "memcpy",
            "strcpy",
            "strncpy",
            "sprintf",
            "GetArrayLength",
        ),
        evidence_hints=(
            "memcpy",
            "strcpy",
            "sprintf",
            "GetArrayLength",
            "GetStringUTFLength",
        ),
        cwe=("CWE-119", "CWE-787"),
        masvs_refs=(),
    ),
    ApkStaticCheck(
        id="APK-NATIVE-VULN-LIB",
        group=ApkStaticGroup.NATIVE,
        mode=ApkStaticMode.EXTRACTOR,
        title=(
            "Bundled native library (openssl / sqlite / ffmpeg / libpng / "
            "webp) at a version with a known CVE."
        ),
        description=(
            "Android apps commonly bundle their own copies of openssl, "
            "sqlite, ffmpeg, libpng, and libwebp and ship whatever version "
            "was current at build time, so any CVE published against that "
            "version is inherited by the app. Requires a native-lib-version "
            "extractor stage that fingerprints each bundled .so (symbol "
            "table, embedded version strings, ida-headless heuristics), "
            "resolves the vendored library and version, and cross-"
            "references NVD / OSV for open CVEs against that pair."
        ),
        verification_steps=(
            "Extractor stage: enumerate lib/<abi>/*.so and, per file, "
            "fingerprint the vendored library and version using symbol "
            "tables plus embedded version strings (SSLeay_version, "
            "OpenSSL_version, sqlite3_libversion, av_version_info, "
            "png_get_libpng_ver, WebPGetInfo).",
            "Query NVD / OSV for CVEs affecting the resolved (library, "
            "version) pair and persist the CVE list alongside the "
            "fingerprint.",
            "Auditor reviews each CVE match and confirms the vulnerable "
            "code path is reachable from the app's JNI surface (not dead "
            "code inside a plugin the app never invokes).",
            "Correlate with the app's cryptography, media-decoding, and "
            "database call sites in the jadx tree before treating a CVE "
            "match as an exploitable finding.",
        ),
        relevant_apis=(
            "SSLeay_version",
            "OpenSSL_version",
            "sqlite3_libversion",
            "av_version_info",
            "png_get_libpng_ver",
        ),
        evidence_hints=(
            "OpenSSL",
            "sqlite3_libversion",
            "libavcodec",
            "libpng version",
            "WebPGetInfo",
        ),
        cwe=("CWE-1104", "CWE-1035"),
        masvs_refs=(),
    ),
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
            "only the FlutterActivity bootstrap -- no application logic, "
            "no endpoints, no keys. Requires a Flutter-AOT extractor stage "
            "that lifts libapp.so with Blutter or reFlutter, indexes the "
            "recovered Dart sources into an audit_mcp index, and exposes "
            "them to semantic_search / search_functions like any other "
            "tree."
        ),
        verification_steps=(
            "Extractor stage: detect a Flutter build (flutter_assets/ "
            "present, or libflutter.so + libapp.so under lib/<abi>/) and "
            "run Blutter or reFlutter against libapp.so to lift the Dart "
            "AOT snapshot back to readable Dart source.",
            "Register the recovered Dart tree as a new audit_mcp index "
            "under the same target so semantic_search / search_functions "
            "reach it.",
            "Auditor runs semantic_search across the Dart source for "
            "hard-coded HTTP endpoints, embedded api keys, jwt secrets, "
            "and business-logic checks (license verification, receipt "
            "validation, feature flags).",
            "Read the surrounding Dart class with read_function / "
            "read_lines to confirm the string is a live configuration "
            "value before reporting it as a secret.",
        ),
        relevant_apis=(
            "FlutterActivity",
            "FlutterEngine",
            "libapp.so",
            "libflutter.so",
            "flutter_assets/AssetManifest.json",
        ),
        evidence_hints=(
            "libapp.so",
            "libflutter.so",
            "flutter_assets",
            "kDartVmSnapshotData",
            "kDartIsolateSnapshotData",
        ),
        cwe=("CWE-540", "CWE-798"),
        masvs_refs=(),
    ),
    ApkStaticCheck(
        id="APK-SBOM-FULL",
        group=ApkStaticGroup.SBOM,
        mode=ApkStaticMode.EXTRACTOR,
        title=(
            "Full software bill of materials for every bundled component "
            "in the APK."
        ),
        description=(
            "A meaningful SCA pass needs a machine-readable inventory of "
            "every component the APK ships: Java / Kotlin packages, "
            "native libraries, the Flutter engine, embedded JS bundles, "
            "resource-shipped binaries, and Service Provider Interface "
            "entries. Requires a full-SBOM extractor stage that walks the "
            "APK, resolves each detected component and version, and "
            "produces a CycloneDX 1.5 (or SPDX 2.3) document keyed by "
            "purl / cpe."
        ),
        verification_steps=(
            "Extractor stage: traverse classes*.dex (top-level Java / "
            "Kotlin package roots and their manifests), lib/<abi>/*.so "
            "(native library fingerprints and versions), assets/ (bundled "
            "JS bundles, Flutter engine, embedded firmware, third-party "
            "assets), META-INF/ (build metadata, gradle / maven "
            "coordinates), and META-INF/services/ (SPI providers).",
            "Assemble a CycloneDX 1.5 SBOM keyed by purl / cpe with "
            "component name, resolved version, and detection source per "
            "entry; persist the SBOM as a first-class artifact on the "
            "target.",
            "Auditor reviews the SBOM against the internal "
            "component-approval policy and feeds it into an SCA tool "
            "(Trivy, grype, OSV-Scanner) to derive the CVE surface.",
            "Confirm each flagged component is genuinely bundled (not a "
            "false positive from a stripped class name or a leftover in "
            "META-INF) before treating an SCA hit as a finding.",
        ),
        relevant_apis=(
            "classes.dex",
            "META-INF/MANIFEST.MF",
            "META-INF/services/",
            "lib/<abi>/",
            "assets/flutter_assets/",
        ),
        evidence_hints=(
            "classes.dex",
            "META-INF/MANIFEST.MF",
            "META-INF/services/",
            "AndroidManifest.xml",
            "flutter_assets",
        ),
        cwe=("CWE-1104",),
        masvs_refs=("MASVS-CODE-3",),
    ),
    ApkStaticCheck(
        id="APK-DATA-SAFETY-MISMATCH",
        group=ApkStaticGroup.PRIVACY,
        mode=ApkStaticMode.EXTRACTOR,
        title=(
            "Data actually collected by the app does not match the Google "
            "Play Data Safety declaration."
        ),
        description=(
            "Google Play requires each listing to publish a Data Safety "
            "declaration naming every data class collected and shared, "
            "the purposes, whether data is encrypted in transit, and "
            "whether users can request deletion. Requires a Play-listing "
            "scrape extractor stage that fetches the app's Data Safety "
            "section (or the developer console export when available) and "
            "normalizes it into a comparable structure so it can be "
            "diffed against the data-collection surface the static tier "
            "already observes."
        ),
        verification_steps=(
            "Extractor stage: scrape the Google Play Store data-safety "
            "section for the target package and normalize it into a "
            "structured record of {data class, collected?, shared?, "
            "purpose, encrypted in transit?, deletion offered?}.",
            "Combine the observable static evidence already produced by "
            "the pipeline (declared permissions, network destinations, "
            "analytics / advertising SDKs present in the jadx tree) into "
            "an observed data-collection surface.",
            "Auditor diffs the declaration against the observed surface "
            "and flags any class collected or shared by the app but "
            "absent from the declaration, and any class disclosed as "
            "collected only when in fact it is also shared.",
            "Confirm the implicated SDK actually transmits the data class "
            "off-device (rather than reading it locally for a UI hint) "
            "before treating a mismatch as a reportable finding.",
        ),
        relevant_apis=(
            "com.google.android.gms.ads",
            "com.google.firebase.analytics",
            "com.facebook.appevents",
            "AdvertisingIdClient",
            "TelephonyManager.getImei",
        ),
        evidence_hints=(
            "AdvertisingIdClient",
            "FirebaseAnalytics",
            "AppEventsLogger",
            "getSubscriberId",
            "getImei",
        ),
        cwe=("CWE-359",),
        masvs_refs=("MASVS-PRIVACY-3",),
    ),
)
