"""APK static checks for the deserialization, codeload, resilience, and privacy groups."""
from __future__ import annotations

from aila.modules.vr.apk_static.models import (
    ApkStaticCheck,
    ApkStaticGroup,
    ApkStaticMode,
)

CHECKS: tuple[ApkStaticCheck, ...] = (
    ApkStaticCheck(
        id="APK-DESER-JAVA",
        group=ApkStaticGroup.DESERIALIZATION,
        mode=ApkStaticMode.STATIC,
        title="ObjectInputStream.readObject called on data from an untrusted source.",
        description=(
            "Java native deserialization instantiates arbitrary classes "
            "and runs their readObject / readResolve hooks before any "
            "type check. When the input stream is fed from disk cache, "
            "an intent extra, a socket, or a network response the "
            "process may load a gadget chain that ends in code "
            "execution."
        ),
        verification_steps=(
            "search_functions and semantic_search the decompiled tree "
            "for ObjectInputStream construction and readObject / "
            "readUnshared call sites.",
            "read_function each hit and trace the backing InputStream "
            "back to its origin: a file in getFilesDir with only "
            "trusted writers is a pass, anything from an intent, a "
            "socket, a ContentProvider, or an external file is a "
            "finding.",
            "Check for a resolveClass override that restricts the "
            "allowed class set; a broad readObject with no allow-list "
            "on untrusted input is the reportable case.",
            "Confirm the deserialized bytes influence a security "
            "decision or reachable code path before reporting.",
        ),
        relevant_apis=(
            "java.io.ObjectInputStream.readObject",
            "java.io.ObjectInputStream.readUnshared",
            "java.io.ObjectInputStream.resolveClass",
            "java.io.Serializable",
        ),
        evidence_hints=(
            "ObjectInputStream",
            "readObject",
            "readUnshared",
            "resolveClass",
        ),
        cwe=("CWE-502",),
        masvs_refs=("MASVS-CODE-4", "MASVS-PLATFORM-2"),
    ),
    ApkStaticCheck(
        id="APK-DESER-PARCELABLE",
        group=ApkStaticGroup.DESERIALIZATION,
        mode=ApkStaticMode.STATIC,
        title="getSerializableExtra / getParcelableExtra cast into a typed object from an untrusted intent.",
        description=(
            "Intent extras arrive as opaque bundles from any caller "
            "that can address the receiving component. A blind cast of "
            "getSerializableExtra or the pre-Tiramisu single-argument "
            "getParcelableExtra can be steered into instantiating a "
            "different class than the receiver expects, triggering the "
            "same gadget-chain risk as Java native deserialization and "
            "crashing type-confusion bugs into reachable code."
        ),
        verification_steps=(
            "search_functions for getSerializableExtra, "
            "getParcelableExtra, getParcelableArrayListExtra, and the "
            "Bundle equivalents.",
            "read_function each hit: the safe form passes the expected "
            "Class as the second argument (Android 13+ API) or reads "
            "into a strictly-typed helper; the unsafe form is a bare "
            "call plus a cast.",
            "Cross-check the containing component in "
            "AndroidManifest.xml via read_lines: an exported activity, "
            "service, or receiver with no signature-level permission "
            "makes the sink reachable by any installed package.",
            "Confirm the extracted object is used in a security-"
            "relevant path before reporting.",
        ),
        relevant_apis=(
            "android.content.Intent.getSerializableExtra",
            "android.content.Intent.getParcelableExtra",
            "android.os.Bundle.getParcelable",
            "android.os.Parcel.readParcelable",
        ),
        evidence_hints=(
            "getSerializableExtra",
            "getParcelableExtra",
            "getParcelable",
            "readParcelable",
        ),
        cwe=("CWE-502", "CWE-925"),
        masvs_refs=("MASVS-PLATFORM-1", "MASVS-CODE-4"),
    ),
    ApkStaticCheck(
        id="APK-DESER-JSON-GADGET",
        group=ApkStaticGroup.DESERIALIZATION,
        mode=ApkStaticMode.STATIC,
        title="Gson or Jackson polymorphic type handling applied to untrusted JSON.",
        description=(
            "Gson RuntimeTypeAdapterFactory and Jackson default typing "
            "let the payload name the concrete Java class the parser "
            "should build. On untrusted input this collapses into "
            "arbitrary-class instantiation and, with a suitable class "
            "on the app classpath, into code execution or file access "
            "on parse."
        ),
        verification_steps=(
            "search_functions and semantic_search for "
            "RuntimeTypeAdapterFactory, enableDefaultTyping, "
            "activateDefaultTyping, and PolymorphicTypeValidator uses.",
            "read_function each hit and read the type binding: a "
            "closed allow-list of registered subtypes is a pass; "
            "default typing enabled globally or across java.lang.Object "
            "is a finding.",
            "Trace the JSON source: a static asset shipped in assets/ "
            "is trusted, a network response or intent extra is not.",
            "Confirm the parser output feeds a reachable code path or "
            "a persisted object before reporting.",
        ),
        relevant_apis=(
            "com.google.gson.typeadapters.RuntimeTypeAdapterFactory",
            "com.fasterxml.jackson.databind.ObjectMapper.enableDefaultTyping",
            "com.fasterxml.jackson.databind.ObjectMapper.activateDefaultTyping",
            "com.fasterxml.jackson.databind.jsontype.PolymorphicTypeValidator",
        ),
        evidence_hints=(
            "RuntimeTypeAdapterFactory",
            "enableDefaultTyping",
            "activateDefaultTyping",
            "@JsonTypeInfo",
            "PolymorphicTypeValidator",
        ),
        cwe=("CWE-502",),
        masvs_refs=("MASVS-CODE-4",),
    ),
    ApkStaticCheck(
        id="APK-CODELOAD-REMOTE-DEX",
        group=ApkStaticGroup.CODELOAD,
        mode=ApkStaticMode.STATIC,
        title="DexClassLoader or PathClassLoader loading a downloaded dex, apk, or jar.",
        description=(
            "Loading executable bytecode fetched at runtime replaces "
            "the signed, reviewed application with content whose "
            "integrity depends on the transport, the storage location, "
            "and any signature check the caller adds. A fetch over "
            "cleartext, a write to external storage, or the absence of "
            "a signature check turns the loader into a persistent "
            "code-injection primitive."
        ),
        verification_steps=(
            "search_functions for DexClassLoader, PathClassLoader, "
            "InMemoryDexClassLoader, DelegateLastClassLoader, and "
            "BaseDexClassLoader constructor calls.",
            "read_function each hit and trace the dexPath argument to "
            "its origin: a file inside the APK or getCodeCacheDir is a "
            "pass; a download into getExternalFilesDir, "
            "getExternalCacheDir, or a shared path is a finding.",
            "Check for an explicit signature or hash verification of "
            "the loaded artifact before the loader call; absence of "
            "any check on untrusted-origin bytes is the reportable "
            "case.",
            "Confirm the loaded class is actually invoked (reflected "
            "instantiate or a defined entry point) before reporting.",
        ),
        relevant_apis=(
            "dalvik.system.DexClassLoader",
            "dalvik.system.PathClassLoader",
            "dalvik.system.InMemoryDexClassLoader",
            "dalvik.system.DelegateLastClassLoader",
        ),
        evidence_hints=(
            "DexClassLoader",
            "PathClassLoader",
            "InMemoryDexClassLoader",
            "loadClass",
            "getExternalFilesDir",
        ),
        cwe=("CWE-494", "CWE-829"),
        masvs_refs=("MASVS-CODE-2", "MASVS-RESILIENCE-2"),
    ),
    ApkStaticCheck(
        id="APK-CODELOAD-WRITABLE-NATIVE",
        group=ApkStaticGroup.CODELOAD,
        mode=ApkStaticMode.STATIC,
        title="System.load of a native library from a writable or external path.",
        description=(
            "System.load takes an absolute path and links the ELF "
            "unconditionally. When the path lives on external storage, "
            "in a cache directory shared with other apps, or in a "
            "location any process can rewrite, a malicious writer can "
            "swap the library between checks and load, giving the app "
            "process arbitrary native code."
        ),
        verification_steps=(
            "search_functions for System.load, System.loadLibrary, "
            "and Runtime.load / loadLibrary call sites.",
            "read_function each System.load hit: bundled libraries "
            "loaded via loadLibrary(name) from the APK's lib/ ABI dir "
            "are a pass; System.load from getExternalFilesDir, "
            "getExternalCacheDir, /sdcard, or a path derived from a "
            "downloaded artifact is a finding.",
            "Check the manifest via read_lines for "
            "android:extractNativeLibs and android:requestLegacyExternalStorage "
            "to understand where libraries can land.",
            "Confirm the loaded library is not shipped read-only "
            "inside the APK before reporting.",
        ),
        relevant_apis=(
            "java.lang.System.load",
            "java.lang.System.loadLibrary",
            "java.lang.Runtime.load",
            "java.lang.Runtime.loadLibrary",
        ),
        evidence_hints=(
            "System.load",
            "System.loadLibrary",
            "Runtime.load",
            "getExternalFilesDir",
        ),
        cwe=("CWE-427", "CWE-494"),
        masvs_refs=("MASVS-CODE-2", "MASVS-RESILIENCE-2"),
    ),
    ApkStaticCheck(
        id="APK-CODELOAD-REFLECTION-HIDDEN",
        group=ApkStaticGroup.CODELOAD,
        mode=ApkStaticMode.STATIC,
        title="Class.forName / Method.invoke used to reach hidden or restricted APIs.",
        description=(
            "Reflection over Class.forName plus Method.invoke bypasses "
            "the compile-time API surface and reaches @hide, "
            "@SystemApi, or grey/black-listed methods that Android "
            "removed from public use. The call succeeds on some OEM "
            "builds and fails on others, produces silent behavioral "
            "drift, and often signals an intent to skirt platform "
            "restrictions the reviewer needs to understand."
        ),
        verification_steps=(
            "search_functions for Class.forName, "
            "Class.getDeclaredMethod, Method.invoke, Method.setAccessible, "
            "and Field.setAccessible.",
            "read_function each hit and resolve the class-name / "
            "method-name string arguments (search_constants for the "
            "literal helps): flag any fully-qualified name under "
            "android.*, com.android.internal.*, libcore.*, or a "
            "manufacturer namespace.",
            "Correlate with meta-reflection helpers "
            "(HiddenApiBypass, VMRuntime.setHiddenApiExemptions, "
            "unsafe hidden-api bypass patterns) that indicate a "
            "deliberate reach around SDK restrictions.",
            "Confirm the target member is not part of the public SDK "
            "for the app's targetSdkVersion before reporting.",
        ),
        relevant_apis=(
            "java.lang.Class.forName",
            "java.lang.reflect.Method.invoke",
            "java.lang.reflect.Method.setAccessible",
            "java.lang.reflect.Field.setAccessible",
            "dalvik.system.VMRuntime.setHiddenApiExemptions",
        ),
        evidence_hints=(
            "Class.forName",
            "Method.invoke",
            "setAccessible",
            "HiddenApiBypass",
            "setHiddenApiExemptions",
        ),
        cwe=("CWE-470",),
        masvs_refs=("MASVS-CODE-4", "MASVS-PLATFORM-2"),
    ),
    ApkStaticCheck(
        id="APK-RESILIENCE-ROOT-DETECTION",
        group=ApkStaticGroup.RESILIENCE,
        mode=ApkStaticMode.STATIC,
        title="Presence or absence of root detection (su, Magisk, test-keys).",
        description=(
            "Root detection is a defense-in-depth signal for apps that "
            "handle payments, credentials, or DRM-protected content. "
            "Static evidence is the set of literal checks the code "
            "performs: existence of /system/xbin/su, Magisk package "
            "names, test-keys in the build fingerprint, or dedicated "
            "libraries such as RootBeer. Absence in a high-risk app is "
            "the reportable finding; presence and its scope are what "
            "the reviewer records."
        ),
        verification_steps=(
            "search_constants for the standard string set: /system/xbin/su, "
            "/system/bin/su, magisk, supersu, busybox, test-keys, "
            "ro.build.tags.",
            "search_functions for helper names such as isRooted, "
            "checkRoot, RootBeer, detectRoot, isDeviceRooted and "
            "read_function each hit.",
            "Note whether any positive detection changes app behavior "
            "(refuse to run, degrade features, telemetry-only) or is "
            "logged and ignored.",
            "Report the coverage level: no detection at all, string-"
            "only, string-plus-package, or a dedicated library.",
        ),
        relevant_apis=(
            "java.io.File.exists",
            "android.os.Build.TAGS",
            "android.content.pm.PackageManager.getPackageInfo",
            "java.lang.Runtime.exec",
        ),
        evidence_hints=(
            "/system/xbin/su",
            "/system/bin/su",
            "magisk",
            "test-keys",
            "RootBeer",
        ),
        cwe=("CWE-693",),
        masvs_refs=("MASVS-RESILIENCE-1",),
    ),
    ApkStaticCheck(
        id="APK-RESILIENCE-EMULATOR-DETECTION",
        group=ApkStaticGroup.RESILIENCE,
        mode=ApkStaticMode.STATIC,
        title="Presence or absence of emulator detection (build fingerprint, QEMU props).",
        description=(
            "Emulator detection distinguishes an instrumented analysis "
            "environment from a real handset. The static tells are "
            "checks on Build.FINGERPRINT, Build.MODEL, Build.MANUFACTURER, "
            "the ro.kernel.qemu system property, and the presence of "
            "goldfish / ranchu / vbox device files. As with root "
            "detection, the reviewer records the coverage; absence in "
            "a resilience-sensitive app is the reportable case."
        ),
        verification_steps=(
            "search_constants for the emulator string set: goldfish, "
            "ranchu, generic_x86, vbox, ro.kernel.qemu, ro.hardware, "
            "sdk_gphone, google_sdk.",
            "search_functions for Build.FINGERPRINT, Build.MODEL, "
            "Build.MANUFACTURER, Build.HARDWARE, Build.PRODUCT reads "
            "and read_function each hit.",
            "Check for SystemProperties.get calls (reflection or "
            "android.os.SystemProperties) resolving ro.kernel.qemu or "
            "ro.build.characteristics.",
            "Report the coverage level and whether detection changes "
            "behavior or is telemetry-only.",
        ),
        relevant_apis=(
            "android.os.Build.FINGERPRINT",
            "android.os.Build.MODEL",
            "android.os.Build.HARDWARE",
            "android.os.SystemProperties.get",
        ),
        evidence_hints=(
            "goldfish",
            "ranchu",
            "ro.kernel.qemu",
            "Build.FINGERPRINT",
            "sdk_gphone",
        ),
        cwe=("CWE-693",),
        masvs_refs=("MASVS-RESILIENCE-1",),
    ),
    ApkStaticCheck(
        id="APK-RESILIENCE-ANTI-DEBUG",
        group=ApkStaticGroup.RESILIENCE,
        mode=ApkStaticMode.STATIC,
        title="Anti-debug and anti-Frida controls (Debug.isDebuggerConnected, ptrace, Frida scans).",
        description=(
            "Anti-debug controls resist live instrumentation. Common "
            "static signatures are Debug.isDebuggerConnected checks, "
            "ptrace(PT_TRACEME) calls from native code, scans for the "
            "default Frida server port 27042, the frida-gadget library "
            "name, and reads of /proc/self/status TracerPid. Presence "
            "and scope are what the reviewer records; absence in a "
            "resilience-sensitive app is the finding."
        ),
        verification_steps=(
            "search_functions for Debug.isDebuggerConnected, "
            "Debug.waitingForDebugger, and ApplicationInfo.FLAG_DEBUGGABLE "
            "checks; read_function each hit.",
            "search_constants for the Frida / debugger string set: "
            "frida, gum-js-loop, gmain, linjector, 27042, TracerPid, "
            "/proc/self/status, /proc/self/maps.",
            "Look for native-library calls (System.loadLibrary + JNI) "
            "that plausibly host ptrace or /proc parsers; note the "
            "library names to feed a later native-side extractor.",
            "Report the coverage level and whether detection results "
            "trigger a hard stop, degrade, or log-only path.",
        ),
        relevant_apis=(
            "android.os.Debug.isDebuggerConnected",
            "android.os.Debug.waitingForDebugger",
            "android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE",
        ),
        evidence_hints=(
            "isDebuggerConnected",
            "TracerPid",
            "frida",
            "gum-js-loop",
            "27042",
        ),
        cwe=("CWE-693",),
        masvs_refs=("MASVS-RESILIENCE-4",),
    ),
    ApkStaticCheck(
        id="APK-RESILIENCE-OBFUSCATION",
        group=ApkStaticGroup.RESILIENCE,
        mode=ApkStaticMode.STATIC,
        title="Obfuscation level (class-name entropy, ProGuard / R8 / DexGuard markers).",
        description=(
            "Obfuscation raises the reverse-engineering cost of the "
            "app. The static signals are the ratio of short / random "
            "class and method names in the decompiled tree, ProGuard "
            "or R8 mapping remnants, DexGuard-specific markers, and "
            "string-encryption helpers. The reviewer records the tier: "
            "none (fully readable), name-only, name plus string "
            "encryption, or a dedicated commercial packer."
        ),
        verification_steps=(
            "search_functions with an empty query and count the "
            "distribution of class names by length; a large share of "
            "one- or two-character names indicates identifier "
            "obfuscation.",
            "search_constants for ProGuard / R8 / DexGuard markers: "
            "kotlin.Metadata, kotlin.jvm.internal, "
            "com.android.tools.r8, com.guardsquare, dexguard, "
            "$$serializer.",
            "semantic_search for string-decryption helper patterns: a "
            "central static method returning String, called with a "
            "byte-array or index literal from many sites, that is not "
            "a simple resource lookup.",
            "Report the obfuscation tier and whether critical classes "
            "(crypto, auth, network) share the same tier as the rest "
            "of the app.",
        ),
        relevant_apis=(
            "kotlin.Metadata",
            "com.android.tools.r8",
            "proguard.obfuscate",
        ),
        evidence_hints=(
            "kotlin.Metadata",
            "com.android.tools.r8",
            "com.guardsquare",
            "dexguard",
            "$$serializer",
        ),
        cwe=("CWE-693",),
        masvs_refs=("MASVS-RESILIENCE-2", "MASVS-RESILIENCE-3"),
    ),
    ApkStaticCheck(
        id="APK-RESILIENCE-INTEGRITY-CHECK",
        group=ApkStaticGroup.RESILIENCE,
        mode=ApkStaticMode.STATIC,
        title="Runtime integrity check (signature self-verification, Play Integrity, SafetyNet).",
        description=(
            "Runtime integrity verification catches a re-packaged or "
            "tampered APK. The static tells are calls to "
            "PackageManager.getPackageInfo with GET_SIGNATURES / "
            "GET_SIGNING_CERTIFICATES followed by a fingerprint "
            "comparison, Play Integrity API usage "
            "(IntegrityManager.requestIntegrityToken), or legacy "
            "SafetyNet Attestation calls. Absence in an app that ships "
            "root detection or DRM is a coverage gap worth reporting."
        ),
        verification_steps=(
            "search_functions for PackageManager.getPackageInfo, "
            "GET_SIGNATURES, GET_SIGNING_CERTIFICATES, signingInfo, "
            "and read_function each hit to see whether the returned "
            "Signature is compared against a pinned digest.",
            "search_functions for IntegrityManager, "
            "requestIntegrityToken, StandardIntegrityManager, and "
            "SafetyNetClient.attest; read_function each hit.",
            "search_constants for pinned SHA-256 signature digests "
            "(hex strings of length 64) that the comparison could use.",
            "Report the coverage: no integrity check, signature-compare "
            "only, Play Integrity token requested and verified "
            "server-side, or attestation with local-only trust "
            "(a false-security pattern).",
        ),
        relevant_apis=(
            "android.content.pm.PackageManager.getPackageInfo",
            "android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES",
            "com.google.android.play.core.integrity.IntegrityManager",
            "com.google.android.gms.safetynet.SafetyNetClient",
        ),
        evidence_hints=(
            "GET_SIGNATURES",
            "GET_SIGNING_CERTIFICATES",
            "IntegrityManager",
            "requestIntegrityToken",
            "SafetyNetClient",
        ),
        cwe=("CWE-693", "CWE-353"),
        masvs_refs=("MASVS-RESILIENCE-1", "MASVS-RESILIENCE-3"),
    ),
    ApkStaticCheck(
        id="APK-PRIVACY-PERSISTENT-ID",
        group=ApkStaticGroup.PRIVACY,
        mode=ApkStaticMode.STATIC,
        title="Collection of persistent identifiers (IMEI, ANDROID_ID, MAC, serial).",
        description=(
            "Persistent device identifiers cannot be reset by the "
            "user and become long-term tracking keys once they leave "
            "the device. TelephonyManager.getDeviceId (IMEI/MEID), "
            "Settings.Secure.ANDROID_ID, WifiInfo.getMacAddress, "
            "Build.SERIAL, and Build.getSerial fall in the same "
            "category. Any read is a data point; a read that reaches a "
            "network or storage sink is the reportable case."
        ),
        verification_steps=(
            "search_functions for TelephonyManager.getDeviceId, "
            "getImei, getMeid, getSubscriberId, getSimSerialNumber, "
            "and read_function each hit.",
            "search_constants for the string \"android_id\" and "
            "search_functions for Settings.Secure.getString call "
            "sites to catch ANDROID_ID reads.",
            "search_functions for WifiInfo.getMacAddress, "
            "NetworkInterface.getHardwareAddress, Build.SERIAL, and "
            "Build.getSerial reads.",
            "For each collected identifier trace the value into a "
            "sink: log-only is a low-severity note, transmission to a "
            "network endpoint or persistent storage is the finding.",
        ),
        relevant_apis=(
            "android.telephony.TelephonyManager.getDeviceId",
            "android.telephony.TelephonyManager.getImei",
            "android.provider.Settings.Secure.ANDROID_ID",
            "android.net.wifi.WifiInfo.getMacAddress",
            "android.os.Build.getSerial",
        ),
        evidence_hints=(
            "getDeviceId",
            "getImei",
            "ANDROID_ID",
            "getMacAddress",
            "Build.SERIAL",
        ),
        cwe=("CWE-359", "CWE-200"),
        masvs_refs=("MASVS-PRIVACY-1", "MASVS-PRIVACY-2"),
    ),
    ApkStaticCheck(
        id="APK-PRIVACY-AD-ID",
        group=ApkStaticGroup.PRIVACY,
        mode=ApkStaticMode.STATIC,
        title="AdvertisingIdClient usage and linkage of the ad id to PII.",
        description=(
            "The Google Advertising ID is the user-resettable "
            "identifier meant to bound cross-app tracking. Reading it "
            "is allowed; joining it to a persistent identifier "
            "(email, phone, account id, hardware id) rebuilds a "
            "non-resettable profile and violates the platform policy "
            "in addition to being a privacy finding."
        ),
        verification_steps=(
            "search_functions for "
            "AdvertisingIdClient.getAdvertisingIdInfo, isLimitAdTrackingEnabled, "
            "and getId; read_function each hit.",
            "For each ad-id read trace the returned string into any "
            "sink call in the same method (analytics send, HTTP body, "
            "SharedPreferences write, database insert).",
            "search_constants near the sink for co-occurring PII field "
            "names: email, phone, msisdn, user_id, account_id, "
            "customer_id; joint transmission with the ad id is the "
            "reportable case.",
            "Check the manifest for the com.google.android.gms.permission.AD_ID "
            "declaration required by targetSdk 33+ and note its "
            "presence.",
        ),
        relevant_apis=(
            "com.google.android.gms.ads.identifier.AdvertisingIdClient",
            "com.google.android.gms.ads.identifier.AdvertisingIdClient.Info.getId",
            "com.google.android.gms.ads.identifier.AdvertisingIdClient.Info.isLimitAdTrackingEnabled",
        ),
        evidence_hints=(
            "AdvertisingIdClient",
            "getAdvertisingIdInfo",
            "isLimitAdTrackingEnabled",
            "com.google.android.gms.permission.AD_ID",
        ),
        cwe=("CWE-359", "CWE-200"),
        masvs_refs=("MASVS-PRIVACY-1", "MASVS-PRIVACY-2"),
    ),
    ApkStaticCheck(
        id="APK-PRIVACY-TRACKER-INVENTORY",
        group=ApkStaticGroup.PRIVACY,
        mode=ApkStaticMode.STATIC,
        title="Inventory of tracker and analytics SDKs (Exodus-style fingerprints).",
        description=(
            "Third-party analytics, crash-reporting, and advertising "
            "SDKs each carry their own data-collection profile and "
            "their own set of endpoints. The reviewer records which "
            "SDKs are present, at what version if reachable, and how "
            "many of them the app has bundled, so a downstream privacy "
            "review can decide which need consent or removal."
        ),
        verification_steps=(
            "search_functions with an empty query and enumerate class "
            "packages under known tracker namespaces: com.google.firebase.analytics, "
            "com.google.android.gms.analytics, com.facebook, "
            "io.branch, com.appsflyer, io.sentry, com.crashlytics, "
            "com.amplitude, com.mixpanel, com.segment, com.mparticle.",
            "search_constants for tracker endpoint hostnames "
            "(app-measurement.com, graph.facebook.com, api.branch.io, "
            "api.appsflyer.com, sentry.io, api.amplitude.com, "
            "api.mixpanel.com) and version-string constants exposed "
            "by each SDK.",
            "Cross-check with the static summary permissions list: "
            "SDKs that need INTERNET, ACCESS_NETWORK_STATE, "
            "READ_PHONE_STATE, or a foreground-service permission "
            "confirm reachability.",
            "Report the SDK inventory with confidence per hit "
            "(package match, endpoint match, both).",
        ),
        relevant_apis=(
            "com.google.firebase.analytics.FirebaseAnalytics",
            "com.facebook.FacebookSdk",
            "io.branch.referral.Branch",
            "com.appsflyer.AppsFlyerLib",
            "io.sentry.Sentry",
        ),
        evidence_hints=(
            "com.google.firebase.analytics",
            "com.facebook.FacebookSdk",
            "io.branch.referral",
            "com.appsflyer",
            "io.sentry",
        ),
        cwe=("CWE-359", "CWE-200"),
        masvs_refs=("MASVS-PRIVACY-1", "MASVS-PRIVACY-4"),
    ),
    ApkStaticCheck(
        id="APK-PRIVACY-PII-TO-SINK",
        group=ApkStaticGroup.PRIVACY,
        mode=ApkStaticMode.STATIC,
        title="PII from contacts, location, or microphone reaching a third-party network SDK.",
        description=(
            "Sensitive user data collected under a runtime permission "
            "(READ_CONTACTS, ACCESS_FINE_LOCATION, RECORD_AUDIO) is "
            "expected to serve the app's own function. Static evidence "
            "that the same data reaches a third-party analytics, "
            "advertising, or crash-reporting SDK is a disclosure the "
            "user has not consented to and is the reportable case."
        ),
        verification_steps=(
            "Identify PII sources by search_functions: "
            "ContentResolver.query on ContactsContract, "
            "LocationManager.getLastKnownLocation, "
            "FusedLocationProviderClient.getLastLocation, "
            "AudioRecord.read, MediaRecorder.start.",
            "For each source use callers_of / semantic_search / "
            "read_function to build the forward slice to the first "
            "sink: an HTTP client call, a WebSocket send, or an SDK "
            "helper listed in the tracker inventory check.",
            "Flag any slice whose sink package sits outside the app's "
            "own namespace, and record the PII kind, the SDK package, "
            "and the request path or event name if visible in a "
            "constant.",
            "Confirm the path is reachable from a UI entry point "
            "(activity or exported service) before reporting.",
        ),
        relevant_apis=(
            "android.provider.ContactsContract",
            "android.location.LocationManager.getLastKnownLocation",
            "com.google.android.gms.location.FusedLocationProviderClient",
            "android.media.AudioRecord.read",
            "android.media.MediaRecorder.start",
        ),
        evidence_hints=(
            "ContactsContract",
            "getLastKnownLocation",
            "FusedLocationProviderClient",
            "AudioRecord",
            "MediaRecorder",
        ),
        cwe=("CWE-359", "CWE-200", "CWE-312"),
        masvs_refs=("MASVS-PRIVACY-1", "MASVS-PRIVACY-2", "MASVS-PRIVACY-3"),
    ),
)
