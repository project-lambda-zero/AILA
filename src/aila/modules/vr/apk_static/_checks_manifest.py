"""APK static-analysis checks: MANIFEST, SIGNING, and PERMISSIONS groups."""
from __future__ import annotations

from aila.modules.vr.apk_static.models import (
    ApkStaticCheck,
    ApkStaticGroup,
    ApkStaticMode,
)

CHECKS: tuple[ApkStaticCheck, ...] = (
    ApkStaticCheck(
        id="APK-MANIFEST-DEBUGGABLE",
        group=ApkStaticGroup.MANIFEST,
        mode=ApkStaticMode.STATIC,
        title='Application shipped with android:debuggable="true".',
        description=(
            "A release build with android:debuggable=\"true\" lets any local "
            "process attach a jdwp debugger, read app memory, and invoke "
            "methods, defeating client-side protections. The flag belongs "
            "only in debug builds."
        ),
        verification_steps=(
            "Read AndroidManifest.xml via read_lines and locate the "
            "<application> element.",
            "Inspect the android:debuggable attribute: absent or \"false\" is "
            "a pass, \"true\" is a finding.",
            "Cross-check the static summary manifest_analysis section when "
            "present.",
        ),
        relevant_apis=("android:debuggable", "ApplicationInfo.FLAG_DEBUGGABLE"),
        evidence_hints=("android:debuggable", "FLAG_DEBUGGABLE"),
        cwe=("CWE-489",),
        masvs_refs=("MASVS-RESILIENCE-1",),
    ),
    ApkStaticCheck(
        id="APK-MANIFEST-BACKUP-ALLOWED",
        group=ApkStaticGroup.MANIFEST,
        mode=ApkStaticMode.STATIC,
        title="Application allows adb backup with no scoped backup rules.",
        description=(
            "android:allowBackup=\"true\" (the pre-31 default) with no "
            "android:fullBackupContent or android:dataExtractionRules lets "
            "anyone with adb access pull the entire /data/data/<pkg> tree "
            "off an unlocked device via adb backup. Sensitive tokens, "
            "databases, and shared_prefs end up in the tar."
        ),
        verification_steps=(
            "Read AndroidManifest.xml and inspect the <application> element "
            "for android:allowBackup and any android:fullBackupContent or "
            "android:dataExtractionRules attribute.",
            "If allowBackup is true or unset (pre-31 default true) AND no "
            "scoping resource is declared, record a finding.",
            "When a rules resource is referenced, read it from res/xml/ via "
            "read_lines and confirm sensitive paths are excluded, not merely "
            "renamed.",
            "Confirm the app actually stores sensitive data (tokens, PII, "
            "credentials) before reporting.",
        ),
        relevant_apis=(
            "android:allowBackup",
            "android:fullBackupContent",
            "android:dataExtractionRules",
        ),
        evidence_hints=(
            "android:allowBackup",
            "android:fullBackupContent",
            "android:dataExtractionRules",
        ),
        cwe=("CWE-530",),
        masvs_refs=("MASVS-STORAGE-2",),
    ),
    ApkStaticCheck(
        id="APK-MANIFEST-CLEARTEXT",
        group=ApkStaticGroup.MANIFEST,
        mode=ApkStaticMode.STATIC,
        title="Cleartext HTTP traffic permitted by manifest or network policy.",
        description=(
            "android:usesCleartextTraffic=\"true\" (or the pre-28 default of "
            "true with no android:networkSecurityConfig) lets the app open "
            "plain HTTP sockets. Any on-path observer on a shared network "
            "can read and rewrite the traffic."
        ),
        verification_steps=(
            "Read AndroidManifest.xml and record targetSdkVersion, "
            "android:usesCleartextTraffic, and android:networkSecurityConfig.",
            "If usesCleartextTraffic is true, or targetSdk<28 with no "
            "networkSecurityConfig, cleartext is allowed application-wide.",
            "When a networkSecurityConfig resource is referenced, read it "
            "from res/xml/ via read_lines and check <base-config> and every "
            "<domain-config> for cleartextTrafficPermitted=\"true\".",
            "Grep the decompiled code for http:// URLs to confirm cleartext "
            "endpoints are actually reached, not just permitted.",
        ),
        relevant_apis=(
            "android:usesCleartextTraffic",
            "android:networkSecurityConfig",
            "NetworkSecurityConfig",
        ),
        evidence_hints=(
            "usesCleartextTraffic",
            "networkSecurityConfig",
            "cleartextTrafficPermitted",
            "http://",
        ),
        cwe=("CWE-319",),
        masvs_refs=("MASVS-NETWORK-1",),
    ),
    ApkStaticCheck(
        id="APK-MANIFEST-EXPORTED-COMPONENT",
        group=ApkStaticGroup.MANIFEST,
        mode=ApkStaticMode.STATIC,
        title="Exported activity, service, or receiver with no permission guard.",
        description=(
            "A component declared android:exported=\"true\" (or implicitly "
            "exported through an intent-filter) with no android:permission "
            "attribute is callable by any installed app. Any privileged "
            "action or sensitive intent extra it consumes is reachable from "
            "a malicious app on the same device."
        ),
        verification_steps=(
            "Read AndroidManifest.xml and enumerate every <activity>, "
            "<service>, and <receiver> that is android:exported=\"true\" or "
            "has an <intent-filter> without exported=\"false\".",
            "For each exported component, check for a guarding "
            "android:permission attribute at a protectionLevel of signature "
            "or higher.",
            "read_function the target class in the decompiled tree and "
            "inspect onCreate/onStartCommand/onReceive for use of intent "
            "extras that trigger privileged behavior.",
            "Confirm the reachable behavior is sensitive (auth, file access, "
            "IPC to trusted callers) before reporting.",
        ),
        relevant_apis=(
            "android:exported",
            "android:permission",
            "Intent.getExtras",
            "Context.checkCallingPermission",
        ),
        evidence_hints=(
            "android:exported=\"true\"",
            "<intent-filter>",
            "getIntent().getExtras",
            "checkCallingPermission",
        ),
        cwe=("CWE-926",),
        masvs_refs=("MASVS-PLATFORM-1",),
    ),
    ApkStaticCheck(
        id="APK-MANIFEST-DEEPLINK-SURFACE",
        group=ApkStaticGroup.MANIFEST,
        mode=ApkStaticMode.STATIC,
        title="Deep-link intent-filters allow scheme or host hijack.",
        description=(
            "Custom-scheme intent-filters, and http/https App Links declared "
            "without android:autoVerify=\"true\", let any other installed "
            "app register the same scheme or host and receive the deep "
            "link. Auth callbacks, payment returns, and password-reset "
            "flows delivered through such deep links can be intercepted by "
            "a malicious app."
        ),
        verification_steps=(
            "Read AndroidManifest.xml and list every <intent-filter> whose "
            "<data> child declares a custom android:scheme or an http/https "
            "android:host.",
            "For each http/https host, check that the parent <intent-filter> "
            "sets android:autoVerify=\"true\" and that action.VIEW plus "
            "category.BROWSABLE are the only surfaces exposed.",
            "read_function the target activity and inspect its handling of "
            "getIntent().getData() for token extraction with no validation "
            "of the receiving intent's package.",
            "Confirm the deep link carries a security-sensitive parameter "
            "(auth code, token, callback URL) before reporting.",
        ),
        relevant_apis=(
            "android:scheme",
            "android:host",
            "android:autoVerify",
            "Intent.getData",
        ),
        evidence_hints=(
            "android:scheme",
            "android:autoVerify",
            "category.BROWSABLE",
            "getIntent().getData",
        ),
        cwe=("CWE-939",),
        masvs_refs=("MASVS-PLATFORM-1",),
    ),
    ApkStaticCheck(
        id="APK-MANIFEST-MINSDK",
        group=ApkStaticGroup.MANIFEST,
        mode=ApkStaticMode.STATIC,
        title="Low android:minSdkVersion inherits known platform vulnerabilities.",
        description=(
            "A low android:minSdkVersion means the app runs on OS releases "
            "that still ship well-known platform bugs: Janus DEX prepending "
            "on <24, WebView same-origin bypasses on <21, Uri parser "
            "quirks, and BinderProxy leaks. Users on those OS versions "
            "inherit those bugs whether the app triggers them or not."
        ),
        verification_steps=(
            "Read AndroidManifest.xml and record the android:minSdkVersion "
            "declared on <uses-sdk>, or the value from the static "
            "summary when no <uses-sdk> element is present.",
            "If minSdk is below 24, note Janus (CVE-2017-13156) applicability "
            "and cross-reference the signing scheme check.",
            "If minSdk is below 21, note WebView platform-provided render "
            "bugs and the absence of the AndroidX security patch pipeline.",
            "Confirm the low minSdk is a shipped choice (not a debug leftover) "
            "before reporting.",
        ),
        relevant_apis=(
            "android:minSdkVersion",
            "<uses-sdk>",
            "Build.VERSION.SDK_INT",
        ),
        evidence_hints=(
            "android:minSdkVersion",
            "<uses-sdk",
            "Build.VERSION.SDK_INT",
        ),
        cwe=("CWE-1104",),
        masvs_refs=("MASVS-CODE-1",),
    ),
    ApkStaticCheck(
        id="APK-MANIFEST-TASK-HIJACK",
        group=ApkStaticGroup.MANIFEST,
        mode=ApkStaticMode.STATIC,
        title="Task-affinity plus singleTask/singleInstance enables StrandHogg hijack.",
        description=(
            "An activity that sets android:taskAffinity together with "
            "android:launchMode=\"singleTask\" or \"singleInstance\" (or "
            "leaves taskAffinity at the default package name while another "
            "app claims the same affinity) can be shadowed by a malicious "
            "app under the StrandHogg / StrandHogg 2.0 pattern. The "
            "malicious activity is presented to the user in place of the "
            "real one, harvesting credentials."
        ),
        verification_steps=(
            "Read AndroidManifest.xml and list every <activity> that "
            "declares android:taskAffinity or android:launchMode.",
            "Flag any activity whose launchMode is singleTask or "
            "singleInstance and whose taskAffinity is set to a non-empty "
            "value, or that leaves taskAffinity at the default and handles "
            "the launcher intent.",
            "Check that the same activities set "
            "android:allowTaskReparenting=\"false\" and either explicitly "
            "set taskAffinity=\"\" or use a unique affinity.",
            "Confirm the flagged activity handles sensitive input "
            "(login form, payment sheet) before reporting.",
        ),
        relevant_apis=(
            "android:taskAffinity",
            "android:launchMode",
            "android:allowTaskReparenting",
        ),
        evidence_hints=(
            "android:taskAffinity",
            "android:launchMode",
            "singleTask",
            "singleInstance",
            "allowTaskReparenting",
        ),
        cwe=("CWE-940",),
        masvs_refs=("MASVS-PLATFORM-1",),
    ),
    ApkStaticCheck(
        id="APK-MANIFEST-FILEPROVIDER",
        group=ApkStaticGroup.MANIFEST,
        mode=ApkStaticMode.STATIC,
        title="FileProvider exposes an over-broad path tree.",
        description=(
            "A FileProvider whose paths resource maps <root-path> or "
            "<external-path> at the filesystem root shares far more than "
            "the export intended. Combined with android:grantUriPermissions "
            "=\"true\", another app that receives a granted content URI can "
            "traverse to arbitrary files under that root."
        ),
        verification_steps=(
            "Read AndroidManifest.xml and locate every <provider> whose "
            "android:name resolves to a FileProvider (androidx.core or "
            "android.support.v4).",
            "read_lines the referenced paths resource under res/xml/ and "
            "flag any <root-path>, <external-path>, or <external-files-path> "
            "with a name/path pointing at the top of a shared tree.",
            "Check android:grantUriPermissions on the <provider> and any "
            "<intent-filter> that would expose the URIs to third parties.",
            "read_function callers of FileProvider.getUriForFile in the "
            "decompiled tree to confirm the app hands out URIs under the "
            "over-broad root.",
        ),
        relevant_apis=(
            "androidx.core.content.FileProvider",
            "<root-path>",
            "<external-path>",
            "android:grantUriPermissions",
        ),
        evidence_hints=(
            "FileProvider",
            "root-path",
            "external-path",
            "grantUriPermissions",
            "getUriForFile",
        ),
        cwe=("CWE-732",),
        masvs_refs=("MASVS-STORAGE-2",),
    ),
    ApkStaticCheck(
        id="APK-MANIFEST-IMPLICIT-PENDINGINTENT",
        group=ApkStaticGroup.MANIFEST,
        mode=ApkStaticMode.STATIC,
        title="Mutable or implicit PendingIntent routed to an internal component.",
        description=(
            "A PendingIntent built with FLAG_MUTABLE (or on pre-31 with no "
            "mutability flag) around an implicit Intent lets the receiving "
            "app rewrite the component, action, and extras before the app "
            "fires it back with the app's own identity. This has been the "
            "root cause of multiple credential-disclosure CVEs in system "
            "apps."
        ),
        verification_steps=(
            "search_functions the decompiled tree for PendingIntent "
            "constructors (getActivity, getBroadcast, getService, "
            "getForegroundService).",
            "read_function each hit and inspect the base Intent: an implicit "
            "Intent (no component set, no explicit package) combined with "
            "FLAG_MUTABLE or an absent immutability flag is a finding.",
            "Confirm the PendingIntent is handed to a third-party surface "
            "(Notification, AppWidget, another app via bindService) rather "
            "than kept internal.",
            "Check the manifest for exported components that would receive "
            "the rewritten intent with elevated privileges.",
        ),
        relevant_apis=(
            "PendingIntent.getActivity",
            "PendingIntent.getBroadcast",
            "PendingIntent.FLAG_MUTABLE",
            "PendingIntent.FLAG_IMMUTABLE",
        ),
        evidence_hints=(
            "PendingIntent.getActivity",
            "PendingIntent.getBroadcast",
            "FLAG_MUTABLE",
            "FLAG_IMMUTABLE",
        ),
        cwe=("CWE-927",),
        masvs_refs=("MASVS-PLATFORM-1",),
    ),
    ApkStaticCheck(
        id="APK-MANIFEST-EXPORTED-PROVIDER",
        group=ApkStaticGroup.MANIFEST,
        mode=ApkStaticMode.STATIC,
        title="Content provider readable or writable by any installed app.",
        description=(
            "A <provider> that is android:exported=\"true\" (or implicitly "
            "exported on targetSdk<17) with no android:readPermission, "
            "android:writePermission, or grantUriPermissions scoping "
            "publishes its content URIs to every app on the device. Any "
            "SQL-backed provider that also builds queries by string "
            "concatenation compounds the exposure with a SQL-injection "
            "surface."
        ),
        verification_steps=(
            "Read AndroidManifest.xml and enumerate every <provider>: record "
            "android:exported, android:readPermission, "
            "android:writePermission, android:grantUriPermissions, and any "
            "<path-permission> children.",
            "Flag providers that are exported with no readPermission or "
            "writePermission at signature-or-higher protectionLevel, and "
            "note the default exported semantics for targetSdk<17.",
            "read_function the ContentProvider subclass in the decompiled "
            "tree and inspect query/insert/update/delete for URI-derived "
            "input reaching SQLiteDatabase.rawQuery or execSQL.",
            "Confirm the provider surfaces sensitive rows (auth tokens, PII, "
            "message bodies) before reporting.",
        ),
        relevant_apis=(
            "android:exported",
            "android:readPermission",
            "android:writePermission",
            "android:grantUriPermissions",
            "ContentProvider.query",
        ),
        evidence_hints=(
            "<provider",
            "android:readPermission",
            "android:writePermission",
            "grantUriPermissions",
            "SQLiteDatabase.rawQuery",
        ),
        cwe=("CWE-926",),
        masvs_refs=("MASVS-PLATFORM-1",),
    ),
    ApkStaticCheck(
        id="APK-SIGNING-V1-ONLY",
        group=ApkStaticGroup.SIGNING,
        mode=ApkStaticMode.STATIC,
        title="APK signed with v1 (JAR) scheme only, no v2/v3/v4.",
        description=(
            "The v1 JAR signing scheme covers only the file entries listed "
            "in the manifest, not the ZIP container structure, and is "
            "vulnerable to a class of DEX-injection attacks on old OS "
            "versions. A production app in 2026 should be signed with "
            "v2 and v3 (Android 7.0 and 9.0 respectively) at minimum."
        ),
        verification_steps=(
            "Inspect the static summary certificates block, or read "
            "META-INF/ in the raw APK, to record which of v1/v2/v3/v4 are "
            "present.",
            "If only v1 is present, record a finding.",
            "If v2 or v3 is present, verify the signer identity matches the "
            "v1 signer (mixed-signer APKs indicate mis-packaging).",
            "Cross-reference the manifest minSdk: v1-only on minSdk<24 is "
            "the Janus prerequisite, escalated separately.",
        ),
        relevant_apis=(
            "META-INF/MANIFEST.MF",
            "META-INF/CERT.SF",
            "APK Signature Scheme v2",
            "APK Signature Scheme v3",
        ),
        evidence_hints=(
            "META-INF/MANIFEST.MF",
            "CERT.SF",
            "APK Signature Scheme v2 Block",
            "APK-SIG-BLOCK-42",
        ),
        cwe=("CWE-347",),
        masvs_refs=("MASVS-RESILIENCE-2",),
    ),
    ApkStaticCheck(
        id="APK-SIGNING-JANUS",
        group=ApkStaticGroup.SIGNING,
        mode=ApkStaticMode.STATIC,
        title="Janus (CVE-2017-13156) preconditions: v1-only signing plus minSdk<24.",
        description=(
            "The Janus vulnerability lets a DEX file be prepended to a "
            "v1-signed APK so the OS loads the injected DEX while the "
            "signature check still passes. Preconditions are: v1 (JAR) "
            "signing scheme with no v2/v3, and an installation target "
            "running Android <7.0 (SDK 24). An app declaring minSdkVersion "
            "below 24 exposes users on those OS releases."
        ),
        verification_steps=(
            "Confirm the APK-SIGNING-V1-ONLY check has fired: only v1 "
            "signing present, no v2/v3 block.",
            "Read AndroidManifest.xml and record android:minSdkVersion from "
            "<uses-sdk>, or the static summary equivalent.",
            "If minSdk<24 AND v1-only, both Janus preconditions are met -- "
            "record a finding.",
            "Confirm the app is a release build (see APK-MANIFEST-DEBUGGABLE "
            "and cert issuer) before reporting.",
        ),
        relevant_apis=(
            "META-INF/MANIFEST.MF",
            "android:minSdkVersion",
            "APK Signature Scheme v2",
        ),
        evidence_hints=(
            "META-INF/MANIFEST.MF",
            "android:minSdkVersion",
            "CVE-2017-13156",
        ),
        cwe=("CWE-347",),
        masvs_refs=("MASVS-RESILIENCE-2",),
    ),
    ApkStaticCheck(
        id="APK-SIGNING-DEBUG-CERT",
        group=ApkStaticGroup.SIGNING,
        mode=ApkStaticMode.STATIC,
        title="APK signed with the Android debug certificate.",
        description=(
            "The Android SDK debug key (CN=Android Debug, O=Android, C=US) "
            "is shared by every developer install and is not a real "
            "authorship signal. A release APK signed with the debug cert "
            "means anyone can build and publish an update that installs "
            "over the app on the same signing identity."
        ),
        verification_steps=(
            "Read the static summary certificates block and record the "
            "signing cert Subject and Issuer.",
            "Flag any signer whose Subject or Issuer contains "
            "\"CN=Android Debug\" or matches the SDK debug key fingerprint "
            "(sha1 61ed377e85d386a8dfee6b864bd85b0bfaa5af81).",
            "Cross-reference APK-MANIFEST-DEBUGGABLE: debug cert plus "
            "debuggable=\"true\" is a debug artifact that should never ship.",
            "Confirm the APK is intended as a release build (versionName, "
            "distribution channel) before reporting.",
        ),
        relevant_apis=(
            "X509Certificate.getSubjectDN",
            "PackageInfo.signatures",
            "PackageInfo.signingInfo",
        ),
        evidence_hints=(
            "CN=Android Debug",
            "O=Android",
            "61ed377e85d386a8dfee6b864bd85b0bfaa5af81",
        ),
        cwe=(),
        masvs_refs=("MASVS-RESILIENCE-2",),
    ),
    ApkStaticCheck(
        id="APK-SIGNING-WEAK-ALGO",
        group=ApkStaticGroup.SIGNING,
        mode=ApkStaticMode.STATIC,
        title="Signing certificate uses MD5- or SHA1-with-RSA signature algorithm.",
        description=(
            "MD5withRSA and SHA1withRSA are broken for signature use: MD5 "
            "collides in seconds, SHA1 was demonstrated collided in 2017. A "
            "signer cert using either algorithm loses its integrity "
            "guarantee, and Play Store now rejects new uploads on these "
            "algorithms."
        ),
        verification_steps=(
            "Read the static summary certificates block and record the "
            "signature_algorithm field for every signer.",
            "Flag any signer whose algorithm is MD5withRSA, SHA1withRSA, "
            "MD2withRSA, or another SHA-1 or MD-family variant.",
            "Confirm the signer is the primary APK signer (not an unrelated "
            "embedded artifact) before reporting.",
        ),
        relevant_apis=(
            "X509Certificate.getSigAlgName",
            "X509Certificate.getSigAlgOID",
        ),
        evidence_hints=(
            "MD5withRSA",
            "SHA1withRSA",
            "SHA1-with-RSA",
            "signature_algorithm",
        ),
        cwe=("CWE-327",),
        masvs_refs=("MASVS-CRYPTO-1",),
    ),
    ApkStaticCheck(
        id="APK-SIGNING-CERT-VALIDITY",
        group=ApkStaticGroup.SIGNING,
        mode=ApkStaticMode.STATIC,
        title="Signing certificate is expired or has a suspicious issuer.",
        description=(
            "Signing certificates are self-issued but should have a "
            "coherent Subject and a validity window that extends past the "
            "supported lifetime of the app. An expired cert, a validity "
            "window ending within months, or a Subject filled with "
            "placeholder or empty fields indicates the signing identity "
            "is not managed and is a candidate for silent replacement."
        ),
        verification_steps=(
            "Read the static summary certificates block and record "
            "Subject, Issuer, notBefore, and notAfter for every signer.",
            "Flag any signer whose notAfter is in the past or within the "
            "next 12 months.",
            "Flag Subject fields whose CN/O/C are empty, contain placeholder "
            "text (\"Unknown\", \"test\", \"example\"), or do not match a "
            "recognisable publisher identity.",
            "Confirm the certificate is the release-channel signer before "
            "reporting.",
        ),
        relevant_apis=(
            "X509Certificate.getNotAfter",
            "X509Certificate.getSubjectX500Principal",
            "X509Certificate.checkValidity",
        ),
        evidence_hints=(
            "notAfter",
            "Subject:",
            "Issuer:",
            "CN=Unknown",
        ),
        cwe=("CWE-298",),
        masvs_refs=("MASVS-RESILIENCE-2",),
    ),
    ApkStaticCheck(
        id="APK-PERM-OVER-REQUEST",
        group=ApkStaticGroup.PERMISSIONS,
        mode=ApkStaticMode.STATIC,
        title="Dangerous permission requested with no matching feature use.",
        description=(
            "A dangerous permission (READ_SMS, ACCESS_FINE_LOCATION, "
            "READ_CONTACTS, RECORD_AUDIO, CAMERA, and so on) declared in "
            "the manifest but never actually consumed by the code violates "
            "the principle of least privilege and widens the app's blast "
            "radius. It also invites platform-store review flags."
        ),
        verification_steps=(
            "Read AndroidManifest.xml and list every <uses-permission> at "
            "protectionLevel=dangerous.",
            "For each permission, search the decompiled tree "
            "(semantic_search / search_functions) for the corresponding "
            "API surface: SmsManager for SMS, LocationManager or FusedLocation "
            "for location, ContactsContract for contacts, MediaRecorder / "
            "AudioRecord for audio, Camera / CameraX for camera.",
            "A dangerous permission with zero call sites is a finding; a "
            "permission with call sites only in an unused library is a "
            "softer finding worth reporting.",
            "Confirm the permission is not exercised through a JavaScript "
            "bridge, native library, or Flutter plugin before reporting.",
        ),
        relevant_apis=(
            "<uses-permission>",
            "PackageManager.checkPermission",
            "ContextCompat.checkSelfPermission",
        ),
        evidence_hints=(
            "<uses-permission",
            "READ_SMS",
            "ACCESS_FINE_LOCATION",
            "RECORD_AUDIO",
            "READ_CONTACTS",
        ),
        cwe=("CWE-250",),
        masvs_refs=("MASVS-PRIVACY-1",),
    ),
    ApkStaticCheck(
        id="APK-PERM-CUSTOM-WEAK",
        group=ApkStaticGroup.PERMISSIONS,
        mode=ApkStaticMode.STATIC,
        title="App-defined permission at protectionLevel=normal guards a sensitive component.",
        description=(
            "A custom <permission> declared at protectionLevel=\"normal\" "
            "(or the pre-M implicit default) is auto-granted to any "
            "installed app and provides no access control. When such a "
            "permission is used to guard an exported activity, service, or "
            "provider that exposes sensitive data or actions, the guard "
            "is cosmetic."
        ),
        verification_steps=(
            "Read AndroidManifest.xml and list every app-defined "
            "<permission>: record android:name and android:protectionLevel.",
            "Flag permissions declared at protectionLevel=\"normal\" (or "
            "absent, which defaults to normal).",
            "For each flagged permission, grep the manifest for components "
            "using it via android:permission, android:readPermission, or "
            "android:writePermission.",
            "read_function the guarded component and confirm it exposes "
            "sensitive data or actions before reporting.",
        ),
        relevant_apis=(
            "<permission>",
            "android:protectionLevel",
            "android:permission",
        ),
        evidence_hints=(
            "<permission ",
            "android:protectionLevel=\"normal\"",
            "android:protectionLevel=\"signature\"",
        ),
        cwe=("CWE-732",),
        masvs_refs=("MASVS-PLATFORM-1",),
    ),
    ApkStaticCheck(
        id="APK-PERM-ACCESSIBILITY",
        group=ApkStaticGroup.PERMISSIONS,
        mode=ApkStaticMode.STATIC,
        title="Service declares BIND_ACCESSIBILITY_SERVICE.",
        description=(
            "A service bound with android:permission="
            "\"android.permission.BIND_ACCESSIBILITY_SERVICE\" receives "
            "AccessibilityEvents for every foreground UI: it can read "
            "on-screen text (including from banking and messaging apps), "
            "issue synthetic gestures, and paint overlays. The permission "
            "belongs only in genuine accessibility products; on any other "
            "app it is the canonical banking-trojan capability."
        ),
        verification_steps=(
            "Read AndroidManifest.xml and locate any <service> whose "
            "android:permission is BIND_ACCESSIBILITY_SERVICE.",
            "Confirm the accompanying <meta-data> "
            "android.accessibilityservice references an accessibility_service "
            "config XML under res/xml/, and read that config to record the "
            "declared event types, feedback types, and canRetrieveWindowContent "
            "flag.",
            "read_function the service class and inspect onAccessibilityEvent "
            "for cross-package event capture, GLOBAL_ACTION dispatch, or "
            "WindowManager overlay usage.",
            "Judge the app's stated purpose against the capability before "
            "reporting: a real accessibility helper is a pass, anything "
            "else is a finding.",
        ),
        relevant_apis=(
            "AccessibilityService",
            "BIND_ACCESSIBILITY_SERVICE",
            "AccessibilityEvent.getSource",
            "AccessibilityService.performGlobalAction",
        ),
        evidence_hints=(
            "BIND_ACCESSIBILITY_SERVICE",
            "AccessibilityService",
            "onAccessibilityEvent",
            "canRetrieveWindowContent",
        ),
        cwe=("CWE-250",),
        masvs_refs=("MASVS-PLATFORM-1",),
    ),
    ApkStaticCheck(
        id="APK-PERM-OVERLAY",
        group=ApkStaticGroup.PERMISSIONS,
        mode=ApkStaticMode.STATIC,
        title="SYSTEM_ALERT_WINDOW without filterTouchesWhenObscured on sensitive views.",
        description=(
            "SYSTEM_ALERT_WINDOW lets the app draw over other apps and, "
            "conversely, tells the platform to trust the app with overlay "
            "capability. Sensitive views (login, confirm-payment, "
            "biometric-consent) that do not set android:"
            "filterTouchesWhenObscured=\"true\" can be tapjacked by "
            "another app that draws a transparent overlay on top and steals "
            "the touch."
        ),
        verification_steps=(
            "Read AndroidManifest.xml and check for <uses-permission "
            "android:name=\"android.permission.SYSTEM_ALERT_WINDOW\"/>.",
            "search_functions the decompiled tree for "
            "WindowManager.addView and TYPE_APPLICATION_OVERLAY /"
            " TYPE_SYSTEM_ALERT to locate overlay creation sites.",
            "read_lines the layouts under res/layout/ that back sensitive "
            "screens (login, transfer, consent) and confirm the root view "
            "sets android:filterTouchesWhenObscured=\"true\", or that the "
            "activity overrides View.onFilterTouchEventForSecurity.",
            "Confirm the flagged screen collects credentials or authorises "
            "a sensitive action before reporting.",
        ),
        relevant_apis=(
            "android.permission.SYSTEM_ALERT_WINDOW",
            "WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY",
            "android:filterTouchesWhenObscured",
            "View.onFilterTouchEventForSecurity",
        ),
        evidence_hints=(
            "SYSTEM_ALERT_WINDOW",
            "TYPE_APPLICATION_OVERLAY",
            "filterTouchesWhenObscured",
            "onFilterTouchEventForSecurity",
        ),
        cwe=("CWE-1021",),
        masvs_refs=("MASVS-PLATFORM-3",),
    ),
    ApkStaticCheck(
        id="APK-PERM-API31-EXPORTED",
        group=ApkStaticGroup.PERMISSIONS,
        mode=ApkStaticMode.STATIC,
        title="targetSdk>=31 component with intent-filter missing explicit android:exported.",
        description=(
            "From Android 12 (API 31) onward, any activity, service, or "
            "receiver that declares an <intent-filter> MUST set "
            "android:exported explicitly; the install fails otherwise. An "
            "app that targets 31+ but declares such a component without "
            "the attribute either fails to install on modern OS or, when "
            "tooling silently defaulted the attribute during build, ships "
            "with an unintended export state."
        ),
        verification_steps=(
            "Read AndroidManifest.xml and record targetSdkVersion.",
            "If targetSdk>=31, list every <activity>, <service>, and "
            "<receiver> that has an <intent-filter> child.",
            "Flag any such component with no android:exported attribute "
            "declared at the component level.",
            "For each flagged component, cross-reference the "
            "APK-MANIFEST-EXPORTED-COMPONENT and APK-MANIFEST-EXPORTED-"
            "PROVIDER checks to characterise the exposure before reporting.",
        ),
        relevant_apis=(
            "android:exported",
            "android:targetSdkVersion",
            "<intent-filter>",
        ),
        evidence_hints=(
            "android:exported",
            "android:targetSdkVersion",
            "<intent-filter>",
        ),
        cwe=("CWE-926",),
        masvs_refs=("MASVS-PLATFORM-1",),
    ),
)
