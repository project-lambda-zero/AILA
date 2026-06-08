"""OWASP MASVS catalog — flat tuple of every catalogued control.

The catalog is populated group by group following the project's
``IMPLEMENTATION_PLAN.md`` (C-1b through C-1i). Each group lives in
its own private tuple (``_STORAGE_CONTROLS``, ``_CRYPTO_CONTROLS``,
…) so future iterations append a group by adding one block and
splicing it into :data:`MASVS_CONTROLS`. Downstream code never sees
the group tuples — it iterates :data:`MASVS_CONTROLS` and filters by
``control.group`` / ``control.level`` itself.

The first batch (this commit) covers the eight L1 MSTG-STORAGE
controls from OWASP MASVS v1.4.2 (the granular MSTG-prefixed ids
that map cleanly onto static-analysis evidence on a decompiled Java
tree). Subsequent commits add the remaining seven groups.

Field rationale per :class:`MasvsControl`:

* ``description`` is paraphrased from the OWASP source rather than
  quoted, so the repository's banned-word policy (see
  ``~/.claude/CLAUDE.md`` and project ``AGENTS.md``) can be enforced
  on the catalog body without round-tripping through external text.
* ``verification_steps`` are written as concrete imperative actions
  the auditor persona executes against ``apk_overview`` + the
  decompiled jadx index, NOT as abstract requirements. They feed
  directly into the child investigation's ``initial_question``.
* ``relevant_apis`` lists the Android / Java / Kotlin / Compose
  symbols the persona should grep for when classifying a finding.
* ``evidence_hints`` are literal substrings the persona feeds into
  ``audit_mcp.semantic_search`` and ``audit_mcp.search_functions``
  against the parent apk_overview's ``audit_mcp_index_id``.
"""
from __future__ import annotations

from aila.modules.vr.masvs.models import MasvsControl, MasvsGroup, MasvsLevel

__all__ = [
    "CATALOG_VERSION",
    "MASVS_CONTROLS",
]


# Catalog spec version pinned on every MASVS audit parent investigation.
# Bumped together with any catalog-content change (new control, edited
# evidence_hints, retired control). Historical audits keep their
# original version on the parent's secondary_target_refs_json so the
# PDF report can label which catalog produced each verdict — later
# edits to this file never silently invalidate a shipped report.
#
# Current value pairs the v1.4.2 MSTG ids that populate STORAGE / CRYPTO
# / AUTH / NETWORK / PLATFORM / CODE / RESILIENCE with the v2.1.0
# PRIVACY group (the only group v1.4.2 omits). The ``-aila`` suffix
# marks this as AILA's compiled snapshot rather than the verbatim OWASP
# release, so a future iteration that lifts PRIVACY into a v2.1.0
# wholesale rewrite can bump the suffix without colliding with an
# upstream tag.
CATALOG_VERSION: str = "1.4.2-aila"


_STORAGE_CONTROLS: tuple[MasvsControl, ...] = (
    MasvsControl(
        id="MSTG-STORAGE-1",
        group=MasvsGroup.STORAGE,
        level=MasvsLevel.L1,
        title=(
            "System credential storage facilities must be used to store sensitive data such as PII, "
            "user credentials, and cryptographic keys."
        ),
        description=(
            "Sensitive runtime data — authentication tokens, session identifiers, payment "
            "credentials, encryption keys, and personally identifiable information — must rest on "
            "the Android Keystore or a Keystore-backed wrapper (EncryptedSharedPreferences, "
            "EncryptedFile, Jetpack Security Crypto). Direct writes to SharedPreferences, plain "
            "SQLite, or app-container files without a Keystore-derived encryption key fail this "
            "control because forensic acquisition of the device file system recovers the data in "
            "clear."
        ),
        verification_steps=(
            "Enumerate every persistent write call (SharedPreferences.Editor.put*, "
            "openFileOutput, SQLiteDatabase.insert/update, Room @Insert) and tag each call site "
            "with the data classification of its payload.",
            "For each call site holding sensitive data, walk the call chain to confirm the "
            "payload is wrapped in EncryptedSharedPreferences / EncryptedFile / a manually-"
            "encrypted blob whose key derives from AndroidKeyStore.",
            "Verify the underlying KeyGenParameterSpec uses setUserAuthenticationRequired or "
            "setUnlockedDeviceRequired where appropriate and that the key alias is not exported "
            "or written out of the Keystore boundary.",
        ),
        relevant_apis=(
            "android.security.keystore.KeyGenParameterSpec",
            "android.security.keystore.KeyProperties",
            "java.security.KeyStore.getInstance(\"AndroidKeyStore\")",
            "javax.crypto.KeyGenerator.getInstance",
            "androidx.security.crypto.EncryptedSharedPreferences",
            "androidx.security.crypto.EncryptedFile",
            "androidx.security.crypto.MasterKey",
            "android.content.SharedPreferences.Editor.putString",
            "android.database.sqlite.SQLiteDatabase",
        ),
        evidence_hints=(
            "EncryptedSharedPreferences",
            "AndroidKeyStore",
            "KeyGenParameterSpec",
            "MasterKey.Builder",
            "getSharedPreferences",
            "openFileOutput",
            "SQLiteOpenHelper",
            "Room",
        ),
    ),
    MasvsControl(
        id="MSTG-STORAGE-2",
        group=MasvsGroup.STORAGE,
        level=MasvsLevel.L1,
        title=(
            "Sensitive data must not be stored outside of the app container or system credential "
            "storage facilities."
        ),
        description=(
            "Any directory reachable without the app's UID (external storage, public MediaStore "
            "collections, world-readable cache directories, SD card paths) is shared with every "
            "other app that holds the corresponding storage permission. Writing sensitive data "
            "to those locations exposes it to co-installed apps and to anyone with physical or "
            "ADB access to the device. The verification target is therefore that every write "
            "containing sensitive data terminates inside the private app container or the "
            "Keystore."
        ),
        verification_steps=(
            "Locate every external-storage path resolver call (Environment.getExternalStorage*, "
            "Context.getExternalFilesDir, MediaStore content URIs) and capture the file payloads "
            "those paths receive.",
            "Map each manifest permission of WRITE_EXTERNAL_STORAGE / READ_EXTERNAL_STORAGE / "
            "MANAGE_EXTERNAL_STORAGE to its runtime request sites and the data those sites end "
            "up writing.",
            "Confirm that any sensitive payload (tokens, credentials, account data, financial "
            "records) reaching an external path is first encrypted with a Keystore-backed key "
            "and that decryption keys are never co-located with the ciphertext on external "
            "storage.",
        ),
        relevant_apis=(
            "android.os.Environment.getExternalStorageDirectory",
            "android.os.Environment.getExternalStoragePublicDirectory",
            "android.content.Context.getExternalFilesDir",
            "android.content.Context.getExternalCacheDir",
            "android.provider.MediaStore",
            "android.content.ContentResolver.openOutputStream",
            "java.io.FileOutputStream",
            "androidx.core.content.FileProvider",
        ),
        evidence_hints=(
            "getExternalStorageDirectory",
            "getExternalFilesDir",
            "WRITE_EXTERNAL_STORAGE",
            "MANAGE_EXTERNAL_STORAGE",
            "MediaStore",
            "FileProvider",
            "openOutputStream",
            "FileOutputStream",
        ),
    ),
    MasvsControl(
        id="MSTG-STORAGE-3",
        group=MasvsGroup.STORAGE,
        level=MasvsLevel.L1,
        title="No sensitive data must be written to application logs.",
        description=(
            "Android log buffers are accessible to every process on the device that holds the "
            "READ_LOGS permission (debug builds, OEM diagnostic tooling, USB-connected "
            "developers, on-device crash collectors). Any token, credential, request body, or "
            "PII written to ``android.util.Log`` — directly or via wrappers like Timber, "
            "OkHttp's HttpLoggingInterceptor, or Throwable.printStackTrace — is therefore "
            "exfiltratable. The verification target is that release builds either strip "
            "logging entirely (via R8 / ProGuard rules) or that every log site provably emits "
            "non-sensitive content."
        ),
        verification_steps=(
            "Scan every Log.{v,d,i,w,e,wtf} / System.out.println / printStackTrace / "
            "HttpLoggingInterceptor / Timber call site and capture its argument expressions.",
            "For each call site, classify the argument payload (constant string, request body, "
            "response body, exception message, model object .toString) and flag any payload "
            "that may carry tokens, credentials, request bodies with Authorization headers, or "
            "PII fields.",
            "Verify ProGuard / R8 rules strip ``android.util.Log`` and equivalent loggers in "
            "release builds, OR that every flagged call site is wrapped in a "
            "``BuildConfig.DEBUG`` guard so it does not execute in release configuration.",
        ),
        relevant_apis=(
            "android.util.Log",
            "java.lang.System.out",
            "java.lang.System.err",
            "java.lang.Throwable.printStackTrace",
            "okhttp3.logging.HttpLoggingInterceptor",
            "timber.log.Timber",
            "org.slf4j.Logger",
            "android.util.EventLog",
        ),
        evidence_hints=(
            "Log.d",
            "Log.v",
            "Log.i",
            "Log.e",
            "Log.wtf",
            "HttpLoggingInterceptor",
            "Timber.tag",
            "printStackTrace",
            "System.out.println",
            "BuildConfig.DEBUG",
        ),
    ),
    MasvsControl(
        id="MSTG-STORAGE-4",
        group=MasvsGroup.STORAGE,
        level=MasvsLevel.L1,
        title=(
            "No sensitive data is shared with third parties unless it is a necessary part of the "
            "architecture."
        ),
        description=(
            "Analytics, crash-reporting, advertising, attribution, and customer-support SDKs are "
            "embedded with the same UID as the app and inherit every grant the user issued. Any "
            "data fed into ``logEvent`` / ``setUserProperty`` / ``recordException`` / ``track`` "
            "leaves the device toward third-party infrastructure operating under their own "
            "retention policy. Sensitive payloads (PII, account identifiers tied to a real "
            "person, payment data, auth tokens) must not be routed into those SDKs unless the "
            "data flow is documented in the app's privacy policy and required by the feature."
        ),
        verification_steps=(
            "Enumerate every third-party SDK in the dependency graph (Firebase, Crashlytics, "
            "Sentry, Mixpanel, Amplitude, AppsFlyer, Adjust, Branch, Facebook SDK, AdMob, "
            "Bugsnag, Datadog RUM, Instabug).",
            "For each SDK, locate every call site emitting events / user properties / breadcrumbs "
            "/ custom keys / exceptions and capture the argument expressions feeding those "
            "calls.",
            "Cross-reference the captured payloads against the app's data classification — "
            "verify no PII, auth tokens, payment data, or account secrets are emitted, and "
            "verify the data flow appears in the published privacy policy when any quasi-"
            "identifier (device id, advertising id, email hash) is shared.",
        ),
        relevant_apis=(
            "com.google.firebase.analytics.FirebaseAnalytics",
            "com.google.firebase.crashlytics.FirebaseCrashlytics",
            "io.sentry.Sentry",
            "com.mixpanel.android.mpmetrics.MixpanelAPI",
            "com.amplitude.api.Amplitude",
            "com.appsflyer.AppsFlyerLib",
            "com.adjust.sdk.Adjust",
            "com.facebook.appevents.AppEventsLogger",
        ),
        evidence_hints=(
            "FirebaseAnalytics",
            "Crashlytics",
            "Sentry.capture",
            "Mixpanel",
            "Amplitude",
            "AppsFlyerLib",
            "Adjust.trackEvent",
            "logEvent",
            "setUserProperty",
            "recordException",
        ),
    ),
    MasvsControl(
        id="MSTG-STORAGE-5",
        group=MasvsGroup.STORAGE,
        level=MasvsLevel.L1,
        title=(
            "The keyboard cache must be disabled on text inputs that process sensitive data."
        ),
        description=(
            "Android IMEs (the Google Keyboard, Samsung Keyboard, SwiftKey, third-party IMEs) "
            "build a personalized prediction dictionary from text the user types into ordinary "
            "input fields. Tokens, OTPs, payment card numbers, account numbers, and similar "
            "high-entropy secrets that flow through such a field land in that dictionary and "
            "subsequently appear as autocomplete suggestions in unrelated apps. Sensitive input "
            "fields must opt out of suggestion / autofill / personalisation via "
            "``inputType=textNoSuggestions`` (or password variants) and "
            "``importantForAutofill=no`` where the autofill framework would otherwise capture "
            "the value."
        ),
        verification_steps=(
            "Locate every EditText / TextInputEditText in the inflated XML layouts and every "
            "Jetpack Compose TextField in source, then identify the subset whose semantics "
            "carry sensitive data (passwords, OTPs, PINs, payment data, security questions).",
            "For each sensitive XML field, confirm the inputType bitmask includes "
            "``textNoSuggestions`` (or a textPassword / numberPassword variant) and "
            "``android:importantForAutofill`` excludes the value when autofill should not "
            "capture it.",
            "For each sensitive Compose field, confirm KeyboardOptions sets "
            "autoCorrect=false, keyboardType=Password / NumberPassword, and that "
            "visualTransformation is PasswordVisualTransformation for credential entry.",
        ),
        relevant_apis=(
            "android:inputType",
            "android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS",
            "android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD",
            "android:importantForAutofill",
            "androidx.compose.foundation.text.KeyboardOptions",
            "androidx.compose.ui.text.input.KeyboardType.Password",
            "androidx.compose.ui.text.input.PasswordVisualTransformation",
            "com.google.android.material.textfield.TextInputEditText",
        ),
        evidence_hints=(
            "inputType",
            "textNoSuggestions",
            "textPassword",
            "numberPassword",
            "importantForAutofill",
            "KeyboardOptions",
            "KeyboardType.Password",
            "PasswordVisualTransformation",
        ),
    ),
    MasvsControl(
        id="MSTG-STORAGE-6",
        group=MasvsGroup.STORAGE,
        level=MasvsLevel.L1,
        title="No sensitive data must be exposed via IPC mechanisms.",
        description=(
            "Exported Activities, Services, BroadcastReceivers, and ContentProviders form the "
            "app's inter-process surface. Any co-installed app on the device can invoke them "
            "unless explicit signature-level permissions guard the call. A finding here means "
            "an external caller can read sensitive data out of the app — either via an "
            "intentionally-exported component returning data without permission checks, or via "
            "an implicit pending intent that leaks the receiving app's grant to a malicious "
            "redirect target. The verification target is that every exported surface either "
            "returns no sensitive data or enforces a signature-level permission."
        ),
        verification_steps=(
            "Parse the merged AndroidManifest.xml and list every component declared with "
            "``android:exported=\"true\"`` (or implicitly exported via an intent-filter).",
            "For each exported component, trace its entry point (onCreate / onStartCommand / "
            "onReceive / query / insert / update / delete / call) and identify what data it "
            "returns, writes, or makes reachable via the resulting Cursor / Bundle / Intent.",
            "Verify every exported component that handles sensitive data declares a "
            "signature-level permission via ``android:permission`` (defined with "
            "``protectionLevel=signature``) AND that the implementation rechecks the caller's "
            "identity (Binder.getCallingUid, getCallingPackage) instead of relying on the "
            "manifest declaration alone.",
        ),
        relevant_apis=(
            "android.content.ContentProvider",
            "android.app.Service",
            "android.app.Activity",
            "android.content.BroadcastReceiver",
            "android.os.Binder.getCallingUid",
            "android.os.Binder.getCallingPid",
            "android.content.Intent",
            "android.app.PendingIntent",
        ),
        evidence_hints=(
            "android:exported=\"true\"",
            "android:permission",
            "protectionLevel=\"signature\"",
            "intent-filter",
            "ContentProvider",
            "BroadcastReceiver",
            "getStringExtra",
            "PendingIntent.getActivity",
            "Binder.getCallingUid",
        ),
    ),
    MasvsControl(
        id="MSTG-STORAGE-7",
        group=MasvsGroup.STORAGE,
        level=MasvsLevel.L1,
        title=(
            "Sensitive data such as passwords, PINs, and one-time codes must not be exposed "
            "through the user interface."
        ),
        description=(
            "Screen content is visible to anyone with line-of-sight to the device, harvestable "
            "by malicious overlays (TYPE_APPLICATION_OVERLAY) under poor user-permission "
            "hygiene, and captured by the OS's recent-apps screenshot snapshotter. Credentials, "
            "PINs, OTPs, and payment details rendered without masking violate this control. "
            "The verification target is that every sensitive field uses a "
            "PasswordTransformationMethod (or Compose equivalent) and that activities rendering "
            "such data set FLAG_SECURE so the OS does not write a thumbnail of the screen to "
            "disk."
        ),
        verification_steps=(
            "Identify every UI field rendering a password, PIN, OTP, or full payment-card "
            "number (XML EditText with inputType containing Password, Compose TextField with "
            "PasswordVisualTransformation, custom Canvas-drawn views).",
            "Confirm every such field applies the masking transformation by default and only "
            "lifts it via an explicit user gesture (the eye-icon reveal pattern), never via "
            "passive timeouts or default-visible state.",
            "Inspect each Activity hosting sensitive UI for "
            "``WindowManager.LayoutParams.FLAG_SECURE`` (set via ``window.setFlags`` or "
            "``window.addFlags``) so the OS does not snapshot the activity for the recent-"
            "apps switcher.",
        ),
        relevant_apis=(
            "android.view.WindowManager.LayoutParams.FLAG_SECURE",
            "android.text.method.PasswordTransformationMethod",
            "android.widget.EditText.setTransformationMethod",
            "androidx.compose.ui.text.input.PasswordVisualTransformation",
            "android.view.Window.setFlags",
            "android.view.Window.addFlags",
        ),
        evidence_hints=(
            "FLAG_SECURE",
            "PasswordTransformationMethod",
            "setTransformationMethod",
            "PasswordVisualTransformation",
            "textPassword",
            "window.addFlags",
            "WindowManager.LayoutParams",
        ),
    ),
    MasvsControl(
        id="MSTG-STORAGE-12",
        group=MasvsGroup.STORAGE,
        level=MasvsLevel.L1,
        title=(
            "The app must educate the user about the types of personally identifiable "
            "information it processes and the security practices the user should follow."
        ),
        description=(
            "Static analysis can not measure user comprehension, but it can verify the "
            "presence of the building blocks that user education depends on: a reachable "
            "privacy policy, a first-run consent or notice surface that lists the categories "
            "of PII the app processes, and contextual prompts at the point of sensitive data "
            "collection (camera, location, contacts, biometrics). A finding here means the app "
            "collects PII but offers no visible disclosure to the user. The verification target "
            "is presence of these surfaces, not their narrative quality."
        ),
        verification_steps=(
            "Search the resource bundle (strings.xml across locales, raw assets, embedded "
            "HTML) for a privacy policy URL, terms of service URL, or onboarding consent text "
            "that names the PII categories the app collects.",
            "Trace the navigation graph from the launcher Activity and identify the screen "
            "(or web view) that surfaces the privacy policy to the user — confirm it is "
            "reachable from a top-level menu, the settings screen, or the first-run flow.",
            "For each runtime-dangerous permission requested (Manifest.permission.CAMERA, "
            "ACCESS_FINE_LOCATION, READ_CONTACTS, READ_PHONE_STATE, USE_BIOMETRIC, …), confirm "
            "an in-app rationale surface explains why the permission is required before the "
            "OS permission dialog fires (shouldShowRequestPermissionRationale path).",
        ),
        relevant_apis=(
            "androidx.core.app.ActivityCompat.shouldShowRequestPermissionRationale",
            "android.Manifest.permission.CAMERA",
            "android.Manifest.permission.ACCESS_FINE_LOCATION",
            "android.Manifest.permission.READ_CONTACTS",
            "android.Manifest.permission.READ_PHONE_STATE",
            "android.content.Intent.ACTION_VIEW",
            "android.webkit.WebView",
        ),
        evidence_hints=(
            "privacy_policy",
            "privacy policy",
            "terms_of_service",
            "shouldShowRequestPermissionRationale",
            "onboarding",
            "consent",
            "PII",
            "data_processing",
        ),
    ),
)


_CRYPTO_CONTROLS: tuple[MasvsControl, ...] = (
    MasvsControl(
        id="MSTG-CRYPTO-1",
        group=MasvsGroup.CRYPTO,
        level=MasvsLevel.L1,
        title=(
            "The app does not rely on symmetric cryptography with hardcoded keys as a sole "
            "method of encryption."
        ),
        description=(
            "A symmetric key embedded in the APK — as a string literal in dex, a byte array "
            "constant in a native library, a resource file, or a BuildConfig field — is "
            "recoverable by anyone who can read the file off the device or pull it from any "
            "app store mirror. Once recovered, the key decrypts every payload the app has "
            "ever produced under it, including data exfiltrated from backups or transit "
            "captures. Symmetric keys protecting sensitive data must therefore derive from a "
            "Keystore-resident master key, from a user-supplied passphrase passed through "
            "PBKDF2 / Argon2 with a per-install random salt, or from a server-issued "
            "per-session key — never from a constant baked into the binary."
        ),
        verification_steps=(
            "Enumerate every javax.crypto.spec.SecretKeySpec / IvParameterSpec / PBEKeySpec "
            "/ SecretKey instantiation and capture the byte source feeding the constructor "
            "(string literal, hex constant, BuildConfig field, resource read, JNI call, "
            "Keystore alias, network response).",
            "For every key whose source is a constant inside the APK, classify the data it "
            "protects (token, payment data, session secret, local DB row, settings blob) and "
            "flag the call site as a finding when the data classification is sensitive.",
            "For keys derived from a passphrase, confirm a per-install random salt is used "
            "(SecureRandom-generated, persisted out-of-band from the ciphertext) and that "
            "the KDF is PBKDF2 with iteration count at or above 10000 or a memory-hard "
            "alternative (scrypt, Argon2).",
        ),
        relevant_apis=(
            "javax.crypto.spec.SecretKeySpec",
            "javax.crypto.spec.IvParameterSpec",
            "javax.crypto.spec.PBEKeySpec",
            "javax.crypto.SecretKey",
            "javax.crypto.Cipher.init",
            "javax.crypto.SecretKeyFactory.generateSecret",
            "java.security.KeyStore.getKey",
            "android.security.keystore.KeyGenParameterSpec",
        ),
        evidence_hints=(
            "SecretKeySpec",
            "PBEKeySpec",
            "Cipher.getInstance",
            "Cipher.init",
            "new String(",
            "getBytes()",
            "BuildConfig.",
            "AES",
            "HmacSHA",
        ),
    ),
    MasvsControl(
        id="MSTG-CRYPTO-2",
        group=MasvsGroup.CRYPTO,
        level=MasvsLevel.L1,
        title="The app uses proven implementations of cryptographic primitives.",
        description=(
            "Hand-rolled cryptography — XOR loops, bespoke S-box substitutions, custom "
            "stream-cipher constructions, reimplemented hash functions — historically "
            "introduces side-channel and bias defects that the audited primitives in the "
            "JCA, Conscrypt, Tink, and Bouncy Castle do not have. The verification target "
            "is that every cryptographic operation routes through a reviewed provider "
            "(AndroidOpenSSL / Conscrypt / BC / SunJCE / Tink) and that any class whose "
            "name or shape resembles a cryptographic primitive is in fact a thin wrapper "
            "around such a provider, not an independent implementation."
        ),
        verification_steps=(
            "List every javax.crypto.* / java.security.* call site and confirm the provider "
            "resolution lands on a reviewed provider (AndroidOpenSSL, Conscrypt, Bouncy "
            "Castle, SunJCE, Tink) rather than a custom Provider subclass.",
            "Enumerate classes whose names contain Cipher / Crypt / Hash / Digest / Encrypt "
            "/ Decrypt / AES / RSA but are not part of a known dependency, and inspect "
            "their bodies for bitwise loops (XOR, ROT, S-box lookups) that indicate an "
            "in-tree cryptographic implementation.",
            "For every Security.addProvider / Security.insertProviderAt call, verify the "
            "added Provider is a reviewed third-party package — raise a finding against "
            "any locally-defined Provider that injects custom Cipher / MessageDigest / Mac "
            "SPIs.",
        ),
        relevant_apis=(
            "javax.crypto.Cipher.getInstance",
            "java.security.MessageDigest.getInstance",
            "javax.crypto.Mac.getInstance",
            "javax.crypto.KeyGenerator.getInstance",
            "java.security.Provider",
            "java.security.Security.addProvider",
            "java.security.Security.insertProviderAt",
            "org.bouncycastle.jce.provider.BouncyCastleProvider",
        ),
        evidence_hints=(
            "Cipher.getInstance",
            "MessageDigest.getInstance",
            "Mac.getInstance",
            "addProvider",
            "BouncyCastleProvider",
            "Conscrypt",
            "extends Provider",
            "implements Cipher",
            "^ 0x",
        ),
    ),
    MasvsControl(
        id="MSTG-CRYPTO-3",
        group=MasvsGroup.CRYPTO,
        level=MasvsLevel.L1,
        title=(
            "The app uses cryptographic primitives that are appropriate for the particular "
            "use-case, configured with parameters that adhere to industry best practices."
        ),
        description=(
            "Selecting AES is necessary but not sufficient — the mode of operation, IV "
            "discipline, padding, key length, and authenticated-encryption choice "
            "determine whether the construction is sound. AES/ECB leaks plaintext "
            "structure. AES/CBC without an accompanying MAC accepts ciphertext "
            "modifications. AES/GCM with a reused (key, IV) pair loses both confidentiality "
            "and authenticity. PBKDF2 with low iteration count or a constant salt collapses "
            "to a dictionary lookup. The verification target is that every primitive choice "
            "and parameter set holds up against the current NIST / ECRYPT / OWASP guidance "
            "for the use-case in question."
        ),
        verification_steps=(
            "For every Cipher.getInstance(…) call, capture the transformation string and "
            "flag any mode of ECB, CBC without an accompanying MAC, or stream cipher reused "
            "across messages.",
            "For every AES/GCM call site, trace the IV / nonce source — confirm it is drawn "
            "from SecureRandom per encryption (or is a monotonically-incrementing counter "
            "under a single-writer guarantee) rather than zeroed, constant, or reused across "
            "messages.",
            "For every PBEKeySpec / SecretKeyFactory.PBKDF2WithHmacSHA* call, capture "
            "iterationCount and salt source — flag iterationCount below 10000 (legacy "
            "minimum) and any salt that is a constant, the username, or shared across "
            "users.",
        ),
        relevant_apis=(
            "javax.crypto.Cipher.getInstance",
            "javax.crypto.spec.IvParameterSpec",
            "javax.crypto.spec.GCMParameterSpec",
            "javax.crypto.spec.PBEKeySpec",
            "javax.crypto.SecretKeyFactory.getInstance",
            "java.security.SecureRandom.nextBytes",
            "android.security.keystore.KeyGenParameterSpec.Builder",
            "android.security.keystore.KeyProperties.BLOCK_MODE_GCM",
        ),
        evidence_hints=(
            "AES/ECB",
            "AES/CBC",
            "AES/GCM",
            "DES/",
            "GCMParameterSpec",
            "IvParameterSpec",
            "PBEKeySpec",
            "PBKDF2WithHmac",
            "iterationCount",
            "BLOCK_MODE",
        ),
    ),
    MasvsControl(
        id="MSTG-CRYPTO-4",
        group=MasvsGroup.CRYPTO,
        level=MasvsLevel.L1,
        title=(
            "The app does not use cryptographic protocols or algorithms that are widely "
            "considered deprecated for security purposes."
        ),
        description=(
            "MD5 and SHA-1 are broken against collision resistance and must not appear in "
            "any security-relevant context (signature verification, certificate pinning, "
            "integrity checks, password storage). DES, 3DES, RC4, and RC2 fall below the "
            "112-bit security floor most regulators require. SSLv3 / TLSv1.0 / TLSv1.1 are "
            "decommissioned. Findings here apply when a deprecated primitive is reachable "
            "from a security-relevant code path — non-security uses (content-addressable "
            "caches keyed by MD5, file deduplication) are out of scope and should be "
            "tagged not_applicable."
        ),
        verification_steps=(
            "Search every MessageDigest.getInstance / Mac.getInstance / Cipher.getInstance "
            "call site for the deprecated set — MD5, MD2, SHA-1, SHA1, DES, DESede, 3DES, "
            "RC4, RC2, Blowfish — and capture each match's surrounding context.",
            "For every match, classify the use as security-relevant (token derivation, "
            "signature verification, password hash, integrity check, TLS pinning hash) or "
            "non-security (cache key, file dedupe, content hash for analytics) and raise a "
            "finding only on the security-relevant subset.",
            "Inspect every SSLContext.getInstance / SSLSocketFactory configuration for "
            "explicit enablement of SSLv3 / TLSv1.0 / TLSv1.1, and inspect "
            "network_security_config.xml for protocol overrides that re-enable a "
            "deprecated TLS version.",
        ),
        relevant_apis=(
            "java.security.MessageDigest.getInstance",
            "javax.crypto.Mac.getInstance",
            "javax.crypto.Cipher.getInstance",
            "javax.net.ssl.SSLContext.getInstance",
            "javax.net.ssl.SSLSocket.setEnabledProtocols",
            "okhttp3.ConnectionSpec.Builder.tlsVersions",
            "okhttp3.TlsVersion",
        ),
        evidence_hints=(
            "MD5",
            "SHA-1",
            "SHA1",
            "DES",
            "DESede",
            "3DES",
            "RC4",
            "Blowfish",
            "TLSv1",
            "SSLv3",
        ),
    ),
    MasvsControl(
        id="MSTG-CRYPTO-5",
        group=MasvsGroup.CRYPTO,
        level=MasvsLevel.L1,
        title="The app does not re-use the same cryptographic key for multiple purposes.",
        description=(
            "Reusing a single symmetric key for encryption and authentication, for two "
            "independent encryption channels, or for both data-at-rest and data-in-transit "
            "couples the security of those purposes together — a flaw in one operation "
            "lowers the security of every other operation under the same key. The "
            "verification target is that every distinct cryptographic purpose binds to a "
            "distinct key, ideally derived from a single root key via HKDF with a "
            "purpose-specific info parameter, or via separate KeyGenerator runs."
        ),
        verification_steps=(
            "Enumerate every javax.crypto.SecretKey / KeyStore.Entry obtained in the code "
            "base, capturing the alias / variable name and every call site that uses it "
            "(Cipher.init, Mac.init, Signature.initSign, KeyAgreement).",
            "Build the matrix of (key, purpose) pairs and flag any key reused across two "
            "distinct security-relevant purposes (encryption + MAC, two unrelated "
            "encryption channels, both at-rest and in-transit, both signing and key "
            "wrapping).",
            "Where a single root key is intentionally shared, verify per-purpose subkey "
            "derivation through HKDF (javax.crypto.KeyGenerator with an HKDF transformation, "
            "Tink's HKDF, or BC's HKDFBytesGenerator) with a purpose-specific info "
            "parameter that distinguishes the use.",
        ),
        relevant_apis=(
            "java.security.KeyStore.getKey",
            "java.security.KeyStore.getEntry",
            "javax.crypto.SecretKey",
            "javax.crypto.Mac.init",
            "javax.crypto.Cipher.init",
            "java.security.Signature.initSign",
            "javax.crypto.KeyGenerator.generateKey",
            "org.bouncycastle.crypto.generators.HKDFBytesGenerator",
        ),
        evidence_hints=(
            "KeyStore.getKey",
            "KeyStore.getEntry",
            "KeyGenerator.generateKey",
            "Cipher.init",
            "Mac.init",
            "HKDF",
            "deriveKey",
            "info=",
        ),
    ),
    MasvsControl(
        id="MSTG-CRYPTO-6",
        group=MasvsGroup.CRYPTO,
        level=MasvsLevel.L1,
        title=(
            "All random values are generated using a sufficiently secure random number "
            "generator."
        ),
        description=(
            "java.util.Random and Math.random are linear congruential generators whose "
            "next output is predictable from a small handful of prior outputs — they must "
            "not produce security-relevant values (session ids, nonces, OTPs, salts, IVs, "
            "key material, CSRF tokens). java.security.SecureRandom routed through the "
            "AndroidOpenSSL / Conscrypt provider draws from /dev/urandom and is the "
            "correct primitive. Seeding SecureRandom with a constant or with a "
            "known-low-entropy value (System.currentTimeMillis, the device id) "
            "neutralises the upgrade and re-introduces the predictability defect."
        ),
        verification_steps=(
            "Enumerate every java.util.Random / Math.random / ThreadLocalRandom call site "
            "and capture what each random value is used for (UI animation jitter, retry "
            "backoff, security-relevant token, IV, salt, key generation).",
            "Flag any security-relevant value (nonce, salt, IV, session id, OTP, CSRF "
            "token, key bytes) produced by a non-SecureRandom source as a finding.",
            "For every SecureRandom usage, verify no SecureRandom.setSeed(…) call feeds a "
            "constant, a low-entropy clock value, or a device identifier — any such call "
            "neutralises the generator and must be removed.",
        ),
        relevant_apis=(
            "java.security.SecureRandom",
            "java.security.SecureRandom.nextBytes",
            "java.security.SecureRandom.getInstanceStrong",
            "java.util.Random",
            "java.util.concurrent.ThreadLocalRandom",
            "java.lang.Math.random",
            "kotlin.random.Random",
        ),
        evidence_hints=(
            "SecureRandom",
            "getInstanceStrong",
            "setSeed",
            "java.util.Random",
            "Math.random",
            "ThreadLocalRandom",
            "kotlin.random.Random",
            "nextBytes",
            "nextInt",
        ),
    ),
)


_AUTH_CONTROLS: tuple[MasvsControl, ...] = (
    MasvsControl(
        id="MSTG-AUTH-1",
        group=MasvsGroup.AUTH,
        level=MasvsLevel.L1,
        title=(
            "If the app provides users access to a remote service, some form of authentication "
            "such as username/password authentication is performed at the remote endpoint."
        ),
        description=(
            "Every protected operation an app exposes — reading user records, writing user "
            "records, triggering account actions, viewing financial data — must verify the "
            "requesting user's identity at the server before responding. Client-only checks "
            "(UI flags, hidden screens, role booleans the client trusts) are flippable by a "
            "repackaged APK, by a rooted device, or by anyone running a Frida script against "
            "their own install, and therefore do not satisfy this control. The verification "
            "target is that every protected endpoint requires a server-validated credential "
            "(session cookie, bearer token, mTLS certificate, signed request) and that the "
            "client transmits that credential on every protected call."
        ),
        verification_steps=(
            "Enumerate every Retrofit / OkHttp / HttpURLConnection / Volley call site and "
            "record the endpoint path plus whether the request carries an Authorization "
            "header or a session cookie.",
            "Identify the login flow (screens that submit credentials) and trace the resulting "
            "token / session id into client storage; confirm protected endpoint calls reuse "
            "that token rather than recomputing access from a local flag.",
            "Flag any 'guest', 'anonymous', or 'offline' mode that returns non-public data "
            "without a server-validated token, including offline caches whose freshness is "
            "never re-checked against the server.",
        ),
        relevant_apis=(
            "okhttp3.Interceptor.intercept",
            "okhttp3.OkHttpClient.Builder.addInterceptor",
            "retrofit2.http.Header",
            "retrofit2.http.Headers",
            "java.net.HttpURLConnection.setRequestProperty",
            "com.android.volley.toolbox.JsonObjectRequest",
            "android.webkit.CookieManager",
            "okhttp3.CookieJar",
        ),
        evidence_hints=(
            "Authorization",
            "Bearer ",
            "@Header",
            "addHeader",
            "OkHttpClient",
            "Retrofit",
            "login",
            "signin",
            "CookieJar",
        ),
    ),
    MasvsControl(
        id="MSTG-AUTH-2",
        group=MasvsGroup.AUTH,
        level=MasvsLevel.L1,
        title=(
            "If stateful session management is used, the remote endpoint uses randomly "
            "generated session identifiers to authenticate client requests without sending "
            "the user's credentials."
        ),
        description=(
            "After the initial login the client must reference the user's session via an "
            "opaque server-issued identifier (session cookie, server-side bearer token) and "
            "must never replay the username, password, or PIN on subsequent requests. "
            "Replaying credentials extends their exposure across every request log, every "
            "TLS-terminating proxy, and every crash report that captures a request body. The "
            "verification target is that credentials appear in exactly one request (the login "
            "submission), the session identifier is treated as opaque (never parsed, "
            "modified, or recomputed client-side), and the identifier carries enough entropy "
            "that brute-force enumeration over a realistic budget is infeasible."
        ),
        verification_steps=(
            "Identify every endpoint that receives credentials (request body keyed by "
            "'password' / 'pin' / 'credential' / 'secret') and confirm credentials appear "
            "only on the /login or equivalent registration endpoint, never on subsequent "
            "calls.",
            "Inspect the login response handler to identify the session token or cookie "
            "returned by the server, then trace where it is persisted (SharedPreferences, "
            "EncryptedSharedPreferences, AccountManager, in-memory only) and how it travels "
            "with later requests.",
            "Verify the session identifier is treated as opaque on the client — no Base64 "
            "decode-then-mutate, no client-side issuance, no concatenation with locally "
            "derived data that the server then trusts.",
        ),
        relevant_apis=(
            "okhttp3.Cookie",
            "okhttp3.CookieJar",
            "java.net.CookieHandler",
            "android.webkit.CookieManager.setCookie",
            "android.accounts.AccountManager.setAuthToken",
            "android.content.SharedPreferences.Editor.putString",
            "androidx.security.crypto.EncryptedSharedPreferences",
            "retrofit2.http.Body",
        ),
        evidence_hints=(
            "Set-Cookie",
            "JSESSIONID",
            "PHPSESSID",
            "session_id",
            "sessionId",
            "CookieJar",
            "password",
            "credential",
            "setAuthToken",
        ),
    ),
    MasvsControl(
        id="MSTG-AUTH-3",
        group=MasvsGroup.AUTH,
        level=MasvsLevel.L1,
        title=(
            "If stateless token-based authentication is used, the server provides a token "
            "that has been signed using a secure algorithm."
        ),
        description=(
            "Stateless tokens such as JWTs encode their own validity claims and must be "
            "rejected by the verifier when the signature is missing, when the declared "
            "algorithm is 'none', or when the signing key has been substituted for a "
            "client-controllable value. From the APK side the verification target is that "
            "the client never mints its own tokens (a client-side issuer means the server "
            "is not verifying), never parses 'alg: none' as acceptable, and never trusts "
            "the alg header from the token without checking the expected algorithm against "
            "a fixed allowlist."
        ),
        verification_steps=(
            "Locate JWT-handling libraries on the classpath (java-jwt, jose4j, nimbus-jose-"
            "jwt, jjwt) and inspect every verify / parse call to confirm a signature check "
            "is enforced and the algorithm comes from a fixed allowlist (RS256 / ES256 / "
            "HS256 with strong secret).",
            "Flag any code path that issues a JWT from the client (Jwts.builder().signWith) "
            "and any code that accepts an unsigned token (JwtParserBuilder without "
            ".verifyWith / .setSigningKey) as a finding.",
            "Inspect alg-handling code for explicit acceptance of 'none' or for derivation "
            "of the verification algorithm from the token's own header.alg field — both are "
            "the canonical JWT confusion patterns.",
        ),
        relevant_apis=(
            "io.jsonwebtoken.Jwts.parser",
            "io.jsonwebtoken.Jwts.builder",
            "io.jsonwebtoken.JwtParserBuilder.verifyWith",
            "io.jsonwebtoken.SignatureAlgorithm",
            "com.auth0.jwt.JWT.decode",
            "com.auth0.jwt.JWT.require",
            "com.auth0.jwt.algorithms.Algorithm",
            "java.util.Base64.getUrlDecoder",
        ),
        evidence_hints=(
            "Jwts.parser",
            "Jwts.builder",
            "Algorithm.none",
            "Algorithm.HMAC",
            "JwtParserBuilder",
            "verifyWith",
            "signWith",
            "HS256",
            "RS256",
            "decodeJwt",
        ),
    ),
    MasvsControl(
        id="MSTG-AUTH-4",
        group=MasvsGroup.AUTH,
        level=MasvsLevel.L1,
        title="The remote endpoint terminates the existing session when the user logs out.",
        description=(
            "Logout must call a server endpoint that invalidates the current session or "
            "revokes the current token; clearing the client-side store alone leaves the "
            "token valid at the server until it expires naturally, which means any copy of "
            "the token (in a captured backup, in a previously-logged request, in a "
            "third-party SDK that mirrored it) can replay successful authenticated calls. "
            "The verification target is that every logout UI handler reaches a server "
            "logout / revoke endpoint, that the server's success response is observed "
            "before local credential material is wiped, and that no offline-only logout "
            "path silently skips the server call when the network is unreachable."
        ),
        verification_steps=(
            "Find every logout / sign-out UI handler (onClick listener, Compose callback, "
            "navigation observer) and trace the network call it issues; confirm the call "
            "hits a server endpoint that revokes the session (typical paths: /logout, "
            "/signout, /sessions DELETE, /oauth/revoke).",
            "Confirm the local token storage is cleared after the server call succeeds, "
            "not before; a clear-then-call ordering means a network failure leaves the "
            "server session live while the user believes they are logged out.",
            "Inspect for offline-only logout paths that wipe local storage and skip the "
            "server call when no network is available; flag with a note that the token "
            "remains valid server-side until natural expiry.",
        ),
        relevant_apis=(
            "android.content.SharedPreferences.Editor.clear",
            "android.content.SharedPreferences.Editor.remove",
            "android.accounts.AccountManager.removeAccountExplicitly",
            "android.accounts.AccountManager.invalidateAuthToken",
            "okhttp3.Request.Builder.delete",
            "retrofit2.http.DELETE",
            "androidx.security.crypto.EncryptedSharedPreferences",
            "android.webkit.CookieManager.removeAllCookies",
        ),
        evidence_hints=(
            "logout",
            "signOut",
            "sign_out",
            "clearTokens",
            "invalidateAuthToken",
            "/logout",
            "/signout",
            "/revoke",
            "removeAccountExplicitly",
            "removeAllCookies",
        ),
    ),
    MasvsControl(
        id="MSTG-AUTH-5",
        group=MasvsGroup.AUTH,
        level=MasvsLevel.L1,
        title="A password policy exists and is enforced at the remote endpoint.",
        description=(
            "The server must reject weak passwords on registration and on password change — "
            "too short, common-list, leaked-corpus matches — because client-side checks are "
            "skippable by anyone interacting with the API directly. From the APK side the "
            "verification target is that the client at minimum mirrors the documented "
            "server policy (so a user is not led to submit a password the server will "
            "reject), that the client surfaces server-side policy rejections clearly "
            "instead of generic error toasts, and that the password value never leaks "
            "into a logger, an analytics event, or a third-party crash reporter on its way "
            "to the network layer."
        ),
        verification_steps=(
            "Find the registration and password-change screens; identify the client-side "
            "validators (length checks, character-class regex, Pattern.matches calls) and "
            "record whether they match the documented server policy.",
            "Inspect the submit-response handler; verify the client distinguishes a "
            "server-side policy rejection (4xx with a structured error body) from a "
            "generic network failure and surfaces the rejection reason to the user.",
            "Confirm the password value is not passed to android.util.Log, Timber, "
            "Crashlytics, Sentry, Bugsnag, Firebase Analytics, or any HttpLoggingInterceptor "
            "set to BODY level on the way to the network layer.",
        ),
        relevant_apis=(
            "android.text.TextWatcher",
            "android.text.InputFilter",
            "java.util.regex.Pattern.matches",
            "android.widget.EditText.setError",
            "okhttp3.logging.HttpLoggingInterceptor",
            "com.google.firebase.crashlytics.FirebaseCrashlytics.log",
            "android.util.Log.d",
            "timber.log.Timber.d",
        ),
        evidence_hints=(
            "password",
            "validatePassword",
            "passwordPolicy",
            "minLength",
            "Pattern.matches",
            "/register",
            "/password",
            "/change-password",
            "HttpLoggingInterceptor",
        ),
    ),
    MasvsControl(
        id="MSTG-AUTH-6",
        group=MasvsGroup.AUTH,
        level=MasvsLevel.L1,
        title=(
            "The remote endpoint implements a mechanism to protect against the submission "
            "of credentials an excessive number of times."
        ),
        description=(
            "The server must rate-limit failed authentication and lock or throttle accounts "
            "above a threshold of failures, otherwise credential stuffing against leaked "
            "password corpora runs unobstructed. From the APK side the verification target "
            "is that the client does not undermine that defence: the login handler must not "
            "auto-retry on 401 / 429 / 423 without exponential backoff or user interaction, "
            "must surface lockout responses (Retry-After header, 423 Locked) to the user "
            "rather than swallow them, and must not include any client-derivable bypass "
            "header (debug flag, internal-build token) that a repackaged APK can flip."
        ),
        verification_steps=(
            "Inspect the login response handler for retry loops; flag any loop that retries "
            "on 401 / 429 / 423 without a backoff or explicit user re-prompt.",
            "Verify the login screen handles HTTP 429 and 423 by reading the Retry-After "
            "header (when present) and displaying a wait-time message, rather than treating "
            "either status as a generic failure.",
            "Search for credential-bypass code paths: build-flavor checks that skip the "
            "auth call, debug-only login shortcuts, hardcoded fallback credentials in "
            "BuildConfig — any of which give a repackaged APK an unrate-limited path.",
        ),
        relevant_apis=(
            "okhttp3.Authenticator",
            "okhttp3.Interceptor.Chain.proceed",
            "okhttp3.Response.code",
            "okhttp3.Headers.get",
            "java.net.HttpURLConnection.getResponseCode",
            "androidx.work.WorkRequest.setBackoffCriteria",
            "com.android.volley.DefaultRetryPolicy",
            "io.reactivex.rxjava3.core.Single.retryWhen",
        ),
        evidence_hints=(
            "429",
            "423",
            "Retry-After",
            "Authenticator",
            "loginAttempts",
            "lockout",
            "retryWhen",
            "DefaultRetryPolicy",
            "BuildConfig.DEBUG",
        ),
    ),
    MasvsControl(
        id="MSTG-AUTH-7",
        group=MasvsGroup.AUTH,
        level=MasvsLevel.L1,
        title=(
            "Sessions are invalidated at the remote endpoint after a predefined period of "
            "inactivity and access tokens expire."
        ),
        description=(
            "Server-issued tokens must carry a bounded lifetime so that a copy captured "
            "from a backup or a stale log stops working after a known window. From the APK "
            "side the verification target is that the client honours that expiry: it checks "
            "the exp claim or the server-issued expires_in field before sending, drives a "
            "refresh flow (or a re-login) when the server returns 401-due-to-expiry, and "
            "stores any long-lived refresh token in a Keystore-backed wrapper rather than "
            "plain SharedPreferences. Silent indefinite retries on a 401 mean a leaked "
            "token is replayable for as long as the server allows."
        ),
        verification_steps=(
            "Identify the token storage layer and inspect the expiry field; confirm the "
            "client checks expiry before sending a protected request and triggers a refresh "
            "or re-login path rather than sending an expired token.",
            "Verify the refresh token (if any) is stored in EncryptedSharedPreferences, "
            "AccountManager, or a Keystore-backed wrapper — not plain SharedPreferences and "
            "not a flat file under getFilesDir.",
            "Find the 401 handler in the OkHttp Authenticator or Interceptor chain and "
            "confirm it triggers exactly one refresh attempt followed by a forced logout "
            "on second failure, never a silent indefinite retry.",
        ),
        relevant_apis=(
            "okhttp3.Authenticator.authenticate",
            "okhttp3.Interceptor.Chain.proceed",
            "androidx.security.crypto.EncryptedSharedPreferences",
            "android.accounts.AccountManager.getAuthToken",
            "android.accounts.AccountManager.invalidateAuthToken",
            "java.security.KeyStore",
            "io.jsonwebtoken.Claims.getExpiration",
            "java.time.Instant.isAfter",
        ),
        evidence_hints=(
            "expires_in",
            "\"exp\"",
            "refreshToken",
            "refresh_token",
            "Authenticator",
            "401",
            "Bearer ",
            "accessToken",
            "getAuthToken",
        ),
    ),
    MasvsControl(
        id="MSTG-AUTH-12",
        group=MasvsGroup.AUTH,
        level=MasvsLevel.L1,
        title="Authorization rules are enforced at the remote endpoint.",
        description=(
            "After authentication answers 'who is this user', authorization answers 'is "
            "this user permitted to perform this action against this resource'. That "
            "second decision must run at the server with the server's view of the user's "
            "identity and role; client-side hide/show of UI elements is convenience, never "
            "security. From the APK side the verification target is that protected requests "
            "carry only the server-issued identity (token / session), never a "
            "client-derived role / permission / is_admin flag in the request payload, and "
            "that no path skips the Authorization header based on a flippable local flag "
            "such as 'trustedDevice' or 'BuildConfig.INTERNAL'."
        ),
        verification_steps=(
            "Enumerate every API call carrying a user-id, account-id, customer-id, or "
            "resource-id in the URL path / query / body; confirm the call also carries an "
            "Authorization header so the server can re-derive the requester independently "
            "of the client-supplied id.",
            "Search request bodies for client-derived role / permission / capability "
            "claims (is_admin, role, capabilities, scopes, is_premium) the server might "
            "trust; flag each one — the server must derive these from the authenticated "
            "identity, never accept them from the client.",
            "Confirm the OkHttp interceptor / Retrofit @Header chain does not skip the "
            "Authorization header based on a flag like trustedDevice, BuildConfig.DEBUG, "
            "BuildConfig.INTERNAL, or a SharedPreferences entry — any such flag is "
            "flippable by a repackaged APK and can short-circuit auth.",
        ),
        relevant_apis=(
            "okhttp3.Interceptor.intercept",
            "okhttp3.Request.Builder.header",
            "okhttp3.Request.Builder.addHeader",
            "retrofit2.http.Header",
            "retrofit2.http.HeaderMap",
            "retrofit2.http.Path",
            "retrofit2.http.Query",
            "retrofit2.http.Body",
        ),
        evidence_hints=(
            "Authorization",
            "X-User-Id",
            "X-Account",
            "isAdmin",
            "\"role\"",
            "permission",
            "scope",
            "addHeader",
            "@Header",
            "trustedDevice",
        ),
    ),
)


_NETWORK_CONTROLS: tuple[MasvsControl, ...] = (
    MasvsControl(
        id="MSTG-NETWORK-1",
        group=MasvsGroup.NETWORK,
        level=MasvsLevel.L1,
        title=(
            "Data is encrypted on the network using TLS. The secure channel is used "
            "consistently throughout the app."
        ),
        description=(
            "Every request the app issues over the network — REST calls, WebView page "
            "loads, WebSocket connections, gRPC channels, file downloads, analytics "
            "beacons — must travel over TLS. Cleartext requests expose payloads to "
            "anyone on the same network segment (a coffee-shop wifi, a captive "
            "portal, a compromised corporate proxy) and to anyone with administrative "
            "access to a TLS-terminating intermediate. The verification target is "
            "that no production endpoint is reached over http:// or ws://, that "
            "AndroidManifest.xml denies cleartext globally on API ≥ 28 "
            "(usesCleartextTraffic=false or absent), and that no module installs an "
            "all-accepting TrustManager or a null-checking HostnameVerifier that "
            "silently downgrades an https:// URL to an unauthenticated channel."
        ),
        verification_steps=(
            "Enumerate every network call site (OkHttp / Retrofit / "
            "HttpURLConnection / WebView.loadUrl / WebSocket / Volley / gRPC "
            "ManagedChannel) and record the scheme used; flag any literal http:// "
            "or ws:// URL that is not a localhost loopback or a test fixture.",
            "Inspect AndroidManifest.xml for android:usesCleartextTraffic (must be "
            "false or absent on API ≥ 28) and parse res/xml/network_security_config.xml "
            "for <base-config cleartextTrafficPermitted=\"true\"> or any "
            "<domain-config cleartextTrafficPermitted=\"true\"> override, flagging "
            "each.",
            "Search for code that downgrades the channel by overriding the "
            "HostnameVerifier to return true unconditionally or by installing an "
            "X509TrustManager whose checkServerTrusted body is empty — both convert "
            "an https:// URL into an authenticated-in-name-only channel.",
        ),
        relevant_apis=(
            "okhttp3.OkHttpClient.Builder.connectionSpecs",
            "okhttp3.ConnectionSpec.MODERN_TLS",
            "okhttp3.ConnectionSpec.CLEARTEXT",
            "javax.net.ssl.HttpsURLConnection",
            "java.net.HttpURLConnection",
            "android.webkit.WebView.loadUrl",
            "okhttp3.WebSocket",
            "io.grpc.ManagedChannelBuilder.usePlaintext",
        ),
        evidence_hints=(
            "http://",
            "ws://",
            "cleartextTrafficPermitted",
            "usesCleartextTraffic",
            "CLEARTEXT",
            "MODERN_TLS",
            "network_security_config",
            "loadUrl",
            "usePlaintext",
        ),
    ),
    MasvsControl(
        id="MSTG-NETWORK-2",
        group=MasvsGroup.NETWORK,
        level=MasvsLevel.L1,
        title=(
            "The TLS settings are in line with current best practices, or as close as "
            "possible if the mobile operating system does not support the recommended "
            "standards."
        ),
        description=(
            "TLS protocol and cipher suite selection determines what an on-path "
            "observer can do with captured traffic. SSLv3 and TLS 1.0 / 1.1 carry "
            "documented weaknesses (BEAST, POODLE, downgrade prefixes); NULL and "
            "EXPORT ciphers omit confidentiality; RC4 and CBC-mode-without-AEAD "
            "suites lack the integrity guarantees current OWASP guidance requires. "
            "The verification target is that every SSLContext, OkHttp ConnectionSpec, "
            "and network_security_config protocol allowlist starts at TLS 1.2 "
            "(TLSv1.3 preferred), that cipher suites are restricted to AEAD families "
            "(GCM, CHACHA20-POLY1305) with forward-secrecy key exchange "
            "(ECDHE / DHE), and that no per-domain override loosens this for a "
            "marketing subdomain or a legacy partner endpoint."
        ),
        verification_steps=(
            "Inspect every SSLContext construction (SSLContext.getInstance) and "
            "SSLSocket configuration (setEnabledProtocols / setEnabledCipherSuites); "
            "flag any explicit \"TLS\" / \"SSL\" / \"TLSv1\" / \"TLSv1.1\" protocol "
            "name or any cipher suite containing NULL / RC4 / 3DES / EXPORT / anon.",
            "Inspect OkHttp ConnectionSpec definitions; confirm the app uses "
            "ConnectionSpec.MODERN_TLS or ConnectionSpec.RESTRICTED_TLS and not a "
            "hand-rolled ConnectionSpec.Builder that re-adds deprecated TLS "
            "versions or cipher suites for compatibility with a stated legacy "
            "server.",
            "Parse res/xml/network_security_config.xml for <network-security-config> "
            "<base-config> / <domain-config> entries with explicit <protocol> or "
            "trust-anchors lowering the minimum below TLSv1.2; flag every "
            "domain-specific override that loosens the base policy.",
        ),
        relevant_apis=(
            "okhttp3.ConnectionSpec.Builder.tlsVersions",
            "okhttp3.ConnectionSpec.Builder.cipherSuites",
            "okhttp3.TlsVersion.TLS_1_2",
            "okhttp3.TlsVersion.TLS_1_3",
            "javax.net.ssl.SSLContext.getInstance",
            "javax.net.ssl.SSLSocket.setEnabledProtocols",
            "javax.net.ssl.SSLSocket.setEnabledCipherSuites",
            "javax.net.ssl.SSLParameters.setProtocols",
        ),
        evidence_hints=(
            "TLSv1.0",
            "TLSv1.1",
            "SSLv3",
            "TLS_1_0",
            "TLS_1_1",
            "MODERN_TLS",
            "RESTRICTED_TLS",
            "setEnabledProtocols",
            "cipherSuites",
            "SSLContext.getInstance",
        ),
    ),
    MasvsControl(
        id="MSTG-NETWORK-3",
        group=MasvsGroup.NETWORK,
        level=MasvsLevel.L1,
        title=(
            "The app verifies the X.509 certificate of the remote endpoint when the "
            "secure channel is established. Only certificates signed by a trusted CA "
            "are accepted."
        ),
        description=(
            "A TLS handshake authenticates the server only if the client validates "
            "the server's certificate against a trusted CA set AND confirms the "
            "certificate's subject matches the hostname being contacted. Either "
            "check disabled means the encrypted channel terminates at whoever is "
            "closest on the network path with a self-signed cert (a corporate "
            "TLS-terminating proxy, a developer running mitmproxy or Burp Suite for "
            "testing, a network operator with an inspection appliance) — "
            "confidentiality and integrity flow to that intermediary, not the "
            "intended server. The verification target is that every X509TrustManager "
            "implementation rejects unknown CAs (no empty checkServerTrusted, no "
            "catch-then-ignore of CertificateException), that every HostnameVerifier "
            "enforces the SAN / CN match (no return-true bodies, no ALLOW_ALL "
            "constants from Apache HttpClient, no NoopHostnameVerifier), and that "
            "the release-build network_security_config does not include "
            "user-installed CAs in its trust-anchors set."
        ),
        verification_steps=(
            "Search for X509TrustManager implementations and inspect each "
            "checkServerTrusted method; flag any empty body, any catch-then-ignore "
            "of CertificateException, and any caller that passes a null or "
            "all-trusting TrustManager[] array to SSLContext.init.",
            "Search for HostnameVerifier implementations and inspect each verify "
            "method; flag any return true with no hostname check, any caller "
            "installing HttpsURLConnection.setDefaultHostnameVerifier with "
            "ALLOW_ALL_HOSTNAME_VERIFIER, and any OkHttpClient.Builder."
            "hostnameVerifier set to a NoopHostnameVerifier or a lambda that "
            "ignores its arguments.",
            "Parse res/xml/network_security_config.xml for <trust-anchors> "
            "entries; confirm <certificates src=\"user\"/> appears ONLY inside "
            "<debug-overrides> (release builds must not trust user-installed CAs), "
            "and confirm no <domain-config> override adds a private CA for a "
            "third-party domain that should be served from the public WebPKI.",
        ),
        relevant_apis=(
            "javax.net.ssl.X509TrustManager.checkServerTrusted",
            "javax.net.ssl.HostnameVerifier.verify",
            "javax.net.ssl.SSLContext.init",
            "javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier",
            "okhttp3.OkHttpClient.Builder.hostnameVerifier",
            "okhttp3.OkHttpClient.Builder.sslSocketFactory",
            "org.apache.http.conn.ssl.NoopHostnameVerifier",
            "org.apache.http.conn.ssl.SSLConnectionSocketFactory",
        ),
        evidence_hints=(
            "checkServerTrusted",
            "X509TrustManager",
            "HostnameVerifier",
            "ALLOW_ALL_HOSTNAME_VERIFIER",
            "NoopHostnameVerifier",
            "TrustManager[]",
            "trust-anchors",
            "debug-overrides",
            "src=\"user\"",
            "SSLContext.init",
        ),
    ),
)


_PLATFORM_CONTROLS: tuple[MasvsControl, ...] = (
    MasvsControl(
        id="MSTG-PLATFORM-1",
        group=MasvsGroup.PLATFORM,
        level=MasvsLevel.L1,
        title="The app only requests the minimum set of permissions necessary.",
        description=(
            "Every permission an Android app declares becomes a standing capability tied "
            "to the install: the system grants it (install-time normal permissions) or "
            "the user is prompted to grant it (runtime dangerous permissions), and from "
            "that point on any code path inside the app can use it without further "
            "consent. Permissions the app does not actually need expand the blast "
            "radius of any client-side compromise, raise the cost of a Play Store "
            "review, and give a malicious SDK pulled in transitively a wider surface "
            "to abuse. The verification target is that every <uses-permission> entry "
            "in AndroidManifest.xml is consumed by a real feature shipped in the build, "
            "that dangerous permissions follow the runtime-request flow with a stated "
            "user benefit at the prompt site, and that no permission tagged signature / "
            "system / privileged is requested by an app that could not legitimately "
            "hold it."
        ),
        verification_steps=(
            "Parse AndroidManifest.xml for every <uses-permission> entry and "
            "cross-reference each against actual call sites — Manifest.permission.X "
            "constant references, ContextCompat.checkSelfPermission, "
            "ActivityCompat.requestPermissions, and any API the permission gates; flag "
            "any permission with no consuming code path as either dead or covertly used "
            "via reflection.",
            "For each android.permission-group.DANGEROUS permission (READ_CONTACTS, "
            "ACCESS_FINE_LOCATION, READ_EXTERNAL_STORAGE, RECORD_AUDIO, CAMERA, "
            "READ_PHONE_STATE, READ_SMS, etc.) trace the runtime-request flow and "
            "confirm the requesting feature is reachable from the app's UI with a "
            "user-visible justification, not a silent background prompt at first "
            "launch.",
            "Flag overly-broad permissions for the app's stated purpose "
            "(READ_PHONE_STATE / READ_SMS / RECEIVE_SMS used only for analytics, "
            "WRITE_EXTERNAL_STORAGE without a file-export feature, ACCESS_FINE_LOCATION "
            "where ACCESS_COARSE_LOCATION would do) and confirm protectionLevel="
            "\"signature\" / \"signatureOrSystem\" / \"privileged\" permissions are "
            "appropriate for the app's signing identity.",
        ),
        relevant_apis=(
            "android.Manifest.permission",
            "android.app.Activity.requestPermissions",
            "androidx.core.content.ContextCompat.checkSelfPermission",
            "androidx.core.app.ActivityCompat.requestPermissions",
            "androidx.activity.result.contract.ActivityResultContracts.RequestPermission",
            "android.content.pm.PackageManager.checkPermission",
            "android.content.pm.PackageManager.PERMISSION_GRANTED",
            "android.content.pm.PackageInfo.requestedPermissions",
        ),
        evidence_hints=(
            "<uses-permission",
            "android.permission.",
            "checkSelfPermission",
            "requestPermissions",
            "PERMISSION_GRANTED",
            "android:protectionLevel",
            "RequestPermission",
            "shouldShowRequestPermissionRationale",
        ),
    ),
    MasvsControl(
        id="MSTG-PLATFORM-2",
        group=MasvsGroup.PLATFORM,
        level=MasvsLevel.L1,
        title=(
            "All inputs from external sources and the user are validated and if "
            "necessary sanitized. This includes data received via the UI, IPC "
            "mechanisms such as intents, custom URLs, and network sources."
        ),
        description=(
            "Every value the app reads from an untrusted boundary — Intent extras "
            "delivered by another app, deep-link parameters parsed from a Uri, "
            "ContentProvider selection clauses passed by an external querier, JSON "
            "fields pulled from a network response, free-form text entered by the "
            "user — must be type-checked, length-checked, and (where the destination "
            "is a structured sink such as SQL, a shell, an HTML render, or a file "
            "path) sanitized for that sink before use. Skipped validation allows "
            "injection (SQLi via rawQuery, command injection via Runtime.exec, "
            "path traversal via File constructors), state-machine confusion (an "
            "invalid enum value driving an unintended branch), and crashes that "
            "external untrusted callers can trigger at will to deny service. The "
            "verification target is that every external-input read passes through a "
            "validator (typed accessor, length bound, allowlist, regex check) before "
            "reaching a sink."
        ),
        verification_steps=(
            "Identify every Intent entry point (Activity.getIntent / "
            "BroadcastReceiver.onReceive / Service.onStartCommand) and inspect how "
            "its extras and data Uri are consumed; flag every path that reads a "
            "string and passes it to a sink (SQLiteDatabase.rawQuery, "
            "Runtime.exec, File constructors, WebView.loadUrl, Retrofit URL "
            "concatenation) without an intervening allowlist / regex / length "
            "check.",
            "Inspect every ContentProvider.query / insert / update / delete "
            "override for SQL string concatenation; flag any rawQuery / execSQL "
            "using selection clauses that interpolate caller-supplied extras "
            "instead of using parameter binding (selectionArgs) with a fixed "
            "selection template.",
            "Inspect deep-link handlers (Activities exported with "
            "<intent-filter><data android:scheme=\"...\"/>) and confirm "
            "parameters are parsed via Uri.getQueryParameter and then validated "
            "(numeric range, enum lookup, signature check) before driving "
            "navigation, file reads, or network calls; flag any handler that "
            "concatenates getQueryParameter results into a request URL or a SQL "
            "selection.",
        ),
        relevant_apis=(
            "android.content.Intent.getStringExtra",
            "android.content.Intent.getData",
            "android.content.ContentProvider.query",
            "android.database.sqlite.SQLiteDatabase.rawQuery",
            "android.database.sqlite.SQLiteDatabase.execSQL",
            "android.net.Uri.getQueryParameter",
            "android.webkit.WebView.loadUrl",
            "java.lang.Runtime.exec",
            "java.io.File",
        ),
        evidence_hints=(
            "getStringExtra",
            "getQueryParameter",
            "rawQuery",
            "execSQL",
            "Runtime.getRuntime",
            "exec(",
            "intent-filter",
            "<data android:scheme",
            "getIntent",
            "loadUrl",
        ),
    ),
    MasvsControl(
        id="MSTG-PLATFORM-3",
        group=MasvsGroup.PLATFORM,
        level=MasvsLevel.L1,
        title=(
            "The app does not export sensitive functionality via custom URL schemes, "
            "unless these mechanisms are properly protected."
        ),
        description=(
            "A custom URL scheme registered via <intent-filter><data "
            "android:scheme=\"foo\"/> can be invoked by any other app on the device, "
            "by a web page the user visits in any browser, and by a QR code the user "
            "scans — the calling identity is not authenticated by the system unless "
            "the app re-checks. If the scheme handler performs sensitive operations "
            "(account changes, money transfers, settings writes, file deletes, "
            "credential resets) without a per-invocation identity / consent check, "
            "any unrelated app or any visited web page can trigger those operations "
            "silently. The verification target is that every custom-scheme entry "
            "point either restricts itself to read-only navigation, or requires "
            "fresh user consent (a confirmation screen the user must tap through) "
            "for any state-changing action, and that web links use Android App "
            "Links with android:autoVerify=\"true\" + a /.well-known/assetlinks.json "
            "association so unrelated apps cannot register the same scheme to "
            "phish users."
        ),
        verification_steps=(
            "Enumerate every Activity / Receiver in AndroidManifest.xml with "
            "<intent-filter><data android:scheme=\"...\"/> (excluding http / https "
            "with autoVerify); for each, record the scheme + host + path pattern "
            "and identify the handler class and method.",
            "For each custom-scheme entry point, inspect the handler for sensitive "
            "actions (account mutation, payment trigger, settings write, password "
            "reset, file delete) and confirm an authentication / authorization gate "
            "(recent-login check, biometric prompt, signature verification of the "
            "calling package via Binder.getCallingUid + PackageManager.checkSignatures) "
            "runs before the action; flag any handler that performs a sensitive "
            "action from getIntent extras without such a gate.",
            "Confirm http / https <intent-filter> entries use App Links semantics — "
            "android:autoVerify=\"true\" plus a published "
            "/.well-known/assetlinks.json on the named host — so unrelated apps "
            "cannot register the same domain and intercept the user's clicks; flag "
            "any web-link handler without autoVerify as a phishing surface.",
        ),
        relevant_apis=(
            "android.content.Intent.ACTION_VIEW",
            "android.net.Uri.parse",
            "android.content.Intent.getData",
            "android.app.Activity.getIntent",
            "android.content.pm.PackageManager.queryIntentActivities",
            "android.os.Binder.getCallingUid",
            "android.content.pm.PackageManager.checkSignatures",
        ),
        evidence_hints=(
            "android:scheme",
            "intent-filter",
            "autoVerify",
            "assetlinks.json",
            "ACTION_VIEW",
            "getIntent",
            "getData",
            "getCallingUid",
        ),
    ),
    MasvsControl(
        id="MSTG-PLATFORM-4",
        group=MasvsGroup.PLATFORM,
        level=MasvsLevel.L1,
        title=(
            "The app does not export sensitive functionality through IPC facilities, "
            "unless these mechanisms are properly protected."
        ),
        description=(
            "Activities, Services, Broadcast Receivers, and Content Providers marked "
            "android:exported=\"true\" (or implicitly exported by an <intent-filter> "
            "declaration on API < 31) are reachable by every other app on the "
            "device. If those components perform sensitive operations without a "
            "permission gate or a caller-identity check, any installed app can "
            "invoke them: reading private data via ContentProvider.query, triggering "
            "account actions via Activity startActivityForResult, exfiltrating "
            "files via FileProvider misconfigurations, or sending broadcasts that "
            "drive state-machine transitions. The verification target is that "
            "every exported component either is intentionally public (a launcher "
            "Activity, a shared share-sheet target) or carries a "
            "android:permission=\"...\" attribute with android:protectionLevel="
            "\"signature\" plus a runtime caller check before any sensitive "
            "action."
        ),
        verification_steps=(
            "Enumerate every Activity / Service / Receiver / Provider in "
            "AndroidManifest.xml with android:exported=\"true\" (and on API < 31, "
            "every component with an <intent-filter> child but no explicit "
            "android:exported attribute — these are implicitly exported); record "
            "each entry point's intended caller class (system_only, the app's own "
            "UI, any signed-by-same-key app, any installed app).",
            "For each exported component handling sensitive operations (account, "
            "payment, settings, content read, file read), confirm an "
            "android:permission=\"<custom>\" attribute with android:protectionLevel="
            "\"signature\" restricts use to apps signed with the same key, AND a "
            "runtime caller check via Binder.getCallingUid + "
            "PackageManager.checkSignatures rejects calls from unexpected uids; "
            "flag any exported component that performs a sensitive action without "
            "both checks.",
            "Inspect every <provider> for android:grantUriPermissions semantics and "
            "FileProvider authority configuration; confirm exported providers do "
            "not return arbitrary file paths from caller-supplied authority / path "
            "parameters (path traversal via ../ segments) and that "
            "<paths>/<external-path> entries scope the share root to a specific "
            "subdirectory, not the entire app data directory.",
        ),
        relevant_apis=(
            "android.os.Binder.getCallingUid",
            "android.content.pm.PackageManager.checkSignatures",
            "android.content.Context.checkCallingPermission",
            "android.content.Context.enforceCallingPermission",
            "androidx.core.content.FileProvider",
            "android.content.ContentProvider.call",
            "android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION",
        ),
        evidence_hints=(
            "android:exported",
            "android:permission",
            "protectionLevel=\"signature\"",
            "getCallingUid",
            "checkSignatures",
            "checkCallingPermission",
            "FileProvider",
            "grantUriPermissions",
            "<external-path",
        ),
    ),
    MasvsControl(
        id="MSTG-PLATFORM-5",
        group=MasvsGroup.PLATFORM,
        level=MasvsLevel.L1,
        title="JavaScript is disabled in WebViews unless explicitly required.",
        description=(
            "A WebView with JavaScript enabled becomes a script-execution surface "
            "for whatever HTML reaches it: a remote page loaded from a non-HTTPS "
            "endpoint, a file:// page reached through a path-traversal bug, an "
            "Intent-supplied URL the app forwards into loadUrl without a domain "
            "allowlist. If JavaScript is on by default and the loaded origin can "
            "be influenced by external untrusted callers, hostile script runs in "
            "the WebView's process — reading WebView cookies, exfiltrating "
            "localStorage, calling any @JavascriptInterface bridge the app "
            "exposes (see MSTG-PLATFORM-7). The verification target is that every "
            "WebSettings.setJavaScriptEnabled(true) call site has a documented "
            "need (an in-app help renderer, a checkout flow against a vetted "
            "domain) AND the URL loaded into that WebView is restricted to a "
            "trusted origin: a bundled asset under file:///android_asset, a "
            "hard-coded https:// allowlist, or a domain validated against a "
            "compile-time constant — never a Uri pulled from getIntent or a "
            "network response without validation."
        ),
        verification_steps=(
            "Enumerate every android.webkit.WebView instantiation and its "
            "getSettings() configuration; flag every setJavaScriptEnabled(true) "
            "call site and trace the URL ultimately loaded into that WebView (a "
            "remote http(s) host, a file:///android_asset path, a content:// "
            "URI) to confirm JS is enabled only for trusted content.",
            "For WebViews loading remote HTML, confirm the loaded origin is an "
            "allowlist constant (a specific app-controlled domain) or validated "
            "against a constant before loadUrl is called; flag any path that "
            "passes getIntent.getData().toString() or a Retrofit response field "
            "straight to WebView.loadUrl with JS enabled.",
            "Confirm setJavaScriptEnabled(true) is not flipped on globally by a "
            "base WebViewClient or a shared WebView factory that downstream code "
            "reuses for every WebView instance — a single factory enabling JS "
            "affects every consumer including ones that load untrusted HTML.",
        ),
        relevant_apis=(
            "android.webkit.WebView.getSettings",
            "android.webkit.WebSettings.setJavaScriptEnabled",
            "android.webkit.WebSettings.setJavaScriptCanOpenWindowsAutomatically",
            "android.webkit.WebView.loadUrl",
            "android.webkit.WebView.loadData",
            "android.webkit.WebView.loadDataWithBaseURL",
            "android.webkit.WebViewClient",
        ),
        evidence_hints=(
            "setJavaScriptEnabled",
            "getSettings",
            "WebView",
            "loadUrl",
            "loadDataWithBaseURL",
            "file:///android_asset",
            "WebSettings",
            "WebViewClient",
        ),
    ),
    MasvsControl(
        id="MSTG-PLATFORM-6",
        group=MasvsGroup.PLATFORM,
        level=MasvsLevel.L1,
        title=(
            "WebViews are configured to allow only the minimum set of protocol "
            "handlers required (ideally, only https is supported). Potentially "
            "dangerous handlers, such as file, tel and app-id, are disabled."
        ),
        description=(
            "A WebView accepts more URI schemes than http and https by default — "
            "file://, content://, javascript:, intent://, tel:, sms:, mailto: — "
            "and each one carries distinct trust semantics. file:// reads can "
            "expose private app storage when setAllowFileAccessFromFileURLs is "
            "true; javascript: URIs trigger script execution in whatever origin "
            "the WebView currently holds; intent:// hops out of the WebView and "
            "back into Android Intent dispatch with caller-supplied extras; "
            "tel: / sms: / mailto: launch external apps with caller-supplied "
            "parameters. If the WebViewClient forwards every scheme to the "
            "system without an allowlist, an HTML page (loaded over https) can "
            "trigger any of these by setting window.location, and an external "
            "untrusted page can chain through to scheme handlers the app never "
            "intended to expose. The verification target is that "
            "setAllowFileAccessFromFileURLs / setAllowUniversalAccessFromFileURLs "
            "are false on every WebView, that shouldOverrideUrlLoading restricts "
            "scheme handling to an explicit allowlist, and that the loaded "
            "origin cannot reach file:// content unless the page is itself a "
            "trusted file:///android_asset bundle."
        ),
        verification_steps=(
            "For every WebView instance inspect WebSettings configuration — "
            "setAllowFileAccess / setAllowFileAccessFromFileURLs / "
            "setAllowUniversalAccessFromFileURLs / setAllowContentAccess; flag "
            "every true value on a WebView loading remote HTML, and call out the "
            "FromFileURLs variants in particular since they permit cross-origin "
            "reads under a file:// origin.",
            "Inspect every WebViewClient.shouldOverrideUrlLoading override; "
            "confirm tel:, sms:, mailto:, intent://, javascript:, file:, and "
            "content: schemes are explicitly classified (allowed / blocked / "
            "delegated to the system) rather than passed through with a "
            "default-true return that lets the WebView load them in-place.",
            "Confirm no WebViewClient routes a getIntent-derived deep link "
            "straight into WebView.loadUrl, which would let external untrusted "
            "callers trigger custom-scheme handlers (intent://, javascript:) "
            "inside the app's WebView and bypass the shouldOverrideUrlLoading "
            "allowlist by reaching loadUrl directly.",
        ),
        relevant_apis=(
            "android.webkit.WebSettings.setAllowFileAccess",
            "android.webkit.WebSettings.setAllowFileAccessFromFileURLs",
            "android.webkit.WebSettings.setAllowUniversalAccessFromFileURLs",
            "android.webkit.WebSettings.setAllowContentAccess",
            "android.webkit.WebViewClient.shouldOverrideUrlLoading",
            "android.webkit.WebView.loadUrl",
            "android.content.Intent.parseUri",
        ),
        evidence_hints=(
            "setAllowFileAccess",
            "setAllowFileAccessFromFileURLs",
            "setAllowUniversalAccessFromFileURLs",
            "setAllowContentAccess",
            "shouldOverrideUrlLoading",
            "intent://",
            "javascript:",
            "file://",
            "Intent.parseUri",
        ),
    ),
    MasvsControl(
        id="MSTG-PLATFORM-7",
        group=MasvsGroup.PLATFORM,
        level=MasvsLevel.L1,
        title=(
            "If native methods of the app are exposed to a WebView, verify that the "
            "WebView only renders JavaScript contained within the app package."
        ),
        description=(
            "WebView.addJavascriptInterface(obj, name) injects a JS-callable bridge "
            "into every page the WebView loads. Any method on the bridge class "
            "annotated with @JavascriptInterface (or every public method on API "
            "< 17, where the annotation is not required) becomes invokable from "
            "page-loaded script — including script that the page itself imported "
            "from a different origin, that a redirect chain led to, or that a "
            "third-party ad SDK injected. If the bridge methods do anything "
            "privileged (file reads, settings writes, Intent dispatches, account "
            "operations, Runtime.exec) the page running in the WebView gains "
            "those privileges. The verification target is that every WebView with "
            "addJavascriptInterface loads only JS bundled inside the APK (under "
            "/assets or /res, or a hard-coded https:// allowlist whose contents "
            "the app vendor controls end-to-end), that every @JavascriptInterface "
            "method is read-only or restricted to non-sensitive lookup data, and "
            "that the WebViewClient.shouldOverrideUrlLoading rejects navigation "
            "to URLs outside the trusted origin."
        ),
        verification_steps=(
            "Enumerate every WebView.addJavascriptInterface call site and record "
            "the bridge class plus the URL ultimately loaded into that WebView; "
            "confirm the loaded URL points to an asset bundled in /assets or "
            "/res or a hard-coded https:// allowlist, NOT a remote URL derived "
            "from getIntent / a Retrofit response / a content URI.",
            "For each @JavascriptInterface-annotated method, inspect the body "
            "for side effects that could escalate privilege if invoked from a "
            "hostile page (File / FileOutputStream / SharedPreferences edits, "
            "Intent dispatches, AccountManager / KeyStore reads, Runtime.exec, "
            "ContentResolver writes); flag any bridge method that does more "
            "than return immutable lookup data.",
            "Confirm the WebView's WebViewClient.shouldOverrideUrlLoading and "
            "WebChromeClient.onJsAlert / onJsConfirm / onJsPrompt prevent "
            "navigation to URLs outside the trusted origin, so a successful "
            "redirect from a trusted page to a hostile page cannot then use the "
            "JS bridge from a different origin.",
        ),
        relevant_apis=(
            "android.webkit.WebView.addJavascriptInterface",
            "android.webkit.JavascriptInterface",
            "android.webkit.WebViewClient.shouldOverrideUrlLoading",
            "android.webkit.WebViewClient.onPageStarted",
            "android.webkit.WebView.loadUrl",
            "android.webkit.WebChromeClient.onJsAlert",
            "android.webkit.WebChromeClient.onJsPrompt",
        ),
        evidence_hints=(
            "addJavascriptInterface",
            "@JavascriptInterface",
            "shouldOverrideUrlLoading",
            "onPageStarted",
            "WebView",
            "loadUrl",
            "WebChromeClient",
        ),
    ),
    MasvsControl(
        id="MSTG-PLATFORM-8",
        group=MasvsGroup.PLATFORM,
        level=MasvsLevel.L1,
        title=(
            "Object deserialization, wherever it is used, is implemented using "
            "safe serialization APIs."
        ),
        description=(
            "Java's java.io.ObjectInputStream materializes object graphs from a "
            "byte stream by walking class names, invoking readObject hooks, and "
            "wiring up references — a process the byte stream itself controls. "
            "If the bytes come from an untrusted source (a file the app did not "
            "write, a network response, an Intent extra, a clipboard read), a "
            "gadget chain through readObject hooks in classpath libraries can "
            "trigger code execution before the application code ever sees the "
            "deserialized object. Android's untyped Intent.getSerializableExtra "
            "exhibits the same shape and has been the source of multiple "
            "Android-specific deserialization CVEs. The verification target is "
            "that every readObject / Externalizable.readExternal call site "
            "operates on bytes the app itself produced, that Intent extras are "
            "read with the type-checked getStringExtra / getParcelableExtra("
            "key, Class<T>) accessors rather than getSerializableExtra, and "
            "that JSON / XML / Protobuf parsers do not perform polymorphic "
            "deserialization against a class set the byte stream chooses."
        ),
        verification_steps=(
            "Search for java.io.ObjectInputStream / java.io.Externalizable / "
            "java.beans.XMLDecoder use; flag every readObject / readExternal / "
            "readObject call site where the input bytes are not provably "
            "app-produced (input from File whose path is caller-supplied, from "
            "the network, from an Intent extra, from the clipboard), since "
            "such call sites enable gadget-chain deserialization attacks.",
            "For Android Parcelable / Bundle reads from Intent extras, confirm "
            "extras are read with type-checked accessors (getStringExtra, "
            "getIntExtra, getParcelableExtra(key, Class<T>)) rather than the "
            "untyped getSerializableExtra / getParcelableExtra(key); flag every "
            "getSerializableExtra call site as a finding and every "
            "getParcelableExtra without an explicit Class<T> argument on API "
            ">= 33 as a hardening gap.",
            "Inspect JSON / XML / Protobuf parsing for unbounded polymorphic "
            "type bindings (Jackson @JsonTypeInfo with class-name discriminators, "
            "Gson RuntimeTypeAdapterFactory with a wildcard, XStream / "
            "SnakeYAML default constructor calls); confirm polymorphic "
            "deserialization is restricted to a fixed sealed-class hierarchy "
            "with an allowlist of permitted concrete types.",
        ),
        relevant_apis=(
            "java.io.ObjectInputStream.readObject",
            "java.io.Externalizable.readExternal",
            "java.beans.XMLDecoder",
            "android.content.Intent.getSerializableExtra",
            "android.content.Intent.getParcelableExtra",
            "android.os.Bundle.getSerializable",
            "com.fasterxml.jackson.databind.ObjectMapper.readValue",
            "com.google.gson.Gson.fromJson",
            "org.yaml.snakeyaml.Yaml.load",
        ),
        evidence_hints=(
            "ObjectInputStream",
            "readObject",
            "Externalizable",
            "getSerializableExtra",
            "getParcelableExtra",
            "@JsonTypeInfo",
            "RuntimeTypeAdapterFactory",
            "XStream",
            "SnakeYAML",
        ),
    ),
)


_CODE_CONTROLS: tuple[MasvsControl, ...] = (
    MasvsControl(
        id="MSTG-CODE-1",
        group=MasvsGroup.CODE,
        level=MasvsLevel.L1,
        title=(
            "The app is signed and provisioned with a valid certificate, of which "
            "the private key is properly protected."
        ),
        description=(
            "Production Android distribution binds every install to a signing "
            "certificate: PackageManager validates the certificate on first install, "
            "rejects any subsequent update signed by a different identity, and gates "
            "signature / signatureOrSystem IPC permissions on the requesting app "
            "carrying the same signer. A release build signed with the Android "
            "debug keystore (CN=Android Debug, O=Android, C=US) carries no "
            "developer-identity guarantee, lets any debug-signed build claim the "
            "same signature-protected IPC surface, and tells the Play Store the "
            "upload is not a real release. The verification target is that the "
            "shipped APK is signed under the v2 / v3 signature scheme with a "
            "non-debug certificate, that the signing key is held under Play App "
            "Signing or an equivalent custody process documented for the team, "
            "and that no runtime code path silently accepts a foreign signer on "
            "update or IPC."
        ),
        verification_steps=(
            "Inspect META-INF/ for the CERT.RSA / CERT.SF pair plus the "
            "v2 / v3 / v4 signature blocks in the APK (the .SF MANIFEST "
            "header should reference SHA-256, not the v1 SHA1-only style); "
            "confirm the certificate Subject DN is not "
            "\"CN=Android Debug, O=Android, C=US\" and that v1-only signing "
            "is not in use against an Android 7.0+ target.",
            "Inspect AndroidManifest.xml for android:debuggable=\"true\" on "
            "the <application> tag and for android:testOnly=\"true\"; either "
            "marker on a build labelled release is a signing / build-flag "
            "failure mode that lets any debugger or `adb install -t` foreign "
            "build land on a user device.",
            "Search the code for PackageInfo.signatures / SigningInfo "
            "consumers and flag any path that calls them only to log the "
            "result instead of comparing the byte sequence to a known signer "
            "constant — signature checks that never assert are noise the "
            "build can still ship without enforcement.",
        ),
        relevant_apis=(
            "android.content.pm.PackageManager.getPackageInfo",
            "android.content.pm.PackageInfo.signatures",
            "android.content.pm.PackageInfo.signingInfo",
            "android.content.pm.SigningInfo.getApkContentsSigners",
            "android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES",
            "android.content.pm.PackageManager.GET_SIGNATURES",
            "android.content.pm.PackageManager.checkSignatures",
            "java.security.cert.X509Certificate",
            "java.security.MessageDigest",
        ),
        evidence_hints=(
            "META-INF/CERT.RSA",
            "android:debuggable",
            "android:testOnly",
            "getPackageInfo",
            "GET_SIGNING_CERTIFICATES",
            "GET_SIGNATURES",
            "signingInfo",
            "checkSignatures",
            "Android Debug",
        ),
    ),
    MasvsControl(
        id="MSTG-CODE-2",
        group=MasvsGroup.CODE,
        level=MasvsLevel.L1,
        title=(
            "The app has been built in release mode, with settings appropriate "
            "for a release build (e.g. non-debuggable)."
        ),
        description=(
            "Android release builds are expected to ship with build flags that "
            "deny runtime instrumentation: android:debuggable=false (the default "
            "when omitted), JNI / Java debugging closed, the Application's "
            "FLAG_DEBUGGABLE manifest bit clear, Crashlytics / Logcat verbose "
            "channels muted, and Gradle's minify / shrink / proguard passes "
            "active on the release variant. A debuggable release lets any "
            "process with android.permission.SET_DEBUG_APP — or any local "
            "user with adb — attach jdwp, dump heap state, set breakpoints, "
            "and walk the stack of the production app, which trivially "
            "exposes keys, tokens, and user data the app handles in memory. "
            "The verification target is that the shipped variant has "
            "debuggable=false on the manifest, that the Gradle release "
            "variant has buildTypes.release { minifyEnabled true; "
            "shrinkResources true } applied, and that no per-flavour override "
            "re-enables debug paths for the release SKU."
        ),
        verification_steps=(
            "Inspect AndroidManifest.xml for android:debuggable on the "
            "<application> tag — explicit `true` is a fail; `false` or "
            "absent is the documented default. Cross-check ApplicationInfo "
            "FLAG_DEBUGGABLE reads at runtime: any code that branches on "
            "the flag being set indicates the build expects to be "
            "debuggable, which a release should never be.",
            "Inspect the Gradle build configuration (app/build.gradle or "
            "build.gradle.kts) for the release buildType: it should set "
            "minifyEnabled true, shrinkResources true, and a proguard / "
            "R8 rule file. Any release variant that disables minify or "
            "sets debuggable=true is a build-flag fail; record the source "
            "line.",
            "Search the decompiled tree for BuildConfig.DEBUG branches and "
            "for any feature gated on a runtime debug flag; flag any "
            "branch that exposes user data, keys, or test endpoints when "
            "DEBUG is true, since accidental release builds with DEBUG=true "
            "(a common Gradle misconfiguration) would expose those paths.",
        ),
        relevant_apis=(
            "android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE",
            "android.content.pm.ApplicationInfo.flags",
            "android.os.Debug.isDebuggerConnected",
            "android.os.Debug.waitForDebugger",
            "android.os.StrictMode",
        ),
        evidence_hints=(
            "android:debuggable",
            "FLAG_DEBUGGABLE",
            "isDebuggerConnected",
            "waitForDebugger",
            "BuildConfig.DEBUG",
            "minifyEnabled",
            "shrinkResources",
            "buildTypes",
            "proguard",
        ),
    ),
    MasvsControl(
        id="MSTG-CODE-3",
        group=MasvsGroup.CODE,
        level=MasvsLevel.L1,
        title="Debugging symbols have been removed from native binaries.",
        description=(
            "Android APKs that ship native libraries (.so files under "
            "lib/<abi>/) frequently retain the original symbol table and "
            "DWARF debug sections from the NDK build. A symbolicated .so "
            "lets a security researcher (or anyone with a hex editor and "
            "an objdump) walk every function name, line-number mapping, "
            "and local-variable layout the developer wrote — turning the "
            "lib's protections (custom obfuscation, root checks, integrity "
            "checks) into a glossary. The verification target is that "
            "every shipped .so is stripped of .symtab, .debug_*, and "
            ".strtab sections, that the build uses an NDK toolchain "
            "configuration that strips by default, and that any kept "
            "symbol set is intentional (e.g. JNI exports the Java loader "
            "needs) rather than a leftover from a debug build."
        ),
        verification_steps=(
            "Enumerate every lib/<abi>/*.so the APK ships and inspect "
            "each with objdump / readelf / llvm-objdump: confirm there is "
            "no .debug_info / .debug_line / .debug_str / .symtab "
            "non-empty section; the only kept symbol table should be "
            ".dynsym (required for JNI exports and dlopen).",
            "If the APK ships no native code (no lib/ directory in the "
            "APK), the control is not applicable — record N/A with the "
            "absence as the evidence.",
            "If kept symbols are required (e.g. JNI_OnLoad, "
            "Java_<pkg>_<class>_<method>), confirm only those symbols are "
            "in .dynsym and that the Gradle / CMakeLists.txt build sets "
            "-fvisibility=hidden plus an explicit __attribute__"
            "((visibility(\"default\"))) on the exported set, so internal "
            "helpers do not leak.",
        ),
        relevant_apis=(
            "System.loadLibrary",
            "System.load",
            "Runtime.getRuntime().loadLibrary",
            "java.lang.Runtime.load",
            "android.os.Build.SUPPORTED_ABIS",
        ),
        evidence_hints=(
            "lib/arm64-v8a",
            "lib/armeabi-v7a",
            "lib/x86_64",
            ".so",
            "loadLibrary",
            "JNI_OnLoad",
            ".debug_info",
            ".symtab",
            "fvisibility",
        ),
    ),
    MasvsControl(
        id="MSTG-CODE-4",
        group=MasvsGroup.CODE,
        level=MasvsLevel.L1,
        title=(
            "Debugging code and developer assistance code (e.g. test code, "
            "backdoors, hidden settings) have been removed. The app does not "
            "log verbose errors or debugging messages."
        ),
        description=(
            "Release builds frequently retain code that exists only to make "
            "development cheap: hidden activities reachable by long-pressing "
            "the version label, debug menus gated by a hardcoded secret PIN, "
            "test endpoints in the network layer toggled by a shared-prefs "
            "key, Log.d / Log.v calls that print API responses and bearer "
            "tokens, Crashlytics breadcrumbs containing PII, and StrictMode "
            "developer-only checks. Any of these paths is a feature the "
            "release ships, not a debug aid — a research team or anyone with "
            "access to the binary will find the hidden activity name in the "
            "manifest and the secret PIN string in the code, and the verbose "
            "log lines surface in logcat or in crash-reporter consoles where "
            "they were never meant. The verification target is that the "
            "release build has no hidden-activity entry points, no debug-PIN "
            "branches, no test endpoints in the production network "
            "configuration, and no Log.{v,d,i} call sites that print "
            "secrets, tokens, request bodies, or PII."
        ),
        verification_steps=(
            "Inspect AndroidManifest.xml for activities, services, and "
            "receivers tagged with android:exported=\"true\" and a name "
            "like *Debug*, *Test*, *Hidden*, *Internal*, *Dev*; flag any "
            "exported developer-only entry point that ships in the "
            "release manifest. Also flag activities with an "
            "<intent-filter> for actions like ACTION_VIEW with a debug "
            "scheme (e.g. `appdebug://`).",
            "Search the decompiled tree for Log.v / Log.d / Log.i / "
            "Log.println calls and for System.out.println — note every "
            "call that prints a Throwable, a network response body, an "
            "auth header, a token, a session id, a user id, or any field "
            "annotated @SensitiveData. Confirm the release build's "
            "ProGuard / R8 config has -assumenosideeffects "
            "class android.util.Log { ... } stripping these.",
            "Search for hardcoded backdoor patterns: string equality "
            "comparisons against literals like \"123456\", \"qwerty\", "
            "\"masterkey\", developer email addresses, or "
            "shared-preferences keys named `internal_*` / `debug_*` / "
            "`override_*` that flip behaviour when set. Flag every "
            "branch gated on a constant the operator did not document.",
        ),
        relevant_apis=(
            "android.util.Log",
            "java.lang.System.out",
            "java.lang.System.err",
            "android.os.StrictMode",
            "com.google.firebase.crashlytics.FirebaseCrashlytics.log",
            "android.content.SharedPreferences",
            "android.content.pm.PackageManager.queryIntentActivities",
        ),
        evidence_hints=(
            "Log.d(",
            "Log.v(",
            "Log.i(",
            "System.out.println",
            "BuildConfig.DEBUG",
            "DebugActivity",
            "TestActivity",
            "internal_",
            "debug_",
            "assumenosideeffects",
        ),
    ),
    MasvsControl(
        id="MSTG-CODE-5",
        group=MasvsGroup.CODE,
        level=MasvsLevel.L1,
        title=(
            "All third-party components used by the mobile app, such as "
            "libraries and frameworks, are identified, and checked for "
            "known vulnerabilities."
        ),
        description=(
            "A modern Android APK pulls in tens to hundreds of transitive "
            "Gradle dependencies, each carrying its own bug history. A "
            "single outdated OkHttp ships with the OkHttp HeaderInjection "
            "CVE; a single outdated Bouncy Castle ships with key-recovery "
            "issues that nullify the app's crypto controls; a single "
            "outdated AndroidX library carries content-provider permission "
            "bypass fixes the app silently misses. The verification target "
            "is that the team maintains an inventory of every direct and "
            "transitive dependency the release ships (a CycloneDX / SPDX "
            "SBOM produced by the build), that the inventory is reconciled "
            "against a vulnerability feed (OSS Index, GitHub Advisory "
            "Database, OSV) on every release, and that no dependency in "
            "the final APK carries an unpatched CVE with a public exploit."
        ),
        verification_steps=(
            "Recover the dependency set from the APK: every `classes*.dex` "
            "package prefix that is not the app's own package id is a "
            "third-party library. Cross-reference against META-INF/*.version "
            "files (Kotlin / AndroidX leave version markers), the "
            "META-INF/MANIFEST.MF Implementation-Title / Implementation-"
            "Version pairs, and any embedded library-name string constants "
            "(\"OkHttp/4.10.0\", \"Retrofit2/2.9.0\").",
            "For every identified component + version pair, query the "
            "OSV.dev / GitHub Advisory Database / NVD feeds and record "
            "every advisory whose affected range matches the shipped "
            "version. Flag every advisory with CVSS ≥ 7.0 or with a "
            "public PoC as a finding, regardless of whether the app "
            "exercises the affected code path (the app's reachability "
            "guarantee can change with a patch).",
            "Inspect the build configuration for evidence of an SBOM step "
            "(cyclonedx-gradle-plugin, dependency-check-gradle, "
            "`./gradlew dependencyUpdates`) and a vulnerability gate in "
            "CI. Absence of a documented SBOM-on-release process is "
            "itself a control failure — even if today's snapshot is "
            "clean, the team has no mechanism to notice tomorrow's CVE.",
        ),
        relevant_apis=(
            "java.lang.Package.getImplementationVersion",
            "java.lang.Package.getName",
            "okhttp3.OkHttp.VERSION",
            "kotlin.KotlinVersion",
            "retrofit2.BuildConfig",
        ),
        evidence_hints=(
            "META-INF/MANIFEST.MF",
            "Implementation-Version",
            "kotlin-stdlib",
            "androidx.",
            "okhttp3",
            "retrofit2",
            "com.google.gson",
            "io.reactivex",
            "cyclonedx",
            "dependencyCheck",
        ),
    ),
    MasvsControl(
        id="MSTG-CODE-6",
        group=MasvsGroup.CODE,
        level=MasvsLevel.L1,
        title="The app catches and handles possible exceptions.",
        description=(
            "Java / Kotlin code that lets a checked or runtime exception "
            "propagate to the framework's uncaught-exception handler "
            "produces a process crash, a logcat stack trace, and (when "
            "Crashlytics or an equivalent is configured) an outbound "
            "report containing local-variable values, request bodies, "
            "and database row contents at the failure site. A crash is "
            "also a denial-of-service vector — any external untrusted "
            "caller that can drive the app into a crash path (a "
            "malformed deep link, an oversized Intent extra, a "
            "NumberFormatException from a manipulated query parameter) "
            "can keep the app unusable. The verification target is that "
            "every external boundary (IPC entry point, network response "
            "decoder, user-input parser) catches the specific exceptions "
            "its operations can throw, that catches do not swallow the "
            "exception silently (no `catch (Exception e) {}` empty "
            "bodies), and that catch bodies do not log secrets or PII "
            "while handling the failure."
        ),
        verification_steps=(
            "Search the decompiled tree for `catch (Exception` and "
            "`catch (Throwable` blocks and inspect each body: an empty "
            "body, a body that only re-prints the trace to logcat, or a "
            "body that returns a default value without a security "
            "decision is a silent-swallow. Flag every silent-swallow "
            "in a path that handles authentication, authorization, "
            "cryptographic verification, or session lifecycle.",
            "For every Activity / BroadcastReceiver / Service entry "
            "point that reads Intent extras, confirm extras are parsed "
            "with typed accessors (getStringExtra / getIntExtra) inside "
            "a try / catch that converts the failure into a "
            "user-visible error or a safe default — not a process "
            "crash that surfaces a stack trace to the caller of "
            "startActivity.",
            "Inspect the Application's uncaught-exception handler (if "
            "configured) and any Crashlytics setup: confirm crash "
            "reports do not include PII or secrets in the breadcrumb "
            "log (FirebaseCrashlytics.log calls with token / "
            "user-id / password material in the format string).",
        ),
        relevant_apis=(
            "java.lang.Thread.UncaughtExceptionHandler",
            "java.lang.Thread.setDefaultUncaughtExceptionHandler",
            "java.lang.Throwable.printStackTrace",
            "android.util.Log.getStackTraceString",
            "com.google.firebase.crashlytics.FirebaseCrashlytics.recordException",
            "kotlin.runCatching",
            "kotlinx.coroutines.CoroutineExceptionHandler",
        ),
        evidence_hints=(
            "catch (Exception",
            "catch (Throwable",
            "printStackTrace",
            "getStackTraceString",
            "UncaughtExceptionHandler",
            "recordException",
            "runCatching",
            "CoroutineExceptionHandler",
        ),
    ),
    MasvsControl(
        id="MSTG-CODE-7",
        group=MasvsGroup.CODE,
        level=MasvsLevel.L1,
        title="Error handling logic in security controls denies access by default.",
        description=(
            "Security controls — authentication checks, authorization "
            "gates, signature verifications, certificate validators — "
            "must fail closed: when the check cannot reach a definitive "
            "positive result, the path denies the operation. A control "
            "that returns `true` from its catch block (\"the network "
            "call failed, assume the user is authorized\") or that "
            "defaults a `Boolean?` to true when the upstream returns "
            "null is a fail-open control, equivalent to no control. "
            "The verification target is that every security boundary "
            "has an explicit deny default: catch blocks return false / "
            "throw / call the deny handler; null / empty / unparseable "
            "responses route to deny; default switch arms in "
            "permission decisions choose deny over allow."
        ),
        verification_steps=(
            "Identify every method whose name or body signals an "
            "authorization decision (isAuthorized, canAccess, "
            "verifySignature, validateToken, checkPermission) and "
            "inspect each catch / null-branch / default-arm: confirm "
            "the failure path returns false / throws SecurityException / "
            "routes to a deny handler. Flag every path that returns "
            "true / unit / a happy-default on failure.",
            "Inspect every certificate / signature validator "
            "(X509TrustManager.checkServerTrusted overrides, "
            "Signature.verify call sites, JWS / JWT validation) and "
            "confirm a thrown exception from the underlying provider "
            "is treated as a verification failure, not as a benign "
            "exception the caller can swallow.",
            "Inspect every server-response decoder that drives a "
            "permission decision: an HTTP 5xx or a JSON parse failure "
            "must route to deny, not to a cached-positive answer. "
            "Flag any code that on a network failure replays the last "
            "successful authorization result without a freshness "
            "check.",
        ),
        relevant_apis=(
            "java.lang.SecurityException",
            "javax.net.ssl.X509TrustManager.checkServerTrusted",
            "java.security.cert.CertPathValidator",
            "java.security.Signature.verify",
            "android.content.pm.PackageManager.checkPermission",
            "androidx.biometric.BiometricPrompt.AuthenticationCallback",
        ),
        evidence_hints=(
            "catch (Exception",
            "return true",
            "isAuthorized",
            "canAccess",
            "checkServerTrusted",
            "SecurityException",
            "checkPermission",
            "default:",
            "?: true",
        ),
    ),
    MasvsControl(
        id="MSTG-CODE-8",
        group=MasvsGroup.CODE,
        level=MasvsLevel.L1,
        title=(
            "In unmanaged code, memory is allocated, freed and used securely."
        ),
        description=(
            "An APK that ships native code (NDK-built .so files under "
            "lib/<abi>/, or Rust / C++ libraries loaded via System."
            "loadLibrary) carries the full set of C/C++ memory-safety "
            "risks: stack and heap buffer overflows, use-after-free, "
            "double-free, integer overflow into allocation sizes, "
            "off-by-one writes, and uninitialized reads. Memory issues "
            "in the native layer turn into RCE / code-execution / "
            "data-leak primitives that the JVM's bytecode-level "
            "guarantees cannot contain. If the APK has no native code, "
            "the control is not applicable for this build. The "
            "verification target is that every native call site that "
            "takes a length, offset, or buffer-derived size from the "
            "Java side is bounds-checked at the JNI boundary, that the "
            "native build enables -fstack-protector-strong / "
            "-D_FORTIFY_SOURCE=2 / -fsanitize=safe-stack, and that the "
            "release shipped through a fuzzer pass over the JNI entry "
            "points."
        ),
        verification_steps=(
            "List every native library the APK ships (lib/<abi>/*.so). "
            "If none, mark N/A. For each, inspect the JNI registration "
            "table (RegisterNatives calls and Java_<pkg>_<class>_<method> "
            "exported symbols) and identify every entry point that "
            "takes a byte[], String, or ByteBuffer plus a length / "
            "offset from the Java side.",
            "Confirm each JNI entry point validates the Java-supplied "
            "length against the actual array length via "
            "GetArrayLength / GetDirectBufferCapacity before passing "
            "the size to memcpy / memmove / strcpy / sprintf in the "
            "C/C++ body. Flag any call site that trusts a Java-side "
            "length without re-checking it native-side.",
            "Inspect the native build configuration (CMakeLists.txt, "
            "Android.mk, build.gradle.kts cmake { cppFlags }) for "
            "stack protectors (-fstack-protector-strong), fortified "
            "libc (-D_FORTIFY_SOURCE=2), control-flow integrity "
            "(-fsanitize=cfi when LTO is enabled), and AddressSanitizer "
            "during fuzzing. Absence of any of these is a finding for "
            "an APK that ships native code.",
        ),
        relevant_apis=(
            "java.lang.System.loadLibrary",
            "java.lang.System.load",
            "jni.h::RegisterNatives",
            "jni.h::GetArrayLength",
            "jni.h::GetByteArrayElements",
            "jni.h::GetDirectBufferCapacity",
            "jni.h::ReleaseByteArrayElements",
        ),
        evidence_hints=(
            "lib/arm64-v8a",
            ".so",
            "JNI_OnLoad",
            "RegisterNatives",
            "GetByteArrayElements",
            "GetArrayLength",
            "fstack-protector",
            "FORTIFY_SOURCE",
            "fsanitize",
            "memcpy",
        ),
    ),
    MasvsControl(
        id="MSTG-CODE-9",
        group=MasvsGroup.CODE,
        level=MasvsLevel.L1,
        title=(
            "Free security features offered by the toolchain, such as byte "
            "code minification, stack protection, PIE support, and automatic "
            "reference counting are activated."
        ),
        description=(
            "The Android toolchain ships free-of-cost defensive features "
            "the build is expected to turn on for release variants: R8 "
            "(or ProGuard) for bytecode shrink / obfuscate / optimize, "
            "resource shrinking for dead-resource removal, "
            "android:extractNativeLibs=\"false\" so .so files run from "
            "the APK without a writable on-disk copy, "
            "android:allowBackup=\"false\" so adb backup cannot exfiltrate "
            "the app's private data dir, android:usesCleartextTraffic=\"false\" "
            "as a network-stack default-deny, and PIE / RELRO / NX / "
            "stack-canary flags on every shipped .so. The verification "
            "target is that the release variant has these flags / "
            "settings active and that no per-flavour override silently "
            "disables them for the shipping SKU."
        ),
        verification_steps=(
            "Inspect the Gradle release buildType for minifyEnabled true, "
            "shrinkResources true, and the proguardFiles / R8 rules path; "
            "absence of any of these is a finding. Cross-check the "
            "decompiled bytecode: heavily-obfuscated method / class names "
            "(a / b / c, or alphabet-soup) plus stripped line numbers "
            "indicate R8 ran; clear method names indicate it did not.",
            "Inspect AndroidManifest.xml for "
            "android:allowBackup, android:extractNativeLibs, "
            "android:usesCleartextTraffic, android:networkSecurityConfig — "
            "the release should set allowBackup=\"false\", "
            "extractNativeLibs=\"false\", usesCleartextTraffic=\"false\", "
            "and reference a network_security_config.xml that denies "
            "cleartext by default. Flag every explicit `true` on the "
            "permissive flags.",
            "For every shipped lib/<abi>/*.so, inspect ELF flags via "
            "checksec / readelf -d / readelf -l: confirm PIE (Type: "
            "DYN), NX (GNU_STACK without PF_X), RELRO (GNU_RELRO present, "
            "BIND_NOW preferred), stack canaries (__stack_chk_fail "
            "symbol referenced), and no executable, writable segments. "
            "Record every shipped library that misses any of these.",
        ),
        relevant_apis=(
            "android.app.Application",
            "android.content.pm.ApplicationInfo.flags",
            "android.content.pm.ApplicationInfo.FLAG_ALLOW_BACKUP",
            "android.content.pm.ApplicationInfo.FLAG_EXTRACT_NATIVE_LIBS",
        ),
        evidence_hints=(
            "android:allowBackup",
            "android:extractNativeLibs",
            "android:networkSecurityConfig",
            "android:usesCleartextTraffic",
            "minifyEnabled",
            "shrinkResources",
            "proguardFiles",
            "__stack_chk_fail",
            "GNU_RELRO",
            "BIND_NOW",
        ),
    ),
)


_RESILIENCE_CONTROLS: tuple[MasvsControl, ...] = (
    MasvsControl(
        id="MSTG-RESILIENCE-1",
        group=MasvsGroup.RESILIENCE,
        level=MasvsLevel.R,
        title=(
            "The app detects, and responds to, the presence of a rooted or "
            "jailbroken device by either alerting the user or terminating the app."
        ),
        description=(
            "Root access lifts every Android sandbox boundary the app relies on: "
            "/data/data/<package> becomes world-readable, the Keystore "
            "implementation is replaceable by a hostile module, Frida / Xposed "
            "gain process-injection capability, and any co-installed app gains "
            "the ability to read this app's memory, snapshot its traffic, or "
            "rewrite its dex / native libs on disk. A high-risk app (banking, "
            "healthcare, identity) is expected to detect this state through "
            "filesystem markers (su binary, Superuser.apk, Magisk manager "
            "package), mount-flag scans of /proc/mounts, package-manager "
            "queries for known rooting toolchains, and a remote attestation "
            "(Play Integrity / SafetyNet Attestation) signal. The verification "
            "target is that the release build references at least one root "
            "signal AND a real response path that activates when the signal "
            "trips — a logout, a refused transaction, an exit — rather than a "
            "Log.d and a swallow."
        ),
        verification_steps=(
            "Search for filesystem root markers: File.exists checks against "
            "/system/xbin/su, /sbin/su, /system/bin/su, /system/app/Superuser.apk, "
            "/system/app/SuperSU.apk, /data/local/xbin/su, "
            "/system/etc/init.d/99SuperSUDaemon; mount-flag scans reading "
            "/proc/mounts looking for `rw,` on /system; PackageManager queries "
            "for com.koushikdutta.superuser, eu.chainfire.supersu, "
            "com.topjohnwu.magisk. Absence of every marker check is a finding.",
            "Search for Play Integrity / SafetyNet Attestation usage: "
            "IntegrityManager.requestIntegrityToken or "
            "SafetyNetClient.attest. Confirm the verdict / decoded JWS is "
            "checked against the expected ctsProfileMatch / basicIntegrity / "
            "deviceRecognitionVerdict, and the result gates a sensitive "
            "operation; absence of attestation or a verdict-discarded path is "
            "a finding for any banking-style app.",
            "For every detection signal, trace the boolean to its consumer "
            "and confirm a non-trivial response: app exit (System.exit / "
            "finishAffinity), refusal of login or transaction, server-side "
            "alert. A signal that only writes Log.d / Timber.w and lets the "
            "code continue is a finding — detection without response gives "
            "the operator nothing.",
        ),
        relevant_apis=(
            "com.google.android.play.core.integrity.IntegrityManager.requestIntegrityToken",
            "com.google.android.gms.safetynet.SafetyNetClient.attest",
            "com.scottyab.rootbeer.RootBeer.isRooted",
            "java.io.File.exists",
            "java.lang.Runtime.exec",
            "android.os.Build.TAGS",
            "android.content.pm.PackageManager.getPackageInfo",
            "android.content.pm.PackageManager.getInstalledPackages",
        ),
        evidence_hints=(
            "RootBeer",
            "isRooted",
            "/system/xbin/su",
            "/system/bin/su",
            "Superuser.apk",
            "com.topjohnwu.magisk",
            "eu.chainfire.supersu",
            "SafetyNet",
            "IntegrityManager",
            "test-keys",
            "Build.TAGS",
            "/proc/mounts",
        ),
    ),
    MasvsControl(
        id="MSTG-RESILIENCE-2",
        group=MasvsGroup.RESILIENCE,
        level=MasvsLevel.R,
        title=(
            "The app prevents debugging and/or detects, and responds to, a "
            "debugger being attached. All available debugging protocols must be "
            "covered."
        ),
        description=(
            "Android exposes multiple independent debugging channels: JDWP at "
            "the Java layer (gated by android:debuggable in the manifest and "
            "ApplicationInfo.FLAG_DEBUGGABLE at runtime), ptrace at the native "
            "layer (any process with the same UID can attach unless "
            "PTRACE_TRACEME blocks it), and JNI / inferior-process inspection "
            "through /proc/<pid>/mem. A release build that closes JDWP via the "
            "manifest still leaves native ptrace open, and vice versa — every "
            "channel must be covered. The verification target is that "
            "android:debuggable is false in the release manifest, that the "
            "Java code checks Debug.isDebuggerConnected before sensitive "
            "operations, that shipped native libraries install a "
            "PTRACE_TRACEME anti-attach guard, and that TracerPid in "
            "/proc/self/status is read periodically with a response path that "
            "trips when a non-zero value is observed."
        ),
        verification_steps=(
            "Inspect AndroidManifest.xml for android:debuggable on the "
            "<application> tag — a release build with debuggable=\"true\" is "
            "a finding regardless of detection logic, because it grants JDWP "
            "to any host running `adb`. Cross-check ApplicationInfo flags at "
            "runtime if the manifest is ambiguous.",
            "Search for Java-side debugger checks: Debug.isDebuggerConnected, "
            "Debug.waitingForDebugger, ApplicationInfo.flags & "
            "ApplicationInfo.FLAG_DEBUGGABLE. Confirm at least one fires "
            "before login / transaction and that its boolean reaches a "
            "real-response path (exit, refused operation), not a swallowed "
            "Log call.",
            "Inspect every shipped .so for native anti-debug: ptrace("
            "PTRACE_TRACEME, 0, 0, 0) called early in JNI_OnLoad or library "
            "constructors; periodic /proc/self/status reads parsing the "
            "TracerPid: line and reacting on non-zero. Absence of any native "
            "anti-debug on a high-risk build is a finding for this control.",
        ),
        relevant_apis=(
            "android.os.Debug.isDebuggerConnected",
            "android.os.Debug.waitingForDebugger",
            "android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE",
            "android.content.pm.ApplicationInfo.flags",
            "ptrace",
            "PTRACE_TRACEME",
            "/proc/self/status",
            "JNI_OnLoad",
        ),
        evidence_hints=(
            "isDebuggerConnected",
            "waitingForDebugger",
            "FLAG_DEBUGGABLE",
            "android:debuggable",
            "ptrace",
            "PTRACE_TRACEME",
            "TracerPid",
            "/proc/self/status",
            "JNI_OnLoad",
            "JDWP",
        ),
    ),
    MasvsControl(
        id="MSTG-RESILIENCE-3",
        group=MasvsGroup.RESILIENCE,
        level=MasvsLevel.R,
        title=(
            "The app detects, and responds to, tampering with executable files "
            "and critical data within its own sandbox."
        ),
        description=(
            "An installed APK can be unpacked, patched, re-signed with a "
            "different developer certificate, and reinstalled — the OS will "
            "accept the resigned build as a fresh first-install. A privileged "
            "caller (root, a custom recovery, an OEM service running as system) "
            "can rewrite files inside /data/data/<package> while the app is "
            "stopped. Tamper detection compares runtime state against a "
            "baseline known at build time: the SHA-256 of the signing "
            "certificate matches a hard-coded constant, the bundled .so files "
            "match their build-time digest, configuration files are unchanged. "
            "The verification target is that the release build performs at "
            "least one signature self-check at startup, that the check compares "
            "against a baked-in constant (not a remote value), and that a "
            "tamper signal triggers a non-trivial response — refuse to "
            "launch, switch to a read-only mode, post a server alert."
        ),
        verification_steps=(
            "Search for signature self-verification: "
            "PackageManager.getPackageInfo(packageName, GET_SIGNATURES) on "
            "API < 28 and GET_SIGNING_CERTIFICATES / "
            "SigningInfo.getApkContentsSigners on API ≥ 28, followed by a "
            "SHA-256 of the resulting byte[] compared to a constant. Flag if "
            "the compared constant is read from a remote source or a writable "
            "config — that defeats the purpose.",
            "Inspect every shipped lib/<abi>/*.so for self-checksum routines "
            "or a build-time hash recorded in the APK (e.g. an asset bundle) "
            "that the JNI bridge verifies at System.loadLibrary time. Absence "
            "of any native integrity check on a high-risk build is a finding.",
            "Confirm a non-trivial response on tamper signal: System.exit, "
            "refused login, downgrade to limited operation, server-side alert "
            "via the analytics or telemetry pipeline. A tamper-signal path "
            "that calls Log.d and returns is detection without response — "
            "flag as a finding.",
        ),
        relevant_apis=(
            "android.content.pm.PackageManager.getPackageInfo",
            "android.content.pm.PackageInfo.signatures",
            "android.content.pm.SigningInfo",
            "android.content.pm.SigningInfo.getApkContentsSigners",
            "android.content.pm.SigningInfo.getSigningCertificateHistory",
            "java.security.MessageDigest.getInstance",
            "java.util.zip.ZipFile",
            "java.lang.System.loadLibrary",
        ),
        evidence_hints=(
            "GET_SIGNATURES",
            "GET_SIGNING_CERTIFICATES",
            "PackageInfo.signatures",
            "SigningInfo",
            "getApkContentsSigners",
            "SHA-256",
            "signatureDigest",
            "MessageDigest",
            "loadLibrary",
        ),
    ),
    MasvsControl(
        id="MSTG-RESILIENCE-4",
        group=MasvsGroup.RESILIENCE,
        level=MasvsLevel.R,
        title=(
            "The app detects, and responds to, the presence of widely used "
            "reverse engineering tools and frameworks on the device."
        ),
        description=(
            "Frida (frida-server, frida-gadget), Xposed (de.robv.android.xposed), "
            "Cydia Substrate, and similar dynamic-instrumentation frameworks "
            "inject code into the target process so a researcher (or anyone "
            "with physical access plus root) can read sensitive variables, "
            "rewrite return values mid-call, or proxy crypto operations through "
            "a logging hook. Detection methods scan /proc/self/maps for known "
            "injected library names, query PackageManager for known framework "
            "installer packages, look for the frida-server default port "
            "(27042) being open on loopback, and watch Thread.getAllStackTraces "
            "output for Frida-internal thread names (gum-js-loop, gmain, "
            "linjector). The verification target is that the release build "
            "carries at least one RE-tool detection signal with a real response "
            "path, not a static-string match buried in dead code."
        ),
        verification_steps=(
            "Search for /proc/self/maps scans: BufferedReader iterations "
            "looking for substrings frida-, gum-js-loop, linjector, "
            "xposedbridge, substrate. Absence of any /proc/self/maps "
            "instrumentation-library scan on a high-risk build is a finding.",
            "Search for PackageManager queries against known RE-tool packages: "
            "de.robv.android.xposed.installer, com.saurik.substrate, "
            "com.devadvance.rootcloak, com.formyhm.hideroot, "
            "org.lsposed.manager. Confirm at least one query exists and its "
            "result reaches a real-response path.",
            "Inspect Thread.getAllStackTraces / ThreadGroup.enumerate "
            "iterations for thread-name checks against gum-js-loop, gmain, "
            "linjector; alternatively look for native code probing the "
            "loopback 27042 port for an open frida-server listener. Confirm "
            "the detection signal triggers exit, refused operation, or "
            "server alert.",
        ),
        relevant_apis=(
            "java.io.BufferedReader.readLine",
            "android.content.pm.PackageManager.getInstalledApplications",
            "android.content.pm.PackageManager.getInstalledPackages",
            "android.content.pm.PackageManager.getPackageInfo",
            "java.lang.Thread.getAllStackTraces",
            "java.lang.ThreadGroup.enumerate",
            "java.net.Socket",
            "java.net.ServerSocket",
            "java.lang.Runtime.exec",
        ),
        evidence_hints=(
            "frida",
            "frida-server",
            "frida-gadget",
            "gum-js-loop",
            "linjector",
            "de.robv.android.xposed",
            "com.saurik.substrate",
            "org.lsposed.manager",
            "rootcloak",
            "/proc/self/maps",
            "27042",
            "getAllStackTraces",
        ),
    ),
)


_PRIVACY_CONTROLS: tuple[MasvsControl, ...] = (
    MasvsControl(
        id="MASVS-PRIVACY-1",
        group=MasvsGroup.PRIVACY,
        level=MasvsLevel.L1,
        title=(
            "The app minimizes access to sensitive data and resources."
        ),
        description=(
            "Permissions and the platform APIs they gate are the boundary that "
            "decides what a compromised module — a third-party SDK, a "
            "WebView-loaded marketing page, a deep-link handler that took a "
            "crafted intent — can reach. Every permission the manifest "
            "declares but the app never exercises is residual blast radius "
            "for free; every dangerous permission requested without a runtime "
            "prompt at the moment of need trains the user to accept future "
            "prompts blindly; every use of an over-broad permission "
            "(ACCESS_FINE_LOCATION when COARSE is enough, persistent CAMERA "
            "when ACTION_IMAGE_CAPTURE picks up a one-shot intent) lets the "
            "app collect strictly more than the feature requires. The "
            "verification target is that the release manifest's "
            "<uses-permission> list is a strict subset of what reachable code "
            "actually needs, that every dangerous permission goes through "
            "ContextCompat.checkSelfPermission + "
            "ActivityCompat.requestPermissions at the call site that needs "
            "it, and that no permission is declared for a code path that the "
            "release build has stripped via ProGuard / R8."
        ),
        verification_steps=(
            "Enumerate every <uses-permission> entry in AndroidManifest.xml "
            "and cross-reference each against actual callers in the "
            "decompiled tree (Manifest.permission.<NAME> string literal, "
            "checkSelfPermission(<NAME>) call site, requestPermissions "
            "array containing it). Flag any permission declared in the "
            "manifest with zero non-test caller references — that is "
            "residual blast radius left over from a removed feature.",
            "For every dangerous permission (READ_CONTACTS, "
            "ACCESS_FINE_LOCATION, ACCESS_COARSE_LOCATION, READ_PHONE_STATE, "
            "RECORD_AUDIO, CAMERA, READ_EXTERNAL_STORAGE, READ_SMS, "
            "READ_CALL_LOG, READ_CALENDAR, BODY_SENSORS), trace the call "
            "site that consumes the corresponding platform API and confirm "
            "a ContextCompat.checkSelfPermission gate plus an "
            "ActivityCompat.requestPermissions prompt fires immediately "
            "before the protected call, not at app launch and not pre-"
            "emptively in a splash screen. A pre-emptive bundled request "
            "is a finding because it severs the prompt from the user-"
            "visible feature it gates.",
            "Search for over-broad permission patterns: "
            "ACCESS_FINE_LOCATION where the feature only needs city-level "
            "(use ACCESS_COARSE_LOCATION); manifest CAMERA where the only "
            "consumer launches ACTION_IMAGE_CAPTURE / "
            "ACTION_VIDEO_CAPTURE (the system camera handles the "
            "permission via the intent contract, the app does not need its "
            "own); manifest READ_EXTERNAL_STORAGE where the only consumer "
            "uses ACTION_OPEN_DOCUMENT / ACTION_GET_CONTENT (the Storage "
            "Access Framework returns a content:// URI without the "
            "permission). Each is a finding.",
        ),
        relevant_apis=(
            "androidx.core.app.ActivityCompat.requestPermissions",
            "androidx.core.content.ContextCompat.checkSelfPermission",
            "android.content.pm.PackageManager.checkPermission",
            "android.Manifest.permission.READ_CONTACTS",
            "android.Manifest.permission.ACCESS_FINE_LOCATION",
            "android.Manifest.permission.ACCESS_COARSE_LOCATION",
            "android.Manifest.permission.READ_PHONE_STATE",
            "android.Manifest.permission.RECORD_AUDIO",
            "android.Manifest.permission.CAMERA",
            "android.Manifest.permission.READ_EXTERNAL_STORAGE",
            "android.content.Intent.ACTION_IMAGE_CAPTURE",
            "android.content.Intent.ACTION_OPEN_DOCUMENT",
        ),
        evidence_hints=(
            "uses-permission",
            "checkSelfPermission",
            "requestPermissions",
            "READ_CONTACTS",
            "ACCESS_FINE_LOCATION",
            "ACCESS_COARSE_LOCATION",
            "READ_PHONE_STATE",
            "RECORD_AUDIO",
            "READ_EXTERNAL_STORAGE",
            "ACTION_IMAGE_CAPTURE",
            "ACTION_OPEN_DOCUMENT",
        ),
    ),
    MasvsControl(
        id="MASVS-PRIVACY-2",
        group=MasvsGroup.PRIVACY,
        level=MasvsLevel.L1,
        title=(
            "The app prevents identification of the user through "
            "persistent device identifiers."
        ),
        description=(
            "Persistent device identifiers — IMEI, IMSI, ICCID, hardware "
            "MAC, Build.SERIAL, ANDROID_ID — survive app uninstall and "
            "reinstall, span apps signed by different keys, and on older "
            "Android versions are readable by any process holding "
            "READ_PHONE_STATE. An app that collects one or more of them, "
            "ships them to a backend, and joins them across sessions has "
            "built a cross-install user identity the user cannot reset. "
            "The current Google Play policy steers apps toward the "
            "advertising id (AdvertisingIdClient) for non-essential "
            "tracking and a per-app-instance resettable id for everything "
            "else; even the advertising id must honor the "
            "isLimitAdTrackingEnabled flag and must not be retained when "
            "the user has opted out. The verification target is that the "
            "release build does not call the persistent-identifier APIs "
            "at all unless a specific feature (carrier auth, IMSI-based "
            "SIM-swap detection) documents the need, and that any "
            "advertising-id consumer respects the limit-ad-tracking signal."
        ),
        verification_steps=(
            "Search for retrievals of persistent telephony identifiers — "
            "TelephonyManager.getDeviceId, getImei, getMeid, "
            "getSubscriberId, getSimSerialNumber. Each is a finding "
            "unless the surrounding code documents a carrier-auth or "
            "SIM-swap-detection use case AND the retrieved value never "
            "reaches an analytics or marketing pipeline.",
            "Search for Settings.Secure.ANDROID_ID and Build.SERIAL "
            "reads. ANDROID_ID is per-signing-key per-user since API 26 "
            "but still survives uninstall within the same signing key; "
            "treat it as a finding when it reaches an analytics call, a "
            "user identifier field in a backend payload, or a "
            "fingerprint-style hash. Build.SERIAL returns UNKNOWN on "
            "API 26+ but legacy reads on older targets are still in "
            "scope.",
            "Search for hardware MAC reads via WifiInfo.getMacAddress, "
            "BluetoothAdapter.getAddress, or NetworkInterface enumeration "
            "looking for wlan0 / eth0. Modern Android randomizes these "
            "but legacy code paths still find them — flag any value that "
            "reaches a network call or a SharedPreferences write.",
            "Search for AdvertisingIdClient.getAdvertisingIdInfo usage "
            "and confirm the consumer checks "
            "AdvertisingIdClient.Info.isLimitAdTrackingEnabled() AND "
            "returns early / clears the cached id when it returns true. "
            "A call that ignores the flag, or that falls back to "
            "ANDROID_ID when the flag is set, is a finding.",
        ),
        relevant_apis=(
            "android.telephony.TelephonyManager.getDeviceId",
            "android.telephony.TelephonyManager.getImei",
            "android.telephony.TelephonyManager.getMeid",
            "android.telephony.TelephonyManager.getSubscriberId",
            "android.telephony.TelephonyManager.getSimSerialNumber",
            "android.provider.Settings.Secure.ANDROID_ID",
            "android.os.Build.SERIAL",
            "android.net.wifi.WifiInfo.getMacAddress",
            "android.bluetooth.BluetoothAdapter.getAddress",
            "java.net.NetworkInterface.getHardwareAddress",
            "com.google.android.gms.ads.identifier.AdvertisingIdClient",
            "com.google.android.gms.ads.identifier.AdvertisingIdClient.Info.isLimitAdTrackingEnabled",
        ),
        evidence_hints=(
            "getDeviceId",
            "getImei",
            "getMeid",
            "getSubscriberId",
            "getSimSerialNumber",
            "ANDROID_ID",
            "Build.SERIAL",
            "getMacAddress",
            "getHardwareAddress",
            "AdvertisingIdClient",
            "isLimitAdTrackingEnabled",
            "READ_PHONE_STATE",
        ),
    ),
    MasvsControl(
        id="MASVS-PRIVACY-3",
        group=MasvsGroup.PRIVACY,
        level=MasvsLevel.L1,
        title=(
            "The app is transparent about the personal data it collects, "
            "the third parties it shares it with, and the purposes it "
            "uses it for."
        ),
        description=(
            "Transparency means a user can, without launching the app, "
            "find out which categories of personal data the app gathers, "
            "where each category goes, and why. The Play Store Data "
            "Safety form is one half of this; the in-app privacy notice "
            "(a link reachable from the about screen, a first-launch "
            "disclosure dialog, a settings entry) is the other. An app "
            "that ships a Firebase Analytics, Crashlytics, AppsFlyer, or "
            "AdMob SDK without disclosing it has lied to the user about "
            "what is happening on their device. The verification target "
            "is that every third-party SDK the build statically links is "
            "named in the in-app privacy notice / Data Safety entry, "
            "that a privacy-policy URL is reachable from a static "
            "settings screen, and that any silent auto-backup of "
            "sensitive data into the user's Google account is either "
            "disclosed or excluded via dataExtractionRules / "
            "fullBackupContent."
        ),
        verification_steps=(
            "Search the resource bundle (strings.xml, asset HTML) and "
            "the AndroidManifest <meta-data> tags for a reachable "
            "privacy-policy URL — common patterns: a string resource "
            "named privacy_policy / privacyPolicy / privacy_url, a "
            "TextView setText reference, an Intent.ACTION_VIEW with a "
            "Uri pointing at /privacy / /legal / /privacy-policy. "
            "Absence of any reachable URL is a finding for any app "
            "shipping to Play (Play policy requires it).",
            "Enumerate every statically-linked third-party SDK by "
            "scanning the package list for known prefixes — "
            "com.google.firebase.analytics, com.google.firebase."
            "crashlytics, com.mixpanel, com.amplitude, com.appsflyer, "
            "io.branch.referral, io.sentry, com.bugsnag, "
            "com.facebook.appevents, com.adjust.sdk, com.singular, "
            "com.google.android.gms.ads. For each, confirm an initialization "
            "call site (FirebaseAnalytics.getInstance, Sentry.init, "
            "AppsFlyerLib.getInstance().start) AND its presence in the "
            "in-app privacy notice strings; an undisclosed analytics "
            "or ads SDK is a finding.",
            "Inspect AndroidManifest.xml <application> for "
            "android:allowBackup, android:dataExtractionRules (API 31+), "
            "and android:fullBackupContent. allowBackup=\"true\" without "
            "an explicit dataExtractionRules / fullBackupContent file "
            "uploads the entire app-private storage to the user's "
            "Google Drive on cloud-backup; for an app handling tokens "
            "or PII this is a finding unless the user is informed and a "
            "<cloud-backup> / <full-backup-content> rule excludes the "
            "sensitive paths.",
        ),
        relevant_apis=(
            "android.app.Application.onCreate",
            "android.content.Intent.ACTION_VIEW",
            "com.google.firebase.analytics.FirebaseAnalytics.getInstance",
            "com.google.firebase.crashlytics.FirebaseCrashlytics.getInstance",
            "io.sentry.Sentry.init",
            "com.appsflyer.AppsFlyerLib.start",
            "com.adjust.sdk.Adjust.onCreate",
            "com.mixpanel.android.mpmetrics.MixpanelAPI.getInstance",
            "com.amplitude.android.Amplitude",
        ),
        evidence_hints=(
            "privacy_policy",
            "privacyPolicy",
            "privacy_url",
            "/privacy",
            "FirebaseAnalytics",
            "Crashlytics",
            "Mixpanel",
            "Amplitude",
            "AppsFlyer",
            "Branch",
            "Sentry",
            "Bugsnag",
            "com.adjust.sdk",
            "allowBackup",
            "dataExtractionRules",
            "fullBackupContent",
        ),
    ),
    MasvsControl(
        id="MASVS-PRIVACY-4",
        group=MasvsGroup.PRIVACY,
        level=MasvsLevel.L1,
        title=(
            "The app gives the user control over their personal data — "
            "access, deletion, and withdrawal of consent."
        ),
        description=(
            "Control means the user can, from inside the app, see what "
            "the app has stored about them, remove it, and revoke any "
            "consent they previously gave to non-essential data "
            "collection. The Play Store account-deletion policy "
            "(effective 2024) requires every app that supports account "
            "creation to also support in-app account deletion plus a "
            "URL-reachable deletion path for users who have already "
            "uninstalled. GDPR adds a right of access and the right to "
            "withdraw consent at any time; CCPA / CPRA adds a "
            "Do-Not-Sell signal. The verification target is that the "
            "release build exposes (a) a user-initiated delete-account "
            "flow that wipes the local cache and POSTs to a server-side "
            "delete endpoint, (b) per-SDK opt-out toggles for analytics "
            "and crash reporting that actually flip the SDK's enabled "
            "flag (not just a SharedPreferences boolean), and (c) a "
            "GDPR / CCPA consent gate that defers SDK initialization "
            "until consent is recorded."
        ),
        verification_steps=(
            "Search for an in-app account-deletion flow: a "
            "TextView / Button referencing a delete_account / "
            "deleteAccount / close_account resource string, a Retrofit / "
            "OkHttp DELETE call against /users/me or /account, plus a "
            "local wipe via SharedPreferences.Editor.clear, "
            "Context.deleteDatabase, AccountManager.removeAccount, and "
            "WorkManager.cancelAllWork. Absence of any in-app deletion "
            "path on an app that supports account creation is a finding "
            "under Play policy.",
            "Search for analytics / crash-reporting opt-out toggles "
            "wired to real SDK calls — "
            "FirebaseAnalytics.setAnalyticsCollectionEnabled(false), "
            "FirebaseCrashlytics.setCrashlyticsCollectionEnabled(false), "
            "AppsFlyerLib.stop(true), Mixpanel.optOutTracking. A "
            "settings toggle that only writes a SharedPreferences "
            "boolean without reaching the SDK is a finding because the "
            "SDK continues collecting until the next app launch.",
            "Search for a consent-management gate that runs before any "
            "non-essential SDK initialization — Google UMP "
            "ConsentInformation.requestConsentInfoUpdate + ConsentForm, "
            "a custom GDPR / CCPA banner that stores the choice and a "
            "conditional branch in Application.onCreate / "
            "MainActivity.onCreate that defers SDK init when consent is "
            "missing. SDK initialization unconditional in Application."
            "onCreate, with no preceding consent check, is a finding "
            "for any app shipping to EU / UK / California users.",
        ),
        relevant_apis=(
            "com.google.firebase.analytics.FirebaseAnalytics.setAnalyticsCollectionEnabled",
            "com.google.firebase.crashlytics.FirebaseCrashlytics.setCrashlyticsCollectionEnabled",
            "com.appsflyer.AppsFlyerLib.stop",
            "com.mixpanel.android.mpmetrics.MixpanelAPI.optOutTracking",
            "com.google.android.ump.ConsentInformation.requestConsentInfoUpdate",
            "com.google.android.ump.ConsentForm.show",
            "android.content.SharedPreferences.Editor.clear",
            "android.content.Context.deleteDatabase",
            "android.accounts.AccountManager.removeAccount",
            "androidx.work.WorkManager.cancelAllWork",
        ),
        evidence_hints=(
            "delete_account",
            "deleteAccount",
            "close_account",
            "setAnalyticsCollectionEnabled",
            "setCrashlyticsCollectionEnabled",
            "optOutTracking",
            "ConsentInformation",
            "ConsentForm",
            "requestConsentInfoUpdate",
            "GDPR",
            "CCPA",
            "UMP",
            "removeAccount",
            "Editor.clear",
            "deleteDatabase",
        ),
    ),
)


MASVS_CONTROLS: tuple[MasvsControl, ...] = (
    *_STORAGE_CONTROLS,
    *_CRYPTO_CONTROLS,
    *_AUTH_CONTROLS,
    *_NETWORK_CONTROLS,
    *_PLATFORM_CONTROLS,
    *_CODE_CONTROLS,
    *_RESILIENCE_CONTROLS,
    *_PRIVACY_CONTROLS,
)
