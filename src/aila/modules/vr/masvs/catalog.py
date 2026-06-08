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
    "MASVS_CONTROLS",
]


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


MASVS_CONTROLS: tuple[MasvsControl, ...] = (
    *_STORAGE_CONTROLS,
    *_CRYPTO_CONTROLS,
)
