"""APK static checks: exploit chains, local-auth gates, SBOM, and Flutter detection."""
from __future__ import annotations

from aila.modules.vr.apk_static.models import (
    ApkStaticCheck,
    ApkStaticGroup,
    ApkStaticMode,
)

CHECKS: tuple[ApkStaticCheck, ...] = (
    ApkStaticCheck(
        id="APK-CHAIN-INTENT-REDIRECTION",
        group=ApkStaticGroup.CHAINS,
        mode=ApkStaticMode.STATIC,
        title="Nested Intent extra re-dispatched via startActivity, reaching non-exported components.",
        description=(
            "An exported component reads a nested Intent supplied by the "
            "caller (getParcelableExtra(\"intent\") / EXTRA_INTENT / a "
            "PendingIntent extra) and re-launches it with startActivity, "
            "startService, or sendBroadcast. A malicious app calls the "
            "exported entry with a nested Intent whose ComponentName "
            "points at an internal, non-exported activity or content "
            "provider, and the host app becomes the confused deputy that "
            "opens it. This is the single most common paid finding in "
            "Android bug bounty programs and is the canonical Intent "
            "redirection pattern documented by Google Play Protect."
        ),
        verification_steps=(
            "search_functions / semantic_search the decompiled tree for "
            "getParcelableExtra with argument \"intent\" or android.content.Intent.EXTRA_INTENT, "
            "and for getParcelable calls returning Intent or PendingIntent.",
            "read_function each hit and follow the returned Intent: a "
            "finding requires the value to reach startActivity, "
            "startActivityForResult, startService, sendBroadcast, or "
            "PendingIntent.send with no ComponentName / package / signature "
            "validation between read and dispatch.",
            "Cross-reference the hosting component in AndroidManifest.xml "
            "via read_lines: only exported components (android:exported=\"true\" "
            "or an intent-filter without permission gating) are reachable "
            "from another app, and confirm the internal target the nested "
            "Intent can reach is genuinely sensitive before reporting.",
        ),
        relevant_apis=(
            "android.content.Intent.getParcelableExtra",
            "android.content.Intent.EXTRA_INTENT",
            "android.app.PendingIntent.send",
            "android.content.Context.startActivity",
            "android.content.Context.sendBroadcast",
        ),
        evidence_hints=(
            "getParcelableExtra(\"intent\"",
            "EXTRA_INTENT",
            "PendingIntent.send",
            "startActivity(",
        ),
        cwe=("CWE-926", "CWE-441"),
        masvs_refs=("MASVS-PLATFORM-1",),
    ),
    ApkStaticCheck(
        id="APK-CHAIN-DEEPLINK-WEBVIEW",
        group=ApkStaticGroup.CHAINS,
        mode=ApkStaticMode.STATIC,
        title="Deep-link parameter flows into WebView.loadUrl, giving one-click arbitrary URL/JS load.",
        description=(
            "A component declared in an intent-filter (custom scheme, "
            "http/https app link, or android-app:// referrer link) reads "
            "a query parameter or path segment from the incoming Uri and "
            "passes it, unvalidated, to WebView.loadUrl or loadDataWithBaseURL. "
            "One click on a crafted URL loads any origin, and if the "
            "WebView has setJavaScriptEnabled(true) or an @JavascriptInterface "
            "bridge, the loaded page can call the bridge, read session "
            "cookies, or exfiltrate an OAuth token that the app is about "
            "to consume. This is the highest-impact modern Android chain."
        ),
        verification_steps=(
            "read_lines AndroidManifest.xml and enumerate every "
            "<intent-filter> with a <data> element that names a scheme, "
            "host, or android:autoVerify; note the receiving activity for "
            "each.",
            "search_functions / semantic_search the receiving activities "
            "for getIntent().getData(), Uri.getQueryParameter, "
            "Uri.getPathSegments, and read_function to trace whether the "
            "value reaches WebView.loadUrl, loadDataWithBaseURL, or "
            "loadData without host / scheme allow-list checks.",
            "Confirm the target WebView calls setJavaScriptEnabled(true) "
            "or addJavascriptInterface, and check that no "
            "shouldOverrideUrlLoading rejects the injected origin, before "
            "reporting; loading a static asset with JS disabled is not a "
            "finding.",
        ),
        relevant_apis=(
            "android.net.Uri.getQueryParameter",
            "android.content.Intent.getData",
            "android.webkit.WebView.loadUrl",
            "android.webkit.WebView.loadDataWithBaseURL",
            "android.webkit.WebSettings.setJavaScriptEnabled",
        ),
        evidence_hints=(
            "getQueryParameter(",
            "getIntent().getData()",
            "loadUrl(",
            "addJavascriptInterface(",
        ),
        cwe=("CWE-939", "CWE-601"),
        masvs_refs=("MASVS-PLATFORM-1", "MASVS-PLATFORM-2"),
    ),
    ApkStaticCheck(
        id="APK-CHAIN-URL-VALIDATION-BYPASS",
        group=ApkStaticGroup.CHAINS,
        mode=ApkStaticMode.STATIC,
        title="Deep-link host allow-list bypassable via userinfo, backslash, or Uri/URL parser disagreement.",
        description=(
            "A custom host / scheme validator compares Uri.getHost() (or "
            "the substring before the first slash) to an allow-list, but "
            "the check is defeated by userinfo (\"trusted.example\\@evil.com\"), "
            "backslash smuggling that android.net.Uri and java.net.URL "
            "parse differently on API level 24 and below, or by IDNA / "
            "Unicode homoglyphs. Downstream code then treats a hostile "
            "origin as first-party and grants it a bridge, token, or "
            "loadUrl."
        ),
        verification_steps=(
            "search_functions / search_constants for the allow-list "
            "itself: getHost, getAuthority, endsWith, startsWith, and "
            "equals comparisons against literal host strings inside "
            "deep-link handlers or WebViewClient.shouldOverrideUrlLoading.",
            "read_function every hit and reason through the parser "
            "difference: an input like \"https://trusted.example\\@evil.com/\" "
            "returns host \"trusted.example\" from android.net.Uri and "
            "host \"evil.com\" from java.net.URL on older API levels, and "
            "a check that uses one before an HTTP client that uses the "
            "other is bypassable.",
            "Confirm the code path reached after the bypass carries "
            "sensitive state (token, cookie, JavaScript bridge, "
            "Intent extra dispatched onward) before reporting; a "
            "cosmetic host mismatch on a static help page is not a "
            "finding.",
        ),
        relevant_apis=(
            "android.net.Uri.getHost",
            "android.net.Uri.getAuthority",
            "java.net.URL.getHost",
            "java.net.URI.getHost",
            "android.webkit.WebViewClient.shouldOverrideUrlLoading",
        ),
        evidence_hints=(
            "getHost()",
            "getAuthority()",
            "endsWith(",
            "shouldOverrideUrlLoading",
        ),
        cwe=("CWE-940", "CWE-601"),
        masvs_refs=("MASVS-PLATFORM-1",),
    ),
    ApkStaticCheck(
        id="APK-CHAIN-DEEPLINK-ATO",
        group=ApkStaticGroup.CHAINS,
        mode=ApkStaticMode.STATIC,
        title="Exported auth-callback activity captures OAuth code/token from a deep link a malicious app can also register.",
        description=(
            "The activity that receives the OAuth / OpenID Connect / SSO "
            "redirect is exported through a custom-scheme intent-filter "
            "with no android:autoVerify http/https app-link and no "
            "signature-level permission. A second app installed on the "
            "device registers the same scheme, wins (or races) the intent "
            "resolution, and receives the authorization code or access "
            "token in the redirect Uri, producing account takeover with "
            "one user tap on the consent screen."
        ),
        verification_steps=(
            "read_lines AndroidManifest.xml and list every activity whose "
            "intent-filter declares a custom scheme (android:scheme with "
            "a non-http/https value) and whose class name or "
            "intent-filter path hints at auth callback handling "
            "(callback, oauth, redirect, sso, login).",
            "search_functions / semantic_search the identified activities "
            "for getIntent().getData() followed by getQueryParameter "
            "reads of code, access_token, id_token, or state, and "
            "read_function to confirm the value is consumed as an "
            "authentication credential rather than being validated "
            "against a PKCE verifier or nonce bound to the pending "
            "request.",
            "Confirm no App Links verification (android:autoVerify=\"true\" "
            "with assetlinks.json), no signature permission, and no "
            "package-name check gates the handler before reporting; a "
            "verified https App Link with PKCE is not a finding.",
        ),
        relevant_apis=(
            "android.content.Intent.getData",
            "android.net.Uri.getQueryParameter",
            "android.content.IntentFilter",
            "android.app.Activity.getCallingPackage",
        ),
        evidence_hints=(
            "getQueryParameter(\"code\"",
            "getQueryParameter(\"access_token\"",
            "android:scheme=",
            "oauth",
        ),
        cwe=("CWE-939", "CWE-940"),
        masvs_refs=("MASVS-PLATFORM-1", "MASVS-AUTH-1"),
    ),
    ApkStaticCheck(
        id="APK-AUTH-EVENT-BOUND-BIOMETRIC",
        group=ApkStaticGroup.AUTH_LOCAL,
        mode=ApkStaticMode.STATIC,
        title="BiometricPrompt.authenticate called without a CryptoObject (result-code-only gate).",
        description=(
            "The app calls BiometricPrompt.authenticate(callback) or "
            "authenticate(CancellationSignal, ...) and treats the "
            "onAuthenticationSucceeded callback as the sole gate for "
            "releasing a secret or unlocking a feature. Because no "
            "Keystore-backed CryptoObject (Cipher, Signature, or Mac) is "
            "bound to the prompt, the success is a boolean the OS delivers "
            "to the app and can be forged by hooking the callback with "
            "Frida, patching the return value, or replaying a prior "
            "success event on a rooted device."
        ),
        verification_steps=(
            "search_functions / semantic_search the decompiled tree for "
            "androidx.biometric.BiometricPrompt or android.hardware.biometrics.BiometricPrompt, "
            "and for BiometricPrompt$AuthenticationCallback.onAuthenticationSucceeded.",
            "read_function each authenticate() call site and check the "
            "overload used: authenticate(PromptInfo) with no CryptoObject "
            "is a finding, whereas authenticate(PromptInfo, CryptoObject) "
            "where the CryptoObject wraps a KeyStore key with "
            "setUserAuthenticationRequired(true) is the correct pattern.",
            "Confirm the guarded operation is genuinely sensitive (unlock "
            "a stored credential, sign a payment, decrypt vault data) "
            "before reporting; a purely UX-level biometric prompt with no "
            "secret behind it is not a finding.",
        ),
        relevant_apis=(
            "androidx.biometric.BiometricPrompt.authenticate",
            "androidx.biometric.BiometricPrompt.CryptoObject",
            "android.hardware.biometrics.BiometricPrompt.authenticate",
            "android.security.keystore.KeyGenParameterSpec.Builder.setUserAuthenticationRequired",
        ),
        evidence_hints=(
            "BiometricPrompt",
            "onAuthenticationSucceeded",
            "CryptoObject",
            "setUserAuthenticationRequired",
        ),
        cwe=("CWE-287", "CWE-1390"),
        masvs_refs=("MASVS-AUTH-2",),
    ),
    ApkStaticCheck(
        id="APK-AUTH-KEYGUARD-ONLY",
        group=ApkStaticGroup.AUTH_LOCAL,
        mode=ApkStaticMode.STATIC,
        title="KeyguardManager.isDeviceSecure / isKeyguardSecure used as the entire local-auth gate.",
        description=(
            "The app calls KeyguardManager.isDeviceSecure() or "
            "isKeyguardSecure() and, on a true return, releases a stored "
            "credential, decrypts data, or exposes a sensitive screen "
            "with no further per-operation user challenge. The API only "
            "reports whether the device HAS a screen-lock configured, "
            "not that the current holder just proved they know it, so "
            "any unlocked device (including a phone left on a desk) "
            "passes the check trivially."
        ),
        verification_steps=(
            "search_functions / semantic_search the decompiled tree for "
            "KeyguardManager.isDeviceSecure, isKeyguardSecure, and "
            "createConfirmDeviceCredentialIntent.",
            "read_function each hit and classify the pattern: "
            "isDeviceSecure / isKeyguardSecure as a gate before releasing "
            "a secret is a finding, whereas createConfirmDeviceCredentialIntent "
            "launched and its RESULT_OK checked in onActivityResult is the "
            "correct pattern.",
            "Confirm the guarded operation actually protects sensitive "
            "state (vault, payment, session token) and is not a purely "
            "cosmetic UI branch that adjusts an icon based on lock-screen "
            "presence before reporting.",
        ),
        relevant_apis=(
            "android.app.KeyguardManager.isDeviceSecure",
            "android.app.KeyguardManager.isKeyguardSecure",
            "android.app.KeyguardManager.createConfirmDeviceCredentialIntent",
        ),
        evidence_hints=(
            "isDeviceSecure(",
            "isKeyguardSecure(",
            "KeyguardManager",
            "createConfirmDeviceCredentialIntent",
        ),
        cwe=("CWE-287", "CWE-1390"),
        masvs_refs=("MASVS-AUTH-2",),
    ),
    ApkStaticCheck(
        id="APK-SBOM-KNOWN-VULN-SDK",
        group=ApkStaticGroup.SBOM,
        mode=ApkStaticMode.STATIC,
        title="Bundled third-party SDK shipped at a version with a known CVE.",
        description=(
            "A general-purpose SDK compiled into the APK (OkHttp, "
            "Retrofit, Volley, ExoPlayer, Glide, Picasso, Gson, "
            "Apache Commons, an older WebView helper library) is at a "
            "version documented as vulnerable in the NVD or the vendor "
            "advisory feed. The version pin is inspectable statically "
            "because the compiled Java tree carries package layout, "
            "class fingerprints, and often an embedded version string "
            "constant. This finding feeds the CVE join that produces the "
            "child audits."
        ),
        verification_steps=(
            "Enumerate third-party packages under the decompiled Java "
            "tree via list_functions / semantic_search on canonical "
            "roots (okhttp3, retrofit2, com.google.android.exoplayer2, "
            "com.bumptech.glide, com.squareup.picasso, com.google.gson, "
            "org.apache.commons).",
            "search_constants for embedded version strings "
            "(userAgent = \"okhttp/x.y.z\", VERSION_NAME, BuildConfig.VERSION_NAME) "
            "and, when the constant is absent, fingerprint the version "
            "by class layout, moved methods, and known API additions.",
            "Feed each (package, version) pair to the CVE join and, for "
            "each returned CVE, confirm the vulnerable API is actually "
            "reachable from the app before reporting; a bundled library "
            "whose vulnerable class is never referenced is a lower-tier "
            "finding.",
        ),
        relevant_apis=(
            "okhttp3.OkHttpClient",
            "retrofit2.Retrofit",
            "com.google.android.exoplayer2.ExoPlayer",
            "com.bumptech.glide.Glide",
            "com.google.gson.Gson",
        ),
        evidence_hints=(
            "okhttp/",
            "VERSION_NAME",
            "BuildConfig.VERSION_NAME",
            "META-INF/",
        ),
        cwe=("CWE-1104", "CWE-937"),
        masvs_refs=("MASVS-CODE-3",),
    ),
    ApkStaticCheck(
        id="APK-SBOM-OUTDATED-TRACKER-SDK",
        group=ApkStaticGroup.SBOM,
        mode=ApkStaticMode.STATIC,
        title="Outdated advertising or analytics SDK with a known vulnerability.",
        description=(
            "An ad-network or analytics SDK (Google Mobile Ads / AdMob, "
            "Firebase Analytics, Facebook Audience Network, AppLovin, "
            "IronSource, Unity Ads, Mixpanel, Amplitude, Adjust, "
            "AppsFlyer) is compiled in at a version below the vendor's "
            "current advisory floor. Tracker SDKs run early in the "
            "process, ship their own WebView-hosted creative rendering, "
            "and are historically the source of remote-execution and "
            "cross-app data-leak CVEs, so an outdated pin here has "
            "disproportionate blast radius."
        ),
        verification_steps=(
            "Enumerate tracker packages under the decompiled Java tree "
            "via list_functions / semantic_search on canonical roots "
            "(com.google.android.gms.ads, com.google.firebase.analytics, "
            "com.facebook.ads, com.applovin, com.unity3d.ads, "
            "com.mixpanel.android, com.amplitude, com.adjust.sdk, "
            "com.appsflyer).",
            "search_constants for the tracker's embedded version string "
            "(SDK_VERSION, VERSION_NAME, buildVersionName, static final "
            "String VERSION) and record every (tracker, version) pair; "
            "read_lines AndroidManifest.xml to confirm the SDK is "
            "actually initialized (a meta-data key such as "
            "com.google.android.gms.ads.APPLICATION_ID or a "
            "ContentProvider registered by the SDK).",
            "Feed each pair to the CVE join and, for each returned CVE, "
            "confirm the vulnerable behavior is reachable in the "
            "shipped configuration before reporting; a dormant SDK "
            "compiled in but never initialized is a lower-tier finding.",
        ),
        relevant_apis=(
            "com.google.android.gms.ads.MobileAds.initialize",
            "com.google.firebase.analytics.FirebaseAnalytics.getInstance",
            "com.facebook.ads.AudienceNetworkAds.initialize",
            "com.applovin.sdk.AppLovinSdk.initializeSdk",
            "com.appsflyer.AppsFlyerLib.init",
        ),
        evidence_hints=(
            "SDK_VERSION",
            "com.google.android.gms.ads.APPLICATION_ID",
            "com.facebook.ads",
            "com.appsflyer",
        ),
        cwe=("CWE-1104", "CWE-937"),
        masvs_refs=("MASVS-CODE-3",),
    ),
    ApkStaticCheck(
        id="APK-FLUTTER-BUNDLE-DETECT",
        group=ApkStaticGroup.FLUTTER,
        mode=ApkStaticMode.STATIC,
        title="APK is a Flutter bundle (libapp.so + libflutter.so): jadx tree is a shell, real logic is Dart AOT.",
        description=(
            "The APK ships lib/<abi>/libapp.so alongside lib/<abi>/libflutter.so, "
            "which is the signature of a Flutter application. The jadx-decompiled "
            "Java tree contains only FlutterActivity / FlutterFragmentActivity "
            "plus generated plugin registrant glue; every business rule, "
            "credential handler, network client, and crypto call lives inside "
            "the Dart AOT snapshot compiled into libapp.so. Every downstream "
            "Java-tree check will under-report against this app until a "
            "Flutter extractor stage (blutter or reFlutter) recovers the Dart "
            "class layout and function bodies."
        ),
        verification_steps=(
            "read the ingestion static summary and list every lib/<abi>/*.so "
            "entry; a co-occurrence of libapp.so and libflutter.so under one or "
            "more ABI directories (arm64-v8a, armeabi-v7a, x86_64) confirms the "
            "app is Flutter.",
            "search_functions / semantic_search the decompiled Java tree for "
            "io.flutter.embedding.android.FlutterActivity, FlutterFragmentActivity, "
            "and GeneratedPluginRegistrant.registerWith to confirm the Java "
            "surface is only the Flutter shell rather than hand-written logic.",
            "When both signals are present, record a Flutter-bundle finding "
            "and flag that a Dart AOT extractor stage is required for "
            "meaningful analysis; do not attempt to draw negative "
            "conclusions from the Java tree alone about crypto, network, or "
            "auth behavior of a confirmed Flutter app.",
        ),
        relevant_apis=(
            "io.flutter.embedding.android.FlutterActivity",
            "io.flutter.embedding.android.FlutterFragmentActivity",
            "io.flutter.plugins.GeneratedPluginRegistrant",
        ),
        evidence_hints=(
            "lib/arm64-v8a/libapp.so",
            "lib/arm64-v8a/libflutter.so",
            "io.flutter.embedding",
            "GeneratedPluginRegistrant",
        ),
        cwe=(),
        masvs_refs=(),
    ),
)
