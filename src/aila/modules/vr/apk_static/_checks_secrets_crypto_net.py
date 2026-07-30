"""SECRETS, CRYPTO, and NETWORK static-analysis checks for android_apk targets."""
from __future__ import annotations

from aila.modules.vr.apk_static.models import (
    ApkStaticCheck,
    ApkStaticGroup,
    ApkStaticMode,
)

CHECKS: tuple[ApkStaticCheck, ...] = (
    # ---------- SECRETS ----------
    ApkStaticCheck(
        id="APK-SECRETS-API-KEY",
        group=ApkStaticGroup.SECRETS,
        mode=ApkStaticMode.STATIC,
        title="Hardcoded API key or bearer token bundled inside the APK.",
        description=(
            "Third-party API keys (Google AIza..., AWS AKIA..., Azure "
            "connection strings) or long-lived bearer tokens shipped "
            "inside strings.xml, BuildConfig constants, or Java string "
            "literals are recoverable by anyone who unpacks the APK. "
            "The compromise cost is proportional to the privileges "
            "attached to the leaked credential."
        ),
        verification_steps=(
            "search_constants and read_lines res/values/strings.xml and "
            "res/values/*.xml for the AIza[0-9A-Za-z_-]{35}, "
            "AKIA[0-9A-Z]{16}, and sk_live_/sk_test_ prefixes.",
            "semantic_search the decompiled tree for BuildConfig fields "
            "named API_KEY / SECRET / TOKEN and read_function each hit "
            "to capture the literal value.",
            "Enumerate assets/ and META-INF/ for .properties, .json, or "
            ".env files containing api_key / client_secret entries.",
            "For each candidate confirm the value is a real credential "
            "and not a placeholder or public identifier before "
            "reporting.",
        ),
        relevant_apis=(
            "android.content.res.Resources.getString",
            "BuildConfig",
            "com.google.android.gms.common.api.ApiKey",
            "android.os.Bundle.getString",
        ),
        evidence_hints=(
            "AIza",
            "AKIA",
            "sk_live_",
            "BuildConfig.",
            "api_key",
        ),
        cwe=("CWE-798",),
        masvs_refs=("MASVS-STORAGE-1", "MASVS-CRYPTO-1"),
    ),
    ApkStaticCheck(
        id="APK-SECRETS-FIREBASE",
        group=ApkStaticGroup.SECRETS,
        mode=ApkStaticMode.STATIC,
        title="Firebase Realtime Database URL exposed in the APK.",
        description=(
            "A bundled firebaseio.com URL points at a Realtime Database "
            "whose read/write rules default to public during "
            "development. When the rules are still permissive at "
            "release time the whole dataset is downloadable with a "
            "single HTTP GET to /.json."
        ),
        verification_steps=(
            "search_constants the tree for firebaseio.com and "
            "firebase-database; also read_lines google-services.json "
            "under assets/ or res/raw/ when present.",
            "read_function each reference and record the exact "
            "database URL plus any auth token passed to "
            "FirebaseDatabase.getInstance.",
            "Report the URL as exposure surface: the rules file is "
            "server-side, so the check names the target for follow-up "
            "GET /.json rules verification.",
        ),
        relevant_apis=(
            "com.google.firebase.database.FirebaseDatabase.getInstance",
            "com.google.firebase.FirebaseApp.initializeApp",
            "google-services.json",
        ),
        evidence_hints=(
            "firebaseio.com",
            "firebase-database",
            "google-services.json",
            "FirebaseDatabase.getInstance",
        ),
        cwe=("CWE-200",),
        masvs_refs=("MASVS-STORAGE-2",),
    ),
    ApkStaticCheck(
        id="APK-SECRETS-CLOUD-BUCKET",
        group=ApkStaticGroup.SECRETS,
        mode=ApkStaticMode.STATIC,
        title="Cloud storage bucket name or embedded cloud credential.",
        description=(
            "S3 (s3.amazonaws.com, s3-<region>.amazonaws.com) and GCS "
            "(storage.googleapis.com) bucket names bundled in the APK "
            "reveal storage targets that may be public. A bundled AWS "
            "access-key pair or GCP service-account JSON is a full "
            "credential leak."
        ),
        verification_steps=(
            "search_constants the tree for s3.amazonaws.com, "
            "s3-*.amazonaws.com, storage.googleapis.com, and bare "
            "bucket names in strings.xml.",
            "semantic_search for AWSCredentials, "
            "BasicAWSCredentials, GoogleCredentials.fromStream, and "
            "read_function each site.",
            "Enumerate assets/ and res/raw/ for *.json files matching "
            "the GCP service-account layout (type: service_account, "
            "private_key_id, private_key).",
            "Report bucket URLs separately from any embedded key "
            "pair; the key pair is the higher-severity item.",
        ),
        relevant_apis=(
            "com.amazonaws.auth.BasicAWSCredentials",
            "com.google.auth.oauth2.GoogleCredentials.fromStream",
            "com.amazonaws.services.s3.AmazonS3Client",
        ),
        evidence_hints=(
            "s3.amazonaws.com",
            "storage.googleapis.com",
            "BasicAWSCredentials",
            "service_account",
            "private_key_id",
        ),
        cwe=("CWE-798",),
        masvs_refs=("MASVS-STORAGE-1",),
    ),
    ApkStaticCheck(
        id="APK-SECRETS-PRIVATE-KEY",
        group=ApkStaticGroup.SECRETS,
        mode=ApkStaticMode.STATIC,
        title="Private key or certificate keystore bundled under assets/ or res/raw/.",
        description=(
            "Shipping a .pem / .p12 / .jks / .bks / .key file inside "
            "the APK exposes the private material to anyone who "
            "unpacks the archive. Even keystores gated by a "
            "passphrase are trivial to brute-force offline when the "
            "passphrase is a constant in the same APK."
        ),
        verification_steps=(
            "List every file under assets/ and res/raw/ with "
            "extensions pem, p12, pfx, jks, bks, key, and inspect the "
            "magic bytes with read_lines to confirm the file type.",
            "For each keystore located, semantic_search the code for "
            "KeyStore.load / KeyStore.getInstance calls and "
            "read_function the callers to recover the passphrase "
            "literal.",
            "Flag any private-key file plus its passphrase as a "
            "combined finding; a certificate-only bundle (public "
            "material for pinning) is a pass.",
        ),
        relevant_apis=(
            "java.security.KeyStore.getInstance",
            "java.security.KeyStore.load",
            "android.content.res.AssetManager.open",
        ),
        evidence_hints=(
            "assets/",
            "res/raw/",
            ".p12",
            ".jks",
            "KeyStore.load",
        ),
        cwe=("CWE-321",),
        masvs_refs=("MASVS-CRYPTO-1", "MASVS-STORAGE-1"),
    ),
    ApkStaticCheck(
        id="APK-SECRETS-INTERNAL-ENDPOINT",
        group=ApkStaticGroup.SECRETS,
        mode=ApkStaticMode.STATIC,
        title="Internal IP or staging/dev hostname reachable from release code.",
        description=(
            "RFC1918 addresses (10.0.0.0/8, 172.16.0.0/12, "
            "192.168.0.0/16), .local mDNS names, and staging or dev "
            "subdomains hardcoded in a release APK reveal internal "
            "topology and often route past production hardening. "
            "Traffic to a dev origin can bypass WAF rules and expose "
            "unfinished APIs."
        ),
        verification_steps=(
            "search_constants the decompiled tree and strings.xml "
            "for regexes matching 10\\.\\d+, 172\\.(1[6-9]|2\\d|3[01])"
            "\\., 192\\.168\\., and hostnames containing dev, "
            "staging, qa, uat, test.",
            "read_function every site and confirm the endpoint is "
            "reached at runtime (used by Retrofit / OkHttp / "
            "HttpURLConnection), not dead code left behind after a "
            "build-flavor merge.",
            "Report internal IPs and staging hostnames as separate "
            "evidence rows; production-only URLs with a debug feature "
            "flag around them are a lower-severity variant.",
        ),
        relevant_apis=(
            "okhttp3.Request.Builder.url",
            "retrofit2.Retrofit.Builder.baseUrl",
            "java.net.URL",
            "android.net.Uri.parse",
        ),
        evidence_hints=(
            "10.",
            "192.168.",
            "staging.",
            "-dev.",
            ".local",
        ),
        cwe=("CWE-200",),
        masvs_refs=("MASVS-STORAGE-1",),
    ),
    ApkStaticCheck(
        id="APK-SECRETS-EMBEDDED-JWT",
        group=ApkStaticGroup.SECRETS,
        mode=ApkStaticMode.STATIC,
        title="Long-lived JWT or OAuth client_secret embedded in the app.",
        description=(
            "A JWT (three base64url segments separated by dots) or an "
            "OAuth2 client_secret shipped as a Java string is a "
            "persistent credential that anyone with the APK can "
            "replay. Public OAuth clients on Android must use PKCE "
            "and MUST NOT bundle a client_secret."
        ),
        verification_steps=(
            "search_constants the tree for the regex "
            "eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+ "
            "(unpadded base64url JWT).",
            "semantic_search for client_secret, CLIENT_SECRET, and "
            "OAuth builders such as AuthorizationServiceConfiguration "
            "and read_function each hit to record the literal.",
            "For each JWT candidate decode the payload and note "
            "exp / iat / iss; a long or absent exp means the token is "
            "effectively permanent.",
            "Report only credentials with material privilege; opaque "
            "session identifiers cached by a mock test run are not "
            "findings.",
        ),
        relevant_apis=(
            "net.openid.appauth.AuthorizationServiceConfiguration",
            "com.auth0.android.jwt.JWT",
            "android.util.Base64.decode",
        ),
        evidence_hints=(
            "eyJ",
            "client_secret",
            "CLIENT_SECRET",
            "Bearer ",
            "AuthorizationService",
        ),
        cwe=("CWE-798",),
        masvs_refs=("MASVS-AUTH-1", "MASVS-STORAGE-1"),
    ),
    # ---------- CRYPTO ----------
    ApkStaticCheck(
        id="APK-CRYPTO-WEAK-CIPHER",
        group=ApkStaticGroup.CRYPTO,
        mode=ApkStaticMode.STATIC,
        title="Weak or broken symmetric cipher or mode in use.",
        description=(
            "DES, 3DES, RC4, or AES in ECB mode (or a block cipher "
            "with no IV) is broken and leaks plaintext structure. "
            "Modern code uses AES-GCM or AES-CBC with a random IV."
        ),
        verification_steps=(
            "search_functions / semantic_search the decompiled tree "
            "for Cipher.getInstance call sites.",
            "read_function each hit and read the transformation "
            "string: flag DES/DESede/RC4/ARCFOUR and any /ECB/ mode "
            "or a missing IV.",
            "Confirm the flagged cipher protects sensitive data, not "
            "a non-security checksum, before reporting.",
        ),
        relevant_apis=(
            "javax.crypto.Cipher.getInstance",
            "javax.crypto.spec.IvParameterSpec",
            "javax.crypto.spec.SecretKeySpec",
        ),
        evidence_hints=(
            "Cipher.getInstance",
            "AES/ECB",
            "DES",
            "RC4",
            "DESede",
        ),
        cwe=("CWE-327",),
        masvs_refs=("MASVS-CRYPTO-1",),
    ),
    ApkStaticCheck(
        id="APK-CRYPTO-WEAK-HASH",
        group=ApkStaticGroup.CRYPTO,
        mode=ApkStaticMode.STATIC,
        title="MD5 or SHA-1 used for integrity or password hashing.",
        description=(
            "MD5 and SHA-1 are broken for collision resistance and "
            "unsuitable for signatures, password storage, or any "
            "integrity check whose forgery matters. Password hashing "
            "additionally requires a memory-hard KDF such as "
            "Argon2id, scrypt, or bcrypt, not a bare digest."
        ),
        verification_steps=(
            "semantic_search / search_functions for "
            "MessageDigest.getInstance and read_function each hit; "
            "flag literal transformations MD5, SHA-1, SHA1.",
            "Trace the digest output through the code and confirm it "
            "gates authentication, signature verification, or "
            "password storage before reporting.",
            "For password paths, verify the code does not use a bare "
            "digest at all; the correct primitive is "
            "PBKDF2WithHmacSHA256 with high iteration count or a "
            "memory-hard KDF.",
        ),
        relevant_apis=(
            "java.security.MessageDigest.getInstance",
            "javax.crypto.SecretKeyFactory.getInstance",
            "javax.crypto.spec.PBEKeySpec",
        ),
        evidence_hints=(
            "MessageDigest.getInstance",
            "\"MD5\"",
            "\"SHA-1\"",
            "\"SHA1\"",
        ),
        cwe=("CWE-328",),
        masvs_refs=("MASVS-CRYPTO-1",),
    ),
    ApkStaticCheck(
        id="APK-CRYPTO-HARDCODED-KEY",
        group=ApkStaticGroup.CRYPTO,
        mode=ApkStaticMode.STATIC,
        title="SecretKeySpec or IvParameterSpec built from literal bytes.",
        description=(
            "A symmetric key or IV constructed from a Java string "
            "literal or a static byte[] is shared with every install "
            "of the app and recoverable by unpacking the APK. The key "
            "provides no confidentiality against anyone with the "
            "binary."
        ),
        verification_steps=(
            "search_functions for new SecretKeySpec, new "
            "IvParameterSpec, and PBEKeySpec constructors; "
            "read_function each caller.",
            "Inspect the byte source: a literal byte[]{...}, a "
            "String.getBytes on a literal, or a Base64.decode of a "
            "literal all count as hardcoded.",
            "Confirm the key material feeds a Cipher / Mac used for "
            "confidentiality or integrity, not a non-security "
            "obfuscation of local cache data before reporting.",
        ),
        relevant_apis=(
            "javax.crypto.spec.SecretKeySpec",
            "javax.crypto.spec.IvParameterSpec",
            "javax.crypto.spec.PBEKeySpec",
            "android.util.Base64.decode",
        ),
        evidence_hints=(
            "new SecretKeySpec",
            "new IvParameterSpec",
            ".getBytes(",
            "Base64.decode",
        ),
        cwe=("CWE-321",),
        masvs_refs=("MASVS-CRYPTO-1",),
    ),
    ApkStaticCheck(
        id="APK-CRYPTO-INSECURE-RNG",
        group=ApkStaticGroup.CRYPTO,
        mode=ApkStaticMode.STATIC,
        title="java.util.Random used to derive keys, tokens, or IVs.",
        description=(
            "java.util.Random and Math.random are linear-congruential "
            "PRNGs whose state can be recovered from a few outputs. "
            "Keys, IVs, session tokens, nonces, and CSRF secrets MUST "
            "come from java.security.SecureRandom."
        ),
        verification_steps=(
            "search_functions for new Random(, Math.random(, and "
            "read_function every caller.",
            "Trace the output: if it feeds a SecretKeySpec, an "
            "IvParameterSpec, a token/nonce field, or a URL parameter "
            "used for authentication, the site is a finding.",
            "Non-security use (jitter, retry backoff, UI animation "
            "seed) is a pass; document the intent for each pass site "
            "so a follow-up audit does not re-flag it.",
        ),
        relevant_apis=(
            "java.util.Random",
            "java.lang.Math.random",
            "java.security.SecureRandom",
        ),
        evidence_hints=(
            "new Random(",
            "Math.random(",
            "ThreadLocalRandom",
            "nextBytes",
        ),
        cwe=("CWE-338",),
        masvs_refs=("MASVS-CRYPTO-1",),
    ),
    ApkStaticCheck(
        id="APK-CRYPTO-KEYSTORE-MISUSE",
        group=ApkStaticGroup.CRYPTO,
        mode=ApkStaticMode.STATIC,
        title="AndroidKeyStore key usable without user authentication or StrongBox.",
        description=(
            "Keys generated in the AndroidKeyStore that guard "
            "credentials, biometric-unlocked secrets, or payment "
            "tokens should require user authentication via "
            "setUserAuthenticationRequired(true) and, on capable "
            "devices, live in StrongBox via "
            "setIsStrongBoxBacked(true). Absence of both means a "
            "malicious app that gains process access or an "
            "unlocked-device thief can invoke the key at will."
        ),
        verification_steps=(
            "search_functions for KeyGenParameterSpec.Builder and "
            "read_function each builder to inspect the chained "
            "calls.",
            "Flag a builder that omits setUserAuthenticationRequired "
            "or passes false when the key backs authentication / "
            "payment / secret storage.",
            "Note whether setIsStrongBoxBacked(true) is present; "
            "absence alone is a lower-severity observation because "
            "StrongBox availability depends on the device.",
            "Confirm the key protects sensitive material before "
            "reporting; keys used only for non-security signing of "
            "local cache entries are out of scope.",
        ),
        relevant_apis=(
            "android.security.keystore.KeyGenParameterSpec.Builder",
            "android.security.keystore.KeyGenParameterSpec.Builder.setUserAuthenticationRequired",
            "android.security.keystore.KeyGenParameterSpec.Builder.setIsStrongBoxBacked",
            "java.security.KeyStore",
        ),
        evidence_hints=(
            "KeyGenParameterSpec.Builder",
            "setUserAuthenticationRequired",
            "setIsStrongBoxBacked",
            "AndroidKeyStore",
        ),
        cwe=("CWE-522",),
        masvs_refs=("MASVS-CRYPTO-2", "MASVS-AUTH-2"),
    ),
    ApkStaticCheck(
        id="APK-CRYPTO-CUSTOM",
        group=ApkStaticGroup.CRYPTO,
        mode=ApkStaticMode.STATIC,
        title="Hand-rolled cryptographic primitive instead of javax.crypto.",
        description=(
            "A class that XORs bytes with a rotating key, implements "
            "its own block cipher, or concatenates a secret with data "
            "and hashes the result (H(secret || msg)) is almost "
            "certainly broken. Cryptographic primitives belong in "
            "vetted libraries (javax.crypto, Tink, BouncyCastle), "
            "never in application code."
        ),
        verification_steps=(
            "semantic_search for phrases matching custom obfuscation "
            "such as encrypt / decrypt / xor / rotate; read_function "
            "each hit and inspect the body for XOR loops, byte "
            "rotations, or ad-hoc substitution tables.",
            "Cross-check against javax.crypto usage: a class that "
            "does not import javax.crypto but still ships an "
            "encrypt/decrypt pair is a strong candidate.",
            "Confirm the primitive protects a security asset "
            "(credential, PII, payment payload) before reporting; a "
            "toy string obfuscator around a UI resource is a lower "
            "severity note.",
        ),
        relevant_apis=(
            "javax.crypto.Cipher",
            "javax.crypto.Mac",
            "com.google.crypto.tink",
        ),
        evidence_hints=(
            " ^ ",
            "xor",
            "rotate",
            "encrypt(",
            "decrypt(",
        ),
        cwe=("CWE-327",),
        masvs_refs=("MASVS-CRYPTO-1",),
    ),
    ApkStaticCheck(
        id="APK-CRYPTO-NONCONSTTIME-COMPARE",
        group=ApkStaticGroup.CRYPTO,
        mode=ApkStaticMode.STATIC,
        title="Non-constant-time comparison of MACs, tokens, or secrets.",
        description=(
            "equals() and Arrays.equals short-circuit on the first "
            "differing byte, leaking the length of the shared prefix "
            "through timing. MACs, HMAC tags, session tokens, and "
            "password hashes MUST be compared with a constant-time "
            "primitive such as MessageDigest.isEqual."
        ),
        verification_steps=(
            "search_functions for Arrays.equals and String.equals "
            "call sites; read_function each hit.",
            "Trace the operands: if either side is the output of a "
            "Mac.doFinal, MessageDigest.digest, KDF, or a comparison "
            "of a session/CSRF token, the site is a finding.",
            "Non-security equality (UI text, config strings, cache "
            "keys) is a pass; note the intent so a follow-up audit "
            "does not re-flag the site.",
            "MessageDigest.isEqual on Android is documented "
            "constant-time; recommend it as the direct replacement.",
        ),
        relevant_apis=(
            "java.util.Arrays.equals",
            "java.security.MessageDigest.isEqual",
            "javax.crypto.Mac.doFinal",
        ),
        evidence_hints=(
            "Arrays.equals",
            ".equals(",
            "Mac.doFinal",
            "MessageDigest.digest",
        ),
        cwe=("CWE-208",),
        masvs_refs=("MASVS-CRYPTO-1",),
    ),
    # ---------- NETWORK ----------
    ApkStaticCheck(
        id="APK-NETWORK-NSC",
        group=ApkStaticGroup.NETWORK,
        mode=ApkStaticMode.STATIC,
        title="network_security_config.xml relaxed for release: cleartext, user CAs, or debug-overrides.",
        description=(
            "The Network Security Config controls which origins may "
            "be reached over cleartext, which trust anchors are "
            "honoured, and whether user-installed CAs are accepted. A "
            "release build with cleartextTrafficPermitted=\"true\", a "
            "<trust-anchors> block that includes user CAs, or an "
            "active <debug-overrides> is downgrading TLS enforcement "
            "for real users."
        ),
        verification_steps=(
            "read_lines AndroidManifest.xml and locate "
            "android:networkSecurityConfig on <application>; then "
            "read_lines the referenced res/xml/*.xml file.",
            "In the NSC XML flag: cleartextTrafficPermitted=\"true\" "
            "(base or per-domain), any <certificates src=\"user\"/> "
            "entry, and any <debug-overrides> that is not gated by "
            "the debuggable flag.",
            "Also inspect <application android:usesCleartextTraffic> "
            "in the manifest; when the NSC is absent this attribute "
            "governs the whole app.",
            "Confirm the app is a release build (debuggable false, "
            "signed with a release key) before reporting; a debug "
            "APK is expected to relax these settings.",
        ),
        relevant_apis=(
            "android:networkSecurityConfig",
            "android:usesCleartextTraffic",
            "res/xml/network_security_config.xml",
        ),
        evidence_hints=(
            "cleartextTrafficPermitted",
            "trust-anchors",
            "debug-overrides",
            "certificates src=\"user\"",
            "networkSecurityConfig",
        ),
        cwe=("CWE-319", "CWE-295"),
        masvs_refs=("MASVS-NETWORK-1", "MASVS-NETWORK-2"),
    ),
    ApkStaticCheck(
        id="APK-NETWORK-TRUSTMANAGER",
        group=ApkStaticGroup.NETWORK,
        mode=ApkStaticMode.STATIC,
        title="Custom X509TrustManager accepts every server certificate.",
        description=(
            "An X509TrustManager whose checkServerTrusted body is "
            "empty, returns immediately, or catches every exception "
            "makes the TLS handshake accept any certificate, "
            "including a self-signed one presented by a machine on "
            "the same network. The connection has no server "
            "authentication."
        ),
        verification_steps=(
            "search_functions for classes that implement "
            "javax.net.ssl.X509TrustManager and read_function the "
            "checkServerTrusted override.",
            "Flag any body that is empty, that only logs, or that "
            "wraps the call in a try/catch swallowing "
            "CertificateException.",
            "Cross-check for SSLContext.init callers that pass the "
            "flagged TrustManager into an HttpsURLConnection, OkHttp "
            "client, or Retrofit builder.",
            "Confirm the code path is reachable in the release build "
            "(not gated behind BuildConfig.DEBUG) before reporting.",
        ),
        relevant_apis=(
            "javax.net.ssl.X509TrustManager",
            "javax.net.ssl.SSLContext.init",
            "okhttp3.OkHttpClient.Builder.sslSocketFactory",
        ),
        evidence_hints=(
            "X509TrustManager",
            "checkServerTrusted",
            "SSLContext.init",
            "TrustAllCerts",
        ),
        cwe=("CWE-295",),
        masvs_refs=("MASVS-NETWORK-2",),
    ),
    ApkStaticCheck(
        id="APK-NETWORK-HOSTNAMEVERIFIER",
        group=ApkStaticGroup.NETWORK,
        mode=ApkStaticMode.STATIC,
        title="HostnameVerifier accepts every hostname.",
        description=(
            "ALLOW_ALL_HOSTNAME_VERIFIER (Apache HttpClient legacy) "
            "or a HostnameVerifier.verify override that returns true "
            "for every input decouples the certificate CN/SAN from "
            "the origin the client is talking to. A machine on the "
            "same network can present any valid certificate and be "
            "trusted."
        ),
        verification_steps=(
            "search_constants for ALLOW_ALL_HOSTNAME_VERIFIER and "
            "search_functions for classes implementing "
            "javax.net.ssl.HostnameVerifier.",
            "read_function every verify override and flag bodies "
            "that return true unconditionally.",
            "Cross-check HttpsURLConnection.setDefaultHostnameVerifier "
            "and OkHttpClient.Builder.hostnameVerifier callers for "
            "the flagged verifier instance.",
            "Confirm the site is reached at runtime and not dead "
            "test code before reporting.",
        ),
        relevant_apis=(
            "javax.net.ssl.HostnameVerifier",
            "javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier",
            "okhttp3.OkHttpClient.Builder.hostnameVerifier",
            "org.apache.http.conn.ssl.AllowAllHostnameVerifier",
        ),
        evidence_hints=(
            "HostnameVerifier",
            "ALLOW_ALL_HOSTNAME_VERIFIER",
            "verify(",
            "return true",
        ),
        cwe=("CWE-297",),
        masvs_refs=("MASVS-NETWORK-2",),
    ),
    ApkStaticCheck(
        id="APK-NETWORK-WEBVIEW-SSL",
        group=ApkStaticGroup.NETWORK,
        mode=ApkStaticMode.STATIC,
        title="WebViewClient.onReceivedSslError calls handler.proceed().",
        description=(
            "onReceivedSslError is invoked when the WebView cannot "
            "validate a server certificate. Calling handler.proceed() "
            "unconditionally, or wrapping it in a "
            "BuildConfig.DEBUG-less branch, tells the WebView to "
            "load the origin anyway and defeats TLS for every "
            "webview-rendered page."
        ),
        verification_steps=(
            "search_functions for onReceivedSslError overrides on "
            "android.webkit.WebViewClient subclasses; read_function "
            "each body.",
            "Flag any code path that reaches handler.proceed() "
            "without a strict pin-verification step or a genuine "
            "operator confirmation dialog.",
            "handler.cancel() or a call that displays a certificate-"
            "error UI and defers to the operator is the pass "
            "condition.",
            "Confirm the WebViewClient is attached to a real WebView "
            "in the release build before reporting.",
        ),
        relevant_apis=(
            "android.webkit.WebViewClient.onReceivedSslError",
            "android.webkit.SslErrorHandler.proceed",
            "android.webkit.SslErrorHandler.cancel",
        ),
        evidence_hints=(
            "onReceivedSslError",
            "handler.proceed",
            "SslErrorHandler",
            "WebViewClient",
        ),
        cwe=("CWE-295",),
        masvs_refs=("MASVS-NETWORK-2", "MASVS-PLATFORM-2"),
    ),
    ApkStaticCheck(
        id="APK-NETWORK-PINNING-PRESENCE",
        group=ApkStaticGroup.NETWORK,
        mode=ApkStaticMode.STATIC,
        title="Certificate pinning presence or absence for outbound TLS.",
        description=(
            "Pinning binds the client to a specific certificate or "
            "public key so a compromised or coerced CA cannot mint a "
            "trusted certificate for the origin. The check enumerates "
            "which pinning mechanism the app uses (OkHttp "
            "CertificatePinner, TrustKit, NSC <pin-set>, a custom "
            "pin store) and reports the origins covered; absence is "
            "reported as an observation, not a defect, since pinning "
            "is a defence-in-depth control."
        ),
        verification_steps=(
            "search_functions for okhttp3.CertificatePinner.Builder "
            "and read_function every caller to enumerate pinned "
            "hosts and SHA-256 pins.",
            "semantic_search for com.datatheorem.android.trustkit "
            "and any custom class that stores pin hashes and checks "
            "them in checkServerTrusted.",
            "read_lines the network_security_config.xml file and "
            "enumerate every <pin-set> plus <domain includeSubdomains> "
            "entry.",
            "Report the union of pinned origins; when no mechanism "
            "is present record that as an observation together with "
            "the list of outbound base URLs discovered elsewhere.",
        ),
        relevant_apis=(
            "okhttp3.CertificatePinner.Builder",
            "com.datatheorem.android.trustkit.TrustKit",
            "res/xml/network_security_config.xml",
            "javax.net.ssl.X509TrustManager",
        ),
        evidence_hints=(
            "CertificatePinner",
            "pin-set",
            "TrustKit",
            "sha256/",
            "pin digest",
        ),
        cwe=(),
        masvs_refs=("MASVS-NETWORK-2",),
    ),
)
