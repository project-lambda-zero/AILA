"""APK static checks for the WEBVIEW, STORAGE, IPC, and INJECTION groups."""
from __future__ import annotations

from aila.modules.vr.apk_static.models import (
    ApkStaticCheck,
    ApkStaticGroup,
    ApkStaticMode,
)

CHECKS: tuple[ApkStaticCheck, ...] = (
    # ---------- WEBVIEW ----------
    ApkStaticCheck(
        id="APK-WEBVIEW-JS-BRIDGE",
        group=ApkStaticGroup.WEBVIEW,
        mode=ApkStaticMode.STATIC,
        title="addJavascriptInterface bridges Java into WebView JavaScript.",
        description=(
            "addJavascriptInterface exposes a Java object to the page's "
            "JavaScript context. Below API 17, every public method of the "
            "bridged object is reachable through reflection, letting any "
            "loaded page run arbitrary Java. Even on API 17+, the bridge "
            "widens the reachable surface if the loaded content is not "
            "fully trusted."
        ),
        verification_steps=(
            "search_functions / semantic_search the decompiled tree for "
            "addJavascriptInterface call sites and for classes annotated "
            "with @JavascriptInterface.",
            "read_function each hit and confirm the WebView loads only "
            "first-party HTTPS URLs; also read minSdkVersion in "
            "AndroidManifest.xml to see whether pre-API-17 devices are in "
            "scope.",
            "Confirm the bridged methods return or accept sensitive data "
            "(auth tokens, file paths, IPC handles) before reporting; a "
            "purely cosmetic bridge is a lower-severity finding.",
        ),
        relevant_apis=(
            "android.webkit.WebView.addJavascriptInterface",
            "android.webkit.JavascriptInterface",
        ),
        evidence_hints=(
            "addJavascriptInterface",
            "@JavascriptInterface",
            "WebView",
        ),
        cwe=("CWE-749",),
        masvs_refs=("MASVS-PLATFORM-2",),
    ),
    ApkStaticCheck(
        id="APK-WEBVIEW-JS-ENABLED",
        group=ApkStaticGroup.WEBVIEW,
        mode=ApkStaticMode.STATIC,
        title="WebView enables JavaScript for content that is not fully trusted.",
        description=(
            "setJavaScriptEnabled(true) turns on script execution inside a "
            "WebView. Combined with content whose origin is not fully "
            "controlled by the app, this opens the door to cross-site "
            "scripting, drive-by exploitation of WebView bugs, and abuse of "
            "any exposed JavaScript bridge."
        ),
        verification_steps=(
            "search_functions / semantic_search for setJavaScriptEnabled "
            "and read_function each hit.",
            "For every true value, trace the same WebView instance to its "
            "loadUrl / loadData / loadDataWithBaseURL calls and check the "
            "URL scheme and host list.",
            "Confirm the loaded content is not fully controlled by the app "
            "(remote HTTP, third-party HTTPS, or a URL sourced from an "
            "intent) before reporting.",
        ),
        relevant_apis=(
            "android.webkit.WebSettings.setJavaScriptEnabled",
            "android.webkit.WebView.loadUrl",
        ),
        evidence_hints=(
            "setJavaScriptEnabled(true)",
            "getSettings()",
            "loadUrl",
        ),
        cwe=("CWE-79",),
        masvs_refs=("MASVS-PLATFORM-2",),
    ),
    ApkStaticCheck(
        id="APK-WEBVIEW-FILE-ACCESS",
        group=ApkStaticGroup.WEBVIEW,
        mode=ApkStaticMode.STATIC,
        title="WebView allows file:// access from web content.",
        description=(
            "setAllowFileAccess, setAllowFileAccessFromFileURLs, and "
            "setAllowUniversalAccessFromFileURLs let a file:// page read "
            "arbitrary local files or make cross-origin requests. A "
            "malicious HTML file dropped into shared storage can then read "
            "the app's private files through the WebView."
        ),
        verification_steps=(
            "search_functions for setAllowFileAccess, "
            "setAllowFileAccessFromFileURLs, and "
            "setAllowUniversalAccessFromFileURLs.",
            "read_function each hit: on API 30+ the platform default is "
            "false, so an explicit true is the finding. On older "
            "minSdkVersion the platform default is true, so a missing call "
            "still inherits the risky value.",
            "Confirm the WebView actually loads content whose path may be "
            "influenced by an intent, a downloaded file, or shared external "
            "storage before reporting.",
        ),
        relevant_apis=(
            "android.webkit.WebSettings.setAllowFileAccess",
            "android.webkit.WebSettings.setAllowFileAccessFromFileURLs",
            "android.webkit.WebSettings.setAllowUniversalAccessFromFileURLs",
        ),
        evidence_hints=(
            "setAllowFileAccess",
            "setAllowUniversalAccessFromFileURLs",
            "setAllowFileAccessFromFileURLs",
        ),
        cwe=("CWE-552",),
        masvs_refs=("MASVS-PLATFORM-2",),
    ),
    ApkStaticCheck(
        id="APK-WEBVIEW-UNTRUSTED-LOADURL",
        group=ApkStaticGroup.WEBVIEW,
        mode=ApkStaticMode.STATIC,
        title="WebView loadUrl / loadData takes value from intent or deep link.",
        description=(
            "A WebView that navigates to a URL taken from getIntent() "
            "extras, an onNewIntent extra, or a deep-link Uri lets another "
            "app or a crafted link steer the WebView to any origin. That "
            "origin can then phish, exfiltrate cookies bound to the "
            "WebView, or reach any exposed JavaScript bridge."
        ),
        verification_steps=(
            "search_functions for loadUrl, loadData, and "
            "loadDataWithBaseURL and read_function each caller.",
            "Trace the URL argument through the enclosing function and its "
            "callers; flag when it originates in getIntent().getStringExtra, "
            "getIntent().getData(), or an exported activity parameter "
            "without an allow-list check.",
            "Confirm the enclosing activity is exported (see "
            "AndroidManifest.xml) or the deep-link intent-filter is present "
            "before reporting.",
        ),
        relevant_apis=(
            "android.webkit.WebView.loadUrl",
            "android.webkit.WebView.loadDataWithBaseURL",
            "android.content.Intent.getStringExtra",
        ),
        evidence_hints=(
            "loadUrl",
            "getStringExtra",
            "getIntent().getData",
        ),
        cwe=("CWE-601",),
        masvs_refs=("MASVS-PLATFORM-2",),
    ),
    ApkStaticCheck(
        id="APK-WEBVIEW-MIXED-CONTENT",
        group=ApkStaticGroup.WEBVIEW,
        mode=ApkStaticMode.STATIC,
        title="WebView permits mixed HTTP content on HTTPS pages.",
        description=(
            "setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW) tells the "
            "WebView to load HTTP subresources into an HTTPS page. That "
            "downgrades the confidentiality and integrity of the HTTPS "
            "session and lets an on-path network observer inject script or "
            "read the mixed traffic."
        ),
        verification_steps=(
            "search_functions / search_constants for setMixedContentMode "
            "and MIXED_CONTENT_ALWAYS_ALLOW.",
            "read_function each caller: MIXED_CONTENT_NEVER_ALLOW (1) is a "
            "pass, MIXED_CONTENT_COMPATIBILITY_MODE (2) is a soft finding, "
            "MIXED_CONTENT_ALWAYS_ALLOW (0) is a hard finding.",
            "Confirm the same WebView actually loads HTTPS URLs; a WebView "
            "that only ever loads local assets is not affected in practice.",
        ),
        relevant_apis=(
            "android.webkit.WebSettings.setMixedContentMode",
            "android.webkit.WebSettings.MIXED_CONTENT_ALWAYS_ALLOW",
        ),
        evidence_hints=(
            "setMixedContentMode",
            "MIXED_CONTENT_ALWAYS_ALLOW",
        ),
        cwe=("CWE-311",),
        masvs_refs=("MASVS-NETWORK-1",),
    ),
    # ---------- STORAGE ----------
    ApkStaticCheck(
        id="APK-STORAGE-WORLD-READABLE-PREFS",
        group=ApkStaticGroup.STORAGE,
        mode=ApkStaticMode.STATIC,
        title="SharedPreferences or openFileOutput opened world-readable / world-writable.",
        description=(
            "MODE_WORLD_READABLE and MODE_WORLD_WRITEABLE make a file "
            "readable or writable by every other app on the device. Both "
            "flags were deprecated in API 17 and throw a SecurityException "
            "on API 24+, so their presence in a modern APK is either dead "
            "code or a real cross-app leak on the older install base the "
            "app still supports."
        ),
        verification_steps=(
            "search_functions / search_constants for getSharedPreferences, "
            "openFileOutput, MODE_WORLD_READABLE, and MODE_WORLD_WRITEABLE.",
            "read_function each caller and read the mode argument: 0 or "
            "MODE_PRIVATE is a pass, MODE_WORLD_READABLE (1) or "
            "MODE_WORLD_WRITEABLE (2) is a finding.",
            "Cross-check minSdkVersion in AndroidManifest.xml: on API 24+ "
            "the flag raises SecurityException at runtime, so the exposure "
            "window is limited to older installs the app still targets.",
        ),
        relevant_apis=(
            "android.content.Context.getSharedPreferences",
            "android.content.Context.openFileOutput",
            "android.content.Context.MODE_WORLD_READABLE",
            "android.content.Context.MODE_WORLD_WRITEABLE",
        ),
        evidence_hints=(
            "MODE_WORLD_READABLE",
            "MODE_WORLD_WRITEABLE",
            "openFileOutput",
        ),
        cwe=("CWE-732",),
        masvs_refs=("MASVS-STORAGE-2",),
    ),
    ApkStaticCheck(
        id="APK-STORAGE-PLAINTEXT-SECRET",
        group=ApkStaticGroup.STORAGE,
        mode=ApkStaticMode.STATIC,
        title="Secrets stored in plain SharedPreferences instead of EncryptedSharedPreferences.",
        description=(
            "SharedPreferences persists to a plaintext XML file inside the "
            "app sandbox. Storing authentication tokens, refresh tokens, "
            "user passwords, or PII there exposes them to any device-level "
            "backup, root path, or adb-backup extraction. AndroidX "
            "EncryptedSharedPreferences wraps the same API with a "
            "keystore-backed AEAD."
        ),
        verification_steps=(
            "search_functions for SharedPreferences.Editor.putString and "
            "search_constants for secret-shaped key strings (token, "
            "password, secret, apikey, jwt, refresh, pin).",
            "read_function each hit and confirm the value being stored is "
            "a secret or PII, not a UI setting.",
            "Check whether EncryptedSharedPreferences or MasterKey is "
            "imported anywhere in the tree; a total absence combined with "
            "secret-shaped keys is the finding.",
        ),
        relevant_apis=(
            "android.content.SharedPreferences.Editor.putString",
            "androidx.security.crypto.EncryptedSharedPreferences",
            "androidx.security.crypto.MasterKey",
        ),
        evidence_hints=(
            "SharedPreferences",
            "putString",
            "EncryptedSharedPreferences",
            "MasterKey",
        ),
        cwe=("CWE-312",),
        masvs_refs=("MASVS-STORAGE-1",),
    ),
    ApkStaticCheck(
        id="APK-STORAGE-SQLI",
        group=ApkStaticGroup.STORAGE,
        mode=ApkStaticMode.STATIC,
        title="SQLiteDatabase.rawQuery or execSQL concatenates untrusted input.",
        description=(
            "rawQuery, execSQL, and query() variants that build the SQL "
            "string via + or String.format let a caller change the "
            "statement structure. In an app context the input often comes "
            "from an intent extra, a content:// URI, or a WebView bridge, "
            "each of which is reachable from another app on the device."
        ),
        verification_steps=(
            "search_functions for rawQuery, execSQL, and "
            "SQLiteDatabase.query, then read_function each hit.",
            "Read the SQL argument: a bare string literal, or a query() "
            "call with parameterised selectionArgs, is a pass; any + "
            "concatenation, String.format, or StringBuilder feeding the "
            "SQL is the finding.",
            "Trace the concatenated variable back to its source and "
            "confirm the input crosses a trust boundary (intent extra, "
            "network response, exported content provider) before "
            "reporting.",
        ),
        relevant_apis=(
            "android.database.sqlite.SQLiteDatabase.rawQuery",
            "android.database.sqlite.SQLiteDatabase.execSQL",
            "android.database.sqlite.SQLiteDatabase.query",
        ),
        evidence_hints=(
            "rawQuery",
            "execSQL",
            "SQLiteDatabase",
        ),
        cwe=("CWE-89",),
        masvs_refs=("MASVS-PLATFORM-2",),
    ),
    ApkStaticCheck(
        id="APK-STORAGE-UNENCRYPTED-DB",
        group=ApkStaticGroup.STORAGE,
        mode=ApkStaticMode.STATIC,
        title="SQLite database stored unencrypted on disk.",
        description=(
            "The stock android.database.sqlite database file is plaintext "
            "on disk. Any backup path, root, or extracted app-data snapshot "
            "reads the rows verbatim. Apps that persist sensitive rows "
            "should either use SQLCipher (net.sqlcipher.database) with a "
            "keystore-derived key, or store nothing sensitive in the "
            "database at all."
        ),
        verification_steps=(
            "search_functions for SQLiteOpenHelper subclasses, "
            "openOrCreateDatabase, and Room.databaseBuilder.",
            "search_constants for net.sqlcipher and SupportFactory to see "
            "whether SQLCipher is wired in.",
            "Enumerate assets/ via glob for *.db / *.sqlite; a pre-built "
            "database shipped in assets/ is stored plaintext unless the "
            "app re-encrypts it after copy. Confirm the schema holds "
            "sensitive data before reporting.",
        ),
        relevant_apis=(
            "android.database.sqlite.SQLiteOpenHelper",
            "androidx.room.Room.databaseBuilder",
            "net.sqlcipher.database.SupportFactory",
        ),
        evidence_hints=(
            "SQLiteOpenHelper",
            "Room.databaseBuilder",
            "net.sqlcipher",
        ),
        cwe=("CWE-311",),
        masvs_refs=("MASVS-STORAGE-1",),
    ),
    ApkStaticCheck(
        id="APK-STORAGE-EXTERNAL-WRITE",
        group=ApkStaticGroup.STORAGE,
        mode=ApkStaticMode.STATIC,
        title="Sensitive data written to external or shared storage.",
        description=(
            "getExternalFilesDir, Environment.getExternalStorageDirectory, "
            "and the MediaStore APIs write to storage that was "
            "world-readable on older Android and is still reachable by any "
            "app holding READ_MEDIA_* or MANAGE_EXTERNAL_STORAGE on newer "
            "Android. Auth tokens, downloaded documents, exported reports, "
            "or database backups written there escape the app sandbox."
        ),
        verification_steps=(
            "search_functions for getExternalFilesDir, "
            "getExternalStorageDirectory, and MediaStore insert / "
            "createDocument calls.",
            "read_function each caller and read the value being written; "
            "flag paths that carry auth tokens, PII, decrypted secrets, or "
            "database exports.",
            "Cross-check AndroidManifest.xml via read_lines for "
            "READ_EXTERNAL_STORAGE / WRITE_EXTERNAL_STORAGE / "
            "MANAGE_EXTERNAL_STORAGE and requestLegacyExternalStorage; "
            "broad permissions plus sensitive writes is the finding.",
        ),
        relevant_apis=(
            "android.content.Context.getExternalFilesDir",
            "android.os.Environment.getExternalStorageDirectory",
            "android.provider.MediaStore",
        ),
        evidence_hints=(
            "getExternalFilesDir",
            "getExternalStorageDirectory",
            "MediaStore",
        ),
        cwe=("CWE-312",),
        masvs_refs=("MASVS-STORAGE-2",),
    ),
    ApkStaticCheck(
        id="APK-STORAGE-SENSITIVE-LOG",
        group=ApkStaticGroup.STORAGE,
        mode=ApkStaticMode.STATIC,
        title="Log.*, System.out, or Timber emits secrets or PII.",
        description=(
            "android.util.Log, System.out.println, and Timber calls end up "
            "in logcat, which is readable by any app with READ_LOGS on "
            "pre-API-16 devices and by any adb-connected host. Emitting "
            "bearer tokens, session ids, passwords, PII, or full "
            "request/response bodies exposes them wherever the log "
            "eventually goes."
        ),
        verification_steps=(
            "search_functions for android.util.Log methods, Timber, and "
            "System.out.println / println.",
            "For each hit, read the format string and arguments; flag "
            "calls that print variables named token, password, secret, "
            "key, cookie, jwt, refresh, ssn, dob, email, or phone.",
            "Confirm the log statement survives release builds by "
            "checking ProGuard rules for -assumenosideeffects on "
            "android.util.Log; guarded debug-only logs are lower severity.",
        ),
        relevant_apis=(
            "android.util.Log.d",
            "android.util.Log.v",
            "timber.log.Timber",
            "java.io.PrintStream.println",
        ),
        evidence_hints=(
            "Log.d",
            "Log.v",
            "Timber",
            "System.out.println",
        ),
        cwe=("CWE-532",),
        masvs_refs=("MASVS-STORAGE-2",),
    ),
    ApkStaticCheck(
        id="APK-STORAGE-CLIPBOARD",
        group=ApkStaticGroup.STORAGE,
        mode=ApkStaticMode.STATIC,
        title="Secrets or tokens copied into the system clipboard.",
        description=(
            "ClipboardManager.setPrimaryClip writes to the global "
            "clipboard that every foreground app on the device can read. "
            "Copying one-time passcodes, recovery phrases, api keys, or "
            "full credentials there hands them to whichever app the user "
            "opens next, and on older Android to background clipboard "
            "listeners."
        ),
        verification_steps=(
            "search_functions for ClipboardManager.setPrimaryClip and "
            "ClipData.newPlainText.",
            "read_function each caller and read the label and value; flag "
            "when the value is a token, seed phrase, password, or secret "
            "rather than an ordinary user-facing string.",
            "Check whether ClipDescription.EXTRA_IS_SENSITIVE (API 33+) "
            "is set on the ClipData; its absence for secret-shaped values "
            "is the finding.",
        ),
        relevant_apis=(
            "android.content.ClipboardManager.setPrimaryClip",
            "android.content.ClipData.newPlainText",
            "android.content.ClipDescription.EXTRA_IS_SENSITIVE",
        ),
        evidence_hints=(
            "setPrimaryClip",
            "ClipData.newPlainText",
            "ClipboardManager",
        ),
        cwe=("CWE-200",),
        masvs_refs=("MASVS-STORAGE-2",),
    ),
    # ---------- IPC ----------
    ApkStaticCheck(
        id="APK-IPC-BROADCAST-INJECTION",
        group=ApkStaticGroup.IPC,
        mode=ApkStaticMode.STATIC,
        title="Exported BroadcastReceiver acts on untrusted intent extras.",
        description=(
            "A receiver declared android:exported=\"true\" (or with an "
            "intent-filter and no explicit android:exported=\"false\") "
            "accepts broadcasts from any app on the device. If onReceive "
            "reads intent extras and drives file writes, database writes, "
            "network calls, or process launches without validating the "
            "caller or the values, any other app can steer the receiver."
        ),
        verification_steps=(
            "read_lines AndroidManifest.xml and list every <receiver> "
            "that is exported (explicit true, or an intent-filter without "
            "exported=\"false\").",
            "search_functions / read_function each receiver's onReceive; "
            "flag getIntent().get*Extra values that reach a "
            "SharedPreferences.Editor, database, HTTP client, or "
            "Runtime.exec without an allow-list check.",
            "Cross-check the static summary receivers section for "
            "android:permission on the receiver; a missing "
            "signature-level permission is the finding.",
        ),
        relevant_apis=(
            "android.content.BroadcastReceiver.onReceive",
            "android.content.Intent.getStringExtra",
            "android:exported",
            "android:permission",
        ),
        evidence_hints=(
            "onReceive",
            "getStringExtra",
            "android:exported",
        ),
        cwe=("CWE-925",),
        masvs_refs=("MASVS-PLATFORM-1",),
    ),
    ApkStaticCheck(
        id="APK-IPC-UNPROTECTED-SERVICE",
        group=ApkStaticGroup.IPC,
        mode=ApkStaticMode.STATIC,
        title="Exported bound Service (AIDL / Messenger) has no permission guard.",
        description=(
            "A <service> that is exported and defines an AIDL or Messenger "
            "onBind entry point is callable by any other app on the "
            "device. Without android:permission on the manifest "
            "declaration, or an in-method checkCallingPermission / "
            "Binder.getCallingUid check, the AIDL methods run with the "
            "app's own identity on behalf of every peer."
        ),
        verification_steps=(
            "read_lines AndroidManifest.xml and list every <service> with "
            "exported=\"true\" or an intent-filter and no "
            "exported=\"false\".",
            "For each exported service, search_functions for its onBind "
            "and the generated Stub subclasses; read_function each AIDL "
            "method and check whether checkCallingPermission, "
            "checkCallingUid, or Binder.getCallingUid gates the work.",
            "Cross-check the static summary services section for "
            "android:permission on the declaration; absent permission "
            "plus no in-method caller check is the finding.",
        ),
        relevant_apis=(
            "android.app.Service.onBind",
            "android.os.Binder.getCallingUid",
            "android.content.Context.checkCallingPermission",
            "android:permission",
        ),
        evidence_hints=(
            "onBind",
            "android:exported",
            "Stub",
            "getCallingUid",
        ),
        cwe=("CWE-926",),
        masvs_refs=("MASVS-PLATFORM-1",),
    ),
    ApkStaticCheck(
        id="APK-IPC-BROADCAST-LEAK",
        group=ApkStaticGroup.IPC,
        mode=ApkStaticMode.STATIC,
        title="Sensitive data sent via sendBroadcast without a receiver permission.",
        description=(
            "Context.sendBroadcast(Intent) with no receiverPermission "
            "second argument delivers to every receiver on the device that "
            "matches the action. If the intent extras carry auth tokens, "
            "PII, or user content, any other app can register a receiver "
            "for the action and read them."
        ),
        verification_steps=(
            "search_functions for sendBroadcast, sendBroadcastAsUser, and "
            "sendOrderedBroadcast.",
            "read_function each caller and read the receiverPermission "
            "argument: an absent or null value paired with an implicit "
            "action (Intent constructed with a String action and no "
            "explicit component) is the finding shape.",
            "Read the intent extras: flag putExtra values that carry "
            "tokens, PII, or user content. LocalBroadcastManager "
            "(in-process) is a pass but has been deprecated; note it in "
            "the report but do not flag it as a leak.",
        ),
        relevant_apis=(
            "android.content.Context.sendBroadcast",
            "android.content.Context.sendOrderedBroadcast",
            "android.content.Intent.putExtra",
        ),
        evidence_hints=(
            "sendBroadcast",
            "sendOrderedBroadcast",
            "putExtra",
        ),
        cwe=("CWE-927",),
        masvs_refs=("MASVS-PLATFORM-3",),
    ),
    # ---------- INJECTION ----------
    ApkStaticCheck(
        id="APK-INJECTION-COMMAND-EXEC",
        group=ApkStaticGroup.INJECTION,
        mode=ApkStaticMode.STATIC,
        title="Runtime.exec or ProcessBuilder called with untrusted arguments.",
        description=(
            "Runtime.getRuntime().exec(String) and "
            "ProcessBuilder(String...) that concatenate a value from an "
            "intent extra, deep-link Uri, WebView bridge, or downloaded "
            "file into the command line let another party inject shell "
            "metacharacters or extra argv entries. Even the String[] form "
            "is a finding when the argv[0] binary path itself is derived "
            "from untrusted input."
        ),
        verification_steps=(
            "search_functions for Runtime.exec, ProcessBuilder, and "
            "java.lang.ProcessBuilder constructors.",
            "read_function each caller; flag any + concatenation, "
            "String.format, or String[] whose contents come from an "
            "external source without an allow-list.",
            "Trace the tainted variable back to its source (intent extras, "
            "content URIs, network response, filesystem path derived from "
            "untrusted input) and confirm a trust boundary before "
            "reporting.",
        ),
        relevant_apis=(
            "java.lang.Runtime.exec",
            "java.lang.ProcessBuilder",
            "java.lang.Process",
        ),
        evidence_hints=(
            "Runtime.getRuntime().exec",
            "ProcessBuilder",
            ".exec(",
        ),
        cwe=("CWE-78",),
        masvs_refs=("MASVS-PLATFORM-2",),
    ),
    ApkStaticCheck(
        id="APK-INJECTION-PATH-TRAVERSAL",
        group=ApkStaticGroup.INJECTION,
        mode=ApkStaticMode.STATIC,
        title="ZipEntry.getName() flows into File() without canonicalization (Zip Slip).",
        description=(
            "Zip and tar archives can name entries with ../ segments or "
            "absolute paths. Passing ZipEntry.getName() (or a deep-link "
            "Uri path segment) straight into new File(baseDir, name) "
            "followed by FileOutputStream lets the archive write outside "
            "the intended directory, overwriting native libraries, code "
            "cache, or SharedPreferences."
        ),
        verification_steps=(
            "search_functions for ZipInputStream, ZipEntry.getName, "
            "TarInputStream, and any custom archive-unpack helper.",
            "read_function each caller; a File.getCanonicalPath check "
            "against the destination root before opening the output "
            "stream is a pass, its absence is the finding.",
            "Also look for File(baseDir, uri.getLastPathSegment()) and "
            "File(baseDir, intent.getStringExtra(...)) shapes, which are "
            "the non-archive path-traversal cousins.",
        ),
        relevant_apis=(
            "java.util.zip.ZipEntry.getName",
            "java.util.zip.ZipInputStream",
            "java.io.File.getCanonicalPath",
        ),
        evidence_hints=(
            "ZipEntry",
            "getName()",
            "getCanonicalPath",
            "../",
        ),
        cwe=("CWE-22",),
        masvs_refs=("MASVS-STORAGE-2",),
    ),
    ApkStaticCheck(
        id="APK-INJECTION-CONTENT-URI",
        group=ApkStaticGroup.INJECTION,
        mode=ApkStaticMode.STATIC,
        title="ContentResolver.openInputStream called on a peer-supplied content:// URI.",
        description=(
            "ContentResolver.openInputStream, openFileDescriptor, and "
            "openTypedAssetFileDescriptor on a Uri taken from an intent "
            "extra open whichever provider the calling app named. A "
            "malicious app can point the Uri at its own provider that "
            "returns bytes for the target app's private storage, letting "
            "the target read its own secrets on the peer's behalf, or "
            "serve poisoned content back into the target's parser."
        ),
        verification_steps=(
            "search_functions for ContentResolver.openInputStream, "
            "openFileDescriptor, and openTypedAssetFileDescriptor.",
            "read_function each caller and trace the Uri argument; flag "
            "Uris that come from getIntent().getData, "
            "getIntent().getParcelableExtra(Intent.EXTRA_STREAM), or a "
            "deep-link path.",
            "Confirm the enclosing component is exported (or the "
            "intent-filter matches an implicit action) and that the "
            "returned bytes flow into a sensitive sink (parser, "
            "execution, upload) before reporting.",
        ),
        relevant_apis=(
            "android.content.ContentResolver.openInputStream",
            "android.content.ContentResolver.openFileDescriptor",
            "android.content.Intent.EXTRA_STREAM",
        ),
        evidence_hints=(
            "openInputStream",
            "openFileDescriptor",
            "EXTRA_STREAM",
            "getParcelableExtra",
        ),
        cwe=("CWE-829",),
        masvs_refs=("MASVS-PLATFORM-1",),
    ),
)
