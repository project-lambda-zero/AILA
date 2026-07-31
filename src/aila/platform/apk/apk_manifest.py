"""AndroidManifest.xml parser for apktool-decoded APK trees.

Reads ``<decoded_dir>/AndroidManifest.xml`` as plain text XML (apktool
already decoded axml to text) via :mod:`xml.etree.ElementTree`, and pulls
minSdk/targetSdk from ``<decoded_dir>/apktool.yml`` when available (apktool
moves them out of ``<uses-sdk>`` into ``sdkInfo``). Produces the same
manifest-summary dict shape the prior extractor
returned, so downstream callers stay identical.

The single public function :func:`parse_manifest` never raises on malformed
input: it returns a dict with an ``error`` key plus empty defaults so the
rest of the static pipeline can proceed against whatever else the decoded
tree still offers.
"""
from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from typing import Any

import yaml

__all__ = ["parse_manifest"]


_ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _aname(attr: str) -> str:
    """Namespaced attribute key ElementTree uses for android:* attributes."""
    return f"{{{_ANDROID_NS}}}{attr}"


_A_NAME = _aname("name")
_A_EXPORTED = _aname("exported")
_A_PERMISSION = _aname("permission")
_A_GRANT_URI = _aname("grantUriPermissions")
_A_VERSION_NAME = _aname("versionName")
_A_VERSION_CODE = _aname("versionCode")
_A_MIN_SDK = _aname("minSdkVersion")
_A_TARGET_SDK = _aname("targetSdkVersion")
_A_COMPILE_SDK = _aname("compileSdkVersion")
_A_DEBUGGABLE = _aname("debuggable")
_A_ALLOW_BACKUP = _aname("allowBackup")
_A_CLEARTEXT = _aname("usesCleartextTraffic")
_A_NET_SEC_CONFIG = _aname("networkSecurityConfig")
_A_SCHEME = _aname("scheme")
_A_HOST = _aname("host")


# Runtime dangerous permission set (matched by suffix after the last ".").
_DANGEROUS_PERMISSIONS: frozenset[str] = frozenset(
    {
        "READ_CONTACTS",
        "WRITE_CONTACTS",
        "ACCESS_FINE_LOCATION",
        "ACCESS_COARSE_LOCATION",
        "ACCESS_BACKGROUND_LOCATION",
        "CAMERA",
        "RECORD_AUDIO",
        "READ_SMS",
        "SEND_SMS",
        "RECEIVE_SMS",
        "READ_PHONE_STATE",
        "READ_CALL_LOG",
        "WRITE_CALL_LOG",
        "READ_EXTERNAL_STORAGE",
        "WRITE_EXTERNAL_STORAGE",
        "BODY_SENSORS",
        "READ_CALENDAR",
        "WRITE_CALENDAR",
        "GET_ACCOUNTS",
        "SYSTEM_ALERT_WINDOW",
        "REQUEST_INSTALL_PACKAGES",
        "BIND_ACCESSIBILITY_SERVICE",
        "QUERY_ALL_PACKAGES",
    }
)


def _empty_result() -> dict[str, Any]:
    """Skeleton with every documented key present and neutrally defaulted."""
    return {
        "package": "",
        "version_name": "",
        "version_code": "",
        "min_sdk": "",
        "target_sdk": "",
        "compile_sdk": "",
        "application_class": "",
        "main_activity": "",
        "permissions": [],
        "dangerous_permissions": [],
        "exported_activities": [],
        "exported_services": [],
        "exported_receivers": [],
        "exported_providers": [],
        "debuggable": False,
        "allow_backup": True,
        "uses_cleartext_traffic": None,
        "network_security_config": "",
        "custom_schemes": [],
        "deep_link_hosts": [],
        "exported_components": [],
    }


def _expand_name(raw: str, package: str) -> str:
    """Apply the manifest's class-name shorthand rules.

    ``.Foo`` becomes ``package.Foo``; a bare ``Foo`` with no dot becomes
    ``package.Foo``; a fully-qualified name is returned as-is. An empty
    input returns an empty string so callers can filter cheaply.
    """
    if not raw:
        return ""
    if raw.startswith("."):
        return f"{package}{raw}" if package else raw
    if "." not in raw and package:
        return f"{package}.{raw}"
    return raw


def _parse_bool(val: str | None) -> bool | None:
    """Manifest tri-state boolean: ``true``/``false`` -> bool, else None."""
    if val is None:
        return None
    low = val.strip().lower()
    if low == "true":
        return True
    if low == "false":
        return False
    return None


def _dedup_preserve(values: list[str]) -> list[str]:
    """Order-preserving de-duplication used for schemes/hosts/permissions."""
    seen: set[str] = set()
    out: list[str] = []
    for v in values:
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _load_sdk_info(decoded_dir: str) -> tuple[str, str]:
    """Return (min_sdk, target_sdk) from ``apktool.yml`` when readable.

    Missing file or malformed yaml is non-fatal: returns ``("", "")`` and
    lets the caller fall back to ``<uses-sdk>`` inside the manifest.
    """
    path = os.path.join(decoded_dir, "apktool.yml")
    try:
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
    except (OSError, yaml.YAMLError):
        return "", ""
    if not isinstance(doc, dict):
        return "", ""
    sdk = doc.get("sdkInfo")
    if not isinstance(sdk, dict):
        return "", ""
    minv = sdk.get("minSdkVersion", "")
    tgtv = sdk.get("targetSdkVersion", "")
    return ("" if minv is None else str(minv)), ("" if tgtv is None else str(tgtv))


def _find_uses_sdk(root: ET.Element) -> tuple[str, str]:
    """Fallback SDK values from a ``<uses-sdk>`` element in the manifest."""
    node = root.find("uses-sdk")
    if node is None:
        return "", ""
    return node.get(_A_MIN_SDK, ""), node.get(_A_TARGET_SDK, "")


def _find_main_activity(activities: list[ET.Element], package: str) -> str:
    """Class name of the activity registered as the launcher entry point.

    An activity qualifies when any of its ``<intent-filter>`` children
    contain both ``action`` ``android.intent.action.MAIN`` and ``category``
    ``android.intent.category.LAUNCHER``. Returns ``""`` when no activity
    matches (e.g. library-only APKs, uncommon in real apps).
    """
    for act in activities:
        for filt in act.findall("intent-filter"):
            actions = {a.get(_A_NAME, "") for a in filt.findall("action")}
            categories = {c.get(_A_NAME, "") for c in filt.findall("category")}
            if (
                "android.intent.action.MAIN" in actions
                and "android.intent.category.LAUNCHER" in categories
            ):
                return _expand_name(act.get(_A_NAME, ""), package)
    return ""


def _is_exported_default(elem: ET.Element, kind: str) -> bool:
    """Apply the pre-API-31 default-export rule for a component.

    Activities, services, and receivers: explicit ``android:exported``
    wins; when the attribute is absent the component counts as exported
    only if it declares at least one ``<intent-filter>``. Providers use
    a broader OR: ``android:exported="true"`` OR
    ``android:grantUriPermissions="true"`` both flag the provider as
    exported, since a granted URI is reachable from other packages
    regardless of the exported attribute.
    """
    explicit = _parse_bool(elem.get(_A_EXPORTED))
    if kind == "provider":
        grant = _parse_bool(elem.get(_A_GRANT_URI))
        return explicit is True or grant is True
    if explicit is True:
        return True
    if explicit is False:
        return False
    return elem.find("intent-filter") is not None


def _collect_intent_filter_data(
    components: list[ET.Element],
) -> tuple[list[str], list[str]]:
    """Walk every intent-filter <data> element and split schemes/hosts.

    ``http`` and ``https`` are excluded from ``custom_schemes`` because
    the field's whole point is to surface non-web URL handlers (custom
    URI targets, deep-link authorities, third-party schemes).
    """
    schemes: list[str] = []
    hosts: list[str] = []
    for comp in components:
        for filt in comp.findall("intent-filter"):
            for data in filt.findall("data"):
                scheme = (data.get(_A_SCHEME) or "").strip()
                host = (data.get(_A_HOST) or "").strip()
                if scheme and scheme.lower() not in {"http", "https"}:
                    schemes.append(scheme)
                if host:
                    hosts.append(host)
    return _dedup_preserve(schemes), _dedup_preserve(hosts)


def _summarize_component(
    elem: ET.Element, kind: str, package: str
) -> dict[str, Any]:
    """Structured per-component entry used in ``exported_components``."""
    return {
        "type": kind,
        "name": _expand_name(elem.get(_A_NAME, ""), package),
        "permission": elem.get(_A_PERMISSION, "") or "",
        "has_intent_filter": elem.find("intent-filter") is not None,
    }


def parse_manifest(decoded_dir: str) -> dict[str, Any]:
    """Parse an apktool-decoded AndroidManifest.xml into a summary dict.

    ``decoded_dir`` is the root of an apktool output tree (the directory
    holding ``AndroidManifest.xml`` and ``apktool.yml``). The return shape
    matches the prior summary shape consumed by the
    static-analysis pipeline; see the module docstring for the full key
    set. Never raises on parse errors: malformed inputs yield a partial
    dict with ``error`` populated and every other key defaulted, so a
    single bad element does not abort the enclosing scan.
    """
    result = _empty_result()
    manifest_path = os.path.join(decoded_dir, "AndroidManifest.xml")
    if not os.path.isfile(manifest_path):
        result["error"] = "manifest_not_found"
        return result

    try:
        tree = ET.parse(manifest_path)
    except (OSError, ET.ParseError) as exc:
        result["error"] = f"manifest_parse_failed: {type(exc).__name__}"
        return result

    try:
        root = tree.getroot()
    except (AttributeError, ET.ParseError) as exc:
        result["error"] = f"manifest_parse_failed: {type(exc).__name__}"
        return result

    # Top-level manifest metadata.
    package = root.get("package", "") or ""
    result["package"] = package
    result["version_name"] = root.get(_A_VERSION_NAME, "") or ""
    version_code_raw = root.get(_A_VERSION_CODE)
    result["version_code"] = (
        "" if version_code_raw is None else str(version_code_raw)
    )
    result["compile_sdk"] = root.get(_A_COMPILE_SDK, "") or ""

    # SDK levels: apktool.yml is authoritative, <uses-sdk> is the fallback.
    yml_min, yml_target = _load_sdk_info(decoded_dir)
    if not (yml_min and yml_target):
        xml_min, xml_target = _find_uses_sdk(root)
    else:
        xml_min, xml_target = "", ""
    result["min_sdk"] = yml_min or xml_min
    result["target_sdk"] = yml_target or xml_target

    # Permissions and the dangerous subset.
    permissions: list[str] = []
    for perm in root.findall("uses-permission"):
        name = perm.get(_A_NAME, "")
        if name:
            permissions.append(name)
    permissions = _dedup_preserve(permissions)
    result["permissions"] = permissions
    result["dangerous_permissions"] = [
        p for p in permissions if p.rsplit(".", 1)[-1] in _DANGEROUS_PERMISSIONS
    ]

    # <application> and everything nested under it.
    app = root.find("application")
    if app is not None:
        result["application_class"] = _expand_name(
            app.get(_A_NAME, ""), package
        )
        debug = _parse_bool(app.get(_A_DEBUGGABLE))
        result["debuggable"] = bool(debug) if debug is not None else False
        backup = _parse_bool(app.get(_A_ALLOW_BACKUP))
        result["allow_backup"] = True if backup is None else backup
        result["uses_cleartext_traffic"] = _parse_bool(app.get(_A_CLEARTEXT))
        result["network_security_config"] = app.get(_A_NET_SEC_CONFIG, "") or ""

        activities = list(app.findall("activity"))
        services = list(app.findall("service"))
        receivers = list(app.findall("receiver"))
        providers = list(app.findall("provider"))

        result["main_activity"] = _find_main_activity(activities, package)

        exported_details: list[dict[str, Any]] = []
        buckets: dict[str, list[str]] = {
            "activity": [],
            "service": [],
            "receiver": [],
            "provider": [],
        }
        for kind, items in (
            ("activity", activities),
            ("service", services),
            ("receiver", receivers),
            ("provider", providers),
        ):
            for elem in items:
                if not _is_exported_default(elem, kind):
                    continue
                name = _expand_name(elem.get(_A_NAME, ""), package)
                if not name:
                    continue
                buckets[kind].append(name)
                exported_details.append(_summarize_component(elem, kind, package))

        result["exported_activities"] = _dedup_preserve(buckets["activity"])
        result["exported_services"] = _dedup_preserve(buckets["service"])
        result["exported_receivers"] = _dedup_preserve(buckets["receiver"])
        result["exported_providers"] = _dedup_preserve(buckets["provider"])
        result["exported_components"] = exported_details

        # Deep-link surface pulled from every child intent-filter data element.
        schemes, hosts = _collect_intent_filter_data(
            activities + services + receivers + providers
        )
        result["custom_schemes"] = schemes
        result["deep_link_hosts"] = hosts

    return result


if __name__ == "__main__":
    # Self-test: build a minimal manifest, parse it, print the summary.
    import json
    import tempfile

    _SAMPLE_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app"
    android:versionCode="42"
    android:versionName="1.2.3"
    android:compileSdkVersion="34">
  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="33"/>
  <uses-permission android:name="android.permission.INTERNET"/>
  <uses-permission android:name="android.permission.CAMERA"/>
  <uses-permission android:name="android.permission.READ_CONTACTS"/>
  <application
      android:name=".MyApp"
      android:debuggable="true"
      android:allowBackup="false"
      android:usesCleartextTraffic="true"
      android:networkSecurityConfig="@xml/network_security_config">
    <activity android:name=".ui.MainActivity">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
      </intent-filter>
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="myapp" android:host="open"/>
        <data android:scheme="https" android:host="example.com"/>
      </intent-filter>
    </activity>
    <activity android:name="com.example.app.ui.SecondActivity"
              android:exported="true"/>
    <service android:name=".svc.BackgroundService"/>
    <receiver android:name=".rcv.BootReceiver" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED"/>
      </intent-filter>
    </receiver>
    <provider android:name=".data.FileProvider"
              android:authorities="com.example.app.files"
              android:exported="false"
              android:grantUriPermissions="true"/>
  </application>
</manifest>
"""
    _SAMPLE_APKTOOL_YML = (
        "!!brut.androlib.meta.MetaInfo\n"
        "sdkInfo:\n"
        "  minSdkVersion: '24'\n"
        "  targetSdkVersion: '33'\n"
    )

    with tempfile.TemporaryDirectory() as _td:
        with open(os.path.join(_td, "AndroidManifest.xml"), "w", encoding="utf-8") as _f:
            _f.write(_SAMPLE_MANIFEST)
        with open(os.path.join(_td, "apktool.yml"), "w", encoding="utf-8") as _f:
            _f.write(_SAMPLE_APKTOOL_YML)
        _parsed = parse_manifest(_td)
        print(json.dumps(_parsed, indent=2, sort_keys=True))

    # Malformed-XML branch: overwrite the manifest with garbage and re-parse.
    with tempfile.TemporaryDirectory() as _td:
        with open(os.path.join(_td, "AndroidManifest.xml"), "w", encoding="utf-8") as _f:
            _f.write("<manifest>this is not valid xml")
        _bad = parse_manifest(_td)
        print(json.dumps({"error": _bad.get("error"), "package": _bad.get("package")}))

    # Missing-manifest branch.
    with tempfile.TemporaryDirectory() as _td:
        _missing = parse_manifest(_td)
        print(json.dumps({"error": _missing.get("error"), "package": _missing.get("package")}))
