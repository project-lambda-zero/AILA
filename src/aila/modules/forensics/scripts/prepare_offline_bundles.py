#!/usr/bin/env python3
"""Prepare offline installation bundles for forensic tools.

Downloads all zip/msi/dmg/exe/pkg bundles and pip wheels needed for
air-gapped analyzer machine installations.  Run this script on a machine
that has internet access BEFORE deploying to an air-gapped environment.

Usage:
    python prepare_offline_bundles.py [--os linux|macos|windows] [--tool NAME]

Outputs to:
    src/aila/modules/forensics/data/offline_bundles/<os>/<bundle>
    src/aila/modules/forensics/data/offline_bundles/pip_wheels/<os>/<package>/

Exit codes:
    0 - all bundles prepared successfully
    1 - one or more bundles failed (check stderr)
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import urllib.request
import urllib.error
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_DATA = _ROOT / "data"
_BUNDLES = _DATA / "offline_bundles"
_REQUIREMENTS = _DATA / "tool_requirements.json"

_SKIP_TYPES = frozenset({"apt", "brew", "builtin", "unsupported", "wsl"})

_PIP_PLATFORM_FLAGS: dict[str, list[str]] = {
    "linux":   ["--platform", "manylinux2014_x86_64", "--python-version", "3.11", "--only-binary=:all:"],
    "macos":   ["--platform", "macosx_11_0_arm64",    "--python-version", "3.11", "--only-binary=:all:"],
    "windows": ["--platform", "win_amd64",             "--python-version", "3.11", "--only-binary=:all:"],
}


def _log(msg: str) -> None:
    print(msg.encode('utf-8', errors='replace').decode('utf-8', errors='replace'), flush=True)


def _err(msg: str) -> None:
    print(f"[ERROR] {msg}".encode('utf-8', errors='replace').decode('utf-8', errors='replace'), file=sys.stderr, flush=True)


def _download(url: str, dest: Path) -> bool:
    """Download url to dest.  Returns True on success."""
    if dest.exists():
        _log(f"  [skip] already cached: {dest.name}")
        return True

    dest.parent.mkdir(parents=True, exist_ok=True)
    _log(f"  Downloading {url}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "aila-offline-prep/1.0"})
        with urllib.request.urlopen(req, timeout=300) as resp, open(dest, "wb") as fh:
            total = int(resp.headers.get("Content-Length", 0))
            downloaded = 0
            chunk = 65536
            while True:
                data = resp.read(chunk)
                if not data:
                    break
                fh.write(data)
                downloaded += len(data)
                if total:
                    pct = downloaded * 100 // total
                    print(f"\r  {pct:3d}% ({downloaded // 1024} KB)", end="", flush=True)
        print()
        _log(f"  Saved to {dest}")
        return True
    except urllib.error.HTTPError as exc:
        _err(f"HTTP {exc.code} downloading {url}")
        return False
    except Exception as exc:
        _err(f"Download failed for {url}: {exc}")
        return False


def _get_github_latest_asset_url(api_url: str, pattern: str) -> str | None:
    """Query GitHub releases API and find the first asset matching pattern."""
    try:
        req = urllib.request.Request(
            api_url,
            headers={"User-Agent": "aila-offline-prep/1.0", "Accept": "application/vnd.github+json"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.load(resp)
        for asset in data.get("assets", []):
            name: str = asset["name"]
            if all(p in name.lower() for p in pattern.lower().split("*")):
                return asset["browser_download_url"]
    except Exception as exc:
        _err(f"GitHub API query failed ({api_url}): {exc}")
    return None


def _prepare_pip_wheels(package: str, target_os: str) -> bool:
    """Download pip wheels for package targeting target_os platform."""
    wheels_dir = _BUNDLES / "pip_wheels" / target_os / package
    existing = list(wheels_dir.glob("*.whl")) + list(wheels_dir.glob("*.tar.gz"))
    if existing:
        _log(f"  [skip] {len(existing)} wheel(s) already cached for {package} ({target_os})")
        return True

    wheels_dir.mkdir(parents=True, exist_ok=True)
    flags = _PIP_PLATFORM_FLAGS.get(target_os, [])
    cmd = ["pip", "download", "--dest", str(wheels_dir), *flags, package]
    _log(f"  pip download {package} to {wheels_dir}")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        _log(f"  [warn] platform-specific pip download failed - retrying without platform flags")
        cmd_fallback = ["pip", "download", "--dest", str(wheels_dir), package]
        result = subprocess.run(cmd_fallback, capture_output=True, text=True, timeout=600)
        if result.returncode != 0:
            _err(f"pip download failed for {package}: {result.stderr[:400]}")
            return False

    fetched = list(wheels_dir.glob("*.whl")) + list(wheels_dir.glob("*.tar.gz"))
    _log(f"  {len(fetched)} file(s) saved for {package}")
    return bool(fetched)


def _prepare_bundle(tool_name: str, os_block: dict, target_os: str) -> bool:
    """Download a binary bundle (zip/msi/dmg/exe/pkg/7z) for a tool."""
    bundle_filename: str | None = os_block.get("offline_bundle")
    download_url: str | None = os_block.get("offline_download_url")
    github_api: str | None = os_block.get("offline_github_api")
    offline_type: str = os_block.get("offline_type", "zip")

    if not bundle_filename:
        _err(f"No offline_bundle defined for {tool_name} ({target_os})")
        return False

    dest = _BUNDLES / target_os / bundle_filename

    # Already cached
    if dest.exists():
        _log(f"  [skip] already cached: {dest}")
        return True

    dest.parent.mkdir(parents=True, exist_ok=True)

    # Try to get latest URL from GitHub releases API
    if github_api and not download_url:
        _log(f"  Querying GitHub API for latest {tool_name} release...")
        # Build a pattern from the bundle filename to match the asset
        pattern = _bundle_to_github_pattern(tool_name, bundle_filename)
        download_url = _get_github_latest_asset_url(github_api, pattern)
        if download_url:
            _log(f"  Found latest release asset: {download_url}")

    if not download_url:
        _err(
            f"No download URL for {tool_name} ({target_os}). "
            f"Manually place {bundle_filename} at {dest}"
        )
        return False

    return _download(download_url, dest)


def _bundle_to_github_pattern(tool_name: str, bundle_filename: str) -> str:
    """Map bundle filename to a GitHub asset name substring for matching."""
    patterns = {
        "yara-win64.zip":          "win64",
        "ghidra.zip":              "PUBLIC",
        "ghidra-win.zip":          "PUBLIC",
        "rizin-installer.exe":     "x86_64.exe",
        "bulk_extractor-win.zip":  "windows",
        "hashcat-win.7z":          "hashcat",
        "john-win.zip":            "winx64*jtr",
        "jadx-win.zip":            "jadx",
        "apktool-win.zip":         "apktool_",
        "jadx-1.5.1.zip":          "jadx",
    }
    return patterns.get(bundle_filename, tool_name)


def prepare_all(target_oses: list[str], tool_filter: str | None) -> dict[str, bool]:
    """Prepare all offline bundles.  Returns {label: success}."""
    requirements = json.loads(_REQUIREMENTS.read_text(encoding="utf-8"))
    results: dict[str, bool] = {}

    for category, tools in requirements.items():
        for tool_def in tools:
            tool_name: str = tool_def["name"]
            if tool_filter and tool_filter.lower() not in tool_name.lower():
                continue

            for target_os in target_oses:
                os_block: dict | None = tool_def.get(target_os)
                if not os_block:
                    continue

                offline_type = os_block.get("offline_type")
                label = f"{tool_name}/{target_os}"

                if not offline_type or offline_type in _SKIP_TYPES:
                    results[label] = True
                    continue

                _log(f"\n=== {tool_name} ({target_os}) - {offline_type} ===")

                if offline_type == "pip_wheels":
                    pkg = os_block.get("offline_package")
                    if not pkg:
                        _err(f"No offline_package for {label}")
                        results[label] = False
                        continue
                    results[label] = _prepare_pip_wheels(pkg, target_os)

                elif offline_type in ("zip", "msi", "dmg", "exe", "pkg", "7z"):
                    results[label] = _prepare_bundle(tool_name, os_block, target_os)

                else:
                    _log(f"  [skip] unhandled offline_type={offline_type}")
                    results[label] = True

    return results


def _print_summary(results: dict[str, bool]) -> None:
    ok = [k for k, v in results.items() if v]
    fail = [k for k, v in results.items() if not v]
    _log(f"\n{'='*60}")
    _log(f"DONE: {len(ok)} ok, {len(fail)} failed")
    if fail:
        _log("\nFailed bundles (manual download required):")
        for f in fail:
            _log(f"  [SKIP] {f}")
    else:
        _log("All bundles ready for offline deployment.")
    _log(f"\nBundle directory: {_BUNDLES}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Prepare offline forensic tool bundles")
    parser.add_argument(
        "--os",
        choices=["linux", "macos", "windows", "all"],
        default="all",
        help="Target OS to prepare bundles for (default: all)",
    )
    parser.add_argument(
        "--tool",
        default=None,
        help="Only prepare bundles for tools matching this name substring",
    )
    args = parser.parse_args()

    target_oses = ["linux", "macos", "windows"] if args.os == "all" else [args.os]
    _log(f"Preparing offline bundles for: {', '.join(target_oses)}")
    if args.tool:
        _log(f"Tool filter: {args.tool}")
    _log(f"Output directory: {_BUNDLES}\n")

    results = prepare_all(target_oses, args.tool)
    _print_summary(results)

    failed = [k for k, v in results.items() if not v]
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
