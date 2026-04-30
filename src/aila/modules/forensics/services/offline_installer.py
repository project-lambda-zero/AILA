"""Offline tool installer for analyzer machines.

When the analyzer machine has no internet access (air-gapped, restricted
firewall, etc.), this service handles the full cycle:

1. **Prepare** — on the *platform server*, download pip wheels / fetch
   .deb / .msi / .zip bundles into a local staging directory.
2. **Upload** — push the bundle to the analyzer machine via SFTP.
3. **Install** — run the appropriate install command on the analyzer
   via SSH (``pip install --no-index``, ``dpkg -i``, ``msiexec /i``,
   ``unzip``, etc.).
4. **Verify** — re-run the tool's check_command to confirm it works.

Supports Linux (apt / pip), macOS (brew / pip / dmg / zip), and
Windows (pip / msi / zip) analyzer machines.
"""
from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from aila.config import Settings
from aila.platform.exceptions import AILAError

__all__ = ["OfflineInstallerService"]

_log = logging.getLogger(__name__)

_BUNDLES_DIR = Path(__file__).parent.parent / "data" / "offline_bundles"

_REMOTE_STAGING: dict[str, str] = {
    "linux": "/tmp/aila_offline_install",
    "macos": "/tmp/aila_offline_install",
    "windows": "%TEMP%\\aila_offline_install",
}


class OfflineInstallerService:
    """Prepare, upload, and install forensic tool bundles on analyzer machines."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def install_tool_offline(
        self,
        integration: dict[str, Any],
        tool_def: dict[str, Any],
        analyzer_os: str,
    ) -> bool:
        """Full offline install pipeline for a single tool.

        Returns True if the tool is verified working after install.
        """
        os_block = tool_def.get(analyzer_os)
        if not os_block:
            _log.warning("No OS block for %s on %s", tool_def["name"], analyzer_os)
            return False

        offline_type = os_block.get("offline_type")
        if not offline_type:
            _log.info("No offline install method for %s on %s", tool_def["name"], analyzer_os)
            return False

        from aila.modules.forensics.tools._ssh_helper import get_ssh_service

        ssh = await get_ssh_service(self.settings)

        await self._ensure_remote_staging(ssh, integration, analyzer_os)

        tool_name = tool_def["name"]
        check_cmd = os_block.get("check_command")

        try:
            if offline_type == "builtin":
                # Tool ships with the OS — if we reach here the check_command failed,
                # meaning the tool genuinely isn't present even though it should be.
                # Nothing we can install offline; report as not available.
                _log.info(
                    "%s is expected to be builtin on %s but check failed — "
                    "OS may be minimal/stripped. Note: %s",
                    tool_name, analyzer_os,
                    os_block.get("offline_note", ""),
                )
                return False

            elif offline_type == "unsupported":
                _log.info(
                    "%s has no offline install for %s. Note: %s",
                    tool_name, analyzer_os,
                    os_block.get("offline_note", "not supported on this platform"),
                )
                return False

            elif offline_type == "pip_wheels":
                return await self._install_pip_offline(
                    ssh, integration, tool_name,
                    os_block["offline_package"], analyzer_os, check_cmd,
                )

            elif offline_type == "apt":
                # apt-get download on the platform server + dpkg on the remote only
                # works when the analyzer is Linux. On Windows/macOS the remote
                # staging path is wrong (_REMOTE_STAGING["linux"] is /tmp/...) and
                # dpkg does not exist. Refuse loudly instead of silently returning
                # False after a confusing upload error.
                if analyzer_os != "linux":
                    _log.warning(
                        "Refusing apt offline install of %s: analyzer_os=%s (apt bundles "
                        "require a Linux analyzer). Define an OS-appropriate offline_type "
                        "(zip/msi/exe/pip_wheels/unsupported) in tool_requirements.json.",
                        tool_name, analyzer_os,
                    )
                    return False
                return await self._install_apt_offline(
                    ssh, integration, tool_name,
                    os_block["offline_package"], check_cmd,
                )

            elif offline_type in ("zip", "msi", "dmg", "exe", "pkg", "7z"):
                # Platform-appropriate extension guard to catch copy-paste config mistakes
                # (e.g. msi/exe declared on a Linux analyzer).
                valid_for_os = {
                    "linux": {"zip", "7z", "dmg"},
                    "macos": {"zip", "dmg", "pkg", "7z"},
                    "windows": {"zip", "msi", "exe", "7z"},
                }
                if offline_type not in valid_for_os.get(analyzer_os, set()):
                    _log.warning(
                        "Refusing %s offline install of %s: not valid for analyzer_os=%s. "
                        "Valid types for %s: %s",
                        offline_type, tool_name, analyzer_os, analyzer_os,
                        sorted(valid_for_os.get(analyzer_os, set())),
                    )
                    return False
                return await self._install_bundle_offline(
                    ssh, integration, tool_name, os_block, analyzer_os, check_cmd,
                )

            elif offline_type == "wsl":
                if analyzer_os != "windows":
                    _log.warning(
                        "Refusing wsl offline install of %s: analyzer_os=%s (WSL is Windows-only).",
                        tool_name, analyzer_os,
                    )
                    return False
                return await self._install_wsl_bundle_offline(
                    ssh, integration, tool_name, os_block, check_cmd,
                )

            elif offline_type == "brew":
                _log.info(
                    "Brew offline install not supported for %s — brew requires internet.",
                    tool_name,
                )
                return False

            else:
                _log.warning("Unknown offline_type '%s' for %s", offline_type, tool_name)
                return False

        except (OSError, RuntimeError, ValueError, AILAError):
            _log.error("Offline install failed for %s on %s", tool_name, analyzer_os, exc_info=True)
            return False

    async def prepare_pip_wheels(
        self,
        package_name: str,
        target_os: str,
    ) -> Path | None:
        """Download pip wheels for a package into the local bundle cache.

        Runs ``pip download`` on the *platform server* to fetch wheels.
        The caller can then upload the resulting directory to the analyzer.
        """
        wheels_dir = _BUNDLES_DIR / "pip_wheels" / target_os / package_name
        wheels_dir.mkdir(parents=True, exist_ok=True)

        existing = list(wheels_dir.glob("*.whl")) + list(wheels_dir.glob("*.tar.gz"))
        if existing:
            _log.info("Using cached wheels for %s (%d files)", package_name, len(existing))
            return wheels_dir

        platform_flags = self._pip_platform_flags(target_os)
        cmd = [
            "pip", "download",
            "--dest", str(wheels_dir),
            *platform_flags,
            package_name,
        ]

        _log.info("Downloading pip wheels: %s", " ".join(cmd))
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=600,
            )
            if result.returncode != 0:
                _log.warning("pip download failed for %s: %s", package_name, result.stderr[:500])
                _log.info("Retrying without platform flags (universal wheels)...")
                cmd_fallback = [
                    "pip", "download", "--dest", str(wheels_dir),
                    "--no-deps" if "dissect" not in package_name else "--only-binary=:all:",
                    package_name,
                ]
                result = subprocess.run(
                    cmd_fallback, capture_output=True, text=True, timeout=600,
                )
                if result.returncode != 0:
                    _log.error("pip download fallback failed: %s", result.stderr[:500])
                    return None
        except (subprocess.TimeoutExpired, FileNotFoundError):
            _log.error("pip download timed out or pip not found", exc_info=True)
            return None

        downloaded = list(wheels_dir.glob("*.whl")) + list(wheels_dir.glob("*.tar.gz"))
        if not downloaded:
            _log.warning("pip download produced no files for %s", package_name)
            return None

        _log.info("Downloaded %d wheel files for %s", len(downloaded), package_name)
        return wheels_dir

    async def prepare_bundle_archive(
        self,
        tool_name: str,
        bundle_filename: str,
        target_os: str,
    ) -> Path | None:
        """Locate a pre-cached bundle archive (zip/msi/dmg) in the bundle cache.

        Operators pre-populate ``data/offline_bundles/<os>/`` with the
        required installer files. This method just verifies the file exists.
        """
        bundle_path = _BUNDLES_DIR / target_os / bundle_filename
        if bundle_path.is_file():
            _log.info("Found offline bundle for %s: %s", tool_name, bundle_path)
            return bundle_path

        _log.warning(
            "Offline bundle not found for %s: %s. "
            "Operators must place the file at %s for offline install to work.",
            tool_name, bundle_filename, bundle_path,
        )
        return None

    async def _ensure_remote_staging(
        self,
        ssh: Any,
        integration: dict[str, Any],
        analyzer_os: str,
    ) -> None:
        """Create the remote staging directory if it doesn't exist."""
        staging = _REMOTE_STAGING[analyzer_os]
        if analyzer_os == "windows":
            cmd = f'if not exist "{staging}" mkdir "{staging}"'
        else:
            cmd = f"mkdir -p {staging}"
        try:
            await ssh.run_command(integration, cmd, timeout_seconds=10.0)
        except (OSError, TimeoutError, RuntimeError, AILAError):
            _log.debug("Staging dir creation may have failed", exc_info=True)

    async def _install_pip_offline(
        self,
        ssh: Any,
        integration: dict[str, Any],
        tool_name: str,
        package_name: str,
        analyzer_os: str,
        check_cmd: str | None,
    ) -> bool:
        """Prepare wheels locally, upload via SFTP, install with --no-index."""
        from aila.modules.forensics.tools._ssh_helper import python_cmd

        wheels_dir = await self.prepare_pip_wheels(package_name, analyzer_os)
        if wheels_dir is None:
            return False

        tar_path = self._pack_directory(wheels_dir, f"{package_name}_wheels")
        if tar_path is None:
            return False

        staging = _REMOTE_STAGING[analyzer_os]
        py = python_cmd(analyzer_os)
        remote_tar = f"{staging}/{tar_path.name}" if analyzer_os != "windows" else f"{staging}\\{tar_path.name}"
        remote_wheels = f"{staging}/{package_name}_wheels" if analyzer_os != "windows" else f"{staging}\\{package_name}_wheels"

        try:
            await ssh.upload_file(integration, tar_path, remote_tar, timeout_seconds=300.0)

            if analyzer_os == "windows":
                extract_cmd = f'powershell -NoProfile -Command "Expand-Archive -Path \'{remote_tar}\' -DestinationPath \'{remote_wheels}\' -Force"'
            else:
                extract_cmd = f"tar xzf {remote_tar} -C {staging}"

            await ssh.run_command(integration, extract_cmd, timeout_seconds=60.0)

            pip_cmd = f"{py} -m pip install --no-index --find-links {remote_wheels} {package_name}"
            await ssh.run_command(integration, pip_cmd, timeout_seconds=300.0)

            return await self._verify_install(ssh, integration, tool_name, check_cmd)
        finally:
            try:
                tar_path.unlink(missing_ok=True)
            except OSError:
                pass

    async def _install_apt_offline(
        self,
        ssh: Any,
        integration: dict[str, Any],
        tool_name: str,
        package_name: str,
        check_cmd: str | None,
    ) -> bool:
        """Download .deb locally, upload, install with dpkg."""
        deb_dir = _BUNDLES_DIR / "apt" / package_name
        deb_dir.mkdir(parents=True, exist_ok=True)

        existing_debs = list(deb_dir.glob("*.deb"))
        if not existing_debs:
            _log.info("Attempting to fetch .deb for %s on platform server...", package_name)
            try:
                result = subprocess.run(
                    ["apt-get", "download", package_name],
                    capture_output=True, text=True, timeout=120,
                    cwd=str(deb_dir),
                )
                if result.returncode != 0:
                    _log.warning("apt-get download failed for %s: %s", package_name, result.stderr[:300])
                    return False
            except (subprocess.TimeoutExpired, FileNotFoundError):
                _log.warning("apt-get not available on platform server for %s", package_name)
                return False

            existing_debs = list(deb_dir.glob("*.deb"))

        if not existing_debs:
            _log.warning("No .deb files available for %s", package_name)
            return False

        staging = _REMOTE_STAGING["linux"]
        for deb_file in existing_debs:
            remote_path = f"{staging}/{deb_file.name}"
            await ssh.upload_file(integration, deb_file, remote_path, timeout_seconds=120.0)
            await ssh.run_command(
                integration,
                f"dpkg -i {remote_path} 2>/dev/null; apt-get install -f -y 2>/dev/null",
                timeout_seconds=120.0,
            )

        return await self._verify_install(ssh, integration, tool_name, check_cmd)

    async def _install_bundle_offline(
        self,
        ssh: Any,
        integration: dict[str, Any],
        tool_name: str,
        os_block: dict[str, Any],
        analyzer_os: str,
        check_cmd: str | None,
    ) -> bool:
        """Upload a pre-cached bundle and run its install command.

        Handles: zip, msi, dmg (existing), plus exe, pkg, 7z (new).
        - exe: run the installer silently (Windows .exe installers)
        - pkg: macOS .pkg installed with the system installer command
        - 7z: extract with 7-zip binary on the analyzer; falls back to Python py7zr
        """
        bundle_filename = os_block.get("offline_bundle")
        install_cmd_template = os_block.get("offline_install_cmd")

        if not bundle_filename or not install_cmd_template:
            _log.warning("Missing offline_bundle or offline_install_cmd for %s", tool_name)
            return False

        bundle_path = await self.prepare_bundle_archive(tool_name, bundle_filename, analyzer_os)
        if bundle_path is None:
            return False

        staging = _REMOTE_STAGING[analyzer_os]
        sep = "\\" if analyzer_os == "windows" else "/"
        remote_bundle = f"{staging}{sep}{bundle_filename}"

        await ssh.upload_file(integration, bundle_path, remote_bundle, timeout_seconds=600.0)

        offline_type = os_block.get("offline_type", "zip")

        if offline_type == "7z":
            # Try 7-zip binary first, then py7zr via Python
            dest_dir = remote_bundle.replace(".7z", "")
            install_cmd = (
                f"7z x \"{remote_bundle}\" -o\"{dest_dir}\" -y 2>nul || "
                f"python -c \"import py7zr; py7zr.SevenZipFile('{remote_bundle}').extractall('{dest_dir}')\""
            )
        else:
            install_cmd = install_cmd_template.replace("{bundle_path}", remote_bundle)

        await ssh.run_command(integration, install_cmd, timeout_seconds=600.0)

        return await self._verify_install(ssh, integration, tool_name, check_cmd)

    async def _install_wsl_bundle_offline(
        self,
        ssh: Any,
        integration: dict[str, Any],
        tool_name: str,
        os_block: dict[str, Any],
        check_cmd: str | None,
    ) -> bool:
        """Import a pre-built WSL2 rootfs tarball and verify the tool inside it.

        The bundle is a ``wsl --export`` tarball produced on a machine that already
        has the tool installed in its WSL2 Ubuntu distro.
        """
        bundle_filename = os_block.get("offline_bundle")
        install_cmd_template = os_block.get("offline_install_cmd")

        if not bundle_filename or not install_cmd_template:
            _log.warning("Missing offline_bundle or offline_install_cmd for WSL %s", tool_name)
            return False

        bundle_path = await self.prepare_bundle_archive(tool_name, bundle_filename, "windows")
        if bundle_path is None:
            _log.warning(
                "WSL bundle for %s not found at %s. "
                "Prepare it with: wsl --export Ubuntu %s",
                tool_name, bundle_path, bundle_filename,
            )
            return False

        staging = _REMOTE_STAGING["windows"]
        remote_bundle = f"{staging}\\{bundle_filename}"

        await ssh.upload_file(integration, bundle_path, remote_bundle, timeout_seconds=600.0)

        install_cmd = install_cmd_template.replace("{bundle_path}", remote_bundle)
        await ssh.run_command(integration, install_cmd, timeout_seconds=300.0)

        return await self._verify_install(ssh, integration, tool_name, check_cmd)

    async def _verify_install(
        self,
        ssh: Any,
        integration: dict[str, Any],
        tool_name: str,
        check_cmd: str | None,
    ) -> bool:
        """Run the check command to verify the tool is actually usable."""
        if not check_cmd:
            _log.info("No check_cmd for %s — assuming success", tool_name)
            return True
        try:
            await ssh.run_command(integration, check_cmd, timeout_seconds=30.0)
            _log.info("Offline install verified for %s", tool_name)
            return True
        except (OSError, TimeoutError, RuntimeError, AILAError):
            _log.warning("Post-offline-install verification failed for %s", tool_name, exc_info=True)
            return False

    def _pack_directory(self, directory: Path, archive_name: str) -> Path | None:
        """Pack a directory into a .tar.gz (or .zip for Windows targets)."""
        try:
            archive_path = Path(tempfile.mkdtemp()) / f"{archive_name}.tar.gz"
            shutil.make_archive(
                str(archive_path).replace(".tar.gz", ""),
                "gztar",
                root_dir=str(directory.parent),
                base_dir=directory.name,
            )
            actual = Path(str(archive_path).replace(".tar.gz", "") + ".tar.gz")
            if actual.exists():
                return actual
            gz_fallback = Path(str(archive_path).replace(".tar.gz", ".tar.gz"))
            return gz_fallback if gz_fallback.exists() else None
        except (OSError, IOError):
            _log.error("Failed to pack directory %s", directory, exc_info=True)
            return None

    @staticmethod
    def _pip_platform_flags(target_os: str) -> list[str]:
        """Return pip download flags to target the analyzer OS platform."""
        if target_os == "windows":
            return ["--platform", "win_amd64", "--python-version", "3", "--only-binary=:all:"]
        elif target_os == "macos":
            return ["--platform", "macosx_11_0_arm64", "--python-version", "3", "--only-binary=:all:"]
        else:
            return ["--platform", "manylinux2014_x86_64", "--python-version", "3", "--only-binary=:all:"]

    async def cleanup_remote_staging(
        self,
        integration: dict[str, Any],
        analyzer_os: str,
    ) -> None:
        """Remove the remote staging directory after installation."""
        from aila.modules.forensics.tools._ssh_helper import get_ssh_service

        ssh = await get_ssh_service(self.settings)
        staging = _REMOTE_STAGING[analyzer_os]
        if analyzer_os == "windows":
            cmd = f'rmdir /s /q "{staging}" 2>nul'
        else:
            cmd = f"rm -rf {staging}"
        try:
            await ssh.run_command(integration, cmd, timeout_seconds=15.0)
        except (OSError, TimeoutError, RuntimeError, AILAError):
            _log.debug("Remote staging cleanup failed", exc_info=True)