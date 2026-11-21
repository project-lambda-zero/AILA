from __future__ import annotations

import importlib
from pathlib import Path

REQUIRED_MODULE_FILES = (
    "__init__.py",
    "module.py",
    "runtime.py",
    "capabilities.py",
    "workflow.py",
    "tool_keys.py",
    "contracts/__init__.py",
    "tools/__init__.py",
    "services/__init__.py",
    "reporting/__init__.py",
)
REQUIRED_MODULE_PACKAGES = (
    "contracts",
    "tools",
    "services",
    "reporting",
)


def validate_module_layout(package_name: str) -> None:
    """Verify that a feature module package satisfies the required layout standard.

    Checks that all files in REQUIRED_MODULE_FILES exist and all packages in
    REQUIRED_MODULE_PACKAGES are directories. Raises ValueError with a list of
    missing files and packages when the layout is incomplete, enabling early
    detection of malformed module packages at startup.
    """
    package = importlib.import_module(package_name)
    package_paths = list(getattr(package, "__path__", []))
    if not package_paths:
        raise ValueError(f"Module package '{package_name}' is not a package.")
    package_root = Path(package_paths[0]).resolve()

    missing_files = [
        required_file
        for required_file in REQUIRED_MODULE_FILES
        if not (package_root / required_file).is_file()
        and not (package_root / required_file.removesuffix(".py")).is_dir()
    ]
    missing_packages = [
        required_package
        for required_package in REQUIRED_MODULE_PACKAGES
        if not (package_root / required_package).is_dir()
    ]
    if missing_files or missing_packages:
        parts: list[str] = []
        if missing_files:
            parts.append("missing files: " + ", ".join(missing_files))
        if missing_packages:
            parts.append("missing packages: " + ", ".join(missing_packages))
        raise ValueError(
            f"Module package '{package_name}' does not satisfy the module standard ({'; '.join(parts)})."
        )
