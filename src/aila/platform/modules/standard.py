from __future__ import annotations

import importlib
import inspect
from collections.abc import Callable
from pathlib import Path

from .protocol import ModuleProtocol

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
ENTRYPOINT_MODULE = "module"
ENTRYPOINT_FACTORY = "create_module"


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


def build_module_factory(package_name: str) -> Callable[[], ModuleProtocol]:
    """Validate a module package and return its zero-argument create_module factory.

    Validates the layout, imports the module.py entrypoint, and verifies that
    create_module() is a callable zero-argument factory returning a
    ModuleProtocol instance with the expected module_id. Raises ValueError with
    an actionable message on any violation so module authors know exactly what
    to fix.
    """
    validate_module_layout(package_name)
    entrypoint_module = importlib.import_module(f"{package_name}.{ENTRYPOINT_MODULE}")
    factory = getattr(entrypoint_module, ENTRYPOINT_FACTORY, None)
    if not callable(factory):
        raise ValueError(
            f"Module package '{package_name}' is missing callable "
            f"{ENTRYPOINT_MODULE}.{ENTRYPOINT_FACTORY}()."
        )
    _assert_zero_arg_factory(factory, package_name)
    instance = _assert_factory_returns_module_protocol(factory, package_name)
    # Construct exactly once: every downstream factory() call (validation plus
    # each load_builtin_modules pass) returns the same instance, so a module's
    # create_module() side effects fire once, not once per call site (#41).
    return lambda: instance


def _assert_zero_arg_factory(factory: Callable[[], object], package_name: str) -> None:
    signature = inspect.signature(factory)
    required_parameters = [
        parameter
        for parameter in signature.parameters.values()
        if parameter.default is inspect.Signature.empty
        and parameter.kind not in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
    ]
    if required_parameters:
        required_names = ", ".join(parameter.name for parameter in required_parameters)
        raise ValueError(
            f"Module package '{package_name}' factory requires arguments ({required_names}). "
            "Factory must be zero-argument."
        )


def _assert_factory_returns_module_protocol(
    factory: Callable[[], object], package_name: str
) -> ModuleProtocol:
    instance = factory()
    if not isinstance(instance, ModuleProtocol):
        raise ValueError(
            f"Module package '{package_name}' factory does not return a ModuleProtocol instance."
        )
    expected_module_id = package_name.rsplit(".", 1)[-1]
    module_id = str(getattr(instance, "module_id", "")).strip()
    if module_id != expected_module_id:
        raise ValueError(
            f"Module package '{package_name}' must declare module_id='{expected_module_id}', "
            f"but got '{module_id}'."
        )
    return instance
