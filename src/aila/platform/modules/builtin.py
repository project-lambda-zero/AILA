from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
from collections.abc import Callable
from functools import lru_cache
from types import ModuleType
from typing import Any

from ..exceptions import AILAError
from .protocol import ModuleProtocol
from .standard import validate_module_layout

_log = logging.getLogger(__name__)
ENTRYPOINT_MODULE = "module"
ENTRYPOINT_FACTORY = "create_module"


def load_builtin_modules() -> list[ModuleProtocol]:
    """Instantiate all built-in modules and return them as a list.

    The PlatformModule (for registry/SSH commands) is always first.
    Feature modules discovered under aila.modules follow in filesystem order.
    """
    return [factory() for factory in builtin_module_factories()]


def register_builtin_modules(module_registry: Any) -> None:
    """Instantiate and register all built-in modules into the given registry.

    Called once during build_platform_runtime() to populate the registry before
    tool registration and runtime construction.

    Per D-05: if a module fails validation, log a visible WARNING and skip it.
    The platform continues startup with reduced functionality rather than crashing.
    """
    for module in load_builtin_modules():
        try:
            module_registry.register(module)
        except (AILAError, ValueError) as exc:
            _log.warning(
                "Module '%s' failed validation -- disabled: %s",
                getattr(module, "module_id", "unknown"),
                exc,
            )


@lru_cache(maxsize=1)
def builtin_module_factories() -> tuple[Callable[[], ModuleProtocol], ...]:
    """Return cached zero-argument factory callables for all built-in modules.

    PlatformModule is always the first factory. Feature module factories are
    discovered and validated once at first call; subsequent calls return the
    cached tuple without rescanning the filesystem.
    """
    from .platform import PlatformModule

    return (PlatformModule, *_discover_feature_module_factories())


def declared_worker_tracks() -> tuple[str, ...]:
    """Sorted, de-duplicated ARQ worker tracks declared by every built-in module."""
    return tuple(
        sorted({track for factory in builtin_module_factories() for track in factory().worker_tracks})
    )


def declared_idempotency_exempt_post_paths() -> tuple[str, ...]:
    """Full POST route templates (module prefix + route template) that skip Idempotency-Key caching."""
    return tuple(
        spec.prefix.rstrip("/") + template
        for factory in builtin_module_factories()
        for spec in factory().route_specs()
        for template in spec.idempotency_exempt_post_paths
    )


@lru_cache(maxsize=1)
def _discover_feature_module_factories() -> tuple[Callable[[], ModuleProtocol], ...]:
    """Scan the aila.modules package for feature module sub-packages and build their factories.

    Only top-level packages (not plain modules) are considered. Packages with a
    leading underscore are skipped. Each discovered package is passed through
    build_module_factory() which validates the module standard layout before
    returning the factory.

    Discovery is deterministic (#200): candidate packages are sorted by their
    short name before validation so first_with / all_with return the same
    winner across operating systems regardless of filesystem traversal order.

    Per-module isolation (#190): a validation or import failure in one module
    logs a WARNING and skips that module rather than aborting the whole
    platform. The failing module is disabled; every well-formed module still
    loads.
    """
    modules_package = _import_modules_package()
    candidates: list[str] = []
    for module_info in pkgutil.iter_modules(modules_package.__path__, modules_package.__name__ + "."):
        short_name = module_info.name.rsplit(".", 1)[-1]
        if not module_info.ispkg or short_name.startswith("_"):
            continue
        candidates.append(module_info.name)
    candidates.sort(key=lambda name: name.rsplit(".", 1)[-1])
    discovered: list[Callable[[], ModuleProtocol]] = []
    for package_name in candidates:
        try:
            discovered.append(build_module_factory(package_name))
        except (ValueError, ImportError, AttributeError, TypeError) as exc:
            _log.warning(
                "Module package %s failed to load -- disabled: %s",
                package_name,
                exc,
                exc_info=True,
            )
    return tuple(discovered)


def _import_modules_package() -> ModuleType:
    """Import and return the aila.modules package object for filesystem scanning."""
    from aila import modules

    return modules


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
