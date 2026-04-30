from __future__ import annotations

import logging
import pkgutil
from collections.abc import Callable
from functools import lru_cache
from types import ModuleType
from typing import Any

from ..exceptions import AILAError
from .protocol import ModuleProtocol
from .standard import build_module_factory

_log = logging.getLogger(__name__)


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


@lru_cache(maxsize=1)
def _discover_feature_module_factories() -> tuple[Callable[[], ModuleProtocol], ...]:
    """Scan the aila.modules package for feature module sub-packages and build their factories.

    Only top-level packages (not plain modules) are considered. Packages with a
    leading underscore are skipped. Each discovered package is passed through
    build_module_factory() which validates the module standard layout before
    returning the factory.
    """
    modules_package = _import_modules_package()
    discovered: list[Callable[[], ModuleProtocol]] = []
    for module_info in pkgutil.iter_modules(modules_package.__path__, modules_package.__name__ + "."):
        short_name = module_info.name.rsplit(".", 1)[-1]
        if not module_info.ispkg or short_name.startswith("_"):
            continue
        discovered.append(build_module_factory(module_info.name))
    return tuple(discovered)


def _import_modules_package() -> ModuleType:
    """Import and return the aila.modules package object for filesystem scanning."""
    from aila import modules

    return modules
