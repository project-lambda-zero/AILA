"""RFC-09 activation: seed file-backed module prompts into the version store.

The platform stays module-agnostic. It iterates the registered modules and
invokes each module's optional ``seed_prompts()`` hook, discovered by
duck-typing the same way ``health_checks`` is collected. A module that
declares no prompt inventory is skipped. Per-module faults are logged and
never abort startup, because a prompt-seed fault degrades that module to its
file-backed baseline rather than taking the whole platform down.
"""
from __future__ import annotations

import structlog
from sqlalchemy.exc import SQLAlchemyError

__all__ = ["seed_module_prompts"]

_log = structlog.get_logger(__name__)


async def seed_module_prompts(module_registry: object) -> dict[str, int]:
    """Seed every registered module's file-backed prompts.

    Returns a map of ``module_id -> count of production aliases newly set``.
    A missing registry (test doubles) or a module without a ``seed_prompts``
    hook is skipped; a module whose hook raises is logged and recorded as 0.
    """
    results: dict[str, int] = {}
    modules = getattr(module_registry, "modules", None)
    if modules is None:
        return results
    for module in modules:
        module_id = getattr(module, "module_id", "?")
        hook = getattr(module, "seed_prompts", None)
        if hook is None:
            continue
        try:
            results[module_id] = await hook()
        except (
            OSError,
            TimeoutError,
            RuntimeError,
            ValueError,
            LookupError,
            SQLAlchemyError,
        ) as exc:
            _log.warning(
                "module_prompt_seed_failed", module_id=module_id, error=str(exc),
            )
            results[module_id] = 0
    return results
