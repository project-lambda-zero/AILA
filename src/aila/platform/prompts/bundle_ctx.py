"""Ambient pinned agent-config bundle for the current turn (RFC-09 Amendment 2).

The pinned-bundle resolver publishes the bundle's routing / roster /
exemplars into a ContextVar when a bundle version is resolved for the
current investigation turn. Downstream call sites (LLM routing in
``platform/llm/config.py`` and the persona-spawn pass in
``platform/workflows/persona_spawn.py``) read the ContextVar as an
additive override over their normal resolution. An empty bundle (the
prompt-only default that every existing register produces) leaves those
consumption paths byte-identical to today.

Why a ContextVar and not a scope wrapper: ``resolve_pinned_prompt`` is
called by the module-level ``_load_prompt`` right before the turn's LLM
call in the same asyncio task, and the LLM stack is many frames deep.
Threading the bundle through every signature would touch the module
agents (out of scope for this slice); a ContextVar propagates across
awaits inside the task without any signature change. Each turn runs in
its own ARQ task, so a set here never leaks across turns of a different
investigation.

Lifecycle:

* Every ``resolve_pinned_prompt`` call sets the ContextVar
  unconditionally -- to a populated ``PinnedBundle`` when a bundle
  resolves, to the empty ``PinnedBundle()`` when the resolver falls
  back to the file registry. That per-turn overwrite prevents the
  previous turn's routing from leaking to a turn that resolves to
  file.
* Consumers read via :func:`current_pinned_bundle` and treat the empty
  bundle exactly like ``None``: no override, current behaviour.
"""
from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "PinnedBundle",
    "clear_pinned_bundle",
    "current_pinned_bundle",
    "set_pinned_bundle",
]


@dataclass(frozen=True, slots=True)
class PinnedBundle:
    """The pinned agent-config bundle for the current turn.

    Every field defaults to its empty representation so an empty bundle
    is a valid, distinguishable value (as opposed to ``None`` = never
    set). A consumer that treats the empty bundle like ``None`` (no
    override) is the intended behaviour.
    """

    roster: dict[str, Any] = field(default_factory=dict)
    routing: dict[str, Any] = field(default_factory=dict)
    exemplars: list[Any] = field(default_factory=list)


_pinned: ContextVar[PinnedBundle | None] = ContextVar(
    "aila_pinned_bundle", default=None,
)


def current_pinned_bundle() -> PinnedBundle:
    """Return the pinned bundle for the current asyncio task.

    Returns an empty :class:`PinnedBundle` when nothing has been
    published to this task -- callers treat the empty bundle exactly
    like "no override" (empty routing / roster / exemplars), so
    ``if bundle.routing:`` reads the same regardless of whether a
    resolve ran on this turn or not. Also guards against a test or
    misuse that stashes a non-:class:`PinnedBundle` object under the
    ContextVar: the guard normalises back to the empty bundle rather
    than propagating a broken value into the LLM routing hot path.
    """
    bundle = _pinned.get()
    if not isinstance(bundle, PinnedBundle):
        return PinnedBundle()
    return bundle


def set_pinned_bundle(bundle: PinnedBundle | None) -> None:
    """Publish ``bundle`` as the current pinned bundle.

    Called by ``resolve_pinned_prompt`` at every prompt-load so the
    routing / roster overrides never outlive the turn that resolved
    them. The token is discarded intentionally: each new turn's resolve
    replaces the previous value; there is no natural scope end in the
    module ``_load_prompt`` -> turn_runner -> LLM call chain that could
    close a ``with`` block. ``None`` clears the override (used by the
    test escape hatch); every production caller passes a
    :class:`PinnedBundle`.
    """
    _pinned.set(bundle)


def clear_pinned_bundle() -> None:
    """Reset the pinned bundle to ``None``. Test-only escape hatch."""
    _pinned.set(None)
