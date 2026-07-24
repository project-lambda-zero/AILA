"""Lazy per-investigation prompt pin resolution (RFC-09 criterion 4).

The distinctive RFC-09 rule for a long-running audited investigation is
that a live production-alias flip must NEVER rewrite the prompt on a
turn that belongs to an already-running investigation. This module owns
the read/persist half of that rule so both researcher modules resolve
through the same code path.

Behaviour:

1. Look up the pin for ``key`` in the row's ``prompt_pins_json``.
2. If pinned, resolve that exact version from the version store and
   return its body + version. Nothing else changes.
3. If not pinned, resolve the current ``production`` alias. When a
   version comes back, persist ``{key: version}`` into the row's pin map
   in a single UPDATE and return that body + version.
4. When the store raises (fail-open), or the alias points at nothing,
   return ``(None, None)`` so the caller can fall back to its file
   registry. Store faults must never block a turn.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import select

from aila.platform.contracts._common import utc_now
from aila.platform.prompts.version_store import PromptVersionStore
from aila.platform.uow import UnitOfWork

__all__ = ["resolve_pinned_prompt"]

_log = logging.getLogger(__name__)


def _decode_pins(pins_json: str | None) -> dict[str, str]:
    """Parse the pin map, tolerating a corrupted row: an empty map is safe."""
    if not pins_json:
        return {}
    try:
        loaded = json.loads(pins_json)
    except (TypeError, ValueError):
        _log.warning("prompt_pins_json corrupted -- treating as empty")
        return {}
    if not isinstance(loaded, dict):
        _log.warning("prompt_pins_json not an object -- treating as empty")
        return {}
    return {str(k): str(v) for k, v in loaded.items() if isinstance(v, str)}


async def resolve_pinned_prompt(
    *,
    investigation_id: str | None,
    key: str,
    investigation_model: type[Any],
    store: PromptVersionStore,
) -> tuple[str | None, str | None]:
    """Resolve ``key`` for ``investigation_id`` through the pin-per-investigation rule.

    Returns ``(body, version)``. Either is ``None`` when the caller must
    fall back to the file registry (no investigation, no production
    alias, an unpinnable path, or a store fault).

    A fresh resolve of a not-yet-pinned key persists the pin in the same
    call so the very next turn on the SAME investigation sees the pin,
    not the live alias.

    ``investigation_model`` is the SQLModel class for the row (VR or
    malware) so this helper stays module-agnostic while still writing
    the pin back to the concrete table.
    """
    if not investigation_id:
        # An out-of-investigation resolve (tests, dev scripts) has
        # nothing to pin against. Preserve the pre-pin behaviour:
        # resolve the live production alias.
        try:
            versioned = await store.resolve(key, alias="production")
        except (SQLAlchemyError, OSError, RuntimeError) as exc:
            _log.warning(
                "prompt version store resolve failed key=%s: %s (using file)",
                key, exc,
            )
            return (None, None)
        if versioned is None:
            return (None, None)
        return (versioned.body, versioned.version)

    async with UnitOfWork() as uow:
        row = (await uow.session.exec(
            select(investigation_model).where(
                investigation_model.id == investigation_id,
            )
        )).first()
        pins = _decode_pins(getattr(row, "prompt_pins_json", None)) if row is not None else {}
        pinned_version = pins.get(key)

        if pinned_version is not None:
            # Existing pin: resolve the exact version. Fail-open on a
            # store fault so the caller still falls back to the file.
            try:
                versioned = await store.resolve(key, version=pinned_version)
            except (SQLAlchemyError, OSError, RuntimeError) as exc:
                _log.warning(
                    "prompt version store resolve (pinned) failed "
                    "key=%s version=%s: %s (using file)",
                    key, pinned_version, exc,
                )
                return (None, None)
            if versioned is None:
                # The pin points at a version that no longer exists in
                # the store. Fall back to the file rather than trying
                # to re-pin: the operator can inspect the divergence.
                _log.warning(
                    "prompt pin key=%s version=%s missing from store "
                    "inv=%s (using file)",
                    key, pinned_version, investigation_id,
                )
                return (None, None)
            return (versioned.body, versioned.version)

        # First resolve: read the live production alias, then persist
        # the pin so the next turn (any next turn on this row) resolves
        # by the pinned version, not the live alias.
        try:
            versioned = await store.resolve(key, alias="production")
        except (SQLAlchemyError, OSError, RuntimeError) as exc:
            _log.warning(
                "prompt version store resolve failed key=%s: %s (using file)",
                key, exc,
            )
            return (None, None)
        if versioned is None:
            # No production alias set -- unpinnable path. Do NOT touch
            # the pin map: a later alias flip should then produce a pin
            # on the next turn.
            return (None, None)
        if row is not None:
            pins[key] = versioned.version
            row.prompt_pins_json = json.dumps(pins)
            row.updated_at = utc_now()
            uow.session.add(row)
            await uow.session.commit()
        return (versioned.body, versioned.version)
