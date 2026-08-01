"""Lazy per-investigation prompt pin resolution (RFC-09 criterion 4 +
RFC-10 canary routing).

The distinctive RFC-09 rule for a long-running audited investigation is
that a live production-alias flip must NEVER rewrite the prompt on a
turn that belongs to an already-running investigation. This module owns
the read/persist half of that rule so both researcher modules resolve
through the same code path.

RFC-10 (#34) extends the first-turn resolve: instead of reading the
``production`` alias directly, the first turn asks
:meth:`AgentLifecycleController.resolve_version_for_investigation` to
choose between the active canary and the production alias by
deterministic hash of the investigation id. The chosen version is
pinned onto the row so every later turn on the same investigation
resolves that exact version -- keeping the transcript on a single
prompt version across the entire run even when the alias or canary
assignment flips mid-run.

Behaviour:

1. Look up the pin for ``key`` in the row's ``prompt_pins_json``.
2. If pinned, resolve that exact version from the version store and
   return its body + version. Nothing else changes.
3. If not pinned, resolve the version via
   :meth:`AgentLifecycleController.resolve_version_for_investigation`
   (canary or production, chosen by hashed cohort). When a version
   comes back, persist ``{key: version}`` into the row's pin map in
   a single UPDATE and return that body + version.
4. When the store raises (fail-open), or neither the canary nor the
   production alias points at anything, return ``(None, None)`` so
   the caller can fall back to its file registry. Store / controller
   faults must never block a turn.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import select

from aila.platform.contracts._common import utc_now
from aila.platform.lifecycle.controller import AgentLifecycleController
from aila.platform.prompts.version_store import PromptVersionStore
from aila.platform.uow import UnitOfWork

__all__ = ["resolve_pinned_prompt"]

_log = logging.getLogger(__name__)

# Process-wide controller singleton. The class carries no per-request
# state; :meth:`resolve_version_for_investigation` opens its own
# session per call via ``async_session_scope`` so reusing one instance
# never leaks connections. Kept module-level so pinning does not pay
# the controller construction cost on every call.
_CONTROLLER = AgentLifecycleController()


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
        # nothing to pin against AND no investigation id to bucket a
        # canary cohort by. Preserve the pre-pin behaviour: resolve
        # the live production alias directly.
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

        # First resolve: route through the lifecycle controller so a
        # canary assignment (RFC-10) can hand this investigation the
        # candidate version deterministically by its hashed cohort.
        # The controller falls back to the production alias when no
        # active canary is on record, so this replaces the prior
        # direct ``store.resolve(alias='production')`` call without
        # regressing the no-canary path. A controller fault degrades
        # to a direct alias resolve so a broken lifecycle table never
        # blocks a turn.
        resolved_version: str | None = None
        try:
            route = await _CONTROLLER.resolve_version_for_investigation(
                key=key, investigation_id=investigation_id,
            )
            resolved_version = route.version
            if route.on_canary:
                _log.info(
                    "prompt pin canary route inv=%s key=%s version=%s "
                    "bucket=%d cohort=%s",
                    investigation_id, key, route.version,
                    route.bucket, route.cohort_percent,
                )
        except (SQLAlchemyError, OSError, RuntimeError, ValueError) as exc:
            _log.warning(
                "prompt lifecycle route resolve failed key=%s inv=%s: %s "
                "(falling back to direct production alias)",
                key, investigation_id, exc,
            )
            try:
                versioned = await store.resolve(key, alias="production")
            except (SQLAlchemyError, OSError, RuntimeError) as fallback_exc:
                _log.warning(
                    "prompt version store resolve failed key=%s: %s (using file)",
                    key, fallback_exc,
                )
                return (None, None)
            if versioned is None:
                return (None, None)
            resolved_version = versioned.version

        if resolved_version is None:
            # No production alias AND no canary version -- unpinnable
            # path. Do NOT touch the pin map: a later alias flip should
            # then produce a pin on the next turn.
            return (None, None)

        # Resolve the chosen version's body from the store. The
        # lifecycle controller returned only the version id; the store
        # still owns body materialisation. A store fault on this fetch
        # degrades to the file baseline like every other store path.
        try:
            versioned = await store.resolve(key, version=resolved_version)
        except (SQLAlchemyError, OSError, RuntimeError) as exc:
            _log.warning(
                "prompt version store resolve (routed) failed key=%s "
                "version=%s: %s (using file)",
                key, resolved_version, exc,
            )
            return (None, None)
        if versioned is None:
            _log.warning(
                "prompt lifecycle route returned version=%s but store "
                "missing key=%s inv=%s (using file)",
                resolved_version, key, investigation_id,
            )
            return (None, None)
        if row is not None:
            pins[key] = versioned.version
            row.prompt_pins_json = json.dumps(pins)
            row.updated_at = utc_now()
            uow.session.add(row)
            await uow.session.commit()
        return (versioned.body, versioned.version)
