"""Publish :class:`EntityStatusChanged` for every committed status write.

Modules register the ORM classes whose ``status`` column they want
announced via :func:`track_status_changes`. A single pair of SQLAlchemy
session listeners then covers every writer of that column, wherever it
lives (API handlers, workers, reconcilers), without each call site
having to remember to publish:

* ``after_flush`` reads the attribute history of tracked rows in
  ``session.new`` / ``session.dirty`` and stashes one event per changed
  status on ``session.info``;
* ``after_commit`` publishes the stashed events on the domain event bus,
  so subscribers only ever see committed transitions;
* ``after_rollback`` discards them.

Bulk Core ``UPDATE ... SET status = ...`` statements bypass the ORM unit
of work and are NOT observed; writers that use them must publish
:class:`EntityStatusChanged` themselves.

Ownership: Platform. Modules call :func:`track_status_changes` with their
own record classes; this module never imports from ``aila.modules``.
"""
from __future__ import annotations

import threading
from typing import Any

from sqlalchemy import event, inspect
from sqlalchemy.orm import Session

from .bus import publish
from .domain_events import EntityStatusChanged, EntityStatusChangedPayload

__all__ = ["track_status_changes"]

_PENDING_KEY = "aila_pending_entity_status_events"

# Tracked ORM class -> (module_id, entity_kind).
_TRACKED: dict[type[Any], tuple[str, str]] = {}
_INSTALL_LOCK = threading.Lock()
_installed = False


def track_status_changes(model: type[Any], *, module_id: str, entity_kind: str) -> None:
    """Announce committed ``status`` changes on ``model`` rows.

    ``model`` must be an ORM-mapped class with a string ``status`` column
    and a ``team_id`` column (delivery scope). Registering the same class
    twice overwrites the earlier labels.
    """
    global _installed
    with _INSTALL_LOCK:
        _TRACKED[model] = (module_id, entity_kind)
        if not _installed:
            event.listen(Session, "after_flush", _collect_status_changes)
            event.listen(Session, "after_commit", _publish_pending)
            event.listen(Session, "after_rollback", _discard_pending)
            _installed = True


def _collect_status_changes(session: Session, _flush_context: Any) -> None:
    for obj in (*session.new, *session.dirty):
        labels = _TRACKED.get(type(obj))
        if labels is None:
            continue
        history = inspect(obj).attrs.status.history
        if not history.added:
            continue
        new_status = str(history.added[-1])
        previous = str(history.deleted[0]) if history.deleted else None
        if previous == new_status:
            continue
        module_id, entity_kind = labels
        session.info.setdefault(_PENDING_KEY, []).append(
            EntityStatusChanged(
                team_id=obj.team_id,
                source_module=module_id,
                payload=EntityStatusChangedPayload(
                    module_id=module_id,
                    entity_kind=entity_kind,
                    entity_id=str(obj.id),
                    previous_status=previous,
                    status=new_status,
                ),
            ),
        )


def _publish_pending(session: Session) -> None:
    for pending in session.info.pop(_PENDING_KEY, ()):
        publish(pending)


def _discard_pending(session: Session) -> None:
    session.info.pop(_PENDING_KEY, None)
