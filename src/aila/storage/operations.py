"""Generic database operation helpers that eliminate copy-pasted upsert/delete blocks.

db_upsert() and db_delete() were introduced to replace 14 identical upsert and
delete patterns scattered across the codebase.  They provide a single definition
with consistent transaction scope: each helper performs its own session.commit()
so callers do not need to manage the transaction boundary.

cached_fetch() wraps the check-fetch-write cache pattern used by intelligence
tools (NVD, EPSS/KEV, OSV) into a generic helper.  Callers provide three
callables -- get, fetch, set -- and receive the result plus a "cache"/"live" label.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import SQLModel

__all__ = ["db_upsert", "db_delete", "cached_fetch", "is_cache_fresh"]

_T = TypeVar("_T", bound=SQLModel)


async def db_upsert(
    session: AsyncSession,
    model_class: type[_T],
    lookup_filter: Any,
    update_fields: dict[str, Any],
) -> tuple[_T, bool]:
    """Look up a record by filter; update fields if found, create a new row if not.

    Conflict resolution: SELECT then UPDATE/INSERT (optimistic read).  This is
    appropriate for low-contention tables like asset tags, config entries, and
    provider configs.  For high-contention tables (e.g. LatestFindingRecord),
    use sa_insert().on_conflict_do_update() directly to get atomic upsert semantics.

    Transaction scope: commits immediately.  Do not call inside an outer
    transaction that you intend to roll back -- the commit is unconditional.

    Args:
        session: Active AsyncSession.
        model_class: The SQLModel table class to operate on.
        lookup_filter: A SQLAlchemy WHERE clause expression used to find an
            existing row (e.g. Model.col == value).
        update_fields: Dict of field names to values applied on update and used
            as constructor kwargs on insert.

    Returns:
        Tuple of (record, created) where created is True when a new row was
        inserted, False when an existing row was updated.

    Example:
        record, created = await db_upsert(
            session,
            AssetTagRecord,
            lookup_filter=(AssetTagRecord.system_id == sid) & (AssetTagRecord.tag_key == key),
            update_fields={"system_id": sid, "tag_key": key, "tag_value": value},
        )
    """
    from sqlmodel import select

    result = await session.exec(select(model_class).where(lookup_filter))
    existing = result.first()
    if existing is not None:
        for field_name, value in update_fields.items():
            setattr(existing, field_name, value)
        session.add(existing)
        await session.commit()
        await session.refresh(existing)
        return existing, False
    record = model_class(**update_fields)  # type: ignore[call-arg]
    session.add(record)
    await session.commit()
    await session.refresh(record)
    return record, True


async def db_delete(
    session: AsyncSession,
    model_class: type[_T],
    lookup_filter: Any,
) -> list[_T]:
    """Delete all records matching the filter and return the deleted records.

    Commits only if at least one record was deleted.  Returns an empty list
    without committing if no records match.

    Args:
        session: Active AsyncSession.
        model_class: The SQLModel table class to delete from.
        lookup_filter: A SQLAlchemy WHERE clause expression.

    Returns:
        List of deleted model instances (may be empty).

    Example:
        deleted = await db_delete(
            session,
            AssetTagRecord,
            (AssetTagRecord.system_id == sid) & (AssetTagRecord.tag_key == key),
        )
    """
    from sqlmodel import select

    result = await session.exec(select(model_class).where(lookup_filter))
    records = list(result)
    for record in records:
        await session.delete(record)
    if records:
        await session.commit()
    return records


def is_cache_fresh(payload: dict | None, *, force_refresh: bool = False) -> bool:
    """Return True when cached data should be used.

    Platform cache policy: keep-forever. Cached data is always considered fresh
    unless force_refresh is explicitly True. Any module can use this -- the
    policy is platform-level, not module-specific.
    """
    if not payload:
        return False
    if force_refresh:
        return False
    return True


def cached_fetch(
    *,
    get_fn: Callable[[], dict | None],
    fetch_fn: Callable[[], Any],
    set_fn: Callable[[Any], None],
    force_refresh: bool = False,
    freshness_check: Callable[[dict | None], bool] | None = None,
) -> tuple[Any, str]:
    """Generic check-fetch-write cache helper.

    Calls get_fn() to retrieve a cached payload. If freshness_check(payload)
    returns True and force_refresh is False, returns (payload, "cache").
    Otherwise calls fetch_fn() for live data, stores it via set_fn(data),
    and returns (data, "live").

    Args:
        get_fn: Retrieves the cached payload, or None on miss.
        fetch_fn: Fetches live data from the upstream source.
        set_fn: Persists the live data to cache.
        force_refresh: When True, bypasses freshness check entirely.
        freshness_check: Callable that returns True when payload is usable.
            Defaults to a simple truthiness check (payload is not None).
    """
    _is_fresh = freshness_check or is_cache_fresh

    payload = get_fn()
    if not force_refresh and _is_fresh(payload):
        return payload, "cache"
    data = fetch_fn()
    set_fn(data)
    return data, "live"


async def async_cached_fetch(
    *,
    get_fn,
    fetch_fn,
    set_fn,
    force_refresh: bool = False,
    freshness_check=None,
) -> tuple:
    """Async version of cached_fetch where get_fn, fetch_fn, and set_fn are async callables."""
    _is_fresh = freshness_check or is_cache_fresh

    payload = await get_fn()
    if not force_refresh and _is_fresh(payload):
        return payload, "cache"
    data = fetch_fn()
    await set_fn(data)
    return data, "live"
