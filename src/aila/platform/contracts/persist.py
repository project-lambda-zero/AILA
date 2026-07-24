from __future__ import annotations

from typing import Any, Protocol, TypeVar, runtime_checkable

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import SQLModel

_T = TypeVar("_T", bound=SQLModel)


@runtime_checkable
class Persistable(Protocol):
    """Protocol for models that declare a natural key for idempotent upsert."""

    __natural_key__: tuple[str, ...]


class PersistContract:
    """Reads __natural_key__ from SQLModel class, generates ON CONFLICT DO UPDATE.

    Per D-05: models with __natural_key__ get atomic upsert via PostgreSQL
    ON CONFLICT. Models without it get plain insert. Replaces both db_upsert()
    and the hardcoded ON CONFLICT in reporting.py.

    CRITICAL: Does NOT call session.commit(). The caller (UoW or service)
    owns the transaction boundary.
    """

    @staticmethod
    async def upsert(
        session: AsyncSession,
        record: SQLModel,
    ) -> None:
        """Idempotent upsert using ON CONFLICT DO UPDATE if __natural_key__ declared."""
        from sqlalchemy.dialects.postgresql import insert as sa_insert

        model_class = type(record)
        natural_key: tuple[str, ...] | None = getattr(model_class, "__natural_key__", None)
        data = record.model_dump(exclude_unset=False)
        # Exclude id when None -- let DB sequence generate it
        if data.get("id") is None:
            data.pop("id", None)

        if natural_key:
            update_fields = {
                k: v for k, v in data.items()
                if k not in natural_key and k != "id"
            }
            stmt = (
                sa_insert(model_class)
                .values(**data)
                .on_conflict_do_update(
                    index_elements=list(natural_key),
                    set_=update_fields,
                )
            )
            # session.execute (not exec): exec is SQLModel's typed shim for
            # Select queries; execute is the SQLAlchemy method that accepts
            # arbitrary DML, so no call-overload type-ignore is needed.
            await session.execute(stmt)
        else:
            session.add(record)

    @staticmethod
    async def upsert_many(
        session: AsyncSession,
        records: list[SQLModel],
        *,
        batch_size: int = 500,
    ) -> None:
        """Batch upsert for multiple records of one model type.

        Collapses N inserts into one INSERT ... VALUES ((...), (...), ...) per
        batch_size chunk -- one round-trip per chunk instead of one per record.
        Records whose model declares __natural_key__ use ON CONFLICT DO UPDATE
        keyed on it; the SET clause references the excluded (proposed) row so
        each conflicting row takes its own incoming values. Records without a
        natural key are added plainly. The caller owns the transaction boundary
        (no commit here).
        """
        from sqlalchemy.dialects.postgresql import insert as sa_insert

        if not records:
            return
        model_class = type(records[0])
        if any(type(r) is not model_class for r in records):
            raise TypeError("upsert_many requires a homogeneous record list")
        natural_key: tuple[str, ...] | None = getattr(model_class, "__natural_key__", None)

        for chunk_start in range(0, len(records), batch_size):
            chunk = records[chunk_start:chunk_start + batch_size]
            values: list[dict[str, Any]] = []
            for record in chunk:
                data = record.model_dump(exclude_unset=False)
                if data.get("id") is None:
                    data.pop("id", None)
                values.append(data)
            if natural_key:
                insert_stmt = sa_insert(model_class).values(values)
                update_fields = {
                    k: insert_stmt.excluded[k]
                    for k in values[0]
                    if k not in natural_key and k != "id"
                }
                stmt = insert_stmt.on_conflict_do_update(
                    index_elements=list(natural_key),
                    set_=update_fields,
                )
                await session.execute(stmt)
            else:
                session.add_all([model_class(**v) for v in values])
