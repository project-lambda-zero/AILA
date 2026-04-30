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
        # Exclude id when None — let DB sequence generate it
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
            await session.exec(stmt)  # type: ignore[call-overload]
        else:
            session.add(record)

    @staticmethod
    async def upsert_many(
        session: AsyncSession,
        records: list[SQLModel],
    ) -> None:
        """Batch upsert for multiple records of the same model type."""
        if not records:
            return
        for record in records:
            await PersistContract.upsert(session, record)
